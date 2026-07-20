from __future__ import annotations

import queue
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import protocol_register


class _CookieJar:
    def __init__(self):
        self.values = {}
        self.jar = []

    def set(self, name, value, domain=None, path="/"):
        self.values[name] = value
        self.jar.append(SimpleNamespace(name=name, value=value, domain=domain, path=path))

    def get(self, name):
        return self.values.get(name, "")


class _Response:
    def __init__(self, text="", status_code=200, headers=None, url="https://accounts.x.ai/"):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url


class _Session:
    def __init__(self, *args, **kwargs):
        self.headers = {}
        self.cookies = _CookieJar()
        self.get_urls = []
        self.post_calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def get(self, url, *args, **kwargs):
        self.get_urls.append(url)
        if url.endswith("/sign-up?redirect=grok-com"):
            return _Response('<script src="/_next/static/chunk.js"></script>')
        if url.endswith("/_next/static/chunk.js"):
            return _Response('self.__next="7f' + 'a' * 40 + '"')
        if "set-cookie" in url:
            self.cookies.set("sso", "sso-token", domain=".x.ai")
            self.cookies.set("sso-rw", "rw-token", domain=".x.ai")
        return _Response()

    def post(self, url, data=None, json=None, headers=None, timeout=None):
        self.post_calls.append({"url": url, "data": data, "json": json, "headers": headers or {}})
        if url.endswith("CreateEmailValidationCode"):
            return _Response(status_code=200, headers={"grpc-status": "0"})
        if url.endswith("VerifyEmailValidationCode"):
            return _Response(status_code=200, headers={"grpc-status": "0"})
        if url.endswith("/sign-up"):
            return _Response('1:"https://auth.grok.com/set-cookie?q=abc"1:')
        if url.endswith("SetTosAcceptedVersion"):
            return _Response(status_code=200, headers={"grpc-status": "0"})
        return _Response()


class ProtocolRegisterTests(unittest.TestCase):
    def test_fetch_action_id_scans_next_static_scripts(self):
        session = _Session()

        action_id = protocol_register.fetch_action_id(session, force=True)

        self.assertEqual(action_id, "7f" + "a" * 40)
        self.assertIn("https://accounts.x.ai/sign-up?redirect=grok-com", session.get_urls)
        self.assertIn("https://accounts.x.ai/_next/static/chunk.js", session.get_urls)

    def test_register_one_protocol_creates_account_and_returns_sso_without_browser(self):
        with (
            mock.patch.object(protocol_register.cf_requests, "Session", _Session),
            mock.patch.object(protocol_register.reg, "get_email_and_token", return_value=("user@example.com", "mail-token")),
            mock.patch.object(protocol_register.reg, "get_oai_code", return_value="ABC-123"),
            mock.patch.object(protocol_register.reg, "build_profile", return_value=("Neo", "Lin", "Passw0rd!")),
            mock.patch.object(protocol_register, "solve_turnstile", return_value="turnstile-token"),
            mock.patch.object(protocol_register.reg, "mark_used") as mark_used,
        ):
            result = protocol_register.register_one_protocol(config={"proxy": "", "protocol_register_max_attempts": 1})

        self.assertTrue(result["ok"])
        self.assertEqual(result["email"], "user@example.com")
        self.assertEqual(result["password"], "Passw0rd!")
        self.assertEqual(result["sso"], "sso-token")
        self.assertEqual(result["sso_rw"], "rw-token")
        self.assertEqual(result["mint_method"], "protocol_register")
        mark_used.assert_called_once_with("user@example.com", "Passw0rd!")

    def test_register_one_protocol_passes_send_timestamp_to_mail_reader(self):
        captured_kwargs = {}

        def fake_get_oai_code(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return "ABC-123"

        with (
            mock.patch.object(protocol_register.cf_requests, "Session", _Session),
            mock.patch.object(protocol_register.reg, "get_email_and_token", return_value=("user@example.com", "mail-token")),
            mock.patch.object(protocol_register.reg, "get_oai_code", side_effect=fake_get_oai_code),
            mock.patch.object(protocol_register.reg, "build_profile", return_value=("Neo", "Lin", "Passw0rd!")),
            mock.patch.object(protocol_register, "solve_turnstile", return_value="turnstile-token"),
            mock.patch.object(protocol_register.reg, "mark_used"),
        ):
            result = protocol_register.register_one_protocol(config={"proxy": "", "protocol_register_max_attempts": 1})

        self.assertTrue(result["ok"])
        self.assertIn("issued_after", captured_kwargs)
        self.assertIsInstance(captured_kwargs["issued_after"], float)

    def test_register_one_protocol_does_not_persist_email_error_on_otp_timeout(self):
        timeout_error = Exception("Hotmail/Outlook 在 30s 内未收到验证码邮件: user@example.com")

        with (
            mock.patch.object(protocol_register.cf_requests, "Session", _Session),
            mock.patch.object(protocol_register.reg, "get_email_and_token", return_value=("user@example.com", "mail-token")),
            mock.patch.object(protocol_register.reg, "get_oai_code", side_effect=timeout_error),
            mock.patch.object(protocol_register.reg, "mark_error") as mark_error,
            mock.patch.object(protocol_register.reg, "release_email", create=True) as release_email,
        ):
            result = protocol_register.register_one_protocol(config={"proxy": ""})

        self.assertFalse(result["ok"])
        self.assertIn("get_oai_code", result["error"])
        mark_error.assert_not_called()
        release_email.assert_called_once_with("user@example.com")


class RegisterCliProtocolBranchTests(unittest.TestCase):
    def test_register_one_uses_protocol_branch_before_browser_start(self):
        import register_cli

        q = queue.Queue()
        with tempfile.TemporaryDirectory() as td:
            accounts = Path(td) / "accounts.txt"
            with (
                mock.patch.object(register_cli.reg, "config", {"protocol_register": True, "cpa_export_enabled": False}),
                mock.patch.object(register_cli, "_ensure_browser", side_effect=AssertionError("browser started")),
                mock.patch.object(protocol_register, "register_one_protocol", return_value={
                    "ok": True,
                    "email": "user@example.com",
                    "password": "Passw0rd!",
                    "sso": "sso-token",
                    "sso_rw": "rw-token",
                    "profile": {"password": "Passw0rd!"},
                    "cookies": [{"name": "sso", "value": "sso-token", "domain": ".x.ai"}],
                }),
            ):
                job = register_cli.register_one(1, 1, 1, str(accounts), mint_queue=q)

            self.assertIsNotNone(job)
            self.assertEqual(accounts.read_text(encoding="utf-8"), "user@example.com----Passw0rd!----sso-token\n")
            self.assertEqual(q.get_nowait()["email"], "user@example.com")


if __name__ == "__main__":
    unittest.main()

class ProtocolRegisterSolverProxyTests(unittest.TestCase):
    def test_2captcha_request_uses_registration_proxy_and_returns_token(self):
        calls = []

        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                return None
            def json(self):
                return self._payload

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/createTask"):
                return JsonResponse({"errorId": 0, "taskId": "task-2captcha"})
            if url.endswith("/getTaskResult"):
                return JsonResponse(
                    {
                        "errorId": 0,
                        "status": "ready",
                        "solution": {
                            "token": "z" * 64,
                            "userAgent": "Mozilla/5.0 Chrome/140.0.0.0",
                        },
                    }
                )
            raise AssertionError(url)

        with (
            mock.patch("requests.post", side_effect=fake_post),
            mock.patch("requests.get", side_effect=AssertionError("local solver should not be used")),
            mock.patch.object(protocol_register.reg, "get_thread_proxy", return_value=""),
            mock.patch.object(protocol_register.time, "sleep", return_value=None),
        ):
            token = protocol_register.solve_turnstile(
                config={
                    "proxy": "socks5h://user:pass@203.0.113.10:1080",
                    "turnstile_solver_provider": "2captcha",
                    "yescaptcha_key": "",
                    "twocaptcha_key": "two-key",
                    "twocaptcha_pass_proxy": True,
                    "twocaptcha_timeout": 5,
                    "twocaptcha_poll_interval": 0.01,
                    "turnstile_site_key": "site-key",
                }
            )

        self.assertEqual(token, "z" * 64)
        create_payload = calls[0][1]["json"]
        self.assertEqual(create_payload["clientKey"], "two-key")
        task = create_payload["task"]
        self.assertEqual(task["type"], "TurnstileTask")
        self.assertEqual(task["websiteURL"], "https://accounts.x.ai")
        self.assertEqual(task["websiteKey"], "site-key")
        self.assertEqual(task["proxyType"], "socks5")
        self.assertEqual(task["proxyAddress"], "203.0.113.10")
        self.assertEqual(task["proxyPort"], 1080)
        self.assertEqual(task["proxyLogin"], "user")
        self.assertEqual(task["proxyPassword"], "pass")

    def test_2captcha_can_use_proxyless_task_when_proxy_passing_disabled(self):
        calls = []

        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                return None
            def json(self):
                return self._payload

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/createTask"):
                return JsonResponse({"errorId": 0, "taskId": "task-2captcha"})
            return JsonResponse({"errorId": 0, "status": "ready", "solution": {"token": "p" * 64}})

        with (
            mock.patch("requests.post", side_effect=fake_post),
            mock.patch("requests.get", side_effect=AssertionError("local solver should not be used")),
            mock.patch.object(protocol_register.time, "sleep", return_value=None),
        ):
            token = protocol_register.solve_turnstile(
                config={
                    "proxy": "http://user:pass@203.0.113.10:8080",
                    "turnstile_solver_provider": "2captcha",
                    "yescaptcha_key": "",
                    "twocaptcha_key": "two-key",
                    "twocaptcha_pass_proxy": False,
                    "twocaptcha_timeout": 5,
                    "twocaptcha_poll_interval": 0.01,
                }
            )

        self.assertEqual(token, "p" * 64)
        task = calls[0][1]["json"]["task"]
        self.assertEqual(task["type"], "TurnstileTaskProxyless")
        self.assertNotIn("proxyAddress", task)

    def test_2captcha_failure_does_not_fall_back_to_local_solver_when_selected(self):
        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def json(self):
                return self._payload

        def fake_post(url, **kwargs):
            if url.endswith("/createTask"):
                return JsonResponse({"errorId": 12, "errorDescription": "bad key"})
            raise AssertionError(url)

        with (
            mock.patch("requests.post", side_effect=fake_post),
            mock.patch("requests.get") as get_mock,
        ):
            token = protocol_register.solve_turnstile(
                config={
                    "turnstile_solver_provider": "2captcha",
                    "yescaptcha_key": "",
                    "twocaptcha_key": "bad-key",
                }
            )

        self.assertIsNone(token)
        get_mock.assert_not_called()

    def test_local_provider_ignores_configured_2captcha_key(self):
        calls = []

        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                return None
            def json(self):
                return self._payload

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/turnstile"):
                return JsonResponse({"taskId": "task-local"})
            return JsonResponse({"solution": {"token": "l" * 64}})

        with (
            mock.patch("requests.post") as post_mock,
            mock.patch("requests.get", side_effect=fake_get),
        ):
            token = protocol_register.solve_turnstile(
                config={
                    "turnstile_solver_provider": "local",
                    "twocaptcha_key": "two-key",
                    "protocol_solver_poll_timeout": 1,
                    "protocol_solver_poll_interval": 0.01,
                }
            )

        self.assertEqual(token, "l" * 64)
        self.assertTrue(calls[0][0].endswith("/turnstile"))
        post_mock.assert_not_called()

    def test_local_solver_request_includes_config_proxy(self):
        calls = []

        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                return None
            def json(self):
                return self._payload

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/turnstile"):
                return JsonResponse({"taskId": "task-1"})
            return JsonResponse({"solution": {"token": "x" * 64}})

        with mock.patch("requests.get", side_effect=fake_get):
            token = protocol_register.solve_turnstile(
                config={
                    "proxy": "http://user:pass@203.0.113.10:8080",
                    "yescaptcha_key": "",
                    "protocol_solver_url": "http://127.0.0.1:5072",
                    "protocol_solver_poll_timeout": 1,
                    "protocol_solver_poll_interval": 0.01,
                }
            )

        self.assertEqual(token, "x" * 64)
        turnstile_call = calls[0][1]["params"]
        self.assertEqual(turnstile_call["proxy"], "http://user:pass@203.0.113.10:8080")

class ProtocolRegisterSolverFingerprintParamTests(unittest.TestCase):
    def test_local_solver_request_includes_timezone_and_locale_overrides(self):
        calls = []

        class JsonResponse:
            status_code = 200
            text = "{}"
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                return None
            def json(self):
                return self._payload

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/turnstile"):
                return JsonResponse({"taskId": "task-1"})
            return JsonResponse({"solution": {"token": "y" * 64}})

        with mock.patch("requests.get", side_effect=fake_get):
            token = protocol_register.solve_turnstile(
                config={
                    "proxy": "",
                    "yescaptcha_key": "",
                    "protocol_solver_url": "http://127.0.0.1:5072",
                    "browser_timezone": "America/New_York",
                    "protocol_solver_locale": "en-US",
                    "protocol_solver_accept_language": "en-US,en;q=0.9",
                    "protocol_solver_poll_timeout": 1,
                    "protocol_solver_poll_interval": 0.01,
                }
            )

        self.assertEqual(token, "y" * 64)
        params = calls[0][1]["params"]
        self.assertEqual(params["timezone"], "America/New_York")
        self.assertEqual(params["locale"], "en-US")
        self.assertEqual(params["accept_language"], "en-US,en;q=0.9")

class ProtocolRegisterThreadProxyTests(unittest.TestCase):
    def test_solver_proxy_prefers_thread_pinned_proxy_even_with_config_override(self):
        with mock.patch.object(protocol_register.reg, "get_thread_proxy", return_value="http://thread-proxy:9000"):
            proxy = protocol_register._solver_proxy_url({"proxy": "", "protocol_solver_pass_proxy": True})
        self.assertEqual(proxy, "http://thread-proxy:9000")

    def test_pool_random_config_is_resolved_and_pinned_for_protocol_http(self):
        with (
            mock.patch("proxy_pool.resolve_special", return_value="http://user:pass@203.0.113.10:8080"),
            mock.patch.object(protocol_register.reg, "get_thread_proxy", return_value=""),
            mock.patch.object(protocol_register.reg, "set_thread_proxy") as set_thread_proxy,
        ):
            proxies = protocol_register._proxy_dict({"proxy": "pool:random"})

        self.assertEqual(proxies["http"], "http://user:pass@203.0.113.10:8080")
        self.assertEqual(proxies["https"], "http://user:pass@203.0.113.10:8080")
        set_thread_proxy.assert_called_once_with("http://user:pass@203.0.113.10:8080")

    def test_pool_random_config_is_not_used_as_literal_solver_proxy(self):
        with (
            mock.patch("proxy_pool.resolve_special", return_value="http://203.0.113.20:8080"),
            mock.patch.object(protocol_register.reg, "get_thread_proxy", return_value=""),
            mock.patch.object(protocol_register.reg, "set_thread_proxy"),
        ):
            proxy = protocol_register._solver_proxy_url(
                {"proxy": "pool:random", "protocol_solver_pass_proxy": True}
            )

        self.assertEqual(proxy, "http://203.0.113.20:8080")
