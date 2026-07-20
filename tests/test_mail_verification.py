from __future__ import annotations

import unittest
import time
from datetime import datetime, timezone
from unittest import mock

import grok_register_ttk as reg


class _GraphResponse:
    status_code = 200
    text = "{}"

    def __init__(self, messages):
        self._messages = messages

    def json(self):
        return {"value": self._messages}


def _graph_message(subject: str, received_ts: float, recipient: str) -> dict:
    received = datetime.fromtimestamp(received_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "subject": subject,
        "receivedDateTime": received,
        "from": {"emailAddress": {"address": "no-reply@x.ai"}},
        "toRecipients": [{"emailAddress": {"address": recipient}}],
        "ccRecipients": [],
        "body": {"contentType": "text", "content": f"Your code is {subject}"},
    }


class HotmailIssuedAfterTests(unittest.TestCase):
    def test_graph_reader_skips_codes_received_before_current_send_time(self):
        issued_after = time.time() - 30
        target = "main+retry@example.com"
        messages = [
            _graph_message("OLD-111 xAI", issued_after - 20, target),
            _graph_message("NEW-222 xAI", issued_after + 5, target),
        ]

        with (
            mock.patch.object(
                reg,
                "config",
                {
                    "hotmail_recent_seconds": 900,
                    "hotmail_imap_last_n": 30,
                    "hotmail_require_recipient_match": True,
                },
            ),
            mock.patch.object(reg, "http_get", return_value=_GraphResponse(messages)),
        ):
            code = reg.hotmail_graph_get_code(
                "main@example.com",
                target,
                "access-token",
                issued_after=issued_after,
            )

        self.assertEqual(code, "NEW-222")

    def test_hotmail_get_oai_code_passes_issued_after_to_graph_reader(self):
        token = "test-dev-token"
        issued_after = 1_234.5
        reg._hotmail_token_map[token] = {
            "account": {"email": "main@example.com"},
            "email": "main+retry@example.com",
            "created_at": 1_000,
        }
        captured_kwargs = {}

        def fake_graph_get_code(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return "ABC-123"

        try:
            with (
                mock.patch.object(reg, "hotmail_detect_protocol", return_value="graph"),
                mock.patch.object(reg, "_hotmail_refresh_token_with_endpoints", return_value="access-token"),
                mock.patch.object(reg, "hotmail_graph_get_code", side_effect=fake_graph_get_code),
            ):
                code = reg.hotmail_get_oai_code(
                    token,
                    "main+retry@example.com",
                    timeout=1,
                    issued_after=issued_after,
                )
        finally:
            reg._hotmail_token_map.pop(token, None)

        self.assertEqual(code, "ABC-123")
        self.assertEqual(captured_kwargs["issued_after"], issued_after)


class VerificationCodeExtractionTests(unittest.TestCase):
    def test_cloudflare_subject_code_wins_over_body_noise(self):
        code = reg.extract_verification_code(
            "some html/css text with per-100 before the real subject",
            subject="SpaceXAI confirmation code: 9F0-3AK",
        )

        self.assertEqual(code, "9F0-3AK")

    def test_lowercase_body_fragment_is_not_treated_as_code(self):
        self.assertIsNone(reg.extract_verification_code("font-size per-100 margin"))

    def test_legacy_subject_shape_still_works(self):
        self.assertEqual(reg.extract_verification_code("", subject="ABC-123 xAI"), "ABC-123")


class CloudflareMailDirectProxyTests(unittest.TestCase):
    class Response:
        status_code = 200
        text = "{}"

        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def test_create_temp_address_does_not_inherit_registration_proxy(self):
        calls = []

        def fake_post(*args, **kwargs):
            calls.append((args, kwargs))
            return self.Response({"address": "u@example.com", "jwt": "mail-token"})

        with (
            mock.patch.object(
                reg,
                "config",
                {
                    "cloudflare_admin_password": "admin",
                    "defaultDomains": "example.com",
                    "proxy": "pool:random",
                },
            ),
            mock.patch.object(reg, "http_post", side_effect=fake_post),
            mock.patch.object(reg, "get_thread_proxy", return_value="http://proxy.example:8080"),
        ):
            email, token = reg.cloudflare_create_temp_address("https://mail.example")

        self.assertEqual(email, "u@example.com")
        self.assertEqual(token, "mail-token")
        self.assertEqual(calls[0][1].get("proxies"), {})

    def test_get_messages_and_detail_are_direct(self):
        calls = []

        def fake_get(*args, **kwargs):
            calls.append((args, kwargs))
            if str(args[0]).endswith("/api/parsed_mails"):
                return self.Response({"messages": []})
            return self.Response({"data": {"subject": "SpaceXAI confirmation code: 9F0-3AK"}})

        with (
            mock.patch.object(reg, "config", {"proxy": "pool:random"}),
            mock.patch.object(reg, "http_get", side_effect=fake_get),
            mock.patch.object(reg, "get_thread_proxy", return_value="http://proxy.example:8080"),
        ):
            reg.cloudflare_get_messages("https://mail.example", "mail-token")
            reg.cloudflare_get_message_detail("https://mail.example", "mail-token", "msg-1")

        self.assertTrue(calls)
        self.assertTrue(all(call[1].get("proxies") == {} for call in calls))


class HotmailOAuthRefreshRetryTests(unittest.TestCase):
    def test_refresh_retries_transient_tls_errors_before_succeeding(self):
        attempts = []

        class Response:
            status_code = 200
            text = "{}"

            def json(self):
                return {"access_token": "access-ok", "refresh_token": "refresh-new"}

        def fake_post(*args, **kwargs):
            attempts.append((args, kwargs))
            if len(attempts) < 3:
                raise RuntimeError("Failed to perform, curl: (35) TLS connect error")
            return Response()

        account = {
            "email": "main@example.com",
            "client_id": "client-id",
            "refresh_token": "refresh-old",
        }

        with (
            mock.patch.object(reg, "http_post", side_effect=fake_post),
            mock.patch.object(reg, "_hotmail_update_refresh_token_file") as update_file,
            mock.patch.object(reg, "config", {"hotmail_oauth_network_retries": 2, "hotmail_oauth_retry_delay_sec": 0}),
        ):
            token = reg._hotmail_refresh_token_with_endpoints(
                account,
                [("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", {})],
            )

        self.assertEqual(token, "access-ok")
        self.assertEqual(len(attempts), 3)
        self.assertEqual(account["refresh_token"], "refresh-new")
        update_file.assert_called_once()

    def test_refresh_does_not_retry_oauth_business_errors(self):
        attempts = []

        class Response:
            status_code = 400
            text = "invalid_grant"

            def json(self):
                return {"error": "invalid_grant"}

        def fake_post(*args, **kwargs):
            attempts.append((args, kwargs))
            return Response()

        account = {
            "email": "main@example.com",
            "client_id": "client-id",
            "refresh_token": "refresh-old",
        }

        with (
            mock.patch.object(reg, "http_post", side_effect=fake_post),
            mock.patch.object(reg, "config", {"hotmail_oauth_network_retries": 3, "hotmail_oauth_retry_delay_sec": 0}),
        ):
            with self.assertRaises(Exception) as cm:
                reg._hotmail_refresh_token_with_endpoints(
                    account,
                    [("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", {})],
                )

        self.assertIn("invalid_grant", str(cm.exception))
        self.assertEqual(len(attempts), 1)


class RegisterCliMailErrorPolicyTests(unittest.TestCase):
    def test_browser_retry_releases_alias_without_persisting_error_on_otp_timeout(self):
        import register_cli

        with (
            mock.patch.object(register_cli.reg, "get_email_provider", return_value="hotmail"),
            mock.patch.object(register_cli.reg, "mark_error") as mark_error,
            mock.patch.object(register_cli.reg, "release_email", create=True) as release_email,
        ):
            register_cli._mark_email_stage_error(
                "main+retry@example.com",
                "Hotmail/Outlook 在 30s 内未收到验证码邮件: main+retry@example.com",
            )

        mark_error.assert_not_called()
        release_email.assert_called_once_with("main+retry@example.com")


if __name__ == "__main__":
    unittest.main()
