from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from webui import mail_tools, store


CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
REFRESH_TOKEN = "M." + "r" * 80


class _Response:
    def __init__(self, status: int, payload: dict | None = None) -> None:
        self.status_code = status
        self._payload = payload or {}
        self.text = json.dumps(self._payload)
        self.content = self.text.encode("utf-8")

    def json(self):
        return dict(self._payload)


class _Imap:
    def __init__(self, *_args, **_kwargs) -> None:
        self.authenticated = False
        self.logged_out = False

    def authenticate(self, mechanism, callback):
        self.authenticated = mechanism == "XOAUTH2" and b"Bearer access-imap" in callback(None)
        if not self.authenticated:
            raise RuntimeError("AUTHENTICATE failed")
        return "OK", []

    def logout(self):
        self.logged_out = True
        return "BYE", []


class MailImportParserTests(unittest.TestCase):
    def test_mixed_delimiters_and_reversed_oauth_fields_are_normalized(self):
        parsed = mail_tools.parse_mail_import(
            "\n".join(
                [
                    f"one@outlook.com----pw1----{CLIENT_ID}----{REFRESH_TOKEN}",
                    f"two@hotmail.com|pw2|{REFRESH_TOKEN}|{CLIENT_ID}",
                    f"three@live.com\t{CLIENT_ID}\t{REFRESH_TOKEN}",
                    "four@outlook.com;password-only",
                ]
            )
        )

        self.assertEqual(len(parsed.records), 4)
        by_email = {record.email: record for record in parsed.records}
        self.assertEqual(by_email["two@hotmail.com"].client_id, CLIENT_ID)
        self.assertEqual(by_email["two@hotmail.com"].refresh_token, REFRESH_TOKEN)
        self.assertEqual(by_email["three@live.com"].password, "")
        self.assertEqual(by_email["four@outlook.com"].auth_type, "password")
        self.assertFalse(parsed.issues)

    def test_csv_headers_and_nested_json_aliases_are_supported(self):
        csv_result = mail_tools.parse_mail_import(
            "email,password,refresh_token,client_id\n"
            f"csv@outlook.com,pw,{REFRESH_TOKEN},{CLIENT_ID}\n"
        )
        json_result = mail_tools.parse_mail_import(
            json.dumps(
                {
                    "data": [
                        {
                            "mail": "json@hotmail.com",
                            "credentials": {
                                "pwd": "secret",
                                "clientId": CLIENT_ID,
                                "refreshToken": REFRESH_TOKEN,
                            },
                        }
                    ]
                }
            )
        )
        keyed_result = mail_tools.parse_mail_import(
            json.dumps(
                {
                    "keyed@outlook.com": {
                        "password": "secret",
                        "client_id": CLIENT_ID,
                        "refresh_token": REFRESH_TOKEN,
                    }
                }
            )
        )

        self.assertEqual(csv_result.records[0].client_id, CLIENT_ID)
        self.assertEqual(json_result.records[0].email, "json@hotmail.com")
        self.assertEqual(json_result.records[0].refresh_token, REFRESH_TOKEN)
        self.assertEqual(json_result.formats, {"json": 1})
        self.assertEqual(keyed_result.records[0].email, "keyed@outlook.com")

    def test_invalid_rows_are_reported_and_last_duplicate_wins(self):
        parsed = mail_tools.parse_mail_import(
            "bad-address----pw\n"
            f"dup@outlook.com----first----{CLIENT_ID}----{REFRESH_TOKEN}\n"
            f"dup@outlook.com----second----{CLIENT_ID}----{REFRESH_TOKEN}\n"
        )

        self.assertEqual(len(parsed.records), 1)
        self.assertEqual(parsed.records[0].password, "second")
        self.assertEqual(parsed.duplicates, 1)
        self.assertEqual(parsed.issues[0]["line"], 1)


class MicrosoftMailboxProbeTests(unittest.TestCase):
    @staticmethod
    def _account() -> dict[str, str]:
        return {
            "email": "user@outlook.com",
            "password": "password",
            "client_id": CLIENT_ID,
            "token": REFRESH_TOKEN,
        }

    def test_real_xoauth_login_identifies_imap(self):
        calls: list[tuple[str, str]] = []

        def request(method, url, **_kwargs):
            calls.append((method, url))
            return _Response(200, {"access_token": "access-imap", "expires_in": 3600})

        probe = mail_tools.MicrosoftMailboxProbe(
            self._account(),
            request_func=request,
            imap_factory=_Imap,
        )
        result = probe.detect()

        self.assertEqual(result["health"], "ok")
        self.assertEqual(result["protocol"], "imap")
        self.assertIn("outlook.live.com", result["reason"])
        self.assertEqual(calls[0][0], "POST")

    def test_graph_mailbox_request_is_required_after_imap_refresh_fails(self):
        calls: list[tuple[str, str]] = []

        def request(method, url, **_kwargs):
            calls.append((method, url))
            if method == "POST" and "graph.microsoft.com" not in str((_kwargs.get("data") or {}).get("scope") or ""):
                return _Response(400, {"error": "invalid_scope"})
            if method == "POST":
                return _Response(200, {"access_token": "graph-access-token"})
            return _Response(200, {"value": []})

        probe = mail_tools.MicrosoftMailboxProbe(
            self._account(),
            request_func=request,
            imap_factory=mock.Mock(side_effect=AssertionError("IMAP must not open without a token")),
        )
        result = probe.detect()

        self.assertEqual(result["health"], "ok")
        self.assertEqual(result["protocol"], "graph")
        self.assertTrue(any(method == "GET" and "graph.microsoft.com" in url for method, url in calls))

    def test_invalid_grant_is_classified_as_invalid(self):
        def request(_method, _url, **_kwargs):
            return _Response(400, {"error": "invalid_grant", "error_description": "token expired"})

        probe = mail_tools.MicrosoftMailboxProbe(self._account(), request_func=request)
        result = probe.detect()

        self.assertEqual(result["protocol"], "unknown")
        self.assertEqual(result["health"], "invalid")
        self.assertNotIn(REFRESH_TOKEN, result["reason"])

    def test_graph_recent_code_is_extracted_after_detection(self):
        def request(method, url, **kwargs):
            scope = str((kwargs.get("data") or {}).get("scope") or "")
            if method == "POST" and "graph.microsoft.com" not in scope:
                return _Response(400, {"error": "invalid_scope"})
            if method == "POST":
                return _Response(200, {"access_token": "graph-access-token"})
            select = str((kwargs.get("params") or {}).get("$select") or "")
            if "body" not in select or "inbox" not in url:
                return _Response(200, {"value": []})
            return _Response(
                200,
                {
                    "value": [
                        {
                            "subject": "Your verification code is 123456",
                            "receivedDateTime": "2099-01-01T00:00:00Z",
                            "from": {"emailAddress": {"address": "sender@example.com"}},
                            "bodyPreview": "Verification code 123456",
                            "body": {"content": "Verification code: 123456"},
                        }
                    ]
                },
            )

        probe = mail_tools.MicrosoftMailboxProbe(self._account(), request_func=request)
        result = probe.latest_code()

        self.assertEqual(result["protocol"], "graph")
        self.assertEqual(result["code"], "123456")
        self.assertEqual(result["sender"], "sender@example.com")


class MailToolManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.mail_path = root / "mail_credentials.txt"
        self.state_path = root / "mail_tool_state.json"
        self._mail_file_patch = mock.patch.object(store, "mail_file", return_value=self.mail_path)
        self._state_patch = mock.patch.object(mail_tools, "MAIL_TOOL_STATE_PATH", self.state_path)
        self._mail_file_patch.start()
        self._state_patch.start()

    def tearDown(self) -> None:
        self._state_patch.stop()
        self._mail_file_patch.stop()
        self._tmp.cleanup()

    def test_import_normalizes_file_and_list_never_returns_secrets(self):
        manager = mail_tools.MailToolManager()
        result = manager.import_accounts(
            f"safe@outlook.com|password-value|{REFRESH_TOKEN}|{CLIENT_ID}",
            mode="replace",
        )

        self.assertEqual(result["imported"], 1)
        self.assertEqual(
            self.mail_path.read_text(encoding="utf-8"),
            f"safe@outlook.com----password-value----{CLIENT_ID}----{REFRESH_TOKEN}\n",
        )
        row = manager.list_accounts()["items"][0]
        serialized = json.dumps(row)
        self.assertNotIn("password-value", serialized)
        self.assertNotIn(REFRESH_TOKEN, serialized)
        self.assertEqual(row["auth_type"], "oauth")

    def test_background_detection_updates_task_and_result(self):
        manager = mail_tools.MailToolManager()
        manager.import_accounts(
            f"worker@outlook.com----pw----{CLIENT_ID}----{REFRESH_TOKEN}",
            mode="replace",
        )
        finished = threading.Event()

        class Probe:
            def __init__(self, account, **_kwargs):
                self.account = account

            def detect(self):
                finished.set()
                return {
                    "email": self.account["email"],
                    "protocol": "imap",
                    "provider": "imap_new",
                    "health": "ok",
                    "reason": "ok",
                    "checked_at": mail_tools.timeutil.now_iso(),
                    "latency_ms": 1,
                    "_refresh_token": "",
                }

        with mock.patch("webui.mail_tools.MicrosoftMailboxProbe", Probe):
            started = manager.start_check(emails=[], workers=1)
            self.assertTrue(started["started"])
            self.assertTrue(finished.wait(timeout=2))
            manager._thread.join(timeout=2)

        status = manager.status()
        self.assertFalse(status["running"])
        self.assertEqual(status["task"]["status"], "completed")
        self.assertEqual(status["task"]["ok"], 1)
        self.assertEqual(manager.list_accounts()["items"][0]["protocol"], "imap")

    def test_rotated_token_update_does_not_overwrite_a_newer_credential(self):
        manager = mail_tools.MailToolManager()
        manager.import_accounts(
            f"cas@outlook.com----pw----{CLIENT_ID}----{REFRESH_TOKEN}",
            mode="replace",
        )

        changed = store.update_mail_refresh_token(
            "cas@outlook.com",
            "M." + "n" * 80,
            expected_refresh_token="stale-token",
        )

        self.assertFalse(changed)
        self.assertIn(REFRESH_TOKEN, self.mail_path.read_text(encoding="utf-8"))

    def test_import_is_rejected_while_detection_is_running(self):
        manager = mail_tools.MailToolManager()
        manager._running = True

        with self.assertRaisesRegex(RuntimeError, "检测任务运行中"):
            manager.import_accounts("blocked@outlook.com----pw", mode="append")


class MailToolUiTests(unittest.TestCase):
    def test_tools_page_has_secondary_navigation_and_mail_workspace(self):
        html = Path("webui/static/index.html").read_text(encoding="utf-8")

        self.assertIn('data-tool-page="convert"', html)
        self.assertIn('data-tool-page="mail"', html)
        self.assertIn('data-tool-panel="mail"', html)
        self.assertIn('id="mail-tool-import-dialog"', html)

    def test_mail_tool_routes_are_registered(self):
        from webui.app import create_app

        paths = {getattr(route, "path", "") for route in create_app().routes}
        self.assertTrue(
            {
                "/api/tools/mail/accounts",
                "/api/tools/mail/inspect",
                "/api/tools/mail/import",
                "/api/tools/mail/check",
                "/api/tools/mail/check/status",
                "/api/tools/mail/check/stop",
            }.issubset(paths)
        )


if __name__ == "__main__":
    unittest.main()
