from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import proxy_pool


class ProxyPoolParsingTests(unittest.TestCase):
    def test_normalize_converts_socks5_to_socks5h_and_rejects_unknown_scheme(self):
        self.assertEqual(
            proxy_pool.normalize_proxy_url("socks5://user:pass@203.0.113.10:1080"),
            "socks5h://user:pass@203.0.113.10:1080",
        )
        self.assertEqual(proxy_pool.normalize_proxy_url("ftp://203.0.113.10:21"), "")


class ProxyPoolHealthTests(unittest.TestCase):
    def test_load_usable_pool_prefers_checked_ok_proxies(self):
        with tempfile.TemporaryDirectory() as td:
            pool_path = Path(td) / "proxies.txt"
            state_path = Path(td) / "proxies_state.json"
            pool_path.write_text(
                "\n".join(
                    [
                        "http://ok.example:8080",
                        "http://bad.example:8080",
                        "http://untested.example:8080",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            state_path.write_text(
                """
{
  "http://ok.example:8080": {"ok": true, "scheme": "http"},
  "http://bad.example:8080": {"ok": false, "scheme": "http", "error": "timeout"}
}
""".strip(),
                encoding="utf-8",
            )

            with (
                mock.patch.object(proxy_pool, "POOL_PATH", pool_path),
                mock.patch.object(proxy_pool, "STATE_PATH", state_path),
            ):
                self.assertEqual(proxy_pool.load_usable_pool(), ["http://ok.example:8080"])

    def test_check_proxy_tests_target_tls_after_exit_ip(self):
        calls: list[str] = []

        class Response:
            def __init__(self, url: str, status_code: int = 200):
                self.url = url
                self.status_code = status_code
                self.text = "{}"

            def json(self):
                return {"ip": "198.51.100.10"}

        def fake_get(url, **kwargs):
            calls.append(url)
            return Response(url)

        with mock.patch("curl_cffi.requests.get", side_effect=fake_get):
            result = proxy_pool.check_proxy("http://user:pass@203.0.113.10:8080")

        self.assertTrue(result["ok"])
        self.assertIn("https://api.ipify.org?format=json", calls)
        self.assertIn("https://accounts.x.ai/", calls)
        self.assertIn("https://auth.x.ai/.well-known/openid-configuration", calls)
        self.assertIn("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", calls)


if __name__ == "__main__":
    unittest.main()
