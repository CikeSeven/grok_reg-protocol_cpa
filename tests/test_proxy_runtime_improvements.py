from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cpa_xai import mint
from webui import jobs


class WebuiProxySelectionTests(unittest.TestCase):
    def test_rotating_proxy_picker_uses_pool_without_replacement_per_cycle(self):
        picker = jobs._rotating_proxy_picker(
            ["proxy-a", "proxy-b", "proxy-c"],
            shuffle=lambda items: items.reverse(),
        )

        first_cycle = [picker() for _ in range(3)]
        second_cycle_first = picker()

        self.assertEqual(sorted(first_cycle), ["proxy-a", "proxy-b", "proxy-c"])
        self.assertEqual(second_cycle_first, "proxy-c")


class CpaMintNetworkRetryTests(unittest.TestCase):
    def test_pkce_mint_retries_once_on_transient_curl_tls_error(self):
        calls = 0

        def fake_pkce(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("Failed to perform, curl: (35) TLS connect error")
            return {
                "access_token": "not.a.jwt",
                "refresh_token": "refresh",
                "id_token": "",
                "expires_in": 21600,
                "mint_method": "pkce",
            }

        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.object(mint, "mint_with_sso_pkce", side_effect=fake_pkce),
                mock.patch.object(mint.time, "sleep", return_value=None),
            ):
                result = mint.mint_and_export(
                    email="user@example.com",
                    password="password",
                    auth_dir=Path(td),
                    sso="sso-cookie",
                    probe=False,
                    prefer_protocol=True,
                    protocol_network_retries=1,
                    protocol_network_retry_delay_sec=0,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(calls, 2)

    def test_pkce_logic_failure_is_not_network_retried(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(
                mint,
                "mint_with_sso_pkce",
                side_effect=mint.PKCEMintError("authorization failed: missing code"),
            ) as pkce:
                result = mint.mint_and_export(
                    email="user@example.com",
                    password="password",
                    auth_dir=Path(td),
                    sso="sso-cookie",
                    prefer_protocol=True,
                    force_standalone=True,
                    protocol_network_retries=2,
                )

        self.assertFalse(result["ok"])
        pkce.assert_called_once()


if __name__ == "__main__":
    unittest.main()
