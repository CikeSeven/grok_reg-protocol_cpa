from __future__ import annotations

import unittest
from unittest import mock

from webui import jobs, store


class WebuiProtocolOptionTests(unittest.TestCase):
    def test_public_config_exposes_protocol_register_keys(self):
        cfg = {
            "protocol_register": True,
            "protocol_only": True,
            "protocol_register_fallback_browser": False,
            "protocol_solver_url": "http://127.0.0.1:5072",
            "protocol_impersonate": "chrome110",
            "protocol_register_max_attempts": 4,
            "turnstile_solver_provider": "2captcha",
            "turnstile_site_key": "site-key",
            "yescaptcha_key": "secret-key",
            "twocaptcha_key": "two-secret",
            "twocaptcha_pass_proxy": True,
            "twocaptcha_timeout": 120,
        }

        public = store.public_config(cfg)

        self.assertIs(public["protocol_register"], True)
        self.assertIs(public["protocol_only"], True)
        self.assertIs(public["protocol_register_fallback_browser"], False)
        self.assertEqual(public["protocol_solver_url"], "http://127.0.0.1:5072")
        self.assertEqual(public["protocol_impersonate"], "chrome110")
        self.assertEqual(public["protocol_register_max_attempts"], 4)
        self.assertEqual(public["turnstile_solver_provider"], "2captcha")
        self.assertEqual(public["turnstile_site_key"], "site-key")
        self.assertEqual(public["yescaptcha_key"], "")
        self.assertIs(public["yescaptcha_key__set"], True)
        self.assertEqual(public["twocaptcha_key"], "")
        self.assertIs(public["twocaptcha_key__set"], True)
        self.assertIs(public["twocaptcha_pass_proxy"], True)
        self.assertEqual(public["twocaptcha_timeout"], 120)

    def test_start_register_keeps_protocol_options_in_job(self):
        runner = jobs.JobRunner()
        with mock.patch.object(jobs.threading.Thread, "start", lambda self: None):
            payload = runner.start_register(
                {
                    "extra": 1,
                    "threads": 1,
                    "mint_workers": -1,
                    "protocol_register": True,
                    "protocol_no_browser_fallback": True,
                    "source": "cpa_pool_auto_refill",
                }
            )

        opts = payload["options"]
        self.assertIs(opts["protocol_register"], True)
        self.assertIs(opts["protocol_no_browser_fallback"], True)
        self.assertEqual(opts["source"], "cpa_pool_auto_refill")

    def test_public_config_includes_default_protocol_solver_pass_proxy(self):
        cfg = store.public_config({})
        self.assertIs(cfg.get("protocol_solver_pass_proxy"), True)
        self.assertIs(cfg.get("twocaptcha_pass_proxy"), True)
        self.assertEqual(cfg.get("turnstile_solver_provider"), "local")


if __name__ == "__main__":
    unittest.main()

class WebuiProtocolPrecedenceTests(unittest.TestCase):
    def test_console_protocol_off_overrides_stale_no_fallback_and_config_protocol(self):
        cfg = {
            "protocol_register": True,
            "protocol_only": True,
            "protocol_register_fallback_browser": False,
        }

        jobs.apply_register_protocol_options(
            cfg,
            {"protocol_register": False, "protocol_no_browser_fallback": True},
        )

        self.assertIs(cfg["protocol_register"], False)
        self.assertIs(cfg["protocol_only"], False)
        self.assertIs(cfg["protocol_register_fallback_browser"], True)

    def test_console_protocol_on_with_fallback_overrides_config_protocol_only(self):
        cfg = {
            "protocol_register": True,
            "protocol_only": True,
            "protocol_register_fallback_browser": False,
        }

        jobs.apply_register_protocol_options(
            cfg,
            {"protocol_register": True, "protocol_no_browser_fallback": False},
        )

        self.assertIs(cfg["protocol_register"], True)
        self.assertIs(cfg["protocol_only"], False)
        self.assertIs(cfg["protocol_register_fallback_browser"], True)
