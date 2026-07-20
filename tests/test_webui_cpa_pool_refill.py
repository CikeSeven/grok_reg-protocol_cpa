from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from webui import cpa_pool


class WebuiCpaPoolRefillTests(unittest.TestCase):
    def _monitor(self) -> cpa_pool.CpaPoolMonitor:
        with mock.patch.object(cpa_pool.CpaPoolMonitor, "_load_state", lambda self: None):
            return cpa_pool.CpaPoolMonitor()

    @staticmethod
    def _settings(**overrides):
        settings = dict(cpa_pool.DEFAULT_SETTINGS)
        settings.update(
            {
                "auto_refill": True,
                "refill_target_active": 10,
                "refill_max_per_scan": 3,
                "refill_workers": 2,
                "refill_probe_chat": True,
            }
        )
        settings.update(overrides)
        return settings

    @staticmethod
    def _active_index(total: int = 5):
        return {f"active-{index}@example.com": {"email": f"active-{index}@example.com"} for index in range(total)}

    @staticmethod
    def _register_config():
        return {
            "cpa_export_enabled": True,
            "register_threads": 10,
            "register_headless": True,
            "protocol_register": True,
            "protocol_only": True,
            "protocol_register_fallback_browser": True,
            "cpa_mint_workers": -1,
            "cpa_mint_queue_max": 0,
        }

    def test_uses_backfill_when_enough_missing_accounts_exist(self):
        monitor = self._monitor()
        candidates = [f"missing-{index}@example.com" for index in range(4)]
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=self._active_index()),
            mock.patch("webui.cpa_pool.store.load_config_raw", return_value=self._register_config()),
            mock.patch.object(monitor, "list_quarantine", return_value={"items": []}),
            mock.patch.object(monitor, "_backfill_candidate_emails", return_value=candidates),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
            mock.patch("webui.jobs.runner.start_backfill", return_value={"id": "backfill1"}) as start_backfill,
            mock.patch("webui.jobs.runner.start_register") as start_register,
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=5, trigger="auto")

        self.assertTrue(result["started"])
        self.assertEqual(result["strategy"], "backfill")
        self.assertEqual(result["limit"], 3)
        self.assertEqual(result["candidates"], 4)
        self.assertEqual(start_backfill.call_args.args[0]["emails"], candidates[:3])
        start_register.assert_not_called()

    def test_registers_full_gap_when_backfill_candidates_are_insufficient(self):
        monitor = self._monitor()
        config = self._register_config()
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=self._active_index()),
            mock.patch("webui.cpa_pool.store.load_config_raw", return_value=config),
            mock.patch.object(monitor, "list_quarantine", return_value={"items": []}),
            mock.patch.object(monitor, "_backfill_candidate_emails", return_value=["only-one@example.com"]),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
            mock.patch("webui.jobs.runner.start_backfill") as start_backfill,
            mock.patch("webui.jobs.runner.start_register", return_value={"id": "register1"}) as start_register,
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=5, trigger="auto")

        self.assertTrue(result["started"])
        self.assertEqual(result["strategy"], "register")
        self.assertEqual(result["need"], 5)
        self.assertEqual(result["limit"], 3)
        options = start_register.call_args.args[0]
        self.assertEqual(options["extra"], 3)
        self.assertEqual(options["threads"], 3)
        self.assertTrue(options["headless"])
        self.assertTrue(options["protocol_register"])
        self.assertTrue(options["protocol_no_browser_fallback"])
        start_backfill.assert_not_called()

    def test_quarantine_manifest_is_not_counted_as_an_account(self):
        monitor = self._monitor()
        with tempfile.TemporaryDirectory() as temp:
            quarantine = Path(temp)
            bucket = quarantine / "hard_bad"
            bucket.mkdir()
            auth = bucket / "xai-bad@example.com.json"
            auth.write_text(json.dumps({"email": "bad@example.com"}), encoding="utf-8")
            auth.with_suffix(auth.suffix + ".meta.json").write_text(
                json.dumps({"source": "/tmp/xai-bad@example.com.json"}),
                encoding="utf-8",
            )
            settings = {**self._settings(), "quarantine_dir": str(quarantine)}
            with mock.patch("webui.cpa_pool.settings_from_config", return_value=settings):
                summary = monitor.quarantine_summary()
                listing = monitor.list_quarantine(page_size=100)

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["counts"], {"hard_bad": 1})
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["email"], "bad@example.com")


if __name__ == "__main__":
    unittest.main()
