from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webui import cpa_pool


class WebuiCpaPoolRefillTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._temp.cleanup()

    def _monitor(self) -> cpa_pool.CpaPoolMonitor:
        with mock.patch.object(cpa_pool.CpaPoolMonitor, "_load_state", lambda self: None):
            monitor = cpa_pool.CpaPoolMonitor()
        monitor._state_path = Path(self._temp.name) / "cpa_pool_state.json"
        return monitor

    @staticmethod
    def _settings(**overrides):
        settings = dict(cpa_pool.DEFAULT_SETTINGS)
        settings.update(
            {
                "auto_refill": True,
                "apply_policy": True,
                "refill_target_active": 10,
                "refill_max_per_scan": 3,
                "refill_workers": 2,
                "refill_probe_chat": True,
                "refill_low_water_hold_sec": 0,
                "refill_low_water_rounds": 1,
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

    def test_uses_all_existing_backfill_candidates_before_registering(self):
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
        self.assertEqual(result["strategy"], "backfill")
        self.assertEqual(result["gap"], 6)
        self.assertEqual(result["limit"], 1)
        self.assertEqual(start_backfill.call_args.args[0]["emails"], ["only-one@example.com"])
        start_register.assert_not_called()

    def test_registers_when_no_backfill_candidates_exist(self):
        monitor = self._monitor()
        config = self._register_config()
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=self._active_index()),
            mock.patch("webui.cpa_pool.store.load_config_raw", return_value=config),
            mock.patch.object(monitor, "list_quarantine", return_value={"items": []}),
            mock.patch.object(monitor, "_backfill_candidate_emails", return_value=[]),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
            mock.patch("webui.jobs.runner.start_register", return_value={"id": "register1"}) as start_register,
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=5, trigger="auto")

        self.assertTrue(result["started"])
        self.assertEqual(result["strategy"], "register")
        self.assertEqual(result["limit"], 3)
        options = start_register.call_args.args[0]
        self.assertEqual(options["extra"], 3)
        self.assertEqual(options["threads"], 3)

    def test_refill_waits_for_complete_health_baseline(self):
        monitor = self._monitor()
        active = self._active_index()
        for index, email in enumerate(active):
            state = cpa_pool.default_state(email, now=100)
            state.update(
                {
                    "tier": "reserve",
                    "desired_priority": 50,
                    "desired_disabled": False,
                    "actual_disabled": False,
                    "last_checked_at": "2026-07-21 10:00:00" if index < 2 else "",
                }
            )
            monitor._repo().upsert_account(state)

        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=active),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
            mock.patch.object(monitor, "_pool_metrics", return_value={"main_routeable": 5, "reserve_routeable": 0}),
            mock.patch("webui.jobs.runner.start_backfill") as start_backfill,
            mock.patch("webui.jobs.runner.start_register") as start_register,
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=5, trigger="auto")

        self.assertFalse(result["started"])
        self.assertTrue(result["waiting_for_baseline"])
        self.assertEqual(result["baseline_checked"], 2)
        self.assertEqual(result["baseline_total"], 5)
        start_backfill.assert_not_called()
        start_register.assert_not_called()

    def test_refill_requires_consecutive_low_water_scans(self):
        monitor = self._monitor()
        settings = self._settings(refill_low_water_rounds=2)
        candidates = ["missing@example.com"]
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=self._active_index()),
            mock.patch("webui.cpa_pool.store.load_config_raw", return_value=self._register_config()),
            mock.patch.object(monitor, "list_quarantine", return_value={"items": []}),
            mock.patch.object(monitor, "_backfill_candidate_emails", return_value=candidates),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
            mock.patch("webui.jobs.runner.start_backfill", return_value={"id": "backfill1"}) as start_backfill,
        ):
            monitor._scan_id = "scan-one"
            first = monitor._maybe_start_refill(settings=settings, initial_total=5, trigger="auto")
            monitor._scan_id = "scan-two"
            second = monitor._maybe_start_refill(settings=settings, initial_total=5, trigger="auto")

        self.assertTrue(first["waiting_for_rounds"])
        self.assertFalse(first["started"])
        self.assertTrue(second["started"])
        start_backfill.assert_called_once()

    def test_short_cooling_accounts_protect_refill_capacity(self):
        monitor = self._monitor()
        active = self._active_index(total=11)
        now = 1_000.0
        for index, email in enumerate(active):
            state = cpa_pool.default_state(email, now=now)
            state.update(
                {
                    "tier": "main" if index < 5 else "cooling",
                    "desired_disabled": index >= 5,
                    "actual_disabled": index >= 5,
                    "last_checked_at": "2026-07-21 10:00:00",
                    "cool_until_ts": now + 3600 if index >= 5 else 0,
                }
            )
            monitor._repo().upsert_account(state)

        with (
            mock.patch("webui.cpa_pool.time.time", return_value=now),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=active),
            mock.patch.object(monitor, "_pool_metrics", return_value={"main_routeable": 5, "reserve_routeable": 0}),
            mock.patch("webui.jobs.runner.active_job", return_value=None),
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=11, trigger="auto")

        self.assertFalse(result["started"])
        self.assertEqual(result["protected_cooling"], 6)
        self.assertEqual(result["gap"], 0)

    def test_inflight_projection_returns_integer_gap(self):
        monitor = self._monitor()
        active_job = SimpleNamespace(
            id="job1",
            kind="backfill",
            status="running",
            options={"limit": 3, "source": "cpa_pool_auto_refill"},
            stats={"done": 1},
        )
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=self._active_index()),
            mock.patch("webui.jobs.runner.active_job", return_value=active_job),
        ):
            result = monitor._maybe_start_refill(settings=self._settings(), initial_total=5, trigger="auto")

        self.assertIsInstance(result["gap"], int)
        self.assertEqual(result["gap"], 5)
        self.assertEqual(result["inflight"], 2)

    def test_register_refill_yield_uses_cpa_mint_outcome(self):
        jobs = [
            {
                "kind": "register",
                "status": "completed",
                "options": {"source": "cpa_pool_auto_refill"},
                "stats": {
                    "reg_success": 10,
                    "reg_fail": 0,
                    "mint_success": 1,
                    "mint_fail": 4,
                    "mint_skip": 0,
                },
            }
        ]
        with mock.patch("webui.jobs.runner.list_jobs", return_value=jobs):
            value = cpa_pool.CpaPoolMonitor._rolling_refill_yield(self._settings())

        self.assertEqual(value, 0.2)

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
