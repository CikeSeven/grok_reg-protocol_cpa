from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest import mock

from webui import cpa_pool


class _InlineExecutor:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def submit(self, function, *args, **kwargs):
        future = Future()
        try:
            future.set_result(function(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001
            future.set_exception(exc)
        return future


class WebuiCpaPoolRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state_path = Path(self._tmp.name) / "cpa_pool_state.json"
        self._state_patch = mock.patch.object(cpa_pool, "STATE_PATH", self.state_path)
        self._state_patch.start()
        self._monitors: list[cpa_pool.CpaPoolMonitor] = []

    def tearDown(self) -> None:
        for monitor in self._monitors:
            monitor._scheduler_stop.set()
            monitor._cancel.set()
        for monitor in self._monitors:
            if monitor._scheduler_thread:
                monitor._scheduler_thread.join(timeout=2)
            if monitor._scan_thread:
                monitor._scan_thread.join(timeout=5)
        self._state_patch.stop()
        self._tmp.cleanup()

    def _monitor(self) -> cpa_pool.CpaPoolMonitor:
        monitor = cpa_pool.CpaPoolMonitor()
        self._monitors.append(monitor)
        return monitor

    @staticmethod
    def _settings(**overrides):
        settings = dict(cpa_pool.DEFAULT_SETTINGS)
        settings.update(
            {
                "auto_scan": False,
                "scan_interval_sec": 300,
                "scan_workers": 1,
                "probe_chat": False,
                "apply_policy": False,
                "auto_refill": False,
            }
        )
        settings.update(overrides)
        if "scan_interval_sec" in overrides and "scheduler_tick_sec" not in overrides:
            settings["scheduler_tick_sec"] = overrides["scan_interval_sec"]
        return settings

    def test_schedule_deadline_survives_monitor_restart(self):
        deadline = time.time() + 1800
        first = self._monitor()
        first._next_scan_at = deadline
        first._scheduled_interval_sec = 1800
        self.assertTrue(first._save_state())

        second = self._monitor()
        settings = self._settings(auto_scan=True, scan_interval_sec=1800)
        with mock.patch("webui.cpa_pool.settings_from_config", return_value=settings):
            second.ensure_scheduler()

        self.assertEqual(second._next_scan_at, deadline)
        self.assertEqual(second._scheduled_interval_sec, 1800)

    def test_monitor_keeps_the_state_path_captured_at_creation(self):
        first = self._monitor()
        other_path = self.state_path.with_name("other-cpa-pool-state.json")

        with mock.patch.object(cpa_pool, "STATE_PATH", other_path):
            second = self._monitor()
            first._scan_id = "first-state"
            second._scan_id = "second-state"
            self.assertTrue(first._save_state())
            self.assertTrue(second._save_state())

        first_payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        second_payload = json.loads(other_path.read_text(encoding="utf-8"))
        self.assertEqual(first_payload["scan_id"], "first-state")
        self.assertEqual(second_payload["scan_id"], "second-state")

    def test_legacy_state_derives_deadline_from_last_finish(self):
        finished_at = cpa_pool._utc_now()
        self.state_path.write_text(
            json.dumps(
                {
                    "finished_at": finished_at,
                    "summary": {"finished_at": finished_at, "counts": {}, "actions": {}},
                    "results": {},
                }
            ),
            encoding="utf-8",
        )
        monitor = self._monitor()
        settings = self._settings(auto_scan=True, scan_interval_sec=1800)

        with mock.patch("webui.cpa_pool.settings_from_config", return_value=settings):
            monitor.ensure_scheduler()

        self.assertEqual(monitor._next_scan_at, cpa_pool._iso_to_ts(finished_at) + 1800)
        self.assertEqual(monitor._scheduled_interval_sec, 1800)

    def test_disabled_auto_scan_does_not_slide_deadline(self):
        monitor = self._monitor()
        monitor._next_scan_at = 1500.0
        monitor._scheduled_interval_sec = 300
        settings = self._settings(auto_scan=False, scan_interval_sec=300)

        with mock.patch("webui.cpa_pool.settings_from_config", return_value=settings):
            monitor._scheduler_tick(now=1000.0)
            monitor._scheduler_tick(now=1200.0)

        self.assertEqual(monitor._next_scan_at, 1500.0)

    def test_interval_change_recalculates_deadline_once(self):
        monitor = self._monitor()
        monitor._next_scan_at = 1300.0
        monitor._scheduled_interval_sec = 300
        settings = self._settings(auto_scan=False, scan_interval_sec=600)

        with mock.patch("webui.cpa_pool.settings_from_config", return_value=settings):
            monitor._scheduler_tick(now=1000.0)
            self.assertEqual(monitor._next_scan_at, 1600.0)
            monitor._scheduler_tick(now=1100.0)

        self.assertEqual(monitor._next_scan_at, 1600.0)
        self.assertEqual(monitor._scheduled_interval_sec, 600)

    def test_fresh_scan_persists_snapshot_before_account_finishes(self):
        monitor = self._monitor()
        entered = threading.Event()
        release = threading.Event()
        settings = self._settings(auto_scan=False, scan_workers=1)
        item = {
            "email": "fresh@example.com",
            "path": "/tmp/xai-fresh.json",
            "location": "auth_dir",
        }

        def scan_one(scan_item, _settings, _proxy_picker):
            entered.set()
            release.wait(timeout=5)
            return {
                "email": scan_item["email"],
                "path": scan_item["path"],
                "filename": Path(scan_item["path"]).name,
                "location": scan_item["location"],
                "checked_at": cpa_pool._utc_now(),
                "status": "ok",
                "reason": "models ok",
                "refreshed": False,
                "reenabled": False,
            }

        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value={"fresh@example.com": item}),
            mock.patch.object(monitor, "_scan_one", side_effect=scan_one),
            mock.patch.object(monitor, "_maybe_start_refill", return_value={"enabled": False, "started": False}),
            mock.patch.object(monitor, "quarantine_summary", return_value={"total": 0}),
        ):
            result = monitor.start_scan({"trigger": "manual", "probe_chat": False})
            self.assertTrue(result["started"])
            self.assertTrue(entered.wait(timeout=2))
            persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
            active = persisted["active_scan"]
            self.assertEqual(active["status"], "running")
            self.assertEqual(active["scan_id"], monitor._scan_id)
            self.assertTrue(active["snapshot_ready"])
            self.assertEqual([row["email"] for row in active["items"]], ["fresh@example.com"])
            self.assertEqual(active["completed"], [])
            release.set()
            monitor._scan_thread.join(timeout=5)

        self.assertFalse(monitor._scan_thread.is_alive())
        self.assertEqual(monitor._progress["done"], 1)
        self.assertEqual(len(monitor._scan_history), 1)
        persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIsNone(persisted["active_scan"])

    def _persist_interrupted_scan(self, *, trigger: str, cancel_requested: bool = False) -> None:
        settings = self._settings(probe_chat=True)
        options = {"trigger": trigger, "probe_chat": True, "limit": 2}
        items = [
            {"email": "done@example.com", "path": "/tmp/xai-done.json", "location": "auth_dir"},
            {"email": "pending@example.com", "path": "/tmp/xai-pending.json", "location": "auth_dir"},
        ]
        monitor = self._monitor()
        monitor._scan_id = "persisted1"
        monitor._started_at = cpa_pool._utc_now()
        monitor._next_scan_at = time.time() + 300
        monitor._scheduled_interval_sec = 300
        monitor._settings = settings
        monitor._progress = {"done": 1, "total": 2, "current": "done@example.com"}
        monitor._summary = {
            "counts": {"ok": 1},
            "actions": {},
            "total": 2,
            "done": 1,
            "refreshed": 0,
            "reenabled": 0,
            "trigger": trigger,
            "started_at": monitor._started_at,
        }
        monitor._results = {
            "done@example.com": {
                "email": "done@example.com",
                "status": "ok",
                "checked_at": monitor._started_at,
                "scan_id": "persisted1",
            }
        }
        monitor._active_scan = {
            "status": "running",
            "scan_id": "persisted1",
            "trigger": trigger,
            "options": options,
            "settings": settings,
            "started_at": monitor._started_at,
            "initial_total": 2,
            "snapshot_ready": True,
            "items": items,
            "completed": ["done@example.com"],
            "cancel_requested": cancel_requested,
            "resume_count": 0,
            "resumed_at": "",
        }
        self.assertTrue(monitor._save_state())

    def _assert_scan_recovers(self, trigger: str) -> None:
        self._persist_interrupted_scan(trigger=trigger)
        monitor = self._monitor()
        checked: list[tuple[str, bool]] = []

        def scan_one(item, settings, _proxy_picker):
            checked.append((str(item.get("email")), bool(settings.get("probe_chat"))))
            return {
                "email": item["email"],
                "path": item["path"],
                "filename": Path(item["path"]).name,
                "location": item["location"],
                "checked_at": cpa_pool._utc_now(),
                "status": "ok",
                "reason": "models ok",
                "refreshed": False,
                "reenabled": False,
            }

        settings = self._settings(auto_scan=False, scan_interval_sec=300)
        index = {
            "done@example.com": {"email": "done@example.com"},
            "pending@example.com": {"email": "pending@example.com"},
        }
        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=index),
            mock.patch.object(monitor, "_scan_one", side_effect=scan_one),
            mock.patch.object(monitor, "_maybe_start_refill", return_value={"enabled": False, "started": False}),
            mock.patch.object(monitor, "quarantine_summary", return_value={"total": 0}),
            mock.patch("webui.cpa_pool.ThreadPoolExecutor", _InlineExecutor),
        ):
            monitor.ensure_scheduler()
            self.assertIsNotNone(monitor._scan_thread)
            monitor._scan_thread.join(timeout=5)

        self.assertFalse(monitor._scan_thread.is_alive())
        self.assertEqual(
            checked,
            [("pending@example.com", True)],
            msg=(
                f"last_error={monitor._last_error!r} progress={monitor._progress!r} "
                f"active={monitor._active_scan!r} logs={list(monitor._logs)[-10:]!r}"
            ),
        )
        self.assertEqual(monitor._scan_id, "persisted1")
        self.assertEqual(monitor._resume_count, 1)
        self.assertEqual(monitor._progress["done"], 2)
        self.assertEqual(len(monitor._scan_history), 1)
        history = monitor._scan_history[0]
        self.assertEqual(history["id"], "persisted1")
        self.assertEqual(history["trigger"], trigger)
        self.assertEqual(history["done"], 2)
        self.assertEqual(history["resume_count"], 1)
        persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIsNone(persisted["active_scan"])

    def test_manual_scan_recovers_and_skips_completed_accounts(self):
        self._assert_scan_recovers("manual")

    def test_auto_scan_recovers_and_skips_completed_accounts(self):
        self._assert_scan_recovers("auto")

    def test_recovery_before_snapshot_reuses_original_filter_options(self):
        settings = self._settings(probe_chat=True)
        monitor = self._monitor()
        monitor._scan_id = "preparing1"
        monitor._started_at = cpa_pool._utc_now()
        monitor._next_scan_at = time.time() + 300
        monitor._scheduled_interval_sec = 300
        monitor._settings = settings
        monitor._summary = {"counts": {}, "actions": {}, "total": 0, "done": 0, "trigger": "manual"}
        monitor._active_scan = {
            "status": "running",
            "scan_id": "preparing1",
            "trigger": "manual",
            "options": {
                "trigger": "manual",
                "emails": ["selected@example.com"],
                "limit": 1,
                "probe_chat": True,
            },
            "settings": settings,
            "started_at": monitor._started_at,
            "initial_total": 0,
            "snapshot_ready": False,
            "items": [],
            "completed": [],
            "cancel_requested": False,
            "resume_count": 0,
        }
        self.assertTrue(monitor._save_state())

        recovered = self._monitor()
        checked: list[str] = []
        index = {
            "other@example.com": {
                "email": "other@example.com",
                "path": "/tmp/xai-other.json",
                "location": "auth_dir",
            },
            "selected@example.com": {
                "email": "selected@example.com",
                "path": "/tmp/xai-selected.json",
                "location": "auth_dir",
            },
        }

        def scan_one(item, scan_settings, _proxy_picker):
            checked.append(str(item["email"]))
            self.assertTrue(scan_settings["probe_chat"])
            return {
                "email": item["email"],
                "path": item["path"],
                "filename": Path(item["path"]).name,
                "location": item["location"],
                "checked_at": cpa_pool._utc_now(),
                "status": "ok",
                "reason": "models ok",
                "refreshed": False,
                "reenabled": False,
            }

        current_settings = self._settings(auto_scan=False, probe_chat=False)
        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=current_settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=index),
            mock.patch.object(recovered, "_scan_one", side_effect=scan_one),
            mock.patch.object(recovered, "_maybe_start_refill", return_value={"enabled": False, "started": False}),
            mock.patch.object(recovered, "quarantine_summary", return_value={"total": 0}),
        ):
            recovered.ensure_scheduler()
            recovered._scan_thread.join(timeout=5)

        self.assertEqual(checked, ["selected@example.com"])
        self.assertEqual(recovered._scan_history[0]["id"], "preparing1")
        self.assertEqual(recovered._scan_history[0]["total"], 1)

    def test_cancelled_scan_is_finalized_instead_of_resumed(self):
        self._persist_interrupted_scan(trigger="manual", cancel_requested=True)
        monitor = self._monitor()
        settings = self._settings(auto_scan=False, scan_interval_sec=300)
        index = {
            "done@example.com": {"email": "done@example.com"},
            "pending@example.com": {"email": "pending@example.com"},
        }
        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=index),
            mock.patch.object(monitor, "_scan_one") as scan_one,
            mock.patch.object(monitor, "quarantine_summary", return_value={"total": 0}),
        ):
            monitor.ensure_scheduler()

        scan_one.assert_not_called()
        self.assertFalse(monitor._running)
        self.assertFalse(monitor._active_scan)
        self.assertEqual(len(monitor._scan_history), 1)
        self.assertEqual(monitor._scan_history[0]["id"], "persisted1")
        self.assertEqual(monitor._scan_history[0]["outcome"], "cancelled")
        persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIsNone(persisted["active_scan"])

    def test_stop_request_is_persisted_before_worker_exits(self):
        monitor = self._monitor()
        monitor._running = True
        monitor._scan_id = "stopping1"
        monitor._active_scan = {
            "status": "running",
            "scan_id": "stopping1",
            "cancel_requested": False,
        }

        with mock.patch.object(monitor, "status", return_value={"running": True}):
            result = monitor.stop_scan()

        self.assertTrue(result["running"])
        persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertTrue(persisted["active_scan"]["cancel_requested"])
        self.assertTrue(persisted["active_scan"]["cancel_requested_at"])

    def test_journal_checkpoint_restores_aggregate_and_skips_reprobe(self):
        self._persist_interrupted_scan(trigger="auto")
        first = self._monitors[-1]
        checked_at = cpa_pool._utc_now()
        row = {
            "email": "pending@example.com",
            "path": "/tmp/xai-pending.json",
            "filename": "xai-pending.json",
            "location": "auth_dir",
            "checked_at": checked_at,
            "status": "quota",
            "reason": "quota exhausted",
            "refreshed": True,
            "reenabled": True,
            "action": "disable",
            "scan_id": "persisted1",
        }
        self.assertTrue(
            first._append_scan_journal(
                scan_id="persisted1",
                item_key="pending@example.com",
                row=row,
            )
        )
        with first._scan_journal_path().open("ab") as handle:
            handle.write(b'{"journal_version":1,"scan_id":"persisted1","row":"\xff')

        recovered = self._monitor()
        self.assertEqual(recovered._progress["done"], 2)
        self.assertEqual(recovered._summary["counts"], {"ok": 1, "quota": 1})
        self.assertEqual(recovered._summary["actions"], {"disable": 1})
        self.assertEqual(recovered._summary["refreshed"], 1)
        self.assertEqual(recovered._summary["reenabled"], 1)
        self.assertEqual(recovered._results["pending@example.com"]["status"], "quota")
        self.assertEqual(
            recovered._active_scan["completed"],
            ["done@example.com", "pending@example.com"],
        )

        settings = self._settings(auto_scan=False, scan_interval_sec=300)
        index = {
            "done@example.com": {"email": "done@example.com"},
            "pending@example.com": {"email": "pending@example.com"},
        }
        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=index),
            mock.patch.object(recovered, "_scan_one") as scan_one,
            mock.patch.object(recovered, "_maybe_start_refill", return_value={"enabled": False, "started": False}),
            mock.patch.object(recovered, "quarantine_summary", return_value={"total": 0}),
        ):
            recovered.ensure_scheduler()
            recovered._scan_thread.join(timeout=5)

        scan_one.assert_not_called()
        self.assertFalse(recovered._scan_journal_path().exists())
        self.assertEqual(recovered._scan_history[0]["done"], 2)
        self.assertEqual(recovered._scan_history[0]["counts"], {"ok": 1, "quota": 1})

    def test_scan_journals_each_account_without_per_item_full_snapshot(self):
        monitor = self._monitor()
        settings = self._settings(auto_scan=False, scan_workers=1)
        index = {
            f"account{number}@example.com": {
                "email": f"account{number}@example.com",
                "path": f"/tmp/xai-account{number}.json",
                "location": "auth_dir",
            }
            for number in range(3)
        }

        def scan_one(item, _settings, _proxy_picker):
            return {
                "email": item["email"],
                "path": item["path"],
                "filename": Path(item["path"]).name,
                "location": item["location"],
                "checked_at": cpa_pool._utc_now(),
                "status": "ok",
                "reason": "models ok",
                "refreshed": False,
                "reenabled": False,
            }

        with (
            mock.patch("webui.cpa_pool.settings_from_config", return_value=settings),
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=index),
            mock.patch.object(monitor, "_scan_one", side_effect=scan_one),
            mock.patch.object(monitor, "_maybe_start_refill", return_value={"enabled": False, "started": False}),
            mock.patch.object(monitor, "quarantine_summary", return_value={"total": 0}),
            mock.patch.object(monitor, "status", return_value={"running": True}),
            mock.patch("webui.cpa_pool.ThreadPoolExecutor", _InlineExecutor),
            mock.patch.object(monitor, "_save_state", wraps=monitor._save_state) as save_state,
            mock.patch.object(monitor, "_append_scan_journal", wraps=monitor._append_scan_journal) as append_journal,
        ):
            result = monitor.start_scan({"trigger": "manual"})
            self.assertTrue(result["started"])
            monitor._scan_thread.join(timeout=5)

        self.assertFalse(monitor._scan_thread.is_alive())
        self.assertEqual(append_journal.call_count, 3)
        self.assertEqual(save_state.call_count, 5)
        self.assertFalse(monitor._scan_journal_path().exists())

    def test_state_serialization_does_not_block_result_reads(self):
        monitor = self._monitor()
        monitor._results = {
            "reader@example.com": {
                "email": "reader@example.com",
                "status": "ok",
                "checked_at": cpa_pool._utc_now(),
            }
        }
        serialization_started = threading.Event()
        release_serialization = threading.Event()
        original_dumps = cpa_pool.json.dumps

        def blocking_dumps(*args, **kwargs):
            serialization_started.set()
            release_serialization.wait(timeout=5)
            return original_dumps(*args, **kwargs)

        writer = threading.Thread(target=monitor._save_state)
        read_result: dict[str, object] = {}
        reader = threading.Thread(target=lambda: read_result.update(monitor.list_results()))
        with mock.patch("webui.cpa_pool.json.dumps", side_effect=blocking_dumps):
            writer.start()
            self.assertTrue(serialization_started.wait(timeout=2))
            reader.start()
            reader.join(timeout=0.5)
            responsive = not reader.is_alive()
            release_serialization.set()
            writer.join(timeout=5)
            reader.join(timeout=5)

        self.assertTrue(responsive, "result reads waited for full-state JSON serialization")
        self.assertEqual(read_result["total"], 1)


if __name__ == "__main__":
    unittest.main()
