from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from webui import cpa_pool


class WebuiCpaPoolHistoryTests(unittest.TestCase):
    def _monitor(self) -> cpa_pool.CpaPoolMonitor:
        with mock.patch.object(cpa_pool.CpaPoolMonitor, "_load_state", lambda self: None):
            return cpa_pool.CpaPoolMonitor()

    def test_append_scan_history_saves_round_overview(self):
        monitor = self._monitor()
        monitor._scan_id = "scan123"
        monitor._started_at = "2026-07-20T15:00:00Z"
        monitor._finished_at = "2026-07-20T15:00:12Z"
        monitor._progress = {"done": 4, "total": 4}
        monitor._summary = {
            "trigger": "auto",
            "counts": {"ok": 2, "quota": 1, "hard_bad": 1},
            "actions": {"quarantine": 1},
            "total": 4,
            "done": 4,
            "elapsed_sec": 12.3,
            "refreshed": 1,
            "reenabled": 0,
            "refill": {"enabled": True, "started": True, "need": 2, "limit": 1},
        }

        settings = {
            **cpa_pool.DEFAULT_SETTINGS,
            "scan_history_limit": 5,
            "probe_proxy": "direct",
            "probe_chat": False,
            "apply_policy": True,
            "auto_refill": True,
        }
        with mock.patch("webui.cpa_pool.store.list_cpa_index", return_value={"a": {}, "b": {}, "c": {}}):
            with mock.patch.object(monitor, "quarantine_summary", return_value={"total": 1}):
                monitor._append_scan_history(settings=settings)

        self.assertEqual(len(monitor._scan_history), 1)
        row = monitor._scan_history[0]
        self.assertEqual(row["id"], "scan123")
        self.assertEqual(row["trigger"], "auto")
        self.assertEqual(row["finished_at"], "2026-07-20 23:00:12")
        self.assertEqual(row["ok"], 2)
        self.assertEqual(row["quota"], 1)
        self.assertEqual(row["bad"], 1)
        self.assertEqual(row["actions"], {"quarantine": 1})
        self.assertEqual(row["cpa_total"], 3)
        self.assertEqual(row["quarantine_total"], 1)
        self.assertEqual(row["outcome"], "warn")

    def test_list_scan_history_filters_by_outcome_and_query(self):
        monitor = self._monitor()
        monitor._scan_history = [
            {"id": "scan-ok", "outcome": "ok", "trigger": "auto", "finished_at": "2026-07-20 10:00:00", "counts": {"ok": 2}},
            {"id": "scan-warn", "outcome": "warn", "trigger": "manual", "finished_at": "2026-07-20 11:00:00", "counts": {"hard_bad": 1}},
            {"id": "scan-error", "outcome": "error", "trigger": "auto", "finished_at": "2026-07-20 12:00:00", "error": "boom"},
        ]

        warn = monitor.list_scan_history(outcome="warn")
        self.assertEqual(warn["total"], 1)
        self.assertEqual(warn["items"][0]["id"], "scan-warn")

        queried = monitor.list_scan_history(query="boom")
        self.assertEqual(queried["total"], 1)
        self.assertEqual(queried["items"][0]["id"], "scan-error")

        all_items = monitor.list_scan_history(page_size=2)
        self.assertEqual(all_items["total"], 3)
        self.assertEqual(all_items["total_pages"], 2)
        self.assertEqual([i["id"] for i in all_items["items"]], ["scan-error", "scan-warn"])

    def test_governance_actions_default_to_ten_rows_per_page(self):
        with tempfile.TemporaryDirectory() as temp:
            monitor = self._monitor()
            monitor._state_path = Path(temp) / "cpa_pool_state.json"
            for index in range(23):
                monitor._repo().add_action(
                    {
                        "action_ts": index + 1,
                        "email": f"audit-{index:02d}@example.com",
                        "action": "scheduled",
                    }
                )

            first = monitor.list_actions()
            last = monitor.list_actions(page=3)

        self.assertEqual(first["page_size"], 10)
        self.assertEqual(first["total"], 23)
        self.assertEqual(first["total_pages"], 3)
        self.assertEqual(len(first["items"]), 10)
        self.assertEqual(len(last["items"]), 3)


if __name__ == "__main__":
    unittest.main()
