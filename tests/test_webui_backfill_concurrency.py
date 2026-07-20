from __future__ import annotations

import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from webui import jobs


@dataclass
class FakeAccount:
    email: str
    password: str = "pw"
    sso: str = "sso"


class WebuiBackfillConcurrencyTests(unittest.TestCase):
    def test_start_backfill_keeps_worker_and_probe_options(self):
        runner = jobs.JobRunner()
        with mock.patch.object(jobs.threading.Thread, "start", lambda self: None):
            payload = runner.start_backfill(
                {"emails": ["a@example.com"], "workers": 12, "probe": True, "probe_chat": False, "sleep": 0}
            )

        self.assertEqual(payload["options"]["workers"], 12)
        self.assertIs(payload["options"]["probe_chat"], False)

    def test_backfill_config_workers_are_capped_conservatively(self):
        self.assertEqual(
            jobs.resolve_backfill_workers({"workers": -1}, {"cpa_mint_workers": 100}),
            8,
        )
        self.assertEqual(
            jobs.resolve_backfill_workers({"workers": 100}, {"cpa_mint_workers": 100}),
            20,
        )

    def test_run_backfill_processes_accounts_concurrently(self):
        runner = jobs.JobRunner()
        job = jobs.Job(
            id="bf-test",
            kind="backfill",
            options={"emails": [], "workers": 3, "probe": False, "probe_chat": False, "sleep": 0},
        )
        active = 0
        max_active = 0
        lock = threading.Lock()

        def fake_mint_and_export(**kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            out = Path(kwargs["auth_dir"]) / f"xai-{kwargs['email']}.json"
            out.write_text("{}", encoding="utf-8")
            with lock:
                active -= 1
            return {"ok": True, "path": str(out)}

        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "cpa_auths"
            with mock.patch("webui.store.load_config_raw", return_value={"cpa_mint_workers": 3, "cpa_copy_to_hotload": False}):
                with mock.patch("webui.store.accounts_file", return_value=Path("accounts_cli.txt")):
                    with mock.patch("webui.store.cpa_dir", return_value=out_dir):
                        with mock.patch("webui.store.hotload_dir", return_value=None):
                            with mock.patch("cpa_xai.parse_accounts_file", return_value=[FakeAccount(f"u{i}@example.com") for i in range(6)]):
                                with mock.patch("cpa_xai.existing_cpa_emails", return_value=set()):
                                    with mock.patch("cpa_xai.mint_and_export", side_effect=fake_mint_and_export):
                                        runner._run_backfill(job)

        self.assertEqual(job.status, "completed")
        self.assertEqual(job.stats["ok"], 6)
        self.assertEqual(job.stats["done"], 6)
        self.assertGreaterEqual(max_active, 2)


if __name__ == "__main__":
    unittest.main()
