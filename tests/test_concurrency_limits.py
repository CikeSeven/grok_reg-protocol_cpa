from __future__ import annotations

import unittest
import queue
from unittest import mock

import register_cli
from webui import jobs


class ConcurrencyLimitTests(unittest.TestCase):
    def test_cli_mint_workers_accepts_values_up_to_100_and_clamps_above(self):
        cfg = {"cpa_export_enabled": True}

        self.assertEqual(
            register_cli.resolve_mint_workers(
                cli_value=100,
                threads=100,
                config=cfg,
                inline_mint=False,
            ),
            100,
        )
        self.assertEqual(
            register_cli.resolve_mint_workers(
                cli_value=150,
                threads=100,
                config=cfg,
                inline_mint=False,
            ),
            100,
        )

    def test_config_mint_workers_accepts_values_up_to_100_and_clamps_above(self):
        self.assertEqual(
            register_cli.resolve_mint_workers(
                cli_value=-1,
                threads=100,
                config={"cpa_export_enabled": True, "cpa_mint_workers": 100},
                inline_mint=False,
            ),
            100,
        )
        self.assertEqual(
            register_cli.resolve_mint_workers(
                cli_value=-1,
                threads=100,
                config={"cpa_export_enabled": True, "cpa_mint_workers": 150},
                inline_mint=False,
            ),
            100,
        )

    def test_thread_start_interval_is_sanitized_from_config(self):
        self.assertEqual(register_cli.resolve_thread_start_interval({}), 0.8)
        self.assertEqual(register_cli.resolve_thread_start_interval({"thread_start_interval": "0.25"}), 0.25)
        self.assertEqual(register_cli.resolve_thread_start_interval({"thread_start_interval": -5}), 0.0)
        self.assertEqual(register_cli.resolve_thread_start_interval({"thread_start_interval": "bad"}), 0.8)

    def test_webui_register_threads_are_clamped_to_100(self):
        runner = jobs.JobRunner()
        with mock.patch.object(jobs.threading.Thread, "start", lambda self: None):
            payload = runner.start_register({"extra": 1, "threads": 150})

        self.assertEqual(payload["options"]["threads"], 100)

    def test_webui_register_keeps_mint_queue_max_option(self):
        runner = jobs.JobRunner()
        with mock.patch.object(jobs.threading.Thread, "start", lambda self: None):
            payload = runner.start_register({"extra": 1, "threads": 1, "mint_queue_max": 100})

        self.assertEqual(payload["options"]["mint_queue_max"], 100)

    def test_account_ledger_append_is_safe_under_concurrency(self):
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as td:
            path = f"{td}/accounts.txt"

            errors: list[BaseException] = []
            errors_lock = threading.Lock()

            def worker(i: int) -> None:
                try:
                    register_cli.append_account_record(
                        path,
                        f"user{i}@example.com",
                        f"pw{i}",
                        f"sso{i}",
                    )
                except BaseException as exc:
                    with errors_lock:
                        errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertFalse(errors, [repr(e) for e in errors[:3]])
            with open(path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

        self.assertEqual(len(lines), 100)
        self.assertEqual(len(set(lines)), 100)
        self.assertTrue(all(line.count("----") == 2 for line in lines))

    def test_register_worker_does_not_restart_browser_after_cancelled_task(self):
        task_queue: queue.Queue = queue.Queue()
        task_queue.put(1)
        cancelled = [False]

        def fake_register_one(*args, **kwargs):
            cancelled[0] = True
            return None

        with mock.patch.object(register_cli, "register_one", side_effect=fake_register_one), \
             mock.patch.object(register_cli.reg, "restart_browser") as restart_browser, \
             mock.patch.object(register_cli.reg, "stop_browser") as stop_browser, \
             mock.patch.object(register_cli, "log"):
            register_cli._register_worker(
                1,
                task_queue,
                1,
                "accounts.txt",
                None,
                False,
                False,
                cancel_callback=lambda: cancelled[0],
            )

        restart_browser.assert_not_called()
        stop_browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
