from __future__ import annotations

import unittest
from unittest import mock

from webui import jobs


class WebuiGptRegisterRetryTests(unittest.TestCase):
    def test_gpt_worker_retries_transient_mail_failure_before_counting_slot_failed(self):
        import gpt_register_flow as gpt
        import grok_register_ttk as reg

        runner = jobs.JobRunner()
        job = jobs.Job(
            id="gpt-test",
            kind="gpt_register",
            options={
                "extra": 1,
                "count": 0,
                "threads": 1,
                "otp_timeout": 10,
                "headless": True,
                "probe": True,
                "proxy_mode": "config",
            },
        )
        job.stats = {
            "target": 1,
            "total": 1,
            "done": 0,
            "ok": 0,
            "fail": 0,
            "reg_success": 0,
            "reg_fail": 0,
            "stage_index": 0,
            "steps": 8,
            "prepared": 0,
            "otp_ready": 0,
            "sentinel_ready": 0,
            "session_ready": 0,
            "probed": 0,
        }

        emails = iter([
            ("first@example.com", "token-1"),
            ("second@example.com", "token-2"),
        ])
        calls: list[str] = []

        def fake_register(**kwargs):
            calls.append(kwargs["email"])
            if kwargs["email"] == "first@example.com":
                raise RuntimeError("Hotmail/Outlook 在 10s 内未收到验证码邮件: first@example.com")
            return {"ok": True, "email": kwargs["email"], "access_token": "access"}

        with (
            mock.patch.object(reg, "load_config", return_value={}),
            mock.patch.object(reg, "config", {"proxy": ""}),
            mock.patch.object(jobs.store, "load_config_raw", return_value={"proxy": "", "mail_retry_count": 2}),
            mock.patch.object(reg, "get_email_and_token", side_effect=lambda: next(emails)),
            mock.patch.object(gpt, "run_gpt_register", side_effect=fake_register),
            mock.patch.object(reg, "release_email") as release_email,
            mock.patch.object(reg, "mark_error") as mark_error,
            mock.patch.object(reg, "mark_used") as mark_used,
            mock.patch.object(reg, "clear_thread_proxy"),
            mock.patch.object(reg, "set_thread_proxy"),
            mock.patch.object(jobs.time, "sleep", return_value=None),
        ):
            runner._run_gpt_register(job)

        self.assertEqual(calls, ["first@example.com", "second@example.com"])
        release_email.assert_called_once_with("first@example.com")
        mark_error.assert_not_called()
        mark_used.assert_called_once_with("second@example.com", "")
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.stats["ok"], 1)
        self.assertEqual(job.stats["fail"], 0)
        self.assertEqual(job.stats["done"], 1)


if __name__ == "__main__":
    unittest.main()
