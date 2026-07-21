from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webui.cpa_health import classify_failure, default_state, transition_state
from webui.cpa_pool_store import PoolStateDB


class CpaHealthClassificationTests(unittest.TestCase):
    def test_capacity_429_is_availability_neutral(self):
        result = classify_failure(
            {
                "status": 429,
                "error": '{"error":{"code":"server_busy","message":"The model is currently at capacity due to high demand"}}',
            },
            stage="chat",
        )
        self.assertEqual(result.status, "upstream_busy")
        self.assertEqual(result.reason_code, "model_capacity")
        self.assertFalse(result.account_attributable)
        self.assertFalse(result.conclusive)

    def test_explicit_free_usage_429_is_account_quota(self):
        result = classify_failure(
            {
                "status": 429,
                "headers": {"Retry-After": "7200"},
                "error": '{"code":"subscription:free-usage-exhausted","error":"included free usage exhausted"}',
            },
            stage="chat",
        )
        self.assertEqual(result.status, "account_quota")
        self.assertTrue(result.account_attributable)
        self.assertEqual(result.retry_after_sec, 7200)

    def test_unknown_429_is_transient_not_quota(self):
        result = classify_failure({"status": 429, "error": "too many requests"}, stage="models")
        self.assertEqual(result.status, "transient_error")
        self.assertEqual(result.reason_code, "rate_limited_unknown")
        self.assertFalse(result.account_attributable)


class CpaHealthTransitionTests(unittest.TestCase):
    def test_upstream_busy_preserves_main_tier(self):
        previous = default_state("main@example.com", now=10)
        previous.update({"tier": "main", "desired_priority": 100, "desired_disabled": False, "health_status": "healthy"})
        result = transition_state(
            previous,
            {"email": "main@example.com", "status": "upstream_busy", "reason": "capacity", "checked_at": "2026-07-21 10:00:00"},
            now=20,
        )
        self.assertEqual(result["tier"], "main")
        self.assertEqual(result["desired_priority"], 100)
        self.assertFalse(result["desired_disabled"])
        self.assertEqual(result["failure_streak"], 0)

    def test_transient_failures_must_be_spaced_before_observe(self):
        state = default_state("flaky@example.com", now=0)
        state.update({"tier": "main", "desired_priority": 100, "desired_disabled": False, "health_status": "healthy"})
        observation = {
            "email": "flaky@example.com",
            "status": "transient_error",
            "reason": "timeout",
            "reason_code": "network_error",
            "fingerprint": "timeout",
            "checked_at": "2026-07-21 10:00:00",
        }
        state = transition_state(state, observation, now=100, independent_failure_interval_sec=600, transient_failure_threshold=3)
        state = transition_state(state, observation, now=200, independent_failure_interval_sec=600, transient_failure_threshold=3)
        self.assertEqual(state["independent_failure_streak"], 1)
        self.assertEqual(state["tier"], "reserve")
        self.assertEqual(state["desired_priority"], 50)
        self.assertFalse(state["desired_disabled"])
        state = transition_state(state, observation, now=800, independent_failure_interval_sec=600, transient_failure_threshold=3)
        state = transition_state(state, observation, now=1500, independent_failure_interval_sec=600, transient_failure_threshold=3)
        self.assertEqual(state["independent_failure_streak"], 3)
        self.assertEqual(state["tier"], "observe")
        self.assertEqual(state["desired_priority"], 10)
        self.assertFalse(state["desired_disabled"])

    def test_chat_capacity_after_models_success_promotes_candidate_to_reserve(self):
        state = default_state("busy@example.com", now=0)
        result = transition_state(
            state,
            {
                "email": "busy@example.com",
                "status": "upstream_busy",
                "reason": "capacity",
                "models_status": 200,
                "checked_at": "2026-07-21 10:00:00",
            },
            now=100,
        )

        self.assertEqual(result["tier"], "reserve")
        self.assertEqual(result["desired_priority"], 50)
        self.assertFalse(result["desired_disabled"])
        self.assertTrue(result["governance_eligible"])

    def test_recovery_requires_two_successes_before_enable(self):
        state = default_state("cool@example.com", now=0)
        state.update({"tier": "cooling", "health_status": "account_quota", "desired_disabled": True})
        success = {"email": "cool@example.com", "status": "ok", "reason": "chat ok", "checked_at": "2026-07-21 10:00:00"}
        state = transition_state(state, success, now=100, recovery_success_threshold=2)
        self.assertEqual(state["tier"], "candidate")
        self.assertTrue(state["desired_disabled"])
        state = transition_state(state, success, now=200, recovery_success_threshold=2)
        self.assertEqual(state["tier"], "main")
        self.assertFalse(state["desired_disabled"])

    def test_missing_required_model_isolated_after_configured_threshold(self):
        state = default_state("no-model@example.com", now=0)
        state.update({"tier": "main", "desired_priority": 100, "desired_disabled": False})
        observation = {
            "email": "no-model@example.com",
            "status": "no_grok45",
            "reason": "model missing",
            "checked_at": "2026-07-21 10:00:00",
        }

        state = transition_state(state, observation, now=100, no_model_failure_threshold=2)
        self.assertEqual(state["tier"], "reserve")
        state = transition_state(state, observation, now=200, no_model_failure_threshold=2)
        self.assertEqual(state["tier"], "quarantine")
        self.assertTrue(state["desired_disabled"])


class CpaPoolStateDBTests(unittest.TestCase):
    def test_state_observation_breaker_and_audit_are_durable(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pool.sqlite3"
            repo = PoolStateDB(path)
            state = default_state("db@example.com", now=100)
            repo.upsert_account(state)
            self.assertEqual(repo.due_emails(now=100, limit=10), ["db@example.com"])
            repo.add_observation(
                scan_id="scan1",
                observed_at=101,
                observation={"email": "db@example.com", "status": "ok", "stage": "models", "fingerprint": "", "account_attributable": False},
            )
            repo.put_breaker("chat", {"scope": "chat", "state": "open", "updated_at": 102})
            repo.add_action(
                {
                    "action_ts": 103,
                    "email": "db@example.com",
                    "action": "promoted",
                    "old_state": "reserve",
                    "new_state": "main",
                    "reason": "low water",
                    "result": "file",
                }
            )

            reopened = PoolStateDB(path)
            self.assertEqual(reopened.get_account("db@example.com")["tier"], "candidate")
            self.assertEqual(len(reopened.breaker_window(stage="models", since=100)), 1)
            self.assertEqual(reopened.breaker_stats(stage="models", since=100)["sample_count"], 1)
            self.assertEqual(reopened.list_breakers()[0]["state"], "open")
            self.assertEqual(reopened.list_actions()[0]["action"], "promoted")

    def test_governance_actions_support_count_and_offset_pagination(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = PoolStateDB(Path(temp) / "pool.sqlite3")
            for index in range(25):
                repo.add_action(
                    {
                        "action_ts": index + 1,
                        "email": f"page-{index:02d}@example.com",
                        "action": "scheduled",
                    }
                )

            first = repo.list_actions(limit=10)
            second = repo.list_actions(limit=10, offset=10)
            third = repo.list_actions(limit=10, offset=20)

            self.assertEqual(repo.count_actions(), 25)
            self.assertEqual([len(first), len(second), len(third)], [10, 10, 5])
            self.assertEqual(first[0]["email"], "page-24@example.com")
            self.assertEqual(second[0]["email"], "page-14@example.com")
            self.assertEqual(third[-1]["email"], "page-00@example.com")

    def test_history_retention_prunes_only_expired_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = PoolStateDB(Path(temp) / "pool.sqlite3")
            for timestamp in (100, 200):
                repo.add_observation(
                    scan_id="scan1",
                    observed_at=timestamp,
                    observation={"email": "db@example.com", "status": "ok", "stage": "models"},
                )
                repo.add_action(
                    {
                        "action_ts": timestamp,
                        "email": "db@example.com",
                        "action": "scheduled",
                    }
                )

            deleted = repo.prune_history(observations_before=150, actions_before=150)

            self.assertEqual(deleted, {"observations": 1, "actions": 1})
            self.assertEqual(len(repo.breaker_window(stage="models", since=0)), 1)
            self.assertEqual(len(repo.list_actions()), 1)


if __name__ == "__main__":
    unittest.main()
