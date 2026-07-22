from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from webui import cpa_pool
from webui.cpa_health import classify_failure, default_state


class CpaPoolGovernanceV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        with mock.patch.object(cpa_pool.CpaPoolMonitor, "_load_state", lambda _self: None):
            self.monitor = cpa_pool.CpaPoolMonitor()
        self.monitor._state_path = Path(self.temp.name) / "cpa_pool_state.json"
        self.settings = {
            **cpa_pool.DEFAULT_SETTINGS,
            "apply_policy": True,
            "file_fallback_enabled": True,
            "cli_management_enabled": False,
            "breaker_min_samples": 5,
            "breaker_min_errors": 3,
            "breaker_error_ratio": 0.5,
            "breaker_window_sec": 300,
            "breaker_open_sec": 180,
        }
        self.monitor._governance_limit = 50

    def tearDown(self):
        self.temp.cleanup()

    def _auth_file(self, email: str, **overrides) -> Path:
        path = Path(self.temp.name) / f"xai-{email}.json"
        payload = {
            "email": email,
            "access_token": "access",
            "refresh_token": "refresh",
            "priority": 100,
            "disabled": False,
            **overrides,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _main_state(self, email: str, path: Path) -> dict:
        state = default_state(email, path=str(path))
        state.update(
            {
                "tier": "main",
                "health_status": "healthy",
                "desired_priority": 100,
                "desired_disabled": False,
                "actual_priority": 100,
                "actual_disabled": False,
                "governance_eligible": True,
            }
        )
        self.monitor._repo().upsert_account(state)
        return state

    def test_capacity_result_preserves_main_schedule(self):
        email = "busy@example.com"
        path = self._auth_file(email)
        self._main_state(email, path)
        classified = classify_failure(
            {"status": 429, "error": "The model is currently at capacity due to high demand"},
            stage="chat",
        )
        row = {
            "email": email,
            "path": str(path),
            "checked_at": cpa_pool._utc_now(),
            **classified.to_dict(),
        }

        result = self.monitor._apply_policy(self.monitor._merge_result(row, settings=self.settings), self.settings)

        self.assertEqual(result["status"], "upstream_busy")
        self.assertNotIn("action", result)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["priority"], 100)
        self.assertFalse(payload["disabled"])
        state = self.monitor._repo().get_account(email)
        self.assertEqual(state["tier"], "main")
        self.assertEqual(state["failure_streak"], 0)

    def test_legacy_capacity_result_migrates_to_routeable_reserve(self):
        state = self.monitor._state_from_legacy_result(
            {
                "email": "legacy-busy@example.com",
                "status": "quota",
                "reason": "The model is currently at capacity due to high demand",
                "checked_at": cpa_pool._utc_now(),
            }
        )

        self.assertEqual(state["tier"], "reserve")
        self.assertEqual(state["desired_priority"], 50)
        self.assertFalse(state["desired_disabled"])
        self.assertTrue(state["governance_eligible"])

    def test_explicit_quota_is_disabled_with_durable_cooldown(self):
        email = "quota@example.com"
        path = self._auth_file(email)
        self._main_state(email, path)
        classified = classify_failure(
            {"status": 429, "error": '{"code":"subscription:free-usage-exhausted","error":"included free usage exhausted"}'},
            stage="chat",
        )
        row = {
            "email": email,
            "path": str(path),
            "checked_at": cpa_pool._utc_now(),
            **classified.to_dict(),
        }

        result = self.monitor._apply_policy(self.monitor._merge_result(row, settings=self.settings), self.settings)

        self.assertEqual(result["action"], "disabled")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(payload["disabled"])
        self.assertEqual(payload["priority"], 10)
        self.assertEqual(payload["_cpa_pool"]["tier"], "cooling")
        self.assertTrue(payload["_cpa_pool"]["cool_until"])

    def test_expired_cooldown_is_probed_while_file_stays_disabled(self):
        email = "recover@example.com"
        expired = cpa_pool._ts_to_iso(time.time() - 60)
        path = self._auth_file(
            email,
            disabled=True,
            priority=10,
            _cpa_pool={"managed": True, "tier": "cooling", "status": "cooling", "cool_until": expired},
        )
        item = {"email": email, "path": str(path), "location": "hotload"}
        with mock.patch("webui.cpa_pool.probe_models", return_value={"ok": True, "status": 200, "model_ids": ["grok-4.5"], "has_grok_45": True}):
            row = self.monitor._scan_one(item, {**self.settings, "probe_chat": False, "refresh_before_probe": False}, lambda: "direct")

        self.assertEqual(row["status"], "ok")
        self.assertTrue(row["recovery_probe"])
        self.assertTrue(json.loads(path.read_text(encoding="utf-8"))["disabled"])

    def test_models_breaker_skips_upstream_probe(self):
        email = "breaker@example.com"
        path = self._auth_file(email)
        self.monitor._breaker_cache["models"] = {
            "scope": "models",
            "state": "open",
            "fingerprint": "provider-down",
            "open_until": time.time() + 60,
        }
        with mock.patch("webui.cpa_pool.probe_models") as probe_models:
            row = self.monitor._scan_one(
                {"email": email, "path": str(path), "location": "hotload"},
                {**self.settings, "probe_chat": False, "refresh_before_probe": False},
                lambda: "direct",
            )

        self.assertEqual(row["status"], "upstream_busy")
        self.assertTrue(row["breaker_skipped"])
        probe_models.assert_not_called()

    def test_same_provider_error_opens_breaker(self):
        previous = default_state("canary@example.com")
        previous.update({"tier": "main", "health_status": "healthy", "desired_disabled": False, "governance_eligible": True})
        rows = [
            {"status": "ok", "reason": "ok", "fingerprint": "", "account_attributable": False},
            {"status": "ok", "reason": "ok", "fingerprint": "", "account_attributable": False},
            {"status": "upstream_busy", "reason": "capacity", "fingerprint": "same-capacity", "account_attributable": False},
            {"status": "upstream_busy", "reason": "capacity", "fingerprint": "same-capacity", "account_attributable": False},
            {"status": "upstream_busy", "reason": "capacity", "fingerprint": "same-capacity", "account_attributable": False},
        ]
        for index, values in enumerate(rows):
            row = {
                "email": f"canary-{index}@example.com",
                "checked_at": cpa_pool._utc_now(),
                "stage": "chat",
                "reason_code": "model_capacity" if values["status"] != "ok" else "probe_ok",
                **values,
            }
            self.monitor._record_observation(row, previous_state=previous, settings=self.settings)

        self.assertTrue(self.monitor._breaker_is_open("chat"))
        breaker = self.monitor._breaker_cache["chat"]
        self.assertEqual(breaker["error_count"], 3)
        self.assertEqual(breaker["sample_count"], 5)

    def test_half_open_canary_is_not_reopened_by_old_window(self):
        base = time.time()
        old_rows = [
            {"status": "ok", "fingerprint": ""},
            {"status": "ok", "fingerprint": ""},
            {"status": "upstream_busy", "fingerprint": "capacity"},
            {"status": "upstream_busy", "fingerprint": "capacity"},
            {"status": "upstream_busy", "fingerprint": "capacity"},
        ]
        previous = default_state("canary@example.com")
        previous.update({"tier": "main", "health_status": "healthy"})
        for index, values in enumerate(old_rows):
            self.monitor._record_observation(
                {
                    "email": f"old-{index}@example.com",
                    "checked_at": cpa_pool._ts_to_iso(base - 10 + index),
                    "stage": "chat",
                    "reason": "capacity",
                    "reason_code": "model_capacity",
                    "account_attributable": False,
                    **values,
                },
                previous_state=previous,
                settings=self.settings,
            )
        breaker = dict(self.monitor._breaker_cache["chat"])
        breaker["open_until"] = base - 1
        self.monitor._breaker_cache["chat"] = breaker
        self.monitor._repo().put_breaker("chat", breaker)

        with mock.patch("webui.cpa_pool.time.time", return_value=base):
            self.assertFalse(self.monitor._breaker_blocks_probe("chat"))
        self.monitor._record_observation(
            {
                "email": "new-canary@example.com",
                "checked_at": cpa_pool._ts_to_iso(base + 1),
                "stage": "chat",
                "status": "ok",
                "reason": "ok",
                "reason_code": "probe_ok",
                "fingerprint": "",
                "account_attributable": False,
            },
            previous_state=previous,
            settings=self.settings,
        )

        self.assertEqual(self.monitor._breaker_cache["chat"]["state"], "half_open")

    def test_runtime_connected_missing_auth_is_not_routeable(self):
        email = "missing-runtime@example.com"
        path = self._auth_file(email)
        self._main_state(email, path)
        self.monitor._runtime_connected = True
        self.monitor._runtime_snapshot = {}
        self.monitor._runtime_loaded_count = 0
        with (
            mock.patch("webui.cpa_pool.store.list_cpa_index", return_value={email: {"email": email, "path": str(path)}}),
            mock.patch.object(self.monitor, "quarantine_summary", return_value={"total": 0}),
        ):
            metrics = self.monitor._pool_metrics()

        self.assertEqual(metrics["main"], 1)
        self.assertEqual(metrics["main_routeable"], 0)
        self.assertEqual(metrics["drift"], 1)

    def test_unmanaged_enabled_inventory_bootstraps_as_reserve(self):
        email = "unclassified@example.com"
        path = self._auth_file(email, priority=0)
        states = self.monitor._sync_inventory_states(
            {
                email: {
                    "email": email,
                    "path": str(path),
                    "disabled": False,
                    "priority": 0,
                    "pool_managed": False,
                }
            }
        )

        state = states[email]
        self.assertEqual(state["tier"], "reserve")
        self.assertEqual(state["desired_priority"], 50)
        self.assertFalse(state["desired_disabled"])
        self.assertFalse(state["governance_eligible"])

    def test_low_water_promotes_verified_reserve_accounts(self):
        for index in range(2):
            email = f"main-{index}@example.com"
            path = self._auth_file(email)
            self._main_state(email, path)
        reserve_paths = []
        for index in range(2):
            email = f"reserve-{index}@example.com"
            path = self._auth_file(email, priority=50)
            reserve_paths.append(path)
            state = default_state(email, path=str(path))
            state.update(
                {
                    "tier": "reserve",
                    "health_status": "healthy",
                    "desired_priority": 50,
                    "desired_disabled": False,
                    "actual_priority": 50,
                    "actual_disabled": False,
                    "governance_eligible": True,
                    "last_success_at": cpa_pool._utc_now(),
                }
            )
            self.monitor._repo().upsert_account(state)

        inventory = {
            path.stem.removeprefix("xai-"): {"email": path.stem.removeprefix("xai-"), "path": str(path)}
            for path in [*reserve_paths, *Path(self.temp.name).glob("xai-main-*.json")]
        }
        with mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=inventory):
            result = self.monitor._rebalance_tiers({**self.settings, "refill_target_active": 4, "main_low_water_percent": 90})

        self.assertEqual(result["promoted"], 2)
        for path in reserve_paths:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["priority"], 100)
            self.assertFalse(payload["disabled"])

    def test_rebalance_promotes_reserve_until_main_target_even_above_low_water(self):
        paths = []
        for index in range(9):
            email = f"main-target-{index}@example.com"
            path = self._auth_file(email)
            paths.append(path)
            self._main_state(email, path)
        reserve_paths = []
        for index in range(2):
            email = f"reserve-target-{index}@example.com"
            path = self._auth_file(email, priority=50)
            paths.append(path)
            reserve_paths.append(path)
            state = default_state(email, path=str(path))
            state.update(
                {
                    "tier": "reserve",
                    "health_status": "healthy",
                    "desired_priority": 50,
                    "desired_disabled": False,
                    "actual_priority": 50,
                    "actual_disabled": False,
                    "governance_eligible": True,
                    "last_success_at": cpa_pool._utc_now(),
                }
            )
            self.monitor._repo().upsert_account(state)

        inventory = {
            path.stem.removeprefix("xai-"): {"email": path.stem.removeprefix("xai-"), "path": str(path)}
            for path in paths
        }
        with mock.patch("webui.cpa_pool.store.list_cpa_index", return_value=inventory):
            result = self.monitor._rebalance_tiers(
                {**self.settings, "refill_target_active": 10, "main_low_water_percent": 90}
            )

        self.assertEqual(result["promoted"], 1)
        promoted = [
            path for path in reserve_paths
            if json.loads(path.read_text(encoding="utf-8")).get("priority") == 100
        ]
        self.assertEqual(len(promoted), 1)


if __name__ == "__main__":
    unittest.main()
