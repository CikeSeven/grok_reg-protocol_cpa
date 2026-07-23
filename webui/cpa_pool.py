"""CPA auth-file pool monitor and governance for the WebUI.

Source of truth: CPA xai-*.json auth files, not the CLIProxyAPI runtime.  This
lets us attribute health to an individual account/file, refresh tokens in-place,
and optionally quarantine/disable bad accounts with reversible operations.
"""

from __future__ import annotations

import json
import math
import os
import random
import shutil
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from cpa_xai.probe import probe_mini_response, probe_models
from cpa_xai.schema import (
    CLIENT_ID,
    DEFAULT_BASE_URL,
    DEFAULT_TOKEN_ENDPOINT,
    expired_from_access_token,
    jwt_payload,
)

from . import store
from . import timeutil
from .cliproxy_management import CLIProxyManagementClient, ManagementSettings
from .cpa_health import (
    MAIN_PRIORITY,
    OBSERVE_PRIORITY,
    RESERVE_PRIORITY,
    classify_failure,
    default_state,
    transition_state,
)
from .cpa_pool_store import PoolStateDB

STATE_PATH = store.ROOT / "cpa_pool_state.json"
SCAN_JOURNAL_FILENAME = "cpa_pool_scan.journal.jsonl"
DEFAULT_QUARANTINE_DIR = store.ROOT / "cpa_quarantine"
STATE_VERSION = 3
SCAN_JOURNAL_VERSION = 1

DEFAULT_SETTINGS: dict[str, Any] = {
    # scan
    "auto_scan": False,
    "scan_interval_sec": 300,
    "scan_workers": 16,
    "probe_timeout_sec": 30.0,
    "probe_chat": False,
    "refresh_before_probe": True,
    "refresh_skew_sec": 2700,
    "max_items_per_scan": 0,
    "probe_proxy": "direct",  # direct | pool:random | proxy URL
    "scheduler_tick_sec": 300,
    "adaptive_batch_size": 200,
    "healthy_check_interval_sec": 12 * 3600,
    "observe_check_interval_sec": 12 * 60,
    "candidate_check_interval_sec": 20 * 60,
    "independent_failure_interval_sec": 10 * 60,
    "recovery_success_threshold": 2,
    "chat_sample_percent": 5,
    "models_probe_rate_per_sec": 8.0,
    "chat_probe_rate_per_sec": 2.0,
    # provider/model circuit breaker
    "breaker_window_sec": 300,
    "breaker_min_samples": 30,
    "breaker_min_errors": 10,
    "breaker_error_ratio": 0.30,
    "breaker_open_sec": 180,
    # state/history
    "history_limit": 8,
    "scan_history_limit": 100,
    "observation_retention_days": 7,
    "governance_action_retention_days": 90,
    # governance switch; off by default for safe rollout
    "apply_policy": False,
    "quarantine_dir": str(DEFAULT_QUARANTINE_DIR),
    "move_with_backup": True,
    # thresholds are consecutive same-status streaks unless noted otherwise
    "hard_bad_threshold": 1,
    "refresh_failed_threshold": 2,
    "invalid_threshold": 1,
    "no_grok45_threshold": 2,
    "soft_fail_threshold": 3,
    "quota_threshold": 1,
    # actions: keep | disable | quarantine | delete(delete=move to deleted quarantine)
    "hard_bad_action": "quarantine",
    "refresh_failed_action": "quarantine",
    "invalid_action": "quarantine",
    "no_grok45_action": "quarantine",
    "soft_fail_action": "keep",
    "quota_action": "keep",
    "quota_cooldown_sec": 24 * 3600,
    "governance_max_downgrades_per_scan": 50,
    "governance_max_downgrade_percent": 1,
    "main_low_water_percent": 90,
    "reserve_target_percent": 10,
    # auto refill: after governance removes/isolates files, start existing
    # backfill job to mint missing CPA files from accounts_cli.txt.
    "auto_refill": False,
    "refill_target_active": 0,  # 0 = keep pre-scan active count
    "refill_max_per_scan": 200,
    "refill_workers": -1,
    "refill_probe_chat": False,
    "refill_controller_interval_sec": 30,
    "refill_emergency_threshold_percent": 90,
    "refill_max_inventory": 4000,
    "refill_low_water_hold_sec": 30 * 60,
    "refill_low_water_rounds": 2,
    "refill_min_baseline_percent": 100,
    "refill_cooling_grace_sec": 24 * 3600,
    "refill_expected_yield_percent": 80,
    "refill_daily_limit": 200,
    # CLIProxyAPI runtime reconciliation
    "cli_management_enabled": False,
    "cli_management_url": "http://127.0.0.1:8317/v0/management",
    "cli_management_key": "",
    "cli_management_timeout_sec": 5.0,
    "cli_management_cache_sec": 10.0,
    "file_fallback_enabled": True,
    "file_fallback_grace_sec": 60,
}

TERMINAL_STATUSES = {
    "ok",
    "account_quota",
    "upstream_busy",
    "transient_error",
    "request_error",
    "cooling",
    "soft_fail",
    "hard_bad",
    "refresh_failed",
    "invalid",
    "disabled",
    "no_grok45",
    "probe_failed",
    "quarantined",
    "deleted",
    "policy_error",
}

_POLICY_ACTIONS = {"keep", "disable", "quarantine", "delete"}
_MANUAL_ACTIONS = {"disable", "enable", "quarantine", "delete"}
_DIRECT_PROXY_VALUES = {"direct", "none", "no_proxy", "noproxy", "off"}
_PRESENTATION_TIME_KEYS = {
    "started_at",
    "finished_at",
    "checked_at",
    "expired",
    "last_ok_at",
    "last_bad_at",
    "first_seen_at",
    "action_at",
    "cool_until",
    "resumed_at",
}


def _utc_now() -> str:
    return timeutil.now_iso()


def _iso_to_ts(value: str | None) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _ts_to_iso(ts: float) -> str:
    return timeutil.timestamp_iso(ts)


def _access_exp_ts(access_token: str) -> float:
    try:
        payload = jwt_payload(access_token)
        return float(int(payload.get("exp") or 0))
    except Exception:
        return 0.0


def _safe_json_load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("auth json is not an object")
    return data


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        mode = path.stat().st_mode & 0o777
        os.chmod(tmp, mode)
    except Exception:
        pass
    os.replace(tmp, path)


def _mask_error(value: Any, limit: int = 260) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _resolve_path(raw: str | Path | None, default: Path) -> Path:
    text = str(raw or "").strip()
    if not text:
        return default
    p = Path(text).expanduser()
    if not p.is_absolute():
        p = (store.ROOT / p).resolve()
    return p


def _status_from_failure(result: dict[str, Any], *, stage: str) -> tuple[str, str]:
    classified = classify_failure(result, stage=stage)
    return classified.status, classified.reason


def _post_refresh_token(*, refresh_token: str, token_endpoint: str, proxy: str | None, timeout: float) -> tuple[int, dict[str, Any] | str]:
    from cpa_xai.oauth_device import _post_form  # type: ignore[attr-defined]

    return _post_form(
        token_endpoint or DEFAULT_TOKEN_ENDPOINT,
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        },
        timeout=timeout,
        proxy=proxy,
        retries=1,
        retry_sleep=1.0,
    )


def refresh_auth_file(path: Path, payload: dict[str, Any], *, proxy: str | None, timeout: float) -> dict[str, Any]:
    refresh_token = str(payload.get("refresh_token") or "").strip()
    if not refresh_token:
        return {"ok": False, "error": "missing refresh_token"}
    token_endpoint = str(payload.get("token_endpoint") or DEFAULT_TOKEN_ENDPOINT).strip()
    try:
        status, body = _post_refresh_token(refresh_token=refresh_token, token_endpoint=token_endpoint, proxy=proxy, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 0, "error": _mask_error(exc)}

    if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
        err = body.get("error") if isinstance(body, dict) else body
        desc = body.get("error_description") if isinstance(body, dict) else ""
        return {"ok": False, "status": status, "error": _mask_error(desc or err or body)}

    access = str(body.get("access_token") or "").strip()
    new_refresh = str(body.get("refresh_token") or refresh_token).strip()
    new_payload = dict(payload)
    new_payload["access_token"] = access
    new_payload["refresh_token"] = new_refresh
    if body.get("id_token"):
        new_payload["id_token"] = str(body.get("id_token") or "").strip()
    new_payload["token_type"] = str(body.get("token_type") or payload.get("token_type") or "Bearer")
    try:
        expired, expires_in, sub = expired_from_access_token(access)
    except Exception:
        expires_in = int(body.get("expires_in") or payload.get("expires_in") or 21600)
        expired = _ts_to_iso(time.time() + expires_in)
        sub = str(payload.get("sub") or "")
    new_payload["expires_in"] = int(body.get("expires_in") or expires_in or 21600)
    new_payload["expired"] = expired
    if sub and not new_payload.get("sub"):
        new_payload["sub"] = sub
    new_payload["last_refresh"] = _utc_now()
    _atomic_write_json(path, new_payload)
    return {"ok": True, "payload": new_payload, "expired": expired, "expires_in": new_payload["expires_in"]}


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "y"}:
        return True
    if text in {"0", "false", "no", "off", "n"}:
        return False
    return default


def _coerce_int(value: Any, default: int, *, min_v: int | None = None, max_v: int | None = None) -> int:
    try:
        out = int(value)
    except Exception:
        out = default
    if min_v is not None:
        out = max(min_v, out)
    if max_v is not None:
        out = min(max_v, out)
    return out


def _coerce_float(value: Any, default: float, *, min_v: float | None = None, max_v: float | None = None) -> float:
    try:
        out = float(value)
    except Exception:
        out = default
    if min_v is not None:
        out = max(min_v, out)
    if max_v is not None:
        out = min(max_v, out)
    return out


def _coerce_action(value: Any, default: str) -> str:
    text = str(value or default).strip().lower()
    return text if text in _POLICY_ACTIONS else default


def settings_from_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config if config is not None else store.load_config_raw()
    s = dict(DEFAULT_SETTINGS)
    s.update(
        {
            "auto_scan": _coerce_bool(cfg.get("cpa_pool_auto_scan"), bool(s["auto_scan"])),
            "scan_interval_sec": _coerce_int(cfg.get("cpa_pool_scan_interval_sec"), int(s["scan_interval_sec"]), min_v=30, max_v=86400),
            "scan_workers": _coerce_int(cfg.get("cpa_pool_scan_workers"), int(s["scan_workers"]), min_v=1, max_v=100),
            "probe_timeout_sec": _coerce_float(cfg.get("cpa_pool_probe_timeout_sec"), float(s["probe_timeout_sec"]), min_v=3.0, max_v=180.0),
            "probe_chat": _coerce_bool(cfg.get("cpa_pool_probe_chat"), bool(s["probe_chat"])),
            "refresh_before_probe": _coerce_bool(cfg.get("cpa_pool_refresh_before_probe"), bool(s["refresh_before_probe"])),
            "refresh_skew_sec": _coerce_int(cfg.get("cpa_pool_refresh_skew_sec"), int(s["refresh_skew_sec"]), min_v=0, max_v=86400),
            "max_items_per_scan": _coerce_int(cfg.get("cpa_pool_max_items_per_scan"), int(s["max_items_per_scan"]), min_v=0, max_v=100000),
            "probe_proxy": str(cfg.get("cpa_pool_probe_proxy") or "direct").strip(),
            "scheduler_tick_sec": _coerce_int(cfg.get("cpa_pool_scheduler_tick_sec"), int(s["scheduler_tick_sec"]), min_v=30, max_v=3600),
            "adaptive_batch_size": _coerce_int(cfg.get("cpa_pool_adaptive_batch_size"), int(s["adaptive_batch_size"]), min_v=1, max_v=10000),
            "healthy_check_interval_sec": _coerce_int(
                cfg.get("cpa_pool_healthy_check_interval_sec", cfg.get("cpa_pool_scan_interval_sec")),
                int(s["healthy_check_interval_sec"]),
                min_v=1800,
                max_v=7 * 86400,
            ),
            "observe_check_interval_sec": _coerce_int(cfg.get("cpa_pool_observe_check_interval_sec"), int(s["observe_check_interval_sec"]), min_v=60, max_v=86400),
            "candidate_check_interval_sec": _coerce_int(cfg.get("cpa_pool_candidate_check_interval_sec"), int(s["candidate_check_interval_sec"]), min_v=60, max_v=86400),
            "independent_failure_interval_sec": _coerce_int(cfg.get("cpa_pool_independent_failure_interval_sec"), int(s["independent_failure_interval_sec"]), min_v=30, max_v=86400),
            "recovery_success_threshold": _coerce_int(cfg.get("cpa_pool_recovery_success_threshold"), int(s["recovery_success_threshold"]), min_v=1, max_v=10),
            "chat_sample_percent": _coerce_int(cfg.get("cpa_pool_chat_sample_percent"), int(s["chat_sample_percent"]), min_v=0, max_v=100),
            "models_probe_rate_per_sec": _coerce_float(cfg.get("cpa_pool_models_probe_rate_per_sec"), float(s["models_probe_rate_per_sec"]), min_v=0.1, max_v=100.0),
            "chat_probe_rate_per_sec": _coerce_float(cfg.get("cpa_pool_chat_probe_rate_per_sec"), float(s["chat_probe_rate_per_sec"]), min_v=0.1, max_v=50.0),
            "breaker_window_sec": _coerce_int(cfg.get("cpa_pool_breaker_window_sec"), int(s["breaker_window_sec"]), min_v=30, max_v=3600),
            "breaker_min_samples": _coerce_int(cfg.get("cpa_pool_breaker_min_samples"), int(s["breaker_min_samples"]), min_v=5, max_v=1000),
            "breaker_min_errors": _coerce_int(cfg.get("cpa_pool_breaker_min_errors"), int(s["breaker_min_errors"]), min_v=3, max_v=1000),
            "breaker_error_ratio": _coerce_float(cfg.get("cpa_pool_breaker_error_ratio"), float(s["breaker_error_ratio"]), min_v=0.05, max_v=1.0),
            "breaker_open_sec": _coerce_int(cfg.get("cpa_pool_breaker_open_sec"), int(s["breaker_open_sec"]), min_v=30, max_v=3600),
            "history_limit": _coerce_int(cfg.get("cpa_pool_history_limit"), int(s["history_limit"]), min_v=0, max_v=100),
            "scan_history_limit": _coerce_int(cfg.get("cpa_pool_scan_history_limit"), int(s["scan_history_limit"]), min_v=0, max_v=1000),
            "observation_retention_days": _coerce_int(cfg.get("cpa_pool_observation_retention_days"), int(s["observation_retention_days"]), min_v=1, max_v=365),
            "governance_action_retention_days": _coerce_int(cfg.get("cpa_pool_governance_action_retention_days"), int(s["governance_action_retention_days"]), min_v=1, max_v=3650),
            "apply_policy": _coerce_bool(cfg.get("cpa_pool_apply_policy"), bool(s["apply_policy"])),
            "quarantine_dir": str(cfg.get("cpa_pool_quarantine_dir") or s["quarantine_dir"]).strip(),
            "move_with_backup": _coerce_bool(cfg.get("cpa_pool_move_with_backup"), bool(s["move_with_backup"])),
            "hard_bad_threshold": _coerce_int(cfg.get("cpa_pool_hard_bad_threshold"), int(s["hard_bad_threshold"]), min_v=1, max_v=100),
            "refresh_failed_threshold": _coerce_int(cfg.get("cpa_pool_refresh_failed_threshold"), int(s["refresh_failed_threshold"]), min_v=1, max_v=100),
            "invalid_threshold": _coerce_int(cfg.get("cpa_pool_invalid_threshold"), int(s["invalid_threshold"]), min_v=1, max_v=100),
            "no_grok45_threshold": _coerce_int(cfg.get("cpa_pool_no_grok45_threshold"), int(s["no_grok45_threshold"]), min_v=1, max_v=100),
            "soft_fail_threshold": _coerce_int(cfg.get("cpa_pool_soft_fail_threshold"), int(s["soft_fail_threshold"]), min_v=1, max_v=100),
            "quota_threshold": _coerce_int(cfg.get("cpa_pool_quota_threshold"), int(s["quota_threshold"]), min_v=1, max_v=100),
            "quota_cooldown_sec": _coerce_int(cfg.get("cpa_pool_quota_cooldown_sec"), int(s["quota_cooldown_sec"]), min_v=60, max_v=30 * 86400),
            "governance_max_downgrades_per_scan": _coerce_int(cfg.get("cpa_pool_governance_max_downgrades_per_scan"), int(s["governance_max_downgrades_per_scan"]), min_v=1, max_v=10000),
            "governance_max_downgrade_percent": _coerce_int(cfg.get("cpa_pool_governance_max_downgrade_percent"), int(s["governance_max_downgrade_percent"]), min_v=1, max_v=100),
            "main_low_water_percent": _coerce_int(cfg.get("cpa_pool_main_low_water_percent"), int(s["main_low_water_percent"]), min_v=10, max_v=100),
            "reserve_target_percent": _coerce_int(cfg.get("cpa_pool_reserve_target_percent"), int(s["reserve_target_percent"]), min_v=0, max_v=100),
            "auto_refill": _coerce_bool(cfg.get("cpa_pool_auto_refill"), bool(s["auto_refill"])),
            "refill_target_active": _coerce_int(cfg.get("cpa_pool_refill_target_active"), int(s["refill_target_active"]), min_v=0, max_v=100000),
            "refill_max_per_scan": _coerce_int(cfg.get("cpa_pool_refill_max_per_scan"), int(s["refill_max_per_scan"]), min_v=1, max_v=10000),
            "refill_workers": _coerce_int(cfg.get("cpa_pool_refill_workers"), int(s["refill_workers"]), min_v=-1, max_v=20),
            "refill_probe_chat": _coerce_bool(cfg.get("cpa_pool_refill_probe_chat"), bool(s["refill_probe_chat"])),
            "refill_controller_interval_sec": _coerce_int(cfg.get("cpa_pool_refill_controller_interval_sec"), int(s["refill_controller_interval_sec"]), min_v=10, max_v=3600),
            "refill_emergency_threshold_percent": _coerce_int(cfg.get("cpa_pool_refill_emergency_threshold_percent"), int(s["refill_emergency_threshold_percent"]), min_v=0, max_v=100),
            "refill_max_inventory": _coerce_int(cfg.get("cpa_pool_refill_max_inventory"), int(s["refill_max_inventory"]), min_v=1, max_v=100000),
            "refill_low_water_hold_sec": _coerce_int(cfg.get("cpa_pool_refill_low_water_hold_sec"), int(s["refill_low_water_hold_sec"]), min_v=0, max_v=7 * 86400),
            "refill_low_water_rounds": _coerce_int(cfg.get("cpa_pool_refill_low_water_rounds"), int(s["refill_low_water_rounds"]), min_v=1, max_v=10),
            "refill_min_baseline_percent": _coerce_int(cfg.get("cpa_pool_refill_min_baseline_percent"), int(s["refill_min_baseline_percent"]), min_v=1, max_v=100),
            "refill_cooling_grace_sec": _coerce_int(cfg.get("cpa_pool_refill_cooling_grace_sec"), int(s["refill_cooling_grace_sec"]), min_v=0, max_v=30 * 86400),
            "refill_expected_yield_percent": _coerce_int(cfg.get("cpa_pool_refill_expected_yield_percent"), int(s["refill_expected_yield_percent"]), min_v=10, max_v=100),
            "refill_daily_limit": _coerce_int(cfg.get("cpa_pool_refill_daily_limit"), int(s["refill_daily_limit"]), min_v=0, max_v=100000),
            "cli_management_enabled": _coerce_bool(cfg.get("cpa_pool_cli_management_enabled"), bool(s["cli_management_enabled"])),
            "cli_management_url": str(cfg.get("cpa_pool_cli_management_url") or s["cli_management_url"]).strip(),
            "cli_management_key": str(cfg.get("cpa_pool_cli_management_key") or os.environ.get("CPA_POOL_CLI_MANAGEMENT_KEY") or "").strip(),
            "cli_management_timeout_sec": _coerce_float(cfg.get("cpa_pool_cli_management_timeout_sec"), float(s["cli_management_timeout_sec"]), min_v=1.0, max_v=30.0),
            "cli_management_cache_sec": _coerce_float(cfg.get("cpa_pool_cli_management_cache_sec"), float(s["cli_management_cache_sec"]), min_v=1.0, max_v=120.0),
            "file_fallback_enabled": _coerce_bool(cfg.get("cpa_pool_file_fallback_enabled"), bool(s["file_fallback_enabled"])),
            "file_fallback_grace_sec": _coerce_int(cfg.get("cpa_pool_file_fallback_grace_sec"), int(s["file_fallback_grace_sec"]), min_v=0, max_v=3600),
            "hard_bad_action": _coerce_action(cfg.get("cpa_pool_hard_bad_action"), str(s["hard_bad_action"])),
            "refresh_failed_action": _coerce_action(cfg.get("cpa_pool_refresh_failed_action"), str(s["refresh_failed_action"])),
            "invalid_action": _coerce_action(cfg.get("cpa_pool_invalid_action"), str(s["invalid_action"])),
            "no_grok45_action": _coerce_action(cfg.get("cpa_pool_no_grok45_action"), str(s["no_grok45_action"])),
            "soft_fail_action": _coerce_action(cfg.get("cpa_pool_soft_fail_action"), str(s["soft_fail_action"])),
            "quota_action": _coerce_action(cfg.get("cpa_pool_quota_action"), str(s["quota_action"])),
        }
    )
    return s


def _managed_meta(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("_cpa_pool")
    return dict(meta) if isinstance(meta, dict) else {}


def _set_managed_disabled(path: Path, payload: dict[str, Any], *, reason: str, status: str, cool_until: str = "") -> None:
    payload = dict(payload)
    payload["disabled"] = True
    meta = _managed_meta(payload)
    meta.update({"managed": True, "disabled_reason": reason, "status": status, "updated_at": _utc_now()})
    if cool_until:
        meta["cool_until"] = cool_until
    payload["_cpa_pool"] = meta
    _atomic_write_json(path, payload)


def _set_enabled(path: Path, payload: dict[str, Any], *, reason: str = "") -> None:
    payload = dict(payload)
    payload["disabled"] = False
    meta = _managed_meta(payload)
    if meta.get("managed"):
        meta.update({"enabled_at": _utc_now(), "enabled_reason": reason or "manual", "cool_until": ""})
        payload["_cpa_pool"] = meta
    _atomic_write_json(path, payload)


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    ts = timeutil.now_compact()
    for i in range(1, 1000):
        cand = path.with_name(f"{stem}-{ts}-{i}{suffix}")
        if not cand.exists():
            return cand
    return path.with_name(f"{stem}-{ts}-{os.getpid()}{suffix}")


def _quarantine_base(settings: dict[str, Any] | None = None) -> Path:
    s = settings or settings_from_config()
    return _resolve_path(s.get("quarantine_dir"), DEFAULT_QUARANTINE_DIR)


def _move_to_quarantine(path: Path, *, bucket: str, settings: dict[str, Any], reason: str = "") -> dict[str, Any]:
    if not path.is_file():
        return {"ok": False, "error": f"file not found: {path}"}
    base = _quarantine_base(settings)
    dst_dir = base / bucket
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = _unique_path(dst_dir / path.name)
    if bool(settings.get("move_with_backup", True)):
        manifest = dst.with_suffix(dst.suffix + ".meta.json")
        meta = {"source": str(path), "target": str(dst), "bucket": bucket, "reason": reason, "moved_at": _utc_now()}
        manifest.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    shutil.move(str(path), str(dst))
    try:
        store._clear_store_caches("cpa", "overview")  # type: ignore[attr-defined]
    except Exception:
        pass
    return {"ok": True, "path": str(dst), "bucket": bucket}


def _email_from_auth_path(path: Path) -> str:
    try:
        payload = _safe_json_load(path)
        email = str(payload.get("email") or "").strip().lower()
        if email:
            return email
    except Exception:
        pass
    name = path.name
    return name[len("xai-") : -len(".json")].lower() if name.startswith("xai-") and name.endswith(".json") else ""


def _is_quarantine_auth_file(path: Path) -> bool:
    return path.name.startswith("xai-") and path.name.endswith(".json") and not path.name.endswith(".meta.json")


def _beijingize_record(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in _PRESENTATION_TIME_KEYS:
        if out.get(key):
            out[key] = timeutil.iso_to_beijing_display(out.get(key))
    hist = out.get("history")
    if isinstance(hist, list):
        out["history"] = [
            {**h, "at": timeutil.iso_to_beijing_display(h.get("at")) if isinstance(h, dict) and h.get("at") else h.get("at")}
            if isinstance(h, dict)
            else h
            for h in hist
        ]
    return out


class _ProbeRateLimiter:
    def __init__(self, rate_per_sec: float) -> None:
        self._interval = 1.0 / max(0.1, float(rate_per_sec))
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self, cancel: threading.Event) -> bool:
        while not cancel.is_set():
            with self._lock:
                now = time.monotonic()
                wait_for = max(0.0, self._next_at - now)
                if wait_for <= 0:
                    self._next_at = now + self._interval
                    return True
            cancel.wait(min(wait_for, 0.25))
        return False


class CpaPoolMonitor:
    def __init__(self) -> None:
        self._state_path = Path(STATE_PATH)
        self._lock = threading.RLock()
        self._state_write_lock = threading.Lock()
        self._results: dict[str, dict[str, Any]] = {}
        self._logs: deque[str] = deque(maxlen=1600)
        self._running = False
        self._cancel = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._scheduler_thread: threading.Thread | None = None
        self._scheduler_stop = threading.Event()
        self._settings = dict(DEFAULT_SETTINGS)
        self._summary: dict[str, Any] = {}
        self._scan_history: list[dict[str, Any]] = []
        self._scan_id = ""
        self._progress: dict[str, Any] = {"done": 0, "total": 0}
        self._started_at = ""
        self._finished_at = ""
        self._last_finished_ts = 0.0
        self._last_error = ""
        self._next_scan_at = 0.0
        self._scheduled_interval_sec = 0
        self._active_scan: dict[str, Any] = {}
        self._recovery_pending = False
        self._resume_count = 0
        self._resumed_at = ""
        self._repo_instance: PoolStateDB | None = None
        self._repo_path: Path | None = None
        self._management_client: CLIProxyManagementClient | None = None
        self._management_signature: tuple[Any, ...] | None = None
        self._runtime_snapshot: dict[str, dict[str, Any]] = {}
        self._runtime_loaded_count = 0
        self._runtime_connected = False
        self._runtime_error = ""
        self._runtime_synced_at = 0.0
        self._model_limiter = _ProbeRateLimiter(DEFAULT_SETTINGS["models_probe_rate_per_sec"])
        self._chat_limiter = _ProbeRateLimiter(DEFAULT_SETTINGS["chat_probe_rate_per_sec"])
        self._breaker_cache: dict[str, dict[str, Any]] = {}
        self._last_maintenance_at = 0.0
        self._governance_downgrades = 0
        self._governance_limit = 0
        self._refill_lock = threading.Lock()
        self._last_refill_controller_at = 0.0
        self._refill_status: dict[str, Any] = {}
        # _pool_metrics 单飞缓存：状态接口被频繁轮询，
        # 5000+ 账号时每次全量重算会拖垮 AnyIO 线程池。
        self._pool_metrics_lock = threading.Lock()
        self._pool_metrics_cache: dict[str, Any] = {"at": 0.0, "value": None, "computing": False}
        self._load_state()

    def _repo(self) -> PoolStateDB:
        path = self._state_path.with_suffix(".sqlite3")
        if self._repo_instance is None or self._repo_path != path:
            self._repo_instance = PoolStateDB(path)
            self._repo_path = path
        return self._repo_instance

    def _management(self, settings: dict[str, Any] | None = None) -> CLIProxyManagementClient:
        current = settings or settings_from_config()
        signature = (
            bool(current.get("cli_management_enabled")),
            str(current.get("cli_management_url") or ""),
            str(current.get("cli_management_key") or ""),
            float(current.get("cli_management_timeout_sec") or 5.0),
            float(current.get("cli_management_cache_sec") or 10.0),
        )
        if self._management_client is None or self._management_signature != signature:
            self._management_client = CLIProxyManagementClient(
                ManagementSettings(
                    enabled=signature[0],
                    base_url=signature[1],
                    key=signature[2],
                    timeout_sec=signature[3],
                    cache_sec=signature[4],
                )
            )
            self._management_signature = signature
        return self._management_client

    @staticmethod
    def _state_from_legacy_result(result: dict[str, Any]) -> dict[str, Any]:
        email = str(result.get("email") or "").strip().lower()
        state = default_state(email, path=str(result.get("path") or ""))
        status = str(result.get("status") or "unchecked")
        reason = str(result.get("reason") or "")
        if status == "ok":
            state.update(
                {
                    "tier": "main",
                    "health_status": "healthy",
                    "confidence": 80,
                    "desired_priority": MAIN_PRIORITY,
                    "desired_disabled": False,
                    "last_success_at": str(result.get("last_ok_at") or result.get("checked_at") or ""),
                    "governance_eligible": True,
                }
            )
        elif status in {"quota", "account_quota", "cooling"}:
            classified = classify_failure({"status": 429, "error": reason}, stage="legacy")
            if classified.status == "upstream_busy":
                state.update(
                    {
                        "tier": "reserve",
                        "health_status": "upstream_busy",
                        "health_reason": reason,
                        "confidence": 50,
                        "desired_priority": RESERVE_PRIORITY,
                        "desired_disabled": False,
                        "governance_eligible": True,
                    }
                )
            else:
                state.update(
                    {
                        "tier": "cooling",
                        "health_status": "account_quota",
                        "health_reason": reason,
                        "desired_disabled": True,
                        "governance_eligible": True,
                    }
                )
        elif status in {"soft_fail", "transient_error", "probe_failed"}:
            state.update({"tier": "candidate", "health_status": "transient_unconfirmed", "health_reason": reason, "desired_disabled": True, "governance_eligible": False})
        elif status in {"hard_bad", "invalid", "invalid_auth", "refresh_failed"}:
            state.update({"tier": "quarantine", "health_status": "invalid_auth", "health_reason": reason, "desired_disabled": True, "governance_eligible": True})
        state["last_checked_at"] = str(result.get("checked_at") or "")
        state["updated_at"] = _iso_to_ts(state["last_checked_at"]) or time.time()
        return state

    def _load_durable_state(self) -> None:
        try:
            repo = self._repo()
            states = repo.list_accounts()
            if not states and self._results:
                migrated = [
                    self._state_from_legacy_result(result)
                    for result in self._results.values()
                    if str(result.get("email") or "").strip()
                ]
                repo.upsert_accounts(migrated)
                states = repo.list_accounts()
            for state in states:
                email = str(state.get("email") or "").strip().lower()
                if not email:
                    continue
                row = dict(self._results.get(email) or {"email": email})
                row.update(
                    {
                        "tier": state.get("tier") or "candidate",
                        "health_status": state.get("health_status") or "unchecked",
                        "confidence": int(state.get("confidence") or 0),
                        "desired_priority": state.get("desired_priority"),
                        "desired_disabled": state.get("desired_disabled"),
                        "actual_priority": state.get("actual_priority"),
                        "actual_disabled": state.get("actual_disabled"),
                        "next_check_at": state.get("next_check_at") or 0,
                    }
                )
                self._results[email] = row
            self._breaker_cache = {
                str(item.get("scope") or ""): item
                for item in repo.list_breakers()
                if str(item.get("scope") or "")
            }
        except Exception as exc:  # noqa: BLE001
            self._logs.append(f"[{timeutil.now_clock()}] CPA 状态数据库加载失败: {_mask_error(exc)}")

    def _log(self, message: str) -> None:
        line = f"[{timeutil.now_clock()}] {str(message).rstrip()}"
        with self._lock:
            self._logs.append(line)

    def _elapsed_sec(self, *, fallback_started: float | None = None) -> float:
        started_ts = _iso_to_ts(self._started_at)
        if started_ts > 0:
            return round(max(0.0, time.time() - started_ts), 2)
        if fallback_started is not None:
            return round(max(0.0, time.monotonic() - fallback_started), 2)
        return 0.0

    def _effective_scan_settings(self, options: dict[str, Any]) -> dict[str, Any]:
        settings = settings_from_config()
        for key in DEFAULT_SETTINGS:
            if key in options:
                settings[key] = options[key]
        settings["scan_workers"] = _coerce_int(settings.get("scan_workers"), 16, min_v=1, max_v=100)
        settings["probe_timeout_sec"] = _coerce_float(settings.get("probe_timeout_sec"), 30.0, min_v=3.0, max_v=180.0)
        settings["probe_chat"] = _coerce_bool(settings.get("probe_chat"), False)
        settings["refresh_before_probe"] = _coerce_bool(settings.get("refresh_before_probe"), True)
        settings["apply_policy"] = _coerce_bool(settings.get("apply_policy"), False)
        settings["auto_refill"] = _coerce_bool(settings.get("auto_refill"), False)
        settings["refresh_skew_sec"] = _coerce_int(settings.get("refresh_skew_sec"), 2700, min_v=0, max_v=86400)
        settings["max_items_per_scan"] = _coerce_int(settings.get("max_items_per_scan"), 0, min_v=0, max_v=100000)
        settings["refill_target_active"] = _coerce_int(settings.get("refill_target_active"), 0, min_v=0, max_v=100000)
        settings["refill_max_per_scan"] = _coerce_int(settings.get("refill_max_per_scan"), 200, min_v=1, max_v=10000)
        settings["refill_workers"] = _coerce_int(settings.get("refill_workers"), -1, min_v=-1, max_v=20)
        settings["refill_probe_chat"] = _coerce_bool(settings.get("refill_probe_chat"), False)
        settings["refill_controller_interval_sec"] = _coerce_int(settings.get("refill_controller_interval_sec"), 30, min_v=10, max_v=3600)
        settings["refill_emergency_threshold_percent"] = _coerce_int(settings.get("refill_emergency_threshold_percent"), 90, min_v=0, max_v=100)
        settings["scan_history_limit"] = _coerce_int(settings.get("scan_history_limit"), 100, min_v=0, max_v=1000)
        settings["observation_retention_days"] = _coerce_int(settings.get("observation_retention_days"), 7, min_v=1, max_v=365)
        settings["governance_action_retention_days"] = _coerce_int(settings.get("governance_action_retention_days"), 90, min_v=1, max_v=3650)
        settings["scheduler_tick_sec"] = _coerce_int(settings.get("scheduler_tick_sec"), 300, min_v=30, max_v=3600)
        settings["adaptive_batch_size"] = _coerce_int(settings.get("adaptive_batch_size"), 200, min_v=1, max_v=10000)
        settings["healthy_check_interval_sec"] = _coerce_int(settings.get("healthy_check_interval_sec"), 43200, min_v=1800, max_v=7 * 86400)
        settings["observe_check_interval_sec"] = _coerce_int(settings.get("observe_check_interval_sec"), 720, min_v=60, max_v=86400)
        settings["candidate_check_interval_sec"] = _coerce_int(settings.get("candidate_check_interval_sec"), 1200, min_v=60, max_v=86400)
        settings["chat_sample_percent"] = _coerce_int(settings.get("chat_sample_percent"), 5, min_v=0, max_v=100)
        settings["refill_low_water_rounds"] = _coerce_int(settings.get("refill_low_water_rounds"), 2, min_v=1, max_v=10)
        settings["refill_min_baseline_percent"] = _coerce_int(settings.get("refill_min_baseline_percent"), 100, min_v=1, max_v=100)
        settings["refill_cooling_grace_sec"] = _coerce_int(settings.get("refill_cooling_grace_sec"), 86400, min_v=0, max_v=30 * 86400)
        return settings

    def _load_state(self) -> None:
        if not self._state_path.is_file():
            self._load_durable_state()
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                self._load_durable_state()
                return
            results = data.get("results") or {}
            if isinstance(results, list):
                results = {str(r.get("email") or "").lower(): r for r in results if isinstance(r, dict)}
            if isinstance(results, dict):
                self._results = {str(k).lower(): _beijingize_record(dict(v)) for k, v in results.items() if isinstance(v, dict)}
            if isinstance(data.get("summary"), dict):
                self._summary = _beijingize_record(dict(data["summary"]))
            history = data.get("scan_history") or []
            if isinstance(history, list):
                self._scan_history = [_beijingize_record(dict(item)) for item in history if isinstance(item, dict)]
            finished_value = data.get("finished_at") or self._summary.get("finished_at") or ""
            self._last_finished_ts = _iso_to_ts(str(finished_value))
            self._finished_at = timeutil.iso_to_beijing_display(finished_value) if finished_value else ""
            self._started_at = str(data.get("started_at") or "")
            self._scan_id = str(data.get("scan_id") or "")
            self._last_error = str(data.get("last_error") or "")
            if isinstance(data.get("progress"), dict):
                self._progress = dict(data["progress"])
            logs = data.get("logs") or []
            if isinstance(logs, list):
                self._logs.extend(str(line) for line in logs if isinstance(line, str))
            try:
                self._next_scan_at = max(0.0, float(data.get("next_scan_at") or 0))
            except (TypeError, ValueError):
                self._next_scan_at = 0.0
            self._scheduled_interval_sec = _coerce_int(data.get("scheduled_interval_sec"), 0, min_v=0, max_v=86400)
            self._resume_count = _coerce_int(data.get("resume_count"), 0, min_v=0)
            self._resumed_at = str(data.get("resumed_at") or "")

            active = data.get("active_scan")
            if isinstance(active, dict) and str(active.get("status") or "") == "running":
                restored = dict(active)
                restored["items"] = [dict(item) for item in (active.get("items") or []) if isinstance(item, dict)]
                restored["completed"] = list(
                    dict.fromkeys(str(key) for key in (active.get("completed") or []) if str(key))
                )
                restored["options"] = dict(active.get("options") or {}) if isinstance(active.get("options"), dict) else {}
                restored["settings"] = dict(active.get("settings") or {}) if isinstance(active.get("settings"), dict) else {}
                self._active_scan = restored
                self._scan_id = str(restored.get("scan_id") or self._scan_id)
                self._started_at = str(restored.get("started_at") or self._started_at)
                self._resume_count = _coerce_int(restored.get("resume_count"), self._resume_count, min_v=0)
                self._resumed_at = str(restored.get("resumed_at") or self._resumed_at)
                if restored["settings"]:
                    loaded_settings = dict(DEFAULT_SETTINGS)
                    loaded_settings.update(restored["settings"])
                    self._settings = loaded_settings
                restored_count = self._restore_scan_journal()
                if restored_count:
                    self._logs.append(
                        f"[{timeutil.now_clock()}] 从巡检检查点恢复 {restored_count} 个已完成账号"
                    )
                self._recovery_pending = not bool(restored.get("cancel_requested"))
        except Exception:
            self._load_durable_state()
            return
        self._load_durable_state()

    def _scan_journal_path(self) -> Path:
        return self._state_path.with_name(SCAN_JOURNAL_FILENAME)

    def _restore_scan_journal(self) -> int:
        active = self._active_scan
        scan_id = str(active.get("scan_id") or "")
        path = self._scan_journal_path()
        if not scan_id or not path.is_file():
            return 0

        item_keys = {
            self._scan_item_key(item)
            for item in (active.get("items") or [])
            if isinstance(item, dict) and self._scan_item_key(item)
        }
        if not item_keys:
            return 0

        journal_rows: dict[str, tuple[dict[str, Any], str]] = {}
        try:
            with path.open("rb") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except (TypeError, UnicodeDecodeError, ValueError):
                        continue
                    if (
                        not isinstance(record, dict)
                        or record.get("journal_version") != SCAN_JOURNAL_VERSION
                        or str(record.get("scan_id") or "") != scan_id
                    ):
                        continue
                    item_key = str(record.get("item_key") or "").strip().lower()
                    row = record.get("row")
                    if item_key not in item_keys or not isinstance(row, dict):
                        continue
                    journal_rows[item_key] = (dict(row), str(record.get("recorded_at") or ""))
        except OSError:
            return 0

        completed = list(
            dict.fromkeys(str(key) for key in (active.get("completed") or []) if str(key))
        )
        completed_set = set(completed)
        summary = dict(self._summary)
        counts = {str(k): int(v or 0) for k, v in dict(summary.get("counts") or {}).items()}
        actions = {str(k): int(v or 0) for k, v in dict(summary.get("actions") or {}).items()}
        refreshed = int(summary.get("refreshed") or 0)
        reenabled = int(summary.get("reenabled") or 0)
        restored_count = 0
        current = ""
        last_checkpoint_at = str(active.get("last_checkpoint_at") or "")

        for item_key, (raw_row, recorded_at) in journal_rows.items():
            row = _beijingize_record(raw_row)
            email = str(row.get("email") or "").strip().lower()
            if email and (item_key not in completed_set or email not in self._results):
                self._results[email] = row
            if item_key in completed_set:
                continue
            completed.append(item_key)
            completed_set.add(item_key)
            status = str(row.get("status") or "probe_failed")
            counts[status] = counts.get(status, 0) + 1
            if row.get("refreshed"):
                refreshed += 1
            if row.get("reenabled"):
                reenabled += 1
            if row.get("action"):
                action = str(row.get("action"))
                actions[action] = actions.get(action, 0) + 1
            restored_count += 1
            current = email or item_key
            if recorded_at:
                last_checkpoint_at = recorded_at

        if not restored_count:
            return 0

        total = len(item_keys)
        summary.update(
            {
                "counts": counts,
                "actions": actions,
                "total": total,
                "done": len(completed_set),
                "refreshed": refreshed,
                "reenabled": reenabled,
                "trigger": active.get("trigger") or summary.get("trigger") or "manual",
                "started_at": active.get("started_at") or summary.get("started_at") or self._started_at,
            }
        )
        self._summary = summary
        self._progress = {"done": len(completed_set), "total": total, "current": current}
        self._active_scan["completed"] = completed
        if last_checkpoint_at:
            self._active_scan["last_checkpoint_at"] = last_checkpoint_at
        return restored_count

    def _append_scan_journal(self, *, scan_id: str, item_key: str, row: dict[str, Any]) -> bool:
        record = {
            "journal_version": SCAN_JOURNAL_VERSION,
            "scan_id": scan_id,
            "item_key": item_key,
            "recorded_at": _utc_now(),
            "row": row,
        }
        try:
            encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            with self._state_write_lock:
                path = self._scan_journal_path()
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
                    handle.flush()
            return True
        except Exception:
            return False

    def _clear_scan_journal(self) -> bool:
        try:
            with self._state_write_lock:
                self._scan_journal_path().unlink(missing_ok=True)
            return True
        except Exception:
            return False

    def _save_state(self) -> bool:
        try:
            with self._state_write_lock:
                with self._lock:
                    active_scan = dict(self._active_scan) if self._active_scan else None
                    if active_scan and isinstance(active_scan.get("settings"), dict):
                        persisted_settings = dict(active_scan["settings"])
                        persisted_settings.pop("cli_management_key", None)
                        active_scan["settings"] = persisted_settings
                    payload = {
                        "state_version": STATE_VERSION,
                        "next_scan_at": self._next_scan_at,
                        "scheduled_interval_sec": self._scheduled_interval_sec,
                        "scan_id": self._scan_id,
                        "started_at": self._started_at,
                        "finished_at": self._finished_at,
                        "last_error": self._last_error,
                        "progress": dict(self._progress),
                        "summary": dict(self._summary),
                        "logs": list(self._logs),
                        "resume_count": self._resume_count,
                        "resumed_at": self._resumed_at,
                        "active_scan": active_scan,
                        "scan_history": list(self._scan_history),
                        "results": dict(self._results),
                    }
                encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._state_path.with_name(
                    f".{self._state_path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
                )
                try:
                    tmp.write_text(encoded, encoding="utf-8")
                    os.replace(tmp, self._state_path)
                finally:
                    tmp.unlink(missing_ok=True)
            return True
        except Exception:
            return False

    def _sync_schedule_locked(self, settings: dict[str, Any], *, now: float) -> bool:
        interval = _coerce_int(settings.get("scheduler_tick_sec"), 300, min_v=30, max_v=3600)
        changed = False
        if self._scheduled_interval_sec <= 0:
            self._scheduled_interval_sec = interval
            changed = True
            if not self._next_scan_at:
                base = self._last_finished_ts or now
                self._next_scan_at = base + interval
        elif self._scheduled_interval_sec != interval:
            self._scheduled_interval_sec = interval
            self._next_scan_at = now + interval
            changed = True
        elif not self._next_scan_at:
            self._next_scan_at = now + interval
            changed = True
        return changed

    def _prepare_recovery_locked(self) -> threading.Thread | None:
        active = self._active_scan
        if self._running or str(active.get("status") or "") != "running" or active.get("cancel_requested"):
            return None
        self._running = True
        self._cancel.clear()
        self._scan_id = str(active.get("scan_id") or self._scan_id or uuid.uuid4().hex[:10])
        self._started_at = str(active.get("started_at") or self._started_at or _utc_now())
        self._finished_at = ""
        self._last_error = ""
        try:
            loaded_settings = settings_from_config()
        except Exception:
            loaded_settings = dict(DEFAULT_SETTINGS)
        loaded_settings.update(dict(active.get("settings") or {}))
        self._settings = loaded_settings
        active["settings"] = loaded_settings
        self._resume_count = _coerce_int(active.get("resume_count"), 0, min_v=0) + 1
        self._resumed_at = _utc_now()
        self._recovery_pending = False
        active.update(
            {
                "scan_id": self._scan_id,
                "started_at": self._started_at,
                "resume_count": self._resume_count,
                "resumed_at": self._resumed_at,
            }
        )
        options = dict(active.get("options") or {})
        t = threading.Thread(
            target=self._run_scan,
            args=(options,),
            kwargs={"resume": True},
            daemon=True,
            name="cpa-pool-scan",
        )
        self._scan_thread = t
        return t

    def _finalize_persisted_cancellation(self, *, schedule_settings: dict[str, Any]) -> None:
        with self._lock:
            active = dict(self._active_scan)
            if str(active.get("status") or "") != "running" or not active.get("cancel_requested"):
                return
            self._scan_id = str(active.get("scan_id") or self._scan_id or uuid.uuid4().hex[:10])
            self._started_at = str(active.get("started_at") or self._started_at or _utc_now())
            self._resume_count = _coerce_int(active.get("resume_count"), self._resume_count, min_v=0)
            self._resumed_at = str(active.get("resumed_at") or self._resumed_at)
            loaded_settings = dict(DEFAULT_SETTINGS)
            loaded_settings.update(dict(active.get("settings") or {}))
            self._settings = loaded_settings
            self._cancel.set()
            self._running = False
            self._recovery_pending = False
            self._finished_at = _utc_now()
            self._last_finished_ts = time.time()
            self._summary.setdefault("trigger", active.get("trigger") or "manual")
            self._summary.setdefault("started_at", self._started_at)
            self._summary["done"] = int(self._progress.get("done") or self._summary.get("done") or 0)
            self._summary["elapsed_sec"] = self._elapsed_sec()
            self._summary["finished_at"] = self._finished_at
            self._summary["refill"] = {
                "enabled": bool(self._settings.get("auto_refill")),
                "started": False,
                "cancelled": True,
            }
            self._active_scan = {}
            interval = _coerce_int(schedule_settings.get("scheduler_tick_sec"), 300, min_v=30, max_v=3600)
            self._scheduled_interval_sec = interval
            self._next_scan_at = time.time() + interval
        self._log("检测到已持久化的停止请求，原巡检任务不再恢复")
        self._append_scan_history(settings=self._settings)
        if self._save_state():
            self._clear_scan_journal()

    def ensure_scheduler(self) -> None:
        cfg_settings = settings_from_config()
        now = time.time()
        recovery_thread: threading.Thread | None = None
        scheduler_thread: threading.Thread | None = None
        finalize_cancel = False
        save_state = False
        with self._lock:
            if not self._running:
                self._settings = cfg_settings
            save_state = self._sync_schedule_locked(cfg_settings, now=now)
            if str(self._active_scan.get("status") or "") == "running":
                if self._active_scan.get("cancel_requested"):
                    finalize_cancel = True
                else:
                    recovery_thread = self._prepare_recovery_locked()
                    save_state = save_state or recovery_thread is not None
            if not self._scheduler_thread or (
                self._scheduler_thread.ident is not None and not self._scheduler_thread.is_alive()
            ):
                self._scheduler_stop.clear()
                scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True, name="cpa-pool-scheduler")
                self._scheduler_thread = scheduler_thread
        if finalize_cancel:
            self._finalize_persisted_cancellation(schedule_settings=cfg_settings)
        elif recovery_thread is not None:
            self._log(
                f"恢复 CPA 巡检：id={self._scan_id} done={self._progress.get('done', 0)}/"
                f"{self._progress.get('total', 0)} resume={self._resume_count}"
            )
            self._save_state()
            recovery_thread.start()
        elif save_state:
            self._save_state()
        if scheduler_thread is not None:
            scheduler_thread.start()

    def _scheduler_loop(self) -> None:
        while not self._scheduler_stop.is_set():
            try:
                self._scheduler_tick()
            except Exception as exc:  # noqa: BLE001
                self._log(f"scheduler error: {exc}")
            self._scheduler_stop.wait(1.0)

    def _scheduler_tick(self, *, now: float | None = None) -> None:
        cfg_settings = settings_from_config()
        current = time.time() if now is None else float(now)
        if current - self._last_maintenance_at >= 3600:
            self._prune_durable_history(cfg_settings, now=current)
        if current - self._runtime_synced_at >= max(5.0, float(cfg_settings.get("cli_management_cache_sec") or 10.0)):
            self._sync_runtime_snapshot(cfg_settings)
            self._reconcile_drift(cfg_settings)
            self._rebalance_tiers(cfg_settings)
        with self._lock:
            if not self._running:
                self._settings = cfg_settings
            schedule_changed = self._sync_schedule_locked(cfg_settings, now=current)
            due = (
                bool(cfg_settings.get("auto_scan"))
                and not self._running
                and not self._recovery_pending
                and str(self._active_scan.get("status") or "") != "running"
                and current >= float(self._next_scan_at or 0)
            )
        if schedule_changed:
            self._save_state()
        if due:
            self.start_scan({"trigger": "auto", "adaptive": True})
        else:
            self._run_refill_controller(cfg_settings, now=current)

    def _run_refill_controller(self, settings: dict[str, Any], *, now: float) -> None:
        interval = int(settings.get("refill_controller_interval_sec") or 30)
        with self._lock:
            if self._running or now - self._last_refill_controller_at < interval:
                return
            self._last_refill_controller_at = now
        if not bool(settings.get("auto_refill")):
            return
        try:
            self._maybe_start_refill(
                settings=settings,
                initial_total=len(store.list_cpa_index()),
                trigger="controller",
            )
        except Exception as exc:  # noqa: BLE001
            self._log(f"自动补号控制器异常：{_mask_error(exc)}")

    def _prune_durable_history(self, settings: dict[str, Any], *, now: float | None = None) -> None:
        current = time.time() if now is None else float(now)
        self._last_maintenance_at = current
        try:
            deleted = self._repo().prune_history(
                observations_before=current - int(settings.get("observation_retention_days") or 7) * 86400,
                actions_before=current - int(settings.get("governance_action_retention_days") or 90) * 86400,
            )
            if any(deleted.values()):
                self._log(
                    "CPA 历史清理："
                    f"observations={deleted['observations']} actions={deleted['actions']}"
                )
        except Exception as exc:  # noqa: BLE001
            self._log(f"CPA 历史清理失败：{_mask_error(exc)}")

    @staticmethod
    def _bootstrap_inventory_state(
        state: dict[str, Any],
        item: dict[str, Any],
        *,
        now: float,
    ) -> dict[str, Any]:
        if str(state.get("health_status") or "unchecked") != "unchecked" or state.get("last_checked_at"):
            return state

        managed = bool(item.get("pool_managed"))
        tier = str(item.get("pool_tier") or "").strip().lower()
        if tier == "recovery":
            tier = "candidate"
        known_tiers = {
            "main",
            "reserve",
            "candidate",
            "observe",
            "cooling",
            "quarantine",
            "malformed",
            "manual_disabled",
        }
        disabled = bool(item.get("disabled"))
        try:
            actual_priority = int(item.get("priority") or 0)
        except (TypeError, ValueError):
            actual_priority = 0

        if managed and tier in known_tiers:
            desired_disabled = tier not in {"main", "reserve", "observe"}
            desired_priority = MAIN_PRIORITY if tier == "main" else RESERVE_PRIORITY if tier == "reserve" else OBSERVE_PRIORITY
            state.update(
                {
                    "tier": tier,
                    "desired_priority": desired_priority,
                    "desired_disabled": desired_disabled,
                    "actual_priority": actual_priority,
                    "actual_disabled": disabled,
                    "manual_override": tier == "manual_disabled",
                    "governance_eligible": tier != "manual_disabled",
                }
            )
            cool_until = str(item.get("cool_until") or "")
            if cool_until:
                state["cool_until"] = cool_until
                state["cool_until_ts"] = _iso_to_ts(cool_until)
                if tier == "cooling":
                    state["next_check_at"] = state["cool_until_ts"] or now
        elif disabled:
            state.update(
                {
                    "tier": "manual_disabled",
                    "desired_priority": actual_priority or OBSERVE_PRIORITY,
                    "desired_disabled": True,
                    "actual_priority": actual_priority,
                    "actual_disabled": True,
                    "manual_override": True,
                    "governance_eligible": False,
                    "next_check_at": 0.0,
                }
            )
        else:
            # Existing unclassified files remain routable only as reserve until
            # a successful probe or runtime request promotes them to main.
            state.update(
                {
                    "tier": "reserve",
                    "desired_priority": RESERVE_PRIORITY,
                    "desired_disabled": False,
                    "actual_priority": actual_priority,
                    "actual_disabled": False,
                    "governance_eligible": False,
                }
            )
        state["updated_at"] = now
        return state

    def _sync_inventory_states(self, index: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        repo = self._repo()
        existing = {str(row.get("email") or "").lower(): row for row in repo.list_accounts()}
        changed: list[dict[str, Any]] = []
        now = time.time()
        for email, item in index.items():
            normalized = str(email or "").strip().lower()
            if not normalized:
                continue
            state = dict(existing.get(normalized) or default_state(normalized, path=str(item.get("path") or ""), now=now))
            before = dict(state)
            state = self._bootstrap_inventory_state(state, item, now=now)
            path = str(item.get("path") or "")
            if path and state.get("path") != path:
                state["path"] = path
                state["updated_at"] = now
                changed.append(state)
            elif normalized not in existing or state != before:
                changed.append(state)
            existing[normalized] = state
        if changed:
            repo.upsert_accounts(changed)
        return existing

    def _sync_runtime_snapshot(self, settings: dict[str, Any], *, force: bool = False) -> None:
        client = self._management(settings)
        if not client.available:
            with self._lock:
                self._runtime_snapshot = {}
                self._runtime_loaded_count = 0
                self._runtime_connected = False
                self._runtime_error = "未配置 CLIProxy 管理 API"
                self._runtime_synced_at = time.time()
            return
        try:
            files = client.list_auth_files(force=force)
            xai_files = [
                item
                for item in files
                if str(item.get("provider") or item.get("type") or "").strip().lower() == "xai"
                or str(item.get("name") or "").lower().startswith("xai-")
            ]
            snapshot = client.by_email(xai_files)
            repo = self._repo()
            try:
                existing = self._sync_inventory_states(store.list_cpa_index())
            except Exception:
                existing = {str(row.get("email") or "").lower(): row for row in repo.list_accounts()}
            changed: list[dict[str, Any]] = []
            now = time.time()
            for email, runtime in snapshot.items():
                state = dict(existing.get(email) or default_state(email, path=str(runtime.get("path") or ""), now=now))
                old_success = int(state.get("runtime_success_count") or 0)
                old_failed = int(state.get("runtime_failed_count") or 0)
                success = int(runtime.get("success") or 0)
                failed = int(runtime.get("failed") or 0)
                if success > old_success:
                    observation = {
                        "email": email,
                        "path": state.get("path") or runtime.get("path") or "",
                        "checked_at": _utc_now(),
                        "status": "ok",
                        "reason": f"CLIProxy runtime success +{success - old_success}",
                        "stage": "runtime",
                    }
                    state = transition_state(
                        state,
                        observation,
                        now=now,
                        recovery_success_threshold=1,
                        healthy_interval_sec=int(settings.get("healthy_check_interval_sec") or 43200),
                    )
                    state["last_runtime_success_at"] = observation["checked_at"]
                elif failed > old_failed:
                    classified = classify_failure(
                        {
                            "status": 0,
                            "error": runtime.get("status_message") or runtime.get("status") or "runtime request failed",
                        },
                        stage="runtime",
                    )
                    if classified.status in {"account_quota", "upstream_busy"}:
                        observation = {
                            "email": email,
                            "path": state.get("path") or runtime.get("path") or "",
                            "checked_at": _utc_now(),
                            **classified.to_dict(),
                        }
                        state = transition_state(
                            state,
                            observation,
                            now=now,
                            recovery_success_threshold=int(settings.get("recovery_success_threshold") or 2),
                            quota_cooldown_sec=int(settings.get("quota_cooldown_sec") or 86400),
                            healthy_interval_sec=int(settings.get("healthy_check_interval_sec") or 43200),
                            observe_interval_sec=int(settings.get("observe_check_interval_sec") or 720),
                            candidate_interval_sec=int(settings.get("candidate_check_interval_sec") or 1200),
                        )
                        state["last_runtime_failure_at"] = observation["checked_at"]
                    elif classified.status == "invalid_auth":
                        state.update(
                            {
                                "health_status": "invalid_auth_pending_probe",
                                "health_reason": classified.reason,
                                "next_check_at": now,
                                "last_runtime_failure_at": _utc_now(),
                            }
                        )
                elif success < old_success or failed < old_failed:
                    state["runtime_counter_reset_at"] = _utc_now()
                state.update(
                    {
                        "actual_priority": int(runtime.get("priority") or 0),
                        "actual_disabled": bool(runtime.get("disabled")),
                        "runtime_unavailable": bool(runtime.get("unavailable")),
                        "runtime_status": str(runtime.get("status") or ""),
                        "runtime_status_message": _mask_error(runtime.get("status_message") or "", 200),
                        "runtime_next_retry_after": str(runtime.get("next_retry_after") or ""),
                        "runtime_success_count": success,
                        "runtime_failed_count": failed,
                        "runtime_seen_at": _utc_now(),
                        "updated_at": now,
                    }
                )
                changed.append(state)
            if changed:
                repo.upsert_accounts(changed)
            with self._lock:
                for state in changed:
                    email = str(state.get("email") or "").lower()
                    row = dict(self._results.get(email) or {"email": email})
                    row.update(
                        {
                            "tier": state.get("tier"),
                            "health_status": state.get("health_status"),
                            "confidence": state.get("confidence"),
                            "desired_priority": state.get("desired_priority"),
                            "desired_disabled": state.get("desired_disabled"),
                            "actual_priority": state.get("actual_priority"),
                            "actual_disabled": state.get("actual_disabled"),
                        }
                    )
                    if state.get("last_runtime_success_at"):
                        row.update({"status": "ok", "reason": "CLIProxy runtime success", "checked_at": state.get("last_runtime_success_at")})
                    self._results[email] = row
                self._runtime_snapshot = snapshot
                self._runtime_loaded_count = len(xai_files)
                self._runtime_connected = True
                self._runtime_error = ""
                self._runtime_synced_at = now
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._runtime_connected = False
                self._runtime_loaded_count = 0
                self._runtime_error = _mask_error(exc)
                self._runtime_synced_at = time.time()

    def _breaker_is_open(self, stage: str | None = None) -> bool:
        now = time.time()
        for scope, breaker in list(self._breaker_cache.items()):
            if stage and scope != stage:
                continue
            state = str(breaker.get("state") or "closed")
            if state == "half_open":
                return True
            if state == "open":
                return True
        return False

    def _breaker_blocks_probe(self, stage: str) -> bool:
        now = time.time()
        with self._lock:
            breaker = dict(self._breaker_cache.get(stage) or {})
            state = str(breaker.get("state") or "closed")
            if state == "open" and float(breaker.get("open_until") or 0) <= now:
                breaker.update({"state": "half_open", "half_open_at": now, "half_open_attempts": 0, "updated_at": now})
                state = "half_open"
            if state == "open":
                return True
            if state != "half_open":
                return False
            attempts = int(breaker.get("half_open_attempts") or 0)
            if attempts >= 5:
                return True
            breaker["half_open_attempts"] = attempts + 1
            breaker["updated_at"] = now
            self._breaker_cache[stage] = breaker
        self._repo().put_breaker(stage, breaker)
        return False

    def _record_observation(
        self,
        row: dict[str, Any],
        *,
        previous_state: dict[str, Any] | None,
        settings: dict[str, Any],
    ) -> None:
        if row.get("breaker_skipped"):
            return
        observed_at = _iso_to_ts(str(row.get("checked_at") or "")) or time.time()
        observation = {
            key: row.get(key)
            for key in (
                "email",
                "path",
                "checked_at",
                "status",
                "reason",
                "reason_code",
                "stage",
                "fingerprint",
                "account_attributable",
                "conclusive",
                "http_status",
                "retry_after_sec",
            )
            if row.get(key) is not None
        }
        observation["known_healthy"] = bool(
            str((previous_state or {}).get("tier") or "") in {"main", "reserve"}
            or str((previous_state or {}).get("health_status") or "") == "healthy"
            or str(row.get("status") or "") == "ok"
        )
        repo = self._repo()
        repo.add_observation(scan_id=self._scan_id, observation=observation, observed_at=observed_at)
        stage = str(row.get("stage") or "probe")
        window_sec = int(settings.get("breaker_window_sec") or 300)
        scope = stage
        current = dict(self._breaker_cache.get(scope) or {"scope": scope, "state": "closed"})
        state_name = str(current.get("state") or "closed")
        if state_name == "open" and observed_at >= float(current.get("open_until") or 0):
            current.update({"state": "half_open", "half_open_at": observed_at, "updated_at": observed_at})
            state_name = "half_open"

        half_open_at = float(current.get("half_open_at") or observed_at) if state_name == "half_open" else None
        stats = repo.breaker_stats(
            stage=stage,
            since=observed_at - window_sec,
            half_open_at=half_open_at,
            canary_limit=5,
        )

        if state_name == "half_open":
            canary_statuses = list(stats.get("canary_statuses") or [])
            if len(canary_statuses) < 5:
                current.update({"state": "half_open", "updated_at": observed_at})
                repo.put_breaker(scope, current)
                self._breaker_cache[scope] = current
                return
            successes = sum(1 for status in canary_statuses if str(status) == "ok")
            if successes >= 4:
                current = {"scope": scope, "state": "closed", "closed_at": observed_at, "updated_at": observed_at}
                self._log(f"上游熔断已恢复：scope={scope} canaries={successes}/5")
            else:
                current.update(
                    {
                        "state": "open",
                        "opened_at": observed_at,
                        "open_until": observed_at + int(settings.get("breaker_open_sec") or 180),
                        "sample_count": len(canary_statuses),
                        "error_count": len(canary_statuses) - successes,
                        "error_ratio": round((len(canary_statuses) - successes) / len(canary_statuses), 4),
                        "updated_at": observed_at,
                    }
                )
                self._log(f"上游熔断继续保持：scope={scope} canaries={successes}/5")
            repo.put_breaker(scope, current)
            self._breaker_cache[scope] = current
            return

        samples = int(stats.get("sample_count") or 0)
        top_fingerprint = str(stats.get("top_fingerprint") or "")
        top_errors = int(stats.get("top_errors") or 0)
        ratio = (top_errors / samples) if samples else 0.0
        if (
            samples >= int(settings.get("breaker_min_samples") or 30)
            and top_errors >= int(settings.get("breaker_min_errors") or 10)
            and ratio >= float(settings.get("breaker_error_ratio") or 0.30)
        ):
            was_open = self._breaker_is_open(stage)
            current = {
                "scope": scope,
                "state": "open",
                "fingerprint": top_fingerprint,
                "sample_count": samples,
                "error_count": top_errors,
                "error_ratio": round(ratio, 4),
                "reason": str(row.get("reason") or "provider/model failure"),
                "opened_at": float(current.get("opened_at") or observed_at) if was_open else observed_at,
                "open_until": observed_at + int(settings.get("breaker_open_sec") or 180),
                "updated_at": observed_at,
            }
            if not was_open:
                self._log(f"上游熔断已打开：scope={scope} errors={top_errors}/{samples}")
        repo.put_breaker(scope, current)
        self._breaker_cache[scope] = current

    _POOL_METRICS_TTL_SEC = 15.0

    def _pool_metrics(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._pool_metrics_lock:
            cached = self._pool_metrics_cache.get("value")
            fresh = cached is not None and now - float(self._pool_metrics_cache.get("at") or 0) < self._POOL_METRICS_TTL_SEC
            if fresh:
                return dict(cached)
            if self._pool_metrics_cache.get("computing"):
                # 已有线程在重算：直接返回旧值，避免请求线程在 IO 上堆积
                return dict(cached) if cached is not None else {}
            self._pool_metrics_cache["computing"] = True
        try:
            metrics = self._compute_pool_metrics()
        finally:
            with self._pool_metrics_lock:
                self._pool_metrics_cache["computing"] = False
        with self._pool_metrics_lock:
            self._pool_metrics_cache.update({"at": time.monotonic(), "value": dict(metrics)})
        return metrics

    def _compute_pool_metrics(self) -> dict[str, Any]:
        try:
            index = store.list_cpa_index()
        except Exception:
            index = {}
        states = {str(item.get("email") or "").lower(): item for item in self._repo().list_accounts()}
        with self._lock:
            runtime = dict(self._runtime_snapshot)
            runtime_loaded_count = self._runtime_loaded_count
            runtime_connected = self._runtime_connected
            runtime_error = self._runtime_error
        metrics: dict[str, Any] = {
            "file_inventory": len(index),
            "cli_loaded": runtime_loaded_count if runtime_connected else None,
            "runtime_connected": runtime_connected,
            "main": 0,
            "main_routeable": 0,
            "reserve": 0,
            "reserve_routeable": 0,
            "candidate": 0,
            "observe": 0,
            "cooling": 0,
            "quarantine": self.quarantine_summary().get("total", 0),
            "manual_disabled": 0,
            "unchecked": 0,
            "baseline_checked": 0,
            "baseline_percent": 0.0,
            "drift": 0,
            "runtime_error": runtime_error,
        }
        for email in index:
            state = states.get(email) or default_state(email, path=str(index[email].get("path") or ""))
            tier = str(state.get("tier") or "candidate")
            if tier in metrics:
                metrics[tier] += 1
            else:
                metrics["candidate"] += 1
            if str(state.get("health_status") or "") == "unchecked":
                metrics["unchecked"] += 1
            if state.get("last_checked_at"):
                metrics["baseline_checked"] += 1
            actual = runtime.get(email)
            if actual is not None:
                routeable = not bool(actual.get("disabled")) and not bool(actual.get("unavailable"))
                actual_priority = int(actual.get("priority") or 0)
                desired_priority = int(state.get("desired_priority") or 0)
                desired_disabled = bool(state.get("desired_disabled"))
                if actual_priority != desired_priority or bool(actual.get("disabled")) != desired_disabled:
                    metrics["drift"] += 1
            elif runtime_connected:
                routeable = False
                if tier in {"main", "reserve"}:
                    metrics["drift"] += 1
            else:
                disabled = state.get("actual_disabled")
                routeable = not bool(disabled if disabled is not None else state.get("desired_disabled"))
            if tier == "main" and routeable:
                metrics["main_routeable"] += 1
            elif tier == "reserve" and routeable:
                metrics["reserve_routeable"] += 1
        breakers = list(self._breaker_cache.values())
        metrics["baseline_percent"] = round(
            (int(metrics["baseline_checked"]) * 100 / len(index)) if index else 100.0,
            2,
        )
        active_breakers = [item for item in breakers if self._breaker_is_open(str(item.get("scope") or ""))]
        metrics["upstream_state"] = "open" if active_breakers else "healthy"
        metrics["breakers"] = active_breakers or breakers
        return metrics

    def _reconcile_drift(self, settings: dict[str, Any], *, limit: int = 50) -> int:
        if not bool(settings.get("apply_policy")) or self._breaker_is_open():
            return 0
        try:
            active_emails = set(store.list_cpa_index())
        except Exception:
            return 0
        states = [
            state
            for state in self._repo().list_accounts()
            if str(state.get("email") or "").lower() in active_emails
        ]
        self._governance_downgrades = 0
        self._governance_limit = min(
            int(settings.get("governance_max_downgrades_per_scan") or 50),
            max(1, math.ceil(max(1, len(states)) * int(settings.get("governance_max_downgrade_percent") or 1) / 100)),
        )
        applied = 0
        for state in states:
            if applied >= max(1, limit):
                break
            if state.get("manual_override") or not state.get("governance_eligible"):
                continue
            actual_priority = state.get("actual_priority")
            actual_disabled = state.get("actual_disabled")
            desired_priority = int(state.get("desired_priority") or 0)
            desired_disabled = bool(state.get("desired_disabled"))
            if actual_priority is not None and actual_disabled is not None:
                if int(actual_priority or 0) == desired_priority and bool(actual_disabled) == desired_disabled:
                    continue
            row = {
                "email": state.get("email"),
                "path": state.get("path"),
                "status": state.get("health_status"),
                "reason_code": "drift_reconcile",
                "previous_tier": state.get("tier"),
            }
            result = self._reconcile_schedule_state(row, state, settings)
            if result.get("action"):
                applied += 1
        return applied

    def list_actions(self, *, page: int = 1, page_size: int = 10) -> dict[str, Any]:
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 10), 1000))
        total = self._repo().count_actions()
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = min(page, total_pages)
        items = []
        for raw in self._repo().list_actions(limit=page_size, offset=(page - 1) * page_size):
            item = dict(raw)
            item["action_at"] = timeutil.timestamp_display(float(item.get("action_ts") or 0)) if item.get("action_ts") else ""
            items.append(item)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    def status(self) -> dict[str, Any]:
        self.ensure_scheduler()
        with self._lock:
            summary = _beijingize_record(dict(self._summary))
            progress = dict(self._progress)
            logs = list(self._logs)[-240:]
            settings = dict(self._settings)
            management_configured = bool(settings.get("cli_management_enabled") and settings.get("cli_management_key"))
            settings.pop("cli_management_key", None)
            settings["cli_management_configured"] = management_configured
            running = self._running
            started_at = timeutil.iso_to_beijing_display(self._started_at) if self._started_at else ""
            finished_at = timeutil.iso_to_beijing_display(self._finished_at) if self._finished_at else ""
            last_error = self._last_error
            next_scan_at = self._next_scan_at
            results_total = len(self._results)
            scan_history_total = len(self._scan_history)
            scan_id = self._scan_id
            resume_count = self._resume_count
            resumed_at = timeutil.iso_to_beijing_display(self._resumed_at) if self._resumed_at else ""
            recovery_pending = self._recovery_pending
            refill_status = dict(self._refill_status)
        pool = self._pool_metrics()
        cpa_total = int(pool.get("file_inventory") or summary.get("total") or 0)
        q_total = int(pool.get("quarantine") or 0)
        counts = dict(summary.get("counts") or {})
        ok = int(pool.get("main_routeable") or counts.get("ok") or 0)
        quota = int(counts.get("quota") or 0) + int(counts.get("account_quota") or 0) + int(counts.get("cooling") or 0)
        bad = sum(
            int(v or 0)
            for k, v in counts.items()
            if k not in {"ok", "quota", "account_quota", "cooling", "upstream_busy"}
        )
        return {
            "state_version": STATE_VERSION,
            "running": running,
            "started_at": started_at,
            "finished_at": finished_at,
            "last_error": last_error,
            "next_scan_at": next_scan_at,
            "next_scan_at_display": timeutil.timestamp_display(next_scan_at) if next_scan_at else "",
            "next_scan_in_sec": max(0, int(next_scan_at - time.time())) if next_scan_at else 0,
            "scan_id": scan_id,
            "resumed": bool(running and resume_count > 0),
            "resume_count": resume_count,
            "resumed_at": resumed_at,
            "recovery_pending": recovery_pending,
            "settings": settings,
            "progress": progress,
            "summary": summary,
            "refill_status": refill_status,
            "pool": pool,
            "logs": logs,
            "cpa_total": cpa_total,
            "quarantine_total": q_total,
            "results_total": results_total,
            "scan_history_total": scan_history_total,
            "ok": ok,
            "quota": quota,
            "bad": bad,
            "upstream_state": pool.get("upstream_state") or "unknown",
        }

    def list_results(self, *, query: str = "", status: str = "all", page: int = 1, page_size: int = 100) -> dict[str, Any]:
        q = query.strip().lower()
        st = status.strip().lower()
        with self._lock:
            result_rows = list(self._results.values())
        items = [_beijingize_record(dict(v)) for v in result_rows]
        if q:
            items = [
                i
                for i in items
                if q in str(i.get("email") or "").lower()
                or q in str(i.get("status") or "").lower()
                or q in str(i.get("tier") or "").lower()
                or q in str(i.get("reason") or "").lower()
            ]
        if st and st != "all":
            if st in {"main", "reserve", "candidate", "observe", "cooling", "quarantine", "manual_disabled"}:
                items = [i for i in items if str(i.get("tier") or "").lower() == st]
            elif st == "quota":
                items = [i for i in items if str(i.get("status") or "").lower() in {"quota", "account_quota", "cooling"}]
            elif st == "bad":
                items = [i for i in items if str(i.get("status") or "").lower() not in {"ok", "quota", "account_quota", "cooling", "upstream_busy"}]
            else:
                items = [i for i in items if str(i.get("status") or "").lower() == st]
        items.sort(key=lambda i: str(i.get("checked_at") or ""), reverse=True)
        total = len(items)
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 100), 10000))
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        return {"items": items[start : start + page_size], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}

    def quarantine_summary(self) -> dict[str, Any]:
        base = _quarantine_base(settings_from_config())
        counts: dict[str, int] = {}
        total = 0
        if base.is_dir():
            for p in base.glob("**/xai-*.json"):
                if not _is_quarantine_auth_file(p):
                    continue
                bucket = p.parent.name
                counts[bucket] = counts.get(bucket, 0) + 1
                total += 1
        return {"total": total, "counts": counts, "dir": str(base)}

    def list_quarantine(self, *, query: str = "", bucket: str = "all", page: int = 1, page_size: int = 100) -> dict[str, Any]:
        base = _quarantine_base(settings_from_config())
        q = query.strip().lower()
        b = bucket.strip().lower()
        items: list[dict[str, Any]] = []
        if base.is_dir():
            for p in sorted(base.glob("**/xai-*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
                if not _is_quarantine_auth_file(p):
                    continue
                item_bucket = p.parent.name
                if b and b != "all" and item_bucket.lower() != b:
                    continue
                email = _email_from_auth_path(p)
                if q and q not in email and q not in item_bucket.lower() and q not in p.name.lower():
                    continue
                meta: dict[str, Any] = {}
                mp = p.with_suffix(p.suffix + ".meta.json")
                if mp.is_file():
                    try:
                        meta = json.loads(mp.read_text(encoding="utf-8"))
                    except Exception:
                        meta = {}
                items.append({"email": email, "bucket": item_bucket, "path": str(p), "filename": p.name, "mtime": p.stat().st_mtime, "mtime_iso": timeutil.timestamp_display(p.stat().st_mtime), "meta": meta})
        total = len(items)
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 100), 10000))
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        return {"items": items[start : start + page_size], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages, "dir": str(base)}

    def stop_scan(self) -> dict[str, Any]:
        with self._lock:
            running = self._running
            if running:
                self._cancel.set()
                if self._active_scan:
                    self._active_scan["cancel_requested"] = True
                    self._active_scan["cancel_requested_at"] = _utc_now()
        if running:
            self._log("收到停止巡检请求")
            self._save_state()
        else:
            self._log("当前没有运行中的 CPA 巡检")
        return self.status()

    def start_scan(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        options = dict(options or {})
        settings = self._effective_scan_settings(options)
        trigger = str(options.get("trigger") or "manual")
        with self._lock:
            if self._running:
                return {"started": False, "running": True, "status": self.status()}
            self._running = True
            self._cancel.clear()
            self._scan_id = uuid.uuid4().hex[:10]
            self._started_at = _utc_now()
            self._finished_at = ""
            self._last_error = ""
            self._progress = {"done": 0, "total": 0}
            self._summary = {
                "counts": {},
                "actions": {},
                "total": 0,
                "trigger": trigger,
                "started_at": self._started_at,
            }
            self._settings = settings
            self._resume_count = 0
            self._resumed_at = ""
            self._recovery_pending = False
            self._active_scan = {
                "status": "running",
                "scan_id": self._scan_id,
                "trigger": trigger,
                "options": options,
                "settings": settings,
                "started_at": self._started_at,
                "initial_total": 0,
                "snapshot_ready": False,
                "items": [],
                "completed": [],
                "cancel_requested": False,
                "resume_count": 0,
                "resumed_at": "",
            }
        self._log(f"CPA 巡检任务已持久化：id={self._scan_id} trigger={trigger}")
        if not self._clear_scan_journal():
            self._log("旧巡检检查点清理失败，将按任务 ID 隔离")
        if not self._save_state():
            with self._lock:
                self._running = False
                self._active_scan = {}
                self._last_error = "无法写入 CPA 巡检状态文件"
            return {"started": False, "running": False, "error": self._last_error, "status": self.status()}
        t = threading.Thread(
            target=self._run_scan,
            args=(options,),
            daemon=True,
            name="cpa-pool-scan",
        )
        self._scan_thread = t
        t.start()
        return {"started": True, "running": True, "status": self.status()}

    def _resolve_proxy_picker(self, raw: str | None):
        raw = str(raw or "").strip()
        if not raw or raw.lower() in _DIRECT_PROXY_VALUES:
            return lambda: "direct"
        try:
            import proxy_pool as pp

            if raw == getattr(pp, "POOL_RANDOM", "pool:random"):
                pool = pp.load_usable_pool()
                if not pool:
                    return lambda: "direct"

                def pick() -> str | None:
                    try:
                        return pp.effective_url(random.choice(pool)) or "direct"
                    except Exception:
                        return "direct"

                return pick
            fixed = pp.resolve_special(raw) or pp.effective_url(raw) or raw
            return lambda: fixed or "direct"
        except Exception:
            return lambda: raw or "direct"

    @staticmethod
    def _apply_failure_classification(
        row: dict[str, Any],
        result: dict[str, Any],
        *,
        stage: str,
    ) -> dict[str, Any]:
        classified = classify_failure(result, stage=stage)
        row.update(classified.to_dict())
        return row

    def _scan_one(self, item: dict[str, Any], settings: dict[str, Any], proxy_picker) -> dict[str, Any]:
        email = str(item.get("email") or "").strip().lower()
        path = Path(str(item.get("path") or ""))
        checked_at = _utc_now()
        base_row: dict[str, Any] = {
            "email": email,
            "path": str(path),
            "filename": path.name,
            "location": item.get("location") or "",
            "checked_at": checked_at,
            "status": "invalid",
            "reason": "not checked",
            "refreshed": False,
            "reenabled": False,
            "expired": item.get("expired") or "",
            "expires_in_sec": None,
            "models_status": None,
            "chat_status": None,
            "latency_ms": None,
        }
        started = time.monotonic()
        try:
            payload = _safe_json_load(path)
        except Exception as exc:  # noqa: BLE001
            base_row.update(
                {
                    "status": "malformed",
                    "reason": f"read json: {_mask_error(exc)}",
                    "reason_code": "malformed_json",
                    "stage": "local",
                    "fingerprint": "malformed_json",
                    "account_attributable": True,
                    "conclusive": True,
                }
            )
            return base_row

        if not email:
            email = str(payload.get("email") or path.name[len("xai-") : -len(".json")]).strip().lower()
            base_row["email"] = email

        meta = _managed_meta(payload)
        if payload.get("disabled") is True:
            cool_until = str(meta.get("cool_until") or "")
            cool_ts = _iso_to_ts(cool_until)
            if meta.get("managed") and cool_ts and cool_ts > time.time():
                base_row.update({"status": "cooling", "reason": str(meta.get("disabled_reason") or "cooling"), "cool_until": cool_until, "cool_remaining_sec": int(cool_ts - time.time())})
                return base_row
            if meta.get("managed") and cool_ts and cool_ts <= time.time():
                base_row["recovery_probe"] = True
            elif meta.get("managed") and str(meta.get("tier") or meta.get("status") or "") in {"candidate", "observe", "recovery"}:
                base_row["recovery_probe"] = True
            else:
                base_row.update({"status": "disabled", "reason": "auth disabled=true"})
                return base_row

        access = str(payload.get("access_token") or "").strip()
        refresh = str(payload.get("refresh_token") or "").strip()
        if not access and not refresh:
            base_row.update(
                {
                    "status": "malformed",
                    "reason": "missing access_token and refresh_token",
                    "reason_code": "missing_tokens",
                    "stage": "local",
                    "fingerprint": "missing_tokens",
                    "account_attributable": True,
                    "conclusive": True,
                }
            )
            return base_row

        exp_ts = _iso_to_ts(str(payload.get("expired") or payload.get("expires_at") or "")) or _access_exp_ts(access)
        if exp_ts:
            base_row["expired"] = _ts_to_iso(exp_ts)
            base_row["expires_in_sec"] = int(exp_ts - time.time())

        proxy = proxy_picker()
        timeout = float(settings.get("probe_timeout_sec") or 30.0)
        refresh_attempted = False
        if bool(settings.get("refresh_before_probe")) and refresh:
            skew = int(settings.get("refresh_skew_sec") or 0)
            should_refresh = not access or not exp_ts or (exp_ts - time.time()) <= skew
            if should_refresh:
                refresh_attempted = True
                rr = refresh_auth_file(path, payload, proxy=proxy, timeout=timeout)
                if rr.get("ok"):
                    payload = dict(rr.get("payload") or payload)
                    access = str(payload.get("access_token") or "").strip()
                    base_row["refreshed"] = True
                    exp_ts = _iso_to_ts(str(payload.get("expired") or "")) or _access_exp_ts(access)
                    base_row["expired"] = _ts_to_iso(exp_ts)
                    base_row["expires_in_sec"] = int(exp_ts - time.time()) if exp_ts else None
                elif not access or (exp_ts and exp_ts <= time.time()):
                    return self._apply_failure_classification(base_row, rr, stage="refresh")
                else:
                    base_row["refresh_error"] = rr.get("error") or rr.get("status") or "refresh failed"

        if not access:
            base_row.update({"status": "malformed", "reason": "missing access_token", "reason_code": "missing_tokens", "stage": "local", "fingerprint": "missing_tokens", "account_attributable": True, "conclusive": True})
            return base_row

        base_url = str(payload.get("base_url") or DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
        if self._breaker_blocks_probe("models"):
            breaker = self._breaker_cache.get("models") or {}
            base_row.update(
                {
                    "status": "upstream_busy",
                    "reason": f"models: upstream breaker {breaker.get('state') or 'open'}",
                    "reason_code": "breaker_open",
                    "stage": "models",
                    "fingerprint": str(breaker.get("fingerprint") or "breaker_open"),
                    "account_attributable": False,
                    "conclusive": False,
                    "breaker_skipped": True,
                    "latency_ms": int((time.monotonic() - started) * 1000),
                }
            )
            return base_row
        if not self._model_limiter.wait(self._cancel):
            return self._apply_failure_classification(base_row, {"status": 0, "error": "cancelled"}, stage="models")
        models = probe_models(access, base_url=base_url, timeout=timeout, proxy=proxy)
        if not models.get("ok") and int(models.get("status") or 0) == 401 and refresh and not refresh_attempted:
            refresh_attempted = True
            rr = refresh_auth_file(path, payload, proxy=proxy, timeout=timeout)
            if rr.get("ok"):
                payload = dict(rr.get("payload") or payload)
                access = str(payload.get("access_token") or "").strip()
                base_row["refreshed"] = True
                if self._model_limiter.wait(self._cancel):
                    models = probe_models(access, base_url=base_url, timeout=timeout, proxy=proxy)
            else:
                refresh_class = classify_failure(rr, stage="refresh")
                if refresh_class.status == "invalid_auth":
                    base_row.update(refresh_class.to_dict())
                    return base_row
        base_row["models_status"] = models.get("status")
        base_row["model_count"] = len(models.get("model_ids") or [])
        if not models.get("ok"):
            self._apply_failure_classification(base_row, models, stage="models")
            base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
            return base_row
        if not models.get("has_grok_45"):
            base_row.update(
                {
                    "status": "no_grok45",
                    "reason": "models ok but grok-4.5 missing",
                    "reason_code": "model_not_entitled",
                    "stage": "models",
                    "fingerprint": "model_not_entitled",
                    "account_attributable": True,
                    "conclusive": True,
                }
            )
            base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
            return base_row

        probe_chat = bool(item.get("_probe_chat", settings.get("probe_chat")))
        if probe_chat:
            if self._breaker_blocks_probe("chat"):
                breaker = self._breaker_cache.get("chat") or {}
                base_row.update(
                    {
                        "status": "upstream_busy",
                        "reason": f"chat: upstream breaker {breaker.get('state') or 'open'}",
                        "reason_code": "breaker_open",
                        "stage": "chat",
                        "fingerprint": str(breaker.get("fingerprint") or "breaker_open"),
                        "account_attributable": False,
                        "conclusive": False,
                        "breaker_skipped": True,
                        "latency_ms": int((time.monotonic() - started) * 1000),
                    }
                )
                return base_row
            if not self._chat_limiter.wait(self._cancel):
                return self._apply_failure_classification(base_row, {"status": 0, "error": "cancelled"}, stage="chat")
            chat = probe_mini_response(access, base_url=base_url, timeout=max(timeout, 30.0), proxy=proxy)
            base_row["chat_status"] = chat.get("status")
            if not chat.get("ok"):
                self._apply_failure_classification(base_row, chat, stage="chat")
                base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
                return base_row

        reason = "models+chat ok" if probe_chat else "models ok"
        if base_row.get("refresh_error"):
            reason += f"; refresh warning: {_mask_error(base_row.get('refresh_error'), 120)}"
        base_row.update(
            {
                "status": "ok",
                "reason": reason,
                "reason_code": "probe_ok",
                "stage": "chat" if probe_chat else "models",
                "fingerprint": "",
                "account_attributable": False,
                "conclusive": True,
                "verified_chat": probe_chat,
            }
        )
        base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
        return base_row

    def _merge_result(self, row: dict[str, Any], *, settings: dict[str, Any]) -> dict[str, Any]:
        email = str(row.get("email") or "").lower()
        now = str(row.get("checked_at") or _utc_now())
        with self._lock:
            prev = dict(self._results.get(email) or {})
        status = str(row.get("status") or "probe_failed")
        prev_status = str(prev.get("status") or "")
        status_counts = dict(prev.get("status_counts") or {})
        status_counts[status] = int(status_counts.get(status) or 0) + 1
        if status == "ok":
            failure_streak = 0
            ok_streak = int(prev.get("ok_streak") or 0) + 1
            last_ok_at = now
            last_bad_at = prev.get("last_bad_at") or ""
        elif status in {"upstream_busy", "request_error"}:
            failure_streak = int(prev.get("failure_streak") or 0)
            ok_streak = 0
            last_ok_at = prev.get("last_ok_at") or ""
            last_bad_at = prev.get("last_bad_at") or ""
        else:
            failure_streak = int(prev.get("failure_streak") or 0) + 1
            ok_streak = 0
            last_ok_at = prev.get("last_ok_at") or ""
            last_bad_at = now
        status_streak = int(prev.get("status_streak") or 0) + 1 if prev_status == status else 1
        hist = list(prev.get("history") or [])
        hist.append({"at": now, "status": status, "reason": _mask_error(row.get("reason"), 160), "refreshed": bool(row.get("refreshed")), "latency_ms": row.get("latency_ms")})
        limit = int(settings.get("history_limit") or 0)
        if limit > 0:
            hist = hist[-limit:]
        else:
            hist = []
        merged = dict(prev)
        merged.update(row)
        merged.update(
            {
                "first_seen_at": prev.get("first_seen_at") or now,
                "last_ok_at": last_ok_at,
                "last_bad_at": last_bad_at,
                "failure_streak": failure_streak,
                "ok_streak": ok_streak,
                "status_streak": status_streak,
                "status_counts": status_counts,
                "history": hist,
            }
        )
        return merged

    def _update_health_state(self, row: dict[str, Any], settings: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        email = str(row.get("email") or "").strip().lower()
        repo = self._repo()
        previous = repo.get_account(email) or default_state(email, path=str(row.get("path") or ""))
        row["previous_tier"] = str(previous.get("tier") or "candidate")
        status = str(row.get("status") or "probe_failed")
        if status not in {"cooling", "disabled", "quarantined", "deleted"}:
            self._record_observation(row, previous_state=previous, settings=settings)
        if status == "cooling":
            state = dict(previous)
            state.update(
                {
                    "tier": "cooling",
                    "health_status": "account_quota",
                    "health_reason": str(row.get("reason") or "cooling"),
                    "desired_disabled": True,
                    "desired_priority": OBSERVE_PRIORITY,
                    "next_check_at": _iso_to_ts(str(row.get("cool_until") or "")) or float(previous.get("next_check_at") or 0),
                    "governance_eligible": True,
                    "updated_at": time.time(),
                }
            )
        elif status == "disabled":
            state = dict(previous)
            state.update({"tier": "manual_disabled", "health_status": "disabled", "desired_disabled": True, "manual_override": True, "governance_eligible": False, "updated_at": time.time()})
        else:
            healthy_interval = int(settings.get("healthy_check_interval_sec") or 43200)
            jitter_limit = min(1800, max(0, healthy_interval // 10))
            state = transition_state(
                previous,
                row,
                independent_failure_interval_sec=int(settings.get("independent_failure_interval_sec") or 600),
                transient_failure_threshold=int(settings.get("soft_fail_threshold") or 3),
                no_model_failure_threshold=int(settings.get("no_grok45_threshold") or 2),
                recovery_success_threshold=int(settings.get("recovery_success_threshold") or 2),
                quota_cooldown_sec=int(settings.get("quota_cooldown_sec") or 86400),
                healthy_interval_sec=healthy_interval,
                observe_interval_sec=int(settings.get("observe_check_interval_sec") or 720),
                candidate_interval_sec=int(settings.get("candidate_check_interval_sec") or 1200),
                jitter_sec=random.randint(0, jitter_limit) if jitter_limit else 0,
            )
        if float(state.get("cool_until_ts") or 0) > 0:
            state["cool_until"] = _ts_to_iso(float(state["cool_until_ts"]))
            row["cool_until"] = state["cool_until"]
        repo.upsert_account(state)
        row.update(
            {
                "tier": state.get("tier") or "candidate",
                "health_status": state.get("health_status") or status,
                "confidence": int(state.get("confidence") or 0),
                "desired_priority": int(state.get("desired_priority") or 0),
                "desired_disabled": bool(state.get("desired_disabled")),
                "actual_priority": state.get("actual_priority"),
                "actual_disabled": state.get("actual_disabled"),
                "independent_failure_streak": int(state.get("independent_failure_streak") or 0),
                "next_check_at": float(state.get("next_check_at") or 0),
            }
        )
        return row, state

    @staticmethod
    def _patch_file_schedule_state(
        path: Path,
        *,
        priority: int,
        disabled: bool,
        tier: str,
        reason: str,
        cool_until: str = "",
    ) -> tuple[bool, str]:
        payload = _safe_json_load(path)
        meta = _managed_meta(payload)
        if payload.get("disabled") is True and not meta.get("managed") and not disabled:
            return False, "manual disabled state preserved"
        old_priority = payload.get("priority")
        if "original_priority" not in meta:
            meta["original_priority"] = old_priority
        payload["priority"] = int(priority)
        payload["disabled"] = bool(disabled)
        meta.update(
            {
                "managed": True,
                "tier": tier,
                "status": tier,
                "disabled_reason": reason if disabled else "",
                "updated_at": _utc_now(),
                "cool_until": cool_until if disabled else "",
            }
        )
        payload["_cpa_pool"] = meta
        _atomic_write_json(path, payload)
        return True, "file"

    def _audit_action(
        self,
        *,
        row: dict[str, Any],
        action: str,
        old_state: str,
        new_state: str,
        reason: str,
        result: str,
    ) -> None:
        self._repo().add_action(
            {
                "action_ts": time.time(),
                "email": str(row.get("email") or "").lower(),
                "action": action,
                "old_state": old_state,
                "new_state": new_state,
                "reason": reason,
                "result": result,
                "scan_id": self._scan_id,
            }
        )

    def _reconcile_schedule_state(self, row: dict[str, Any], state: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
        email = str(row.get("email") or "").strip().lower()
        path = Path(str(row.get("path") or state.get("path") or ""))
        desired_priority = int(state.get("desired_priority") or OBSERVE_PRIORITY)
        desired_disabled = bool(state.get("desired_disabled"))
        tier = str(state.get("tier") or "candidate")
        old_tier = str(row.get("previous_tier") or "candidate")
        if state.get("actual_priority") is not None and state.get("actual_disabled") is not None:
            if int(state.get("actual_priority") or 0) == desired_priority and bool(state.get("actual_disabled")) == desired_disabled:
                return row
        is_downgrade = desired_disabled or desired_priority < int(state.get("actual_priority") or MAIN_PRIORITY)
        if is_downgrade and self._governance_limit > 0 and self._governance_downgrades >= self._governance_limit:
            row["policy_frozen"] = "governance change limit reached"
            return row

        reason = f"tier:{old_tier}->{tier} status={row.get('status')} code={row.get('reason_code') or '-'}"
        cool_until = str(state.get("cool_until") or row.get("cool_until") or "")
        client = self._management(settings)
        result = ""
        applied = False
        if client.available:
            runtime = self._runtime_snapshot.get(email) or {}
            name = client.filename(runtime) or path.name
            try:
                client.patch_fields(
                    name,
                    **{
                        "priority": desired_priority,
                        "disabled": desired_disabled,
                        "_cpa_pool.managed": True,
                        "_cpa_pool.tier": tier,
                        "_cpa_pool.status": tier,
                        "_cpa_pool.disabled_reason": reason if desired_disabled else "",
                        "_cpa_pool.cool_until": cool_until if desired_disabled else "",
                        "_cpa_pool.updated_at": _utc_now(),
                    },
                )
                result = "management_api_pending_verify"
                applied = True
                self._repo().set_meta("management_failure_since", 0)
            except Exception as exc:  # noqa: BLE001
                failure_since = float(self._repo().get_meta("management_failure_since", 0) or 0)
                if not failure_since:
                    failure_since = time.time()
                    self._repo().set_meta("management_failure_since", failure_since)
                row["management_error"] = _mask_error(exc)
                grace = int(settings.get("file_fallback_grace_sec") or 0)
                if bool(settings.get("file_fallback_enabled")) and time.time() - failure_since >= grace:
                    result = "management_failed_file_fallback"
                else:
                    row["policy_pending"] = "management API unavailable"
                    return row
        if not applied and (not client.available or result == "management_failed_file_fallback"):
            if not bool(settings.get("file_fallback_enabled", True)):
                row["policy_pending"] = "file fallback disabled"
                return row
            if not path.is_file():
                row["policy_error"] = f"path not found: {path}"
                return row
            try:
                applied, file_result = self._patch_file_schedule_state(
                    path,
                    priority=desired_priority,
                    disabled=desired_disabled,
                    tier=tier,
                    reason=reason,
                    cool_until=cool_until,
                )
                result = file_result if applied else file_result
            except Exception as exc:  # noqa: BLE001
                row["policy_error"] = _mask_error(exc)
                self._audit_action(row=row, action="reconcile", old_state=old_tier, new_state=tier, reason=reason, result=f"error:{row['policy_error']}")
                return row

        if not applied:
            row["manual_override"] = True
            state["manual_override"] = True
            self._repo().upsert_account(state)
            self._audit_action(row=row, action="reconcile", old_state=old_tier, new_state=tier, reason=reason, result=result or "skipped")
            return row

        if is_downgrade:
            self._governance_downgrades += 1
        state.update({"actual_priority": desired_priority, "actual_disabled": desired_disabled, "last_reconciled_at": _utc_now(), "updated_at": time.time()})
        self._repo().upsert_account(state)
        row.update(
            {
                "actual_priority": desired_priority,
                "actual_disabled": desired_disabled,
                "action": "disabled" if desired_disabled else ("promoted" if desired_priority == MAIN_PRIORITY else "scheduled"),
                "action_at": _utc_now(),
                "action_reason": reason,
                "reconcile_via": result,
            }
        )
        self._audit_action(row=row, action=str(row["action"]), old_state=old_tier, new_state=tier, reason=reason, result=result)
        return row

    def _apply_policy(self, row: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
        row, state = self._update_health_state(row, settings)
        if not bool(settings.get("apply_policy")):
            return row
        if state.get("manual_override") or not state.get("governance_eligible"):
            return row
        if self._breaker_is_open():
            row["policy_frozen"] = "upstream breaker open"
            return row
        status = str(row.get("status") or "")
        tier = str(state.get("tier") or "candidate")
        if status == "upstream_busy":
            return row
        if status in {"transient_error", "probe_failed", "request_error", "no_grok45"} and tier != "observe":
            return row
        if tier in {"quarantine", "malformed"}:
            if self._governance_limit > 0 and self._governance_downgrades >= self._governance_limit:
                row["policy_frozen"] = "governance change limit reached"
                return row
            path = Path(str(row.get("path") or ""))
            if not path.is_file():
                row["policy_error"] = f"path not found for quarantine: {path}"
                return row
            bucket = "malformed" if tier == "malformed" else "invalid_auth"
            reason = f"tier:{row.get('previous_tier')}->{tier} status={status}"
            mv = _move_to_quarantine(path, bucket=bucket, settings=settings, reason=reason)
            if not mv.get("ok"):
                row["policy_error"] = mv.get("error") or "move failed"
                return row
            self._governance_downgrades += 1
            state.update(
                {
                    "path": str(mv.get("path") or state.get("path") or ""),
                    "actual_priority": OBSERVE_PRIORITY,
                    "actual_disabled": True,
                    "next_check_at": 0.0,
                    "updated_at": time.time(),
                }
            )
            self._repo().upsert_account(state)
            row.update({"action": "quarantined", "action_at": _utc_now(), "action_reason": reason, "quarantine_path": mv.get("path"), "path": mv.get("path"), "location": "quarantine"})
            self._audit_action(row=row, action="quarantined", old_state=str(row.get("previous_tier") or ""), new_state=tier, reason=reason, result="file_moved")
            return row
        return self._reconcile_schedule_state(row, state, settings)

    def manual_action(self, *, emails: list[str], action: str, reason: str = "manual") -> dict[str, Any]:
        action = str(action or "").strip().lower()
        if action not in _MANUAL_ACTIONS:
            raise ValueError("action 必须是 disable/enable/quarantine/delete")
        wanted = {str(e).strip().lower() for e in emails if str(e).strip()}
        if not wanted:
            raise ValueError("请选择账号")
        settings = settings_from_config()
        index = store.list_cpa_index()
        results: list[dict[str, Any]] = []
        for email in sorted(wanted):
            item = index.get(email)
            if not item:
                results.append({"email": email, "ok": False, "error": "active CPA file not found"})
                continue
            path = Path(str(item.get("path") or ""))
            previous = self._repo().get_account(email) or default_state(email, path=str(path))
            old_tier = str(previous.get("tier") or "candidate")
            try:
                if action == "enable":
                    payload = _safe_json_load(path)
                    _set_enabled(path, payload, reason=reason)
                    previous.update(
                        {
                            "tier": "reserve",
                            "desired_priority": int(payload.get("priority") or RESERVE_PRIORITY),
                            "desired_disabled": False,
                            "actual_disabled": False,
                            "manual_override": True,
                            "updated_at": time.time(),
                        }
                    )
                    results.append({"email": email, "ok": True, "action": "enabled"})
                elif action == "disable":
                    payload = _safe_json_load(path)
                    _set_managed_disabled(path, payload, reason=reason, status="manual_disabled")
                    previous.update(
                        {
                            "tier": "manual_disabled",
                            "desired_disabled": True,
                            "actual_disabled": True,
                            "manual_override": True,
                            "updated_at": time.time(),
                        }
                    )
                    results.append({"email": email, "ok": True, "action": "disabled"})
                elif action in {"quarantine", "delete"}:
                    bucket = "deleted" if action == "delete" else "manual"
                    mv = _move_to_quarantine(path, bucket=bucket, settings=settings, reason=reason)
                    if not mv.get("ok"):
                        results.append({"email": email, "ok": False, "action": action, "error": mv.get("error") or "move failed"})
                        continue
                    previous.update({"tier": "quarantine", "desired_disabled": True, "actual_disabled": True, "manual_override": True, "updated_at": time.time()})
                    results.append({"email": email, "ok": True, "action": "deleted" if action == "delete" else "quarantined", "path": mv.get("path"), "error": ""})
                self._repo().upsert_account(previous)
                self._audit_action(
                    row={"email": email},
                    action=f"manual_{action}",
                    old_state=old_tier,
                    new_state=str(previous.get("tier") or ""),
                    reason=reason,
                    result="ok",
                )
            except Exception as exc:  # noqa: BLE001
                results.append({"email": email, "ok": False, "error": _mask_error(exc)})
        self._log(f"手动操作 {action}: ok={sum(1 for r in results if r.get('ok'))}/{len(results)} reason={reason}")
        try:
            store._clear_store_caches("cpa", "overview")  # type: ignore[attr-defined]
        except Exception:
            pass
        return {"ok": True, "action": action, "total": len(results), "success": sum(1 for r in results if r.get("ok")), "items": results}

    def restore_quarantine(self, *, emails: list[str], target: str = "hotload", overwrite: bool = False) -> dict[str, Any]:
        wanted = {str(e).strip().lower() for e in emails if str(e).strip()}
        if not wanted:
            raise ValueError("请选择要恢复的账号")
        cfg = store.load_config_raw()
        target_dir = store.hotload_dir(cfg) if target == "hotload" else store.cpa_dir(cfg)
        target_dir = target_dir or store.cpa_dir(cfg)
        target_dir.mkdir(parents=True, exist_ok=True)
        q_items = self.list_quarantine(page_size=10000).get("items") or []
        by_email = {str(i.get("email") or "").lower(): i for i in q_items}
        results = []
        active = store.list_cpa_index()
        for email in sorted(wanted):
            item = by_email.get(email)
            if not item:
                results.append({"email": email, "ok": False, "error": "not found in quarantine"})
                continue
            if email in active and not overwrite:
                results.append({"email": email, "ok": False, "error": "active CPA file exists; set overwrite=true"})
                continue
            src = Path(str(item.get("path") or ""))
            dst = target_dir / src.name
            if dst.exists() and overwrite:
                dst.unlink()
            elif dst.exists():
                dst = _unique_path(dst)
            try:
                payload = _safe_json_load(src)
                payload["disabled"] = True
                payload["priority"] = OBSERVE_PRIORITY
                meta = _managed_meta(payload)
                meta.update(
                    {
                        "managed": True,
                        "tier": "candidate",
                        "status": "recovery",
                        "restored_at": _utc_now(),
                        "restore_target": str(dst),
                        "cool_until": "",
                    }
                )
                payload["_cpa_pool"] = meta
                _atomic_write_json(src, payload)
                shutil.move(str(src), str(dst))
                state = default_state(email, path=str(dst))
                state.update({"actual_priority": OBSERVE_PRIORITY, "actual_disabled": True, "health_status": "recovery_pending", "updated_at": time.time()})
                self._repo().upsert_account(state)
                self._audit_action(row={"email": email}, action="restore_candidate", old_state="quarantine", new_state="candidate", reason="manual restore", result="file_moved")
                results.append({"email": email, "ok": True, "path": str(dst)})
            except Exception as exc:  # noqa: BLE001
                results.append({"email": email, "ok": False, "error": _mask_error(exc)})
        self._log(f"隔离恢复: ok={sum(1 for r in results if r.get('ok'))}/{len(results)} target={target}")
        try:
            store._clear_store_caches("cpa", "overview")  # type: ignore[attr-defined]
        except Exception:
            pass
        return {"ok": True, "total": len(results), "success": sum(1 for r in results if r.get("ok")), "items": results}

    def _backfill_candidate_emails(self, *, active_emails: set[str], excluded_emails: set[str]) -> list[str]:
        from cpa_xai import parse_accounts_file

        cfg = store.load_config_raw()
        accounts = parse_accounts_file(store.accounts_file(cfg))
        return sorted(
            {
                account.email.strip().lower()
                for account in accounts
                if account.email.strip()
                and account.email.strip().lower() not in active_emails
                and account.email.strip().lower() not in excluded_emails
                and (account.sso or account.password)
            }
        )

    @staticmethod
    def _rolling_refill_yield(settings: dict[str, Any]) -> float:
        fallback = max(0.1, min(1.0, int(settings.get("refill_expected_yield_percent") or 80) / 100.0))
        try:
            from .jobs import runner

            success = 0
            attempts = 0
            for job in runner.list_jobs()[:20]:
                if str((job.get("options") or {}).get("source") or "") != "cpa_pool_auto_refill":
                    continue
                if str(job.get("status") or "") not in {"completed", "failed", "stopped"}:
                    continue
                stats = job.get("stats") or {}
                if str(job.get("kind") or "") == "backfill":
                    ok = int(stats.get("ok") or 0)
                    fail = int(stats.get("fail") or 0)
                else:
                    ok = int(stats.get("mint_success") or 0)
                    fail = int(stats.get("mint_fail") or 0) + int(stats.get("mint_skip") or 0)
                success += ok
                attempts += ok + fail
            if attempts >= 5:
                return max(0.1, min(1.0, success / attempts))
        except Exception:
            pass
        return fallback

    def _maybe_start_refill(self, *, settings: dict[str, Any], initial_total: int, trigger: str) -> dict[str, Any]:
        with self._refill_lock:
            result = self._maybe_start_refill_locked(
                settings=settings,
                initial_total=initial_total,
                trigger=trigger,
            )
            result = dict(result)
            result.setdefault("trigger", trigger)
            result["checked_at"] = _utc_now()
            with self._lock:
                self._refill_status = dict(result)
        return result

    def _maybe_start_refill_locked(self, *, settings: dict[str, Any], initial_total: int, trigger: str) -> dict[str, Any]:
        if not bool(settings.get("auto_refill")):
            return {"enabled": False, "started": False}
        if not bool(settings.get("apply_policy")):
            self._repo().set_meta("refill_low_since", 0)
            self._repo().set_meta("refill_low_rounds", {})
            return {
                "enabled": True,
                "started": False,
                "error": "automatic governance is disabled",
                "frozen": True,
            }
        if self._breaker_is_open():
            self._repo().set_meta("refill_low_since", 0)
            self._repo().set_meta("refill_low_rounds", {})
            return {"enabled": True, "started": False, "error": "upstream breaker open", "frozen": True}
        try:
            active_index = store.list_cpa_index()
        except Exception as exc:  # noqa: BLE001
            err = f"active CPA index unavailable: {_mask_error(exc)}"
            self._log(f"自动补号跳过：{err}")
            return {"enabled": True, "started": False, "error": err}
        current_total = len(active_index)
        explicit_target = int(settings.get("refill_target_active") or 0)
        target = explicit_target or int(initial_total or 0)
        reserve_target = math.ceil(target * int(settings.get("reserve_target_percent") or 0) / 100) if explicit_target > 0 else 0
        capacity_target = target + reserve_target
        pool = self._pool_metrics()
        managed_states = [state for state in self._repo().list_accounts() if str(state.get("email") or "").lower() in active_index]
        ready_main = int(pool.get("main_routeable") or 0) if managed_states else current_total
        routeable_reserve = int(pool.get("reserve_routeable") or 0) if managed_states else 0
        now = time.time()
        cooling_grace = int(settings.get("refill_cooling_grace_sec") or 0)
        protected_cooling = 0
        if cooling_grace > 0:
            for state in managed_states:
                if str(state.get("tier") or "") != "cooling":
                    continue
                recovery_at = float(state.get("cool_until_ts") or state.get("next_check_at") or 0)
                if now < recovery_at <= now + cooling_grace:
                    protected_cooling += 1
        expected_yield = self._rolling_refill_yield(settings)
        active_job = None
        inflight = 0
        try:
            from .jobs import runner

            active_job = runner.active_job(lane="grok")
            if active_job and active_job.status in {"queued", "running"}:
                options = active_job.options or {}
                stats = active_job.stats or {}
                planned = int(options.get("limit") or options.get("extra") or stats.get("target") or stats.get("total") or 0)
                done = int(stats.get("done") or 0)
                inflight = max(0, planned - done) if str(options.get("source") or "") == "cpa_pool_auto_refill" else 0
        except Exception:
            active_job = None
        main_gap = max(0, target - ready_main)
        promotable_reserve = min(main_gap, routeable_reserve)
        main_gap_after_reserve = max(0, main_gap - promotable_reserve)
        reserve_after_promotion = max(0, routeable_reserve - promotable_reserve)
        projected_capacity = ready_main + routeable_reserve + protected_cooling + inflight * expected_yield
        gap = max(0, math.ceil(capacity_target - projected_capacity))
        eligible_baseline = [state for state in managed_states if str(state.get("tier") or "") != "manual_disabled"]
        baseline_checked = sum(1 for state in eligible_baseline if state.get("last_checked_at"))
        baseline_percent = (
            round(baseline_checked * 100 / len(eligible_baseline), 2)
            if eligible_baseline
            else (100.0 if not managed_states else 0.0)
        )
        emergency_percent = int(settings.get("refill_emergency_threshold_percent") or 0)
        emergency_floor = math.ceil(target * emergency_percent / 100) if target > 0 and emergency_percent > 0 else 0
        emergency = bool(emergency_floor and ready_main < emergency_floor)
        common = {
            "enabled": True,
            "started": False,
            "target": target,
            "reserve_target": reserve_target,
            "capacity_target": capacity_target,
            "current": ready_main,
            "main_gap": main_gap,
            "promotable_reserve": promotable_reserve,
            "main_gap_after_reserve": main_gap_after_reserve,
            "reserve_after_promotion": reserve_after_promotion,
            "projected": round(projected_capacity, 2),
            "routeable_reserve": routeable_reserve,
            "protected_cooling": protected_cooling,
            "inventory": current_total,
            "inflight": inflight,
            "baseline_checked": baseline_checked,
            "baseline_total": len(eligible_baseline),
            "baseline_percent": baseline_percent,
            "gap": gap,
            "need": math.ceil(gap / expected_yield) if gap > 0 else 0,
            "emergency": emergency,
            "emergency_threshold_percent": emergency_percent,
            "emergency_floor": emergency_floor,
        }
        if gap <= 0:
            self._repo().set_meta("refill_low_since", 0)
            self._repo().set_meta("refill_low_rounds", {})
            return common
        required_baseline = int(settings.get("refill_min_baseline_percent") or 100)
        if baseline_percent < required_baseline:
            self._repo().set_meta("refill_low_since", 0)
            self._repo().set_meta("refill_low_rounds", {})
            common.update(
                {
                    "waiting_for_baseline": True,
                    "required_baseline_percent": required_baseline,
                    "error": "pool baseline is incomplete",
                }
            )
            return common
        if active_job and active_job.status in {"queued", "running"}:
            msg = f"auto_refill waiting for active job {active_job.kind} {active_job.id}"
            common.update({"active_job": active_job.id, "waiting_for_job": True, "message": msg})
            return common
        if not emergency:
            low_since = float(self._repo().get_meta("refill_low_since", 0) or 0)
            if not low_since:
                low_since = now
                self._repo().set_meta("refill_low_since", low_since)
            low_rounds = self._repo().get_meta("refill_low_rounds", {})
            if not isinstance(low_rounds, dict):
                low_rounds = {}
            round_key = self._scan_id or f"{trigger}:{int(now)}"
            if str(low_rounds.get("last_scan_id") or "") != round_key:
                low_rounds = {
                    "count": int(low_rounds.get("count") or 0) + 1,
                    "last_scan_id": round_key,
                    "updated_at": now,
                }
                self._repo().set_meta("refill_low_rounds", low_rounds)
            required_rounds = int(settings.get("refill_low_water_rounds") or 2)
            if int(low_rounds.get("count") or 0) < required_rounds:
                common.update(
                    {
                        "waiting_for_rounds": True,
                        "low_rounds": int(low_rounds.get("count") or 0),
                        "required_low_rounds": required_rounds,
                    }
                )
                return common
            hold_sec = int(settings.get("refill_low_water_hold_sec") or 0)
            if now - low_since < hold_sec:
                common.update(
                    {
                        "waiting_for_stability": True,
                        "low_rounds": int(low_rounds.get("count") or 0),
                        "required_low_rounds": required_rounds,
                        "eligible_in_sec": max(0, int(hold_sec - (now - low_since))),
                    }
                )
                return common
        need = math.ceil(gap / expected_yield)
        max_inventory = int(settings.get("refill_max_inventory") or 4000)
        inventory_headroom = max(0, max_inventory - current_total)
        day_key = datetime.now().astimezone().date().isoformat()
        daily = self._repo().get_meta("refill_daily", {})
        if not isinstance(daily, dict) or daily.get("date") != day_key:
            daily = {"date": day_key, "count": 0}
        daily_soft_limit = int(settings.get("refill_daily_limit") if settings.get("refill_daily_limit") is not None else 200)
        daily_used = int(daily.get("count") or 0)
        daily_remaining = max(0, daily_soft_limit - daily_used) if daily_soft_limit > 0 else None
        bypass_daily_soft_limit = emergency or daily_soft_limit <= 0
        daily_allowance = need if bypass_daily_soft_limit else int(daily_remaining or 0)
        batch_size = int(settings.get("refill_max_per_scan") or 200)
        common.update(
            {
                "batch_size": batch_size,
                "daily_soft_limit": daily_soft_limit,
                "daily_used": daily_used,
                "daily_remaining": daily_remaining,
                "daily_soft_limit_bypassed": bypass_daily_soft_limit,
            }
        )
        limit = min(need, batch_size, inventory_headroom, daily_allowance)
        if limit <= 0:
            if inventory_headroom <= 0:
                return {**common, "need": need, "error": "max inventory reached"}
            return {
                **common,
                "need": need,
                "waiting_for_daily_budget": True,
                "message": "daily refill soft limit reached",
            }
        try:
            from .jobs import runner

            try:
                q_items = self.list_quarantine(page_size=10000).get("items") or []
                exclude_emails = sorted({str(i.get("email") or "").lower() for i in q_items if str(i.get("email") or "").strip()})
            except Exception:
                exclude_emails = []
            candidates = self._backfill_candidate_emails(
                active_emails={str(email).lower() for email in active_index},
                excluded_emails=set(exclude_emails),
            )
            cfg = store.load_config_raw()
            if candidates:
                strategy = "backfill"
                limit = min(limit, len(candidates))
                job = runner.start_backfill(
                    {
                        "emails": candidates[:limit],
                        "limit": limit,
                        "probe": True,
                        "probe_chat": bool(settings.get("refill_probe_chat")),
                        "workers": int(settings.get("refill_workers") or -1),
                        "sleep": 0,
                        "exclude_emails": exclude_emails,
                        "source": "cpa_pool_auto_refill",
                    }
                )
            else:
                if not _coerce_bool(cfg.get("cpa_export_enabled"), True):
                    raise RuntimeError("cpa_export_enabled=false; cannot register replacement CPA accounts")
                strategy = "register"
                register_threads = min(
                    limit,
                    _coerce_int(cfg.get("register_threads"), 1, min_v=1, max_v=100),
                )
                job = runner.start_register(
                    {
                        "extra": limit,
                        "threads": register_threads,
                        "mint_workers": _coerce_int(cfg.get("cpa_mint_workers"), -1, min_v=-1, max_v=100),
                        "mint_queue_max": _coerce_int(cfg.get("cpa_mint_queue_max"), -1, min_v=-1),
                        "headless": _coerce_bool(cfg.get("register_headless"), False),
                        "fast": True,
                        "protocol_register": _coerce_bool(cfg.get("protocol_register"), False),
                        "protocol_no_browser_fallback": _coerce_bool(cfg.get("protocol_only"), False)
                        or not _coerce_bool(cfg.get("protocol_register_fallback_browser"), True),
                        "proxy_mode": "config",
                        "source": "cpa_pool_auto_refill",
                    }
                )
            self._log(
                f"自动补号已启动：strategy={strategy} gap={gap} need={need} batch={limit} "
                f"emergency={emergency} daily={daily_used}/{daily_soft_limit or 'unlimited'} "
                f"candidates={len(candidates)} exclude={len(exclude_emails)} job={job.get('id')} trigger={trigger}"
            )
            daily["count"] = int(daily.get("count") or 0) + limit
            self._repo().set_meta("refill_daily", daily)
            return {
                **common,
                "started": True,
                "strategy": strategy,
                "need": need,
                "expected_yield": round(expected_yield, 4),
                "limit": limit,
                "candidates": len(candidates),
                "excluded": len(exclude_emails),
                "job": job,
            }
        except Exception as exc:  # noqa: BLE001
            err = _mask_error(exc)
            self._log(f"自动补号启动失败：need={need} error={err}")
            return {**common, "need": need, "error": err}

    def _scan_outcome(self, record: dict[str, Any]) -> str:
        if record.get("error"):
            return "error"
        if record.get("cancelled"):
            return "cancelled"
        bad = int(record.get("bad") or 0)
        actions = record.get("actions") or {}
        refill = record.get("refill") or {}
        if bad or actions or refill.get("started") or refill.get("error"):
            return "warn"
        return "ok"

    def _append_scan_history(self, *, settings: dict[str, Any]) -> None:
        with self._lock:
            summary = _beijingize_record(dict(self._summary))
            scan_id = self._scan_id or uuid.uuid4().hex[:10]
            started_at = timeutil.iso_to_beijing_display(self._started_at) if self._started_at else str(summary.get("started_at") or "")
            finished_at = timeutil.iso_to_beijing_display(self._finished_at) if self._finished_at else str(summary.get("finished_at") or "")
            progress = dict(self._progress)
            last_error = self._last_error
            cancelled = self._cancel.is_set()
        counts = dict(summary.get("counts") or {})
        actions = dict(summary.get("actions") or {})
        ok = int(counts.get("ok") or 0)
        quota = int(counts.get("quota") or 0) + int(counts.get("account_quota") or 0) + int(counts.get("cooling") or 0)
        bad = sum(
            int(v or 0)
            for k, v in counts.items()
            if k not in {"ok", "quota", "account_quota", "cooling", "upstream_busy"}
        )
        try:
            cpa_total = len(store.list_cpa_index())
        except Exception:
            cpa_total = 0
        try:
            quarantine_total = int(self.quarantine_summary().get("total") or 0)
        except Exception:
            quarantine_total = 0
        refill = dict(summary.get("refill") or {})
        pool = self._pool_metrics()
        record = {
            "id": scan_id,
            "trigger": summary.get("trigger") or "manual",
            "started_at": started_at,
            "finished_at": finished_at,
            "elapsed_sec": summary.get("elapsed_sec"),
            "total": int(summary.get("total") or progress.get("total") or 0),
            "done": int(summary.get("done") or progress.get("done") or 0),
            "ok": ok,
            "quota": quota,
            "bad": bad,
            "counts": counts,
            "actions": actions,
            "refreshed": int(summary.get("refreshed") or 0),
            "reenabled": int(summary.get("reenabled") or 0),
            "refill": refill,
            "rebalance": dict(summary.get("rebalance") or {}),
            "pool": pool,
            "cpa_total": cpa_total,
            "quarantine_total": quarantine_total,
            "main_routeable": int(pool.get("main_routeable") or 0),
            "reserve": int(pool.get("reserve") or 0),
            "observe": int(pool.get("observe") or 0),
            "cooling": int(pool.get("cooling") or 0),
            "upstream_state": pool.get("upstream_state") or "unknown",
            "proxy": settings.get("probe_proxy") or "direct",
            "probe_chat": bool(settings.get("probe_chat")),
            "refresh_before_probe": bool(settings.get("refresh_before_probe")),
            "apply_policy": bool(settings.get("apply_policy")),
            "auto_refill": bool(settings.get("auto_refill")),
            "scan_workers": int(settings.get("scan_workers") or 0),
            "limit": int(settings.get("max_items_per_scan") or 0),
            "resume_count": self._resume_count,
            "resumed_at": timeutil.iso_to_beijing_display(self._resumed_at) if self._resumed_at else "",
            "cancelled": cancelled or bool(refill.get("cancelled")),
            "error": last_error,
        }
        record["outcome"] = self._scan_outcome(record)
        limit = _coerce_int(settings.get("scan_history_limit"), 100, min_v=0, max_v=1000)
        with self._lock:
            existing = [r for r in self._scan_history if str(r.get("id") or "") != scan_id]
            existing.append(record)
            self._scan_history = existing[-limit:] if limit > 0 else []

    def list_scan_history(self, *, query: str = "", outcome: str = "all", page: int = 1, page_size: int = 50) -> dict[str, Any]:
        q = query.strip().lower()
        oc = outcome.strip().lower()
        with self._lock:
            history_rows = list(self._scan_history)
        items = [_beijingize_record(dict(v)) for v in history_rows]
        if q:
            items = [
                i for i in items
                if q in str(i.get("id") or "").lower()
                or q in str(i.get("trigger") or "").lower()
                or q in str(i.get("error") or "").lower()
                or q in json.dumps(i.get("counts") or {}, ensure_ascii=False).lower()
            ]
        if oc and oc != "all":
            items = [i for i in items if str(i.get("outcome") or "").lower() == oc]
        items.sort(key=lambda i: str(i.get("finished_at") or i.get("started_at") or ""), reverse=True)
        total = len(items)
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 50), 1000))
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        return {"items": items[start : start + page_size], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}

    def export_report(self) -> dict[str, Any]:
        return {
            "generated_at": _utc_now(),
            "status": self.status(),
            "history": self.list_scan_history(page_size=1000).get("items", []),
            "results": self.list_results(page_size=10000).get("items", []),
            "quarantine": self.list_quarantine(page_size=10000).get("items", []),
        }

    def _rebalance_tiers(self, settings: dict[str, Any]) -> dict[str, Any]:
        result = {"promoted": 0, "reserved": 0, "target": int(settings.get("refill_target_active") or 0)}
        if not bool(settings.get("apply_policy")) or self._breaker_is_open() or result["target"] <= 0:
            return result
        try:
            active_emails = set(store.list_cpa_index())
        except Exception:
            return result
        states = [
            state
            for state in self._repo().list_accounts()
            if str(state.get("email") or "").lower() in active_emails
            and str(state.get("health_status") or "") == "healthy"
        ]
        main = [state for state in states if str(state.get("tier") or "") == "main" and not bool(state.get("desired_disabled"))]
        reserve = [state for state in states if str(state.get("tier") or "") == "reserve" and not bool(state.get("desired_disabled"))]
        target = int(result["target"])
        low_water = math.floor(target * int(settings.get("main_low_water_percent") or 90) / 100)
        now = time.time()

        if len(main) < target and reserve:
            promotion_batch = _coerce_int(settings.get("refill_max_per_scan"), 200, min_v=1, max_v=10000)
            needed = min(promotion_batch, target - len(main), len(reserve))
            reserve.sort(key=lambda state: str(state.get("last_success_at") or ""), reverse=True)
            for state in reserve[:needed]:
                previous_tier = str(state.get("tier") or "reserve")
                state.update({"tier": "main", "desired_priority": MAIN_PRIORITY, "desired_disabled": False, "updated_at": now})
                self._repo().upsert_account(state)
                row = {
                    "email": state.get("email"),
                    "path": state.get("path"),
                    "status": "ok",
                    "reason_code": "low_water_promotion",
                    "previous_tier": previous_tier,
                }
                applied = self._reconcile_schedule_state(row, state, settings)
                if applied.get("action"):
                    result["promoted"] += 1
            self._repo().set_meta("main_high_since", 0)
            return result

        if len(main) > target:
            high_since = float(self._repo().get_meta("main_high_since", 0) or 0)
            if not high_since:
                self._repo().set_meta("main_high_since", now)
                return result
            if now - high_since < 1800:
                return result
            excess = min(50, len(main) - target)
            main.sort(key=lambda state: str(state.get("last_success_at") or ""))
            for state in main[:excess]:
                previous_tier = str(state.get("tier") or "main")
                state.update({"tier": "reserve", "desired_priority": RESERVE_PRIORITY, "desired_disabled": False, "updated_at": now})
                self._repo().upsert_account(state)
                row = {
                    "email": state.get("email"),
                    "path": state.get("path"),
                    "status": "ok",
                    "reason_code": "high_water_reserve",
                    "previous_tier": previous_tier,
                }
                applied = self._reconcile_schedule_state(row, state, settings)
                if applied.get("action"):
                    result["reserved"] += 1
            self._repo().set_meta("main_high_since", now if len(main) - excess > target else 0)
        else:
            self._repo().set_meta("main_high_since", 0)
        return result

    @staticmethod
    def _scan_item_key(item: dict[str, Any]) -> str:
        return str(item.get("email") or item.get("path") or "").strip().lower()

    def _run_scan(self, options: dict[str, Any], *, resume: bool = False) -> None:
        fallback_started = time.monotonic()
        with self._lock:
            active = dict(self._active_scan)
            settings = dict(DEFAULT_SETTINGS)
            settings.update(self._settings)
            settings.update(dict(active.get("settings") or {}))
            trigger = str(active.get("trigger") or options.get("trigger") or "manual")
            scan_id = str(active.get("scan_id") or self._scan_id)
            snapshot_ready = bool(active.get("snapshot_ready"))
            index = [dict(item) for item in (active.get("items") or []) if isinstance(item, dict)]
            initial_total = _coerce_int(active.get("initial_total"), 0, min_v=0)
            adaptive = bool(options.get("adaptive")) and trigger == "auto"
        self._log(
            f"CPA 巡检{'恢复执行' if resume else '开始'}：id={scan_id} trigger={trigger} "
            f"workers={settings['scan_workers']} probe_chat={settings['probe_chat']} "
            f"refresh={settings['refresh_before_probe']} proxy={settings.get('probe_proxy')} "
            f"policy={settings.get('apply_policy')}"
        )
        try:
            if not snapshot_ready:
                inventory = store.list_cpa_index()
                initial_total = len(inventory)
                states = self._sync_inventory_states(inventory)
                emails = {str(e).strip().lower() for e in (options.get("emails") or []) if str(e).strip()}
                if emails:
                    selected_emails = [email for email in inventory if email in emails]
                elif adaptive:
                    adaptive_limit = _coerce_int(
                        options.get("limit") or settings.get("max_items_per_scan") or settings.get("adaptive_batch_size"),
                        int(settings.get("adaptive_batch_size") or 200),
                        min_v=1,
                        max_v=10000,
                    )
                    selected_emails = self._repo().due_emails(now=time.time(), limit=adaptive_limit)
                    missing_due = [email for email in selected_emails if email not in inventory]
                    if missing_due:
                        deleted = self._repo().delete_accounts(missing_due)
                        preview = ", ".join(missing_due[:3])
                        suffix = f"：{preview}" if preview else ""
                        self._log(f"CPA 巡检：清理 {deleted} 个已不在库存的历史到期状态{suffix}")
                        with self._lock:
                            for email in missing_due:
                                self._results.pop(email, None)
                        selected_emails = [email for email in selected_emails if email in inventory]
                else:
                    selected_emails = list(inventory)
                index = [dict(inventory[email]) for email in selected_emails if email in inventory]
                tier_order = {"main": 0, "reserve": 1, "candidate": 2, "observe": 3, "cooling": 4}
                index.sort(
                    key=lambda item: (
                        tier_order.get(str((states.get(str(item.get("email") or "").lower()) or {}).get("tier") or "candidate"), 9),
                        float((states.get(str(item.get("email") or "").lower()) or {}).get("next_check_at") or 0),
                    )
                )
                sample_percent = int(settings.get("chat_sample_percent") or 0)
                for item in index:
                    state = states.get(str(item.get("email") or "").lower()) or {}
                    tier = str(state.get("tier") or "candidate")
                    item["_probe_chat"] = bool(settings.get("probe_chat")) or (
                        adaptive
                        and (
                            tier in {"candidate", "observe", "cooling"}
                            or random.random() * 100 < sample_percent
                        )
                    )
                limit_source = options["limit"] if "limit" in options else (0 if adaptive else settings.get("max_items_per_scan"))
                limit = _coerce_int(limit_source, 0, min_v=0, max_v=100000)
                if limit:
                    index = index[:limit]
                index = [dict(item) for item in index]
                with self._lock:
                    if self._active_scan.get("scan_id") == scan_id:
                        self._active_scan.update(
                            {
                                "initial_total": initial_total,
                                "snapshot_ready": True,
                                "items": index,
                                "snapshot_at": _utc_now(),
                            }
                        )
                if not self._save_state():
                    raise RuntimeError("无法持久化 CPA 巡检账号快照")

            total = len(index)
            self._model_limiter = _ProbeRateLimiter(float(settings.get("models_probe_rate_per_sec") or 8.0))
            self._chat_limiter = _ProbeRateLimiter(float(settings.get("chat_probe_rate_per_sec") or 2.0))
            max_changes = int(settings.get("governance_max_downgrades_per_scan") or 50)
            percent_limit = max(1, math.ceil(max(1, initial_total) * int(settings.get("governance_max_downgrade_percent") or 1) / 100))
            self._governance_downgrades = 0
            self._governance_limit = min(max_changes, percent_limit)
            item_keys = {self._scan_item_key(item) for item in index}
            with self._lock:
                completed = list(
                    dict.fromkeys(
                        key
                        for key in (str(value) for value in (self._active_scan.get("completed") or []))
                        if key and key in item_keys
                    )
                )
                done = len(completed)
                summary = dict(self._summary) if resume else {
                    "counts": {},
                    "actions": {},
                }
                summary.update(
                    {
                        "total": total,
                        "done": done,
                        "trigger": trigger,
                        "started_at": self._started_at,
                        "resume_count": self._resume_count,
                        "resumed_at": self._resumed_at,
                    }
                )
                summary.setdefault("counts", {})
                summary.setdefault("actions", {})
                self._summary = summary
                self._progress = {"done": done, "total": total}
                if self._active_scan.get("scan_id") == scan_id:
                    self._active_scan["completed"] = completed
                    self._active_scan["last_checkpoint_at"] = _utc_now()
            if not self._save_state():
                raise RuntimeError("无法持久化 CPA 巡检进度")

            completed_set = set(completed)
            pending = [item for item in index if self._scan_item_key(item) not in completed_set]
            counts = {str(k): int(v or 0) for k, v in dict(self._summary.get("counts") or {}).items()}
            actions = {str(k): int(v or 0) for k, v in dict(self._summary.get("actions") or {}).items()}
            refreshed = int(self._summary.get("refreshed") or 0)
            reenabled = int(self._summary.get("reenabled") or 0)

            if resume:
                self._log(f"巡检检查点已恢复：完成 {done}/{total}，剩余 {len(pending)}")

            proxy_picker = self._resolve_proxy_picker(str(settings.get("probe_proxy") or "direct"))

            def run_item(it: dict[str, Any]) -> dict[str, Any]:
                if self._cancel.is_set():
                    return {
                        "email": str(it.get("email") or "").lower(),
                        "path": str(it.get("path") or ""),
                        "filename": Path(str(it.get("path") or "")).name,
                        "location": it.get("location") or "",
                        "checked_at": _utc_now(),
                        "status": "soft_fail",
                        "reason": "cancelled",
                        "refreshed": False,
                    }
                return self._scan_one(it, settings, proxy_picker)

            if pending and not self._cancel.is_set():
                workers = min(int(settings["scan_workers"]), len(pending))
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cpa-scan") as ex:
                    futs = {ex.submit(run_item, item): item for item in pending}
                    for fut in as_completed(futs):
                        item = futs[fut]
                        if self._cancel.is_set():
                            for queued in futs:
                                queued.cancel()
                            break
                        try:
                            raw_row = fut.result()
                        except Exception as exc:  # noqa: BLE001
                            raw_row = {
                                "email": str(item.get("email") or "").lower(),
                                "path": str(item.get("path") or ""),
                                "filename": Path(str(item.get("path") or "")).name,
                                "location": item.get("location") or "",
                                "checked_at": _utc_now(),
                                "status": "soft_fail",
                                "reason": f"scan worker: {_mask_error(exc)}",
                                "refreshed": False,
                            }
                        merged = self._merge_result(raw_row, settings=settings)
                        row = self._apply_policy(merged, settings)
                        row["scan_id"] = scan_id
                        status = str(row.get("status") or "probe_failed")
                        email = str(row.get("email") or "").lower()
                        item_key = self._scan_item_key(item)
                        journal_saved = self._append_scan_journal(
                            scan_id=scan_id,
                            item_key=item_key,
                            row=row,
                        )
                        counts[status] = counts.get(status, 0) + 1
                        if row.get("refreshed"):
                            refreshed += 1
                        if row.get("reenabled"):
                            reenabled += 1
                        if row.get("action"):
                            action = str(row.get("action"))
                            actions[action] = actions.get(action, 0) + 1
                        with self._lock:
                            if email:
                                self._results[email] = row
                            completed_set.add(item_key)
                            completed = [key for key in completed if key != item_key]
                            completed.append(item_key)
                            done = len(completed_set)
                            self._progress = {"done": done, "total": total, "current": email or item_key}
                            self._summary = {
                                "counts": dict(counts),
                                "actions": dict(actions),
                                "total": total,
                                "done": done,
                                "refreshed": refreshed,
                                "reenabled": reenabled,
                                "trigger": trigger,
                                "started_at": self._started_at,
                                "resume_count": self._resume_count,
                                "resumed_at": self._resumed_at,
                            }
                            if self._active_scan.get("scan_id") == scan_id:
                                self._active_scan["completed"] = list(completed)
                                self._active_scan["last_checkpoint_at"] = _utc_now()
                        if status != "ok" or row.get("action"):
                            act = f" action={row.get('action')}" if row.get("action") else ""
                            self._log(f"{email or row.get('filename')} -> {status}{act}: {row.get('reason')}")
                        elif done <= 5 or done % 100 == 0:
                            self._log(f"进度 {done}/{total}，OK={counts.get('ok', 0)}")
                        if not journal_saved:
                            self._log(f"巡检增量检查点写入失败：{email or item_key}")
                            if not self._save_state():
                                self._log(f"巡检完整检查点写入失败：{email or item_key}")

            if self._cancel.is_set():
                refill = {"enabled": bool(settings.get("auto_refill")), "started": False, "cancelled": True}
            else:
                with self._lock:
                    if self._active_scan.get("scan_id") == scan_id:
                        self._active_scan["phase"] = "refill"
                        self._active_scan["last_checkpoint_at"] = _utc_now()
                self._save_state()
                rebalance = self._rebalance_tiers(settings)
                refill = self._maybe_start_refill(settings=settings, initial_total=initial_total, trigger=trigger)
            elapsed = self._elapsed_sec(fallback_started=fallback_started)
            with self._lock:
                self._summary.update(
                    {
                        "elapsed_sec": elapsed,
                        "finished_at": _utc_now(),
                        "refreshed": refreshed,
                        "reenabled": reenabled,
                        "actions": dict(actions),
                        "refill": refill,
                        "rebalance": rebalance if not self._cancel.is_set() else {},
                    }
                )
            if total == 0:
                if adaptive and initial_total > 0:
                    self._log(f"CPA 巡检：当前没有到期账号，库存 {initial_total} 个，等待分层周期")
                else:
                    self._log("CPA 巡检：没有可检查的 xai-*.json")
            elif self._cancel.is_set():
                self._log(f"CPA 巡检已取消：done={done}/{total} elapsed={elapsed}s")
            else:
                self._log(
                    f"CPA 巡检完成：total={total} ok={counts.get('ok', 0)} refreshed={refreshed} "
                    f"actions={actions} refill={refill.get('started', False)} elapsed={elapsed}s"
                )
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._last_error = _mask_error(exc)
            self._log(f"CPA 巡检异常：{exc}")
        finally:
            finished_at = _utc_now()
            with self._lock:
                self._finished_at = finished_at
                self._last_finished_ts = time.time()
                self._progress = dict(self._progress)
                self._progress["done"] = int(self._progress.get("done") or self._summary.get("done") or 0)
                self._summary.setdefault("elapsed_sec", self._elapsed_sec(fallback_started=fallback_started))
                self._summary["finished_at"] = finished_at
                self._summary["resume_count"] = self._resume_count
                self._summary["resumed_at"] = self._resumed_at
            self._append_scan_history(settings=settings)
            try:
                current_settings = settings_from_config()
            except Exception:
                current_settings = dict(settings)
            with self._lock:
                self._running = False
                self._recovery_pending = False
                if self._active_scan.get("scan_id") == scan_id:
                    self._active_scan = {}
                interval = _coerce_int(current_settings.get("scheduler_tick_sec"), 300, min_v=30, max_v=3600)
                self._scheduled_interval_sec = interval
                self._next_scan_at = time.time() + interval
                self._settings = current_settings
            if self._save_state():
                self._clear_scan_journal()


monitor = CpaPoolMonitor()
