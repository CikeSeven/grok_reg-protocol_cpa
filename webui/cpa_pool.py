"""CPA auth-file pool monitor and governance for the WebUI.

Source of truth: CPA xai-*.json auth files, not the CLIProxyAPI runtime.  This
lets us attribute health to an individual account/file, refresh tokens in-place,
and optionally quarantine/disable bad accounts with reversible operations.
"""

from __future__ import annotations

import json
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

STATE_PATH = store.ROOT / "cpa_pool_state.json"
SCAN_JOURNAL_FILENAME = "cpa_pool_scan.journal.jsonl"
DEFAULT_QUARANTINE_DIR = store.ROOT / "cpa_quarantine"
STATE_VERSION = 2
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
    # state/history
    "history_limit": 8,
    "scan_history_limit": 100,
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
    "quota_cooldown_sec": 6 * 3600,
    # auto refill: after governance removes/isolates files, start existing
    # backfill job to mint missing CPA files from accounts_cli.txt.
    "auto_refill": False,
    "refill_target_active": 0,  # 0 = keep pre-scan active count
    "refill_max_per_scan": 30,
    "refill_workers": -1,
    "refill_probe_chat": False,
}

TERMINAL_STATUSES = {
    "ok",
    "quota",
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
    status = int(result.get("status") or 0)
    error = _mask_error(result.get("error") or result.get("text") or result)
    low = error.lower()
    quota_needles = (
        "free-usage-exhausted",
        "usage_exhausted",
        "quota",
        "rate limit",
        "rate_limit",
        "too many requests",
        "subscription:",
        "cooldown",
        "resource_exhausted",
    )
    hard_needles = (
        "invalid_grant",
        "invalid token",
        "invalid_token",
        "token expired",
        "token is expired",
        "revoked",
        "permission_denied",
        "permission denied",
        "unauthorized",
        "forbidden",
        "not entitled",
    )
    if status == 429 or any(n in low for n in quota_needles):
        return "quota", f"{stage}: {status or '-'} {error}".strip()
    if status in {401, 403} and any(n in low for n in hard_needles):
        return "hard_bad", f"{stage}: {status} {error}".strip()
    if status == 0 or status >= 500:
        return "soft_fail", f"{stage}: {status or '-'} {error}".strip()
    if status in {401, 403}:
        return "hard_bad", f"{stage}: {status} {error}".strip()
    return "probe_failed", f"{stage}: {status or '-'} {error}".strip()


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
            "history_limit": _coerce_int(cfg.get("cpa_pool_history_limit"), int(s["history_limit"]), min_v=0, max_v=100),
            "scan_history_limit": _coerce_int(cfg.get("cpa_pool_scan_history_limit"), int(s["scan_history_limit"]), min_v=0, max_v=1000),
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
            "auto_refill": _coerce_bool(cfg.get("cpa_pool_auto_refill"), bool(s["auto_refill"])),
            "refill_target_active": _coerce_int(cfg.get("cpa_pool_refill_target_active"), int(s["refill_target_active"]), min_v=0, max_v=100000),
            "refill_max_per_scan": _coerce_int(cfg.get("cpa_pool_refill_max_per_scan"), int(s["refill_max_per_scan"]), min_v=1, max_v=10000),
            "refill_workers": _coerce_int(cfg.get("cpa_pool_refill_workers"), int(s["refill_workers"]), min_v=-1, max_v=20),
            "refill_probe_chat": _coerce_bool(cfg.get("cpa_pool_refill_probe_chat"), bool(s["refill_probe_chat"])),
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


class CpaPoolMonitor:
    def __init__(self) -> None:
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
        self._load_state()

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
        settings["refill_max_per_scan"] = _coerce_int(settings.get("refill_max_per_scan"), 30, min_v=1, max_v=10000)
        settings["refill_workers"] = _coerce_int(settings.get("refill_workers"), -1, min_v=-1, max_v=20)
        settings["refill_probe_chat"] = _coerce_bool(settings.get("refill_probe_chat"), False)
        settings["scan_history_limit"] = _coerce_int(settings.get("scan_history_limit"), 100, min_v=0, max_v=1000)
        return settings

    def _load_state(self) -> None:
        if not STATE_PATH.is_file():
            return
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
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
            return

    @staticmethod
    def _scan_journal_path() -> Path:
        return STATE_PATH.with_name(SCAN_JOURNAL_FILENAME)

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
                        "active_scan": dict(self._active_scan) if self._active_scan else None,
                        "scan_history": list(self._scan_history),
                        "results": dict(self._results),
                    }
                encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
                STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
                tmp = STATE_PATH.with_name(f".{STATE_PATH.name}.tmp")
                tmp.write_text(encoded, encoding="utf-8")
                os.replace(tmp, STATE_PATH)
            return True
        except Exception:
            return False

    def _sync_schedule_locked(self, settings: dict[str, Any], *, now: float) -> bool:
        interval = _coerce_int(settings.get("scan_interval_sec"), 300, min_v=30, max_v=86400)
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
            interval = _coerce_int(schedule_settings.get("scan_interval_sec"), 300, min_v=30, max_v=86400)
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
            self.start_scan({"trigger": "auto"})

    def status(self) -> dict[str, Any]:
        self.ensure_scheduler()
        with self._lock:
            summary = _beijingize_record(dict(self._summary))
            progress = dict(self._progress)
            logs = list(self._logs)[-240:]
            settings = dict(self._settings)
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
        try:
            cpa_total = len(store.list_cpa_index())
        except Exception:
            cpa_total = summary.get("total") or 0
        q_total = self.quarantine_summary().get("total", 0)
        counts = dict(summary.get("counts") or {})
        ok = int(counts.get("ok") or 0)
        quota = int(counts.get("quota") or 0) + int(counts.get("cooling") or 0)
        bad = sum(int(v or 0) for k, v in counts.items() if k not in {"ok", "quota", "cooling"})
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
            "logs": logs,
            "cpa_total": cpa_total,
            "quarantine_total": q_total,
            "results_total": results_total,
            "scan_history_total": scan_history_total,
            "ok": ok,
            "quota": quota,
            "bad": bad,
        }

    def list_results(self, *, query: str = "", status: str = "all", page: int = 1, page_size: int = 100) -> dict[str, Any]:
        q = query.strip().lower()
        st = status.strip().lower()
        with self._lock:
            result_rows = list(self._results.values())
        items = [_beijingize_record(dict(v)) for v in result_rows]
        if q:
            items = [i for i in items if q in str(i.get("email") or "").lower() or q in str(i.get("status") or "").lower() or q in str(i.get("reason") or "").lower()]
        if st and st != "all":
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
            base_row.update({"status": "invalid", "reason": f"read json: {_mask_error(exc)}"})
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
                try:
                    _set_enabled(path, payload, reason="cooldown expired; recheck")
                    payload = _safe_json_load(path)
                    base_row["reenabled"] = True
                except Exception as exc:  # noqa: BLE001
                    base_row.update({"status": "disabled", "reason": f"managed re-enable failed: {_mask_error(exc)}"})
                    return base_row
            else:
                base_row.update({"status": "disabled", "reason": "auth disabled=true"})
                return base_row

        access = str(payload.get("access_token") or "").strip()
        refresh = str(payload.get("refresh_token") or "").strip()
        if not access and not refresh:
            base_row.update({"status": "invalid", "reason": "missing access_token and refresh_token"})
            return base_row

        exp_ts = _iso_to_ts(str(payload.get("expired") or payload.get("expires_at") or "")) or _access_exp_ts(access)
        if exp_ts:
            base_row["expired"] = _ts_to_iso(exp_ts)
            base_row["expires_in_sec"] = int(exp_ts - time.time())

        proxy = proxy_picker()
        timeout = float(settings.get("probe_timeout_sec") or 30.0)
        if bool(settings.get("refresh_before_probe")) and refresh:
            skew = int(settings.get("refresh_skew_sec") or 0)
            should_refresh = not access or not exp_ts or (exp_ts - time.time()) <= skew
            if should_refresh:
                rr = refresh_auth_file(path, payload, proxy=proxy, timeout=timeout)
                if rr.get("ok"):
                    payload = dict(rr.get("payload") or payload)
                    access = str(payload.get("access_token") or "").strip()
                    base_row["refreshed"] = True
                    exp_ts = _iso_to_ts(str(payload.get("expired") or "")) or _access_exp_ts(access)
                    base_row["expired"] = _ts_to_iso(exp_ts)
                    base_row["expires_in_sec"] = int(exp_ts - time.time()) if exp_ts else None
                elif not access or (exp_ts and exp_ts <= time.time()):
                    _st, reason = _status_from_failure(rr, stage="refresh")
                    base_row.update({"status": "refresh_failed", "reason": reason or "refresh failed"})
                    return base_row
                else:
                    base_row["refresh_error"] = rr.get("error") or rr.get("status") or "refresh failed"

        if not access:
            base_row.update({"status": "invalid", "reason": "missing access_token"})
            return base_row

        base_url = str(payload.get("base_url") or DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
        models = probe_models(access, base_url=base_url, timeout=timeout, proxy=proxy)
        base_row["models_status"] = models.get("status")
        base_row["model_count"] = len(models.get("model_ids") or [])
        if not models.get("ok"):
            st, reason = _status_from_failure(models, stage="models")
            base_row.update({"status": st, "reason": reason})
            base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
            return base_row
        if not models.get("has_grok_45"):
            base_row.update({"status": "no_grok45", "reason": "models ok but grok-4.5 missing"})
            base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
            return base_row

        if bool(settings.get("probe_chat")):
            chat = probe_mini_response(access, base_url=base_url, timeout=max(timeout, 30.0), proxy=proxy)
            base_row["chat_status"] = chat.get("status")
            if not chat.get("ok"):
                st, reason = _status_from_failure(chat, stage="chat")
                base_row.update({"status": st, "reason": reason})
                base_row["latency_ms"] = int((time.monotonic() - started) * 1000)
                return base_row

        reason = "models+chat ok" if bool(settings.get("probe_chat")) else "models ok"
        if base_row.get("refresh_error"):
            reason += f"; refresh warning: {_mask_error(base_row.get('refresh_error'), 120)}"
        base_row.update({"status": "ok", "reason": reason})
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

    def _policy_decision(self, row: dict[str, Any], settings: dict[str, Any]) -> tuple[str, str, int]:
        status = str(row.get("status") or "")
        streak = int(row.get("status_streak") or 0)
        if status == "hard_bad":
            return str(settings.get("hard_bad_action")), "hard_bad", int(settings.get("hard_bad_threshold") or 1) if streak >= int(settings.get("hard_bad_threshold") or 1) else 10**9
        if status == "refresh_failed":
            th = int(settings.get("refresh_failed_threshold") or 2)
            return (str(settings.get("refresh_failed_action")), "refresh_failed", th) if streak >= th else ("keep", "", th)
        if status == "invalid":
            th = int(settings.get("invalid_threshold") or 1)
            return (str(settings.get("invalid_action")), "invalid", th) if streak >= th else ("keep", "", th)
        if status == "no_grok45":
            th = int(settings.get("no_grok45_threshold") or 2)
            return (str(settings.get("no_grok45_action")), "no_grok45", th) if streak >= th else ("keep", "", th)
        if status in {"soft_fail", "probe_failed"}:
            th = int(settings.get("soft_fail_threshold") or 3)
            return (str(settings.get("soft_fail_action")), "soft_fail", th) if streak >= th else ("keep", "", th)
        if status == "quota":
            th = int(settings.get("quota_threshold") or 1)
            return (str(settings.get("quota_action")), "quota", th) if streak >= th else ("keep", "", th)
        return "keep", "", 0

    def _apply_policy(self, row: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
        if not bool(settings.get("apply_policy")):
            return row
        action, bucket, threshold = self._policy_decision(row, settings)
        if action not in _POLICY_ACTIONS or action == "keep":
            return row
        path = Path(str(row.get("path") or ""))
        if not path.is_file():
            row["policy_error"] = f"path not found for action {action}: {path}"
            return row
        reason = f"policy:{bucket} status={row.get('status')} streak={row.get('status_streak')} threshold={threshold}"
        try:
            if action == "disable":
                payload = _safe_json_load(path)
                cool_until = ""
                if str(row.get("status")) == "quota":
                    cool_until = _ts_to_iso(time.time() + int(settings.get("quota_cooldown_sec") or 21600))
                    row["cool_until"] = cool_until
                _set_managed_disabled(path, payload, reason=reason, status=str(row.get("status") or bucket), cool_until=cool_until)
                row.update({"action": "disabled", "action_at": _utc_now(), "action_reason": reason})
            elif action in {"quarantine", "delete"}:
                q_bucket = "deleted" if action == "delete" else bucket or str(row.get("status") or "bad")
                mv = _move_to_quarantine(path, bucket=q_bucket, settings=settings, reason=reason)
                if not mv.get("ok"):
                    row["policy_error"] = mv.get("error") or "move failed"
                    return row
                row.update({"action": "deleted" if action == "delete" else "quarantined", "action_at": _utc_now(), "action_reason": reason, "quarantine_path": mv.get("path"), "path": mv.get("path"), "location": "quarantine"})
        except Exception as exc:  # noqa: BLE001
            row["policy_error"] = _mask_error(exc)
            row["status"] = row.get("status") or "policy_error"
        return row

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
            try:
                if action == "enable":
                    payload = _safe_json_load(path)
                    _set_enabled(path, payload, reason=reason)
                    results.append({"email": email, "ok": True, "action": "enabled"})
                elif action == "disable":
                    payload = _safe_json_load(path)
                    _set_managed_disabled(path, payload, reason=reason, status="manual_disabled")
                    results.append({"email": email, "ok": True, "action": "disabled"})
                elif action in {"quarantine", "delete"}:
                    bucket = "deleted" if action == "delete" else "manual"
                    mv = _move_to_quarantine(path, bucket=bucket, settings=settings, reason=reason)
                    results.append({"email": email, "ok": bool(mv.get("ok")), "action": "deleted" if action == "delete" else "quarantined", "path": mv.get("path"), "error": mv.get("error", "")})
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
                if _managed_meta(payload).get("managed"):
                    payload["disabled"] = False
                    meta = _managed_meta(payload)
                    meta.update({"restored_at": _utc_now(), "restore_target": str(dst), "cool_until": ""})
                    payload["_cpa_pool"] = meta
                    _atomic_write_json(src, payload)
                shutil.move(str(src), str(dst))
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

    def _maybe_start_refill(self, *, settings: dict[str, Any], initial_total: int, trigger: str) -> dict[str, Any]:
        if not bool(settings.get("auto_refill")):
            return {"enabled": False, "started": False}
        try:
            active_index = store.list_cpa_index()
        except Exception as exc:  # noqa: BLE001
            err = f"active CPA index unavailable: {_mask_error(exc)}"
            self._log(f"自动补号跳过：{err}")
            return {"enabled": True, "started": False, "error": err}
        current_total = len(active_index)
        target = int(settings.get("refill_target_active") or 0) or int(initial_total or 0)
        need = max(0, target - current_total)
        if need <= 0:
            return {"enabled": True, "started": False, "target": target, "current": current_total, "need": 0}
        limit = min(need, int(settings.get("refill_max_per_scan") or 30))
        try:
            from .jobs import runner

            active = runner.active_job()
            if active and active.status in {"queued", "running"}:
                msg = f"auto_refill skipped: active job {active.kind} {active.id}"
                self._log(msg)
                return {"enabled": True, "started": False, "target": target, "current": current_total, "need": need, "error": msg}
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
            if len(candidates) >= limit:
                strategy = "backfill"
                job = runner.start_backfill(
                    {
                        "emails": candidates[:limit],
                        "limit": limit,
                        "probe": True,
                        "probe_chat": bool(settings.get("refill_probe_chat")),
                        "workers": int(settings.get("refill_workers") or -1),
                        "sleep": 0,
                        "exclude_emails": exclude_emails,
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
                    }
                )
            self._log(
                f"自动补号已启动：strategy={strategy} need={need} limit={limit} "
                f"candidates={len(candidates)} exclude={len(exclude_emails)} job={job.get('id')} trigger={trigger}"
            )
            return {
                "enabled": True,
                "started": True,
                "strategy": strategy,
                "target": target,
                "current": current_total,
                "need": need,
                "limit": limit,
                "candidates": len(candidates),
                "excluded": len(exclude_emails),
                "job": job,
            }
        except Exception as exc:  # noqa: BLE001
            err = _mask_error(exc)
            self._log(f"自动补号启动失败：need={need} error={err}")
            return {"enabled": True, "started": False, "target": target, "current": current_total, "need": need, "error": err}

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
        quota = int(counts.get("quota") or 0) + int(counts.get("cooling") or 0)
        bad = sum(int(v or 0) for k, v in counts.items() if k not in {"ok", "quota", "cooling"})
        try:
            cpa_total = len(store.list_cpa_index())
        except Exception:
            cpa_total = 0
        try:
            quarantine_total = int(self.quarantine_summary().get("total") or 0)
        except Exception:
            quarantine_total = 0
        refill = dict(summary.get("refill") or {})
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
            "cpa_total": cpa_total,
            "quarantine_total": quarantine_total,
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
        self._log(
            f"CPA 巡检{'恢复执行' if resume else '开始'}：id={scan_id} trigger={trigger} "
            f"workers={settings['scan_workers']} probe_chat={settings['probe_chat']} "
            f"refresh={settings['refresh_before_probe']} proxy={settings.get('probe_proxy')} "
            f"policy={settings.get('apply_policy')}"
        )
        try:
            if not snapshot_ready:
                index = list(store.list_cpa_index().values())
                initial_total = len(index)
                emails = {str(e).strip().lower() for e in (options.get("emails") or []) if str(e).strip()}
                if emails:
                    index = [i for i in index if str(i.get("email") or "").lower() in emails]
                limit_source = options["limit"] if "limit" in options else settings.get("max_items_per_scan")
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
                    }
                )
            if total == 0:
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
                interval = _coerce_int(current_settings.get("scan_interval_sec"), 300, min_v=30, max_v=86400)
                self._scheduled_interval_sec = interval
                self._next_scan_at = time.time() + interval
                self._settings = current_settings
            if self._save_state():
                self._clear_scan_journal()


monitor = CpaPoolMonitor()
