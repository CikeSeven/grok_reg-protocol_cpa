"""Health classification and state transitions for the CPA account pool."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from email.utils import parsedate_to_datetime
from typing import Any


MAIN_PRIORITY = 100
RESERVE_PRIORITY = 50
OBSERVE_PRIORITY = 10

ROUTABLE_TIERS = {"main", "reserve"}
NON_ROUTABLE_TIERS = {"candidate", "observe", "cooling", "quarantine", "malformed", "manual_disabled"}

_UPSTREAM_BUSY_NEEDLES = (
    "model is currently at capacity",
    "model is at capacity",
    "currently at capacity",
    "capacity due to high demand",
    "high demand",
    "server is overloaded",
    "service overloaded",
    "temporarily overloaded",
    "upstream busy",
)
_ACCOUNT_QUOTA_NEEDLES = (
    "free-usage-exhausted",
    "free_usage_exhausted",
    "usage_exhausted",
    "included free usage",
    "rolling 24-hour window",
    "subscription quota exhausted",
    "account quota exhausted",
)
_INVALID_AUTH_NEEDLES = (
    "invalid_grant",
    "invalid token",
    "invalid_token",
    "token revoked",
    "token has been revoked",
    "permission_denied",
    "permission denied",
    "not entitled",
    "account deactivated",
)


@dataclass(frozen=True)
class FailureClassification:
    status: str
    reason_code: str
    reason: str
    stage: str
    http_status: int
    error_code: str
    fingerprint: str
    account_attributable: bool
    conclusive: bool
    retry_after_sec: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    text = str(value or "").strip()
    if not text or text[0] not in "{[":
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _first_text(payload: dict[str, Any], *paths: tuple[str, ...]) -> str:
    for path in paths:
        value: Any = payload
        for part in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return ""


def _normalized_message(value: Any, *, limit: int = 360) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip().lower()
    text = re.sub(r"\b(?:req|request|trace|ray)[-_ ]?id[=: ]+[a-z0-9_-]+", "request-id", text)
    text = re.sub(r"\b[0-9a-f]{16,}\b", "id", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b", "timestamp", text)
    return text[:limit]


def _retry_after_seconds(result: dict[str, Any]) -> int | None:
    direct = result.get("retry_after_sec")
    if direct is not None:
        try:
            return max(0, int(float(direct)))
        except (TypeError, ValueError):
            pass
    headers = result.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    raw = ""
    for key, value in headers.items():
        if str(key).lower() == "retry-after":
            raw = str(value or "").strip()
            break
    if not raw:
        return None
    try:
        return max(0, int(float(raw)))
    except ValueError:
        try:
            return max(0, int(parsedate_to_datetime(raw).timestamp() - time.time()))
        except (TypeError, ValueError, OverflowError):
            return None


def classify_failure(result: dict[str, Any], *, stage: str) -> FailureClassification:
    """Classify a failed probe without conflating provider capacity with quota."""

    try:
        http_status = int(result.get("status") or 0)
    except (TypeError, ValueError):
        http_status = 0
    raw_error = result.get("error") or result.get("text") or result
    payload = _json_object(raw_error)
    error_code = _first_text(
        payload,
        ("code",),
        ("type",),
        ("error", "code"),
        ("error", "type"),
        ("error", "status"),
    )
    message = _first_text(
        payload,
        ("message",),
        ("detail",),
        ("error_description",),
        ("error", "message"),
        ("error", "detail"),
        ("error",),
    ) or str(raw_error or "")
    normalized = _normalized_message(f"{error_code} {message}")
    retry_after = _retry_after_seconds(result)

    if any(needle in normalized for needle in _UPSTREAM_BUSY_NEEDLES):
        status, reason_code, attributable, conclusive = "upstream_busy", "model_capacity", False, False
    elif any(needle in normalized for needle in _ACCOUNT_QUOTA_NEEDLES):
        status, reason_code, attributable, conclusive = "account_quota", "free_usage_exhausted", True, True
        retry_after = retry_after if retry_after is not None else 24 * 3600
    elif "invalid_grant" in normalized:
        status, reason_code, attributable, conclusive = "invalid_auth", "invalid_grant", True, True
    elif any(needle in normalized for needle in _INVALID_AUTH_NEEDLES):
        status, reason_code, attributable, conclusive = "invalid_auth", "credential_rejected", True, True
    elif http_status == 401:
        status, reason_code, attributable, conclusive = "invalid_auth", "unauthorized", True, True
    elif http_status == 403:
        status, reason_code, attributable, conclusive = "invalid_auth", "forbidden", True, False
    elif http_status == 429:
        status, reason_code, attributable, conclusive = "transient_error", "rate_limited_unknown", False, False
    elif http_status in {400, 404, 409, 422}:
        status, reason_code, attributable, conclusive = "request_error", "request_rejected", False, True
    elif http_status == 0:
        status, reason_code, attributable, conclusive = "transient_error", "network_error", False, False
    elif http_status in {408, 425} or http_status >= 500:
        status, reason_code, attributable, conclusive = "transient_error", "upstream_transient", False, False
    else:
        status, reason_code, attributable, conclusive = "probe_failed", "unknown_probe_failure", False, False

    fingerprint_source = f"{stage}|{http_status}|{reason_code}|{error_code.lower()}|{normalized}"
    fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8", errors="replace")).hexdigest()[:16]
    display = re.sub(r"\s+", " ", str(message or error_code or raw_error)).strip()[:260]
    reason = f"{stage}: {http_status or '-'} {display}".strip()
    return FailureClassification(
        status=status,
        reason_code=reason_code,
        reason=reason,
        stage=stage,
        http_status=http_status,
        error_code=error_code,
        fingerprint=fingerprint,
        account_attributable=attributable,
        conclusive=conclusive,
        retry_after_sec=retry_after,
    )


def default_state(email: str, *, path: str = "", now: float | None = None) -> dict[str, Any]:
    timestamp = time.time() if now is None else float(now)
    return {
        "email": email.strip().lower(),
        "path": path,
        "tier": "candidate",
        "health_status": "unchecked",
        "health_reason": "",
        "confidence": 0,
        "desired_priority": OBSERVE_PRIORITY,
        "desired_disabled": True,
        "actual_priority": None,
        "actual_disabled": None,
        "failure_streak": 0,
        "independent_failure_streak": 0,
        "success_streak": 0,
        "last_failure_fingerprint": "",
        "last_failure_ts": 0.0,
        "last_checked_at": "",
        "last_success_at": "",
        "last_failure_at": "",
        "next_check_at": timestamp,
        "cool_until": "",
        "manual_override": False,
        "governance_eligible": False,
        "updated_at": timestamp,
    }


def transition_state(
    previous: dict[str, Any] | None,
    observation: dict[str, Any],
    *,
    now: float | None = None,
    independent_failure_interval_sec: int = 600,
    transient_failure_threshold: int = 3,
    no_model_failure_threshold: int = 2,
    recovery_success_threshold: int = 2,
    quota_cooldown_sec: int = 24 * 3600,
    healthy_interval_sec: int = 12 * 3600,
    observe_interval_sec: int = 12 * 60,
    candidate_interval_sec: int = 20 * 60,
    jitter_sec: int = 0,
) -> dict[str, Any]:
    """Apply one observation to an account while preserving inconclusive state."""

    timestamp = time.time() if now is None else float(now)
    email = str(observation.get("email") or (previous or {}).get("email") or "").strip().lower()
    state = default_state(email, path=str(observation.get("path") or ""), now=timestamp)
    if previous:
        state.update(previous)
    state["email"] = email
    if observation.get("path"):
        state["path"] = str(observation["path"])
    state["last_checked_at"] = str(observation.get("checked_at") or state.get("last_checked_at") or "")
    state["updated_at"] = timestamp

    status = str(observation.get("status") or "probe_failed")
    reason = str(observation.get("reason") or "")
    fingerprint = str(observation.get("fingerprint") or "")
    reason_code = str(observation.get("reason_code") or "")
    previous_tier = str(state.get("tier") or "candidate")

    if status == "ok":
        successes = int(state.get("success_streak") or 0) + 1
        state.update(
            {
                "health_status": "healthy",
                "health_reason": reason,
                "failure_streak": 0,
                "independent_failure_streak": 0,
                "success_streak": successes,
                "last_success_at": state["last_checked_at"],
                "confidence": min(100, max(70, int(state.get("confidence") or 0) + 25)),
                "next_check_at": timestamp + healthy_interval_sec + max(0, jitter_sec),
                "governance_eligible": True,
            }
        )
        recovering = previous_tier in NON_ROUTABLE_TIERS
        if recovering and successes < max(1, recovery_success_threshold):
            state.update({"tier": "candidate", "desired_priority": OBSERVE_PRIORITY, "desired_disabled": True})
        else:
            state.update({"tier": "main", "desired_priority": MAIN_PRIORITY, "desired_disabled": False})
        return state

    if status == "upstream_busy":
        state.update(
            {
                "health_status": status,
                "health_reason": reason,
                "success_streak": 0,
                "next_check_at": timestamp + candidate_interval_sec + max(0, jitter_sec),
            }
        )
        if previous:
            state["tier"] = previous_tier
            state["desired_priority"] = int(previous.get("desired_priority") or state["desired_priority"])
            state["desired_disabled"] = bool(previous.get("desired_disabled"))
        if (
            previous_tier == "candidate"
            and int(observation.get("models_status") or 0) == 200
            and not bool(state.get("manual_override"))
        ):
            state.update(
                {
                    "tier": "reserve",
                    "desired_priority": RESERVE_PRIORITY,
                    "desired_disabled": False,
                    "governance_eligible": True,
                    "confidence": max(50, int(state.get("confidence") or 0)),
                }
            )
        return state

    if status == "request_error":
        state.update(
            {
                "health_status": status,
                "health_reason": reason,
                "success_streak": 0,
                "next_check_at": timestamp + candidate_interval_sec + max(0, jitter_sec),
            }
        )
        if previous:
            state["tier"] = previous_tier
            state["desired_priority"] = int(previous.get("desired_priority") or state["desired_priority"])
            state["desired_disabled"] = bool(previous.get("desired_disabled"))
        return state

    state["success_streak"] = 0
    state["failure_streak"] = int(state.get("failure_streak") or 0) + 1
    state["last_failure_at"] = state["last_checked_at"]
    state["health_status"] = status
    state["health_reason"] = reason

    if status == "account_quota":
        cooldown = int(observation.get("retry_after_sec") or quota_cooldown_sec)
        state.update(
            {
                "tier": "cooling",
                "desired_priority": OBSERVE_PRIORITY,
                "desired_disabled": True,
                "confidence": max(0, int(state.get("confidence") or 0) - 15),
                "next_check_at": timestamp + max(60, cooldown) + max(0, jitter_sec),
                "cool_until_ts": timestamp + max(60, cooldown),
                "governance_eligible": True,
            }
        )
        return state

    if status in {"invalid_auth", "malformed"}:
        definitive = reason_code in {"invalid_grant", "credential_rejected", "malformed_json", "missing_tokens"}
        threshold = 1 if definitive else 2
        if int(state["failure_streak"]) >= threshold:
            tier = "malformed" if status == "malformed" else "quarantine"
            state.update({"tier": tier, "desired_priority": OBSERVE_PRIORITY, "desired_disabled": True, "next_check_at": 0.0})
            state["governance_eligible"] = True
        else:
            state.update({"tier": "candidate", "desired_priority": OBSERVE_PRIORITY, "desired_disabled": True, "next_check_at": timestamp + observe_interval_sec})
        state["confidence"] = 0
        return state

    if status == "no_grok45":
        state["next_check_at"] = timestamp + observe_interval_sec + max(0, jitter_sec)
        if int(state["failure_streak"]) >= max(1, no_model_failure_threshold):
            state.update(
                {
                    "tier": "quarantine",
                    "desired_priority": OBSERVE_PRIORITY,
                    "desired_disabled": True,
                    "next_check_at": 0.0,
                    "governance_eligible": True,
                    "confidence": 0,
                }
            )
        elif previous_tier in ROUTABLE_TIERS:
            state.update(
                {
                    "tier": "reserve",
                    "desired_priority": RESERVE_PRIORITY,
                    "desired_disabled": False,
                    "governance_eligible": True,
                }
            )
        return state

    last_failure_ts = float(state.get("last_failure_ts") or 0)
    independent = not last_failure_ts or timestamp - last_failure_ts >= max(1, independent_failure_interval_sec)
    if independent:
        state["independent_failure_streak"] = int(state.get("independent_failure_streak") or 0) + 1
        state["last_failure_ts"] = timestamp
        state["last_failure_fingerprint"] = fingerprint
    state["confidence"] = max(0, int(state.get("confidence") or 0) - (10 if independent else 2))
    state["next_check_at"] = timestamp + observe_interval_sec + max(0, jitter_sec)
    if int(state.get("independent_failure_streak") or 0) >= max(1, transient_failure_threshold):
        state.update({"tier": "observe", "desired_priority": OBSERVE_PRIORITY, "desired_disabled": False})
        state["governance_eligible"] = True
    elif previous_tier in ROUTABLE_TIERS:
        state.update(
            {
                "tier": "reserve",
                "desired_priority": RESERVE_PRIORITY,
                "desired_disabled": False,
                "governance_eligible": True,
            }
        )
    elif previous:
        state["tier"] = previous_tier
        state["desired_priority"] = int(previous.get("desired_priority") or state["desired_priority"])
        state["desired_disabled"] = bool(previous.get("desired_disabled"))
    return state
