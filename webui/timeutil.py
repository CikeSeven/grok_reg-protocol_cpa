"""WebUI time formatting helpers.

The operational UI is intended for Beijing time (Asia/Shanghai, UTC+08:00).
Token math can still use epoch seconds; these helpers are only for timestamps
shown or persisted by the WebUI/job/pool layers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


BEIJING_TZ = timezone(timedelta(hours=8), "Asia/Shanghai")


def now_iso() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")


def now_clock() -> str:
    return datetime.now(BEIJING_TZ).strftime("%H:%M:%S")


def now_compact() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y%m%d-%H%M%S")


def timestamp_iso(ts: float | int | str | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(float(ts), tz=BEIJING_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    except Exception:
        return ""


def timestamp_display(ts: float | int | str | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(float(ts), tz=BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S 北京时间")
    except Exception:
        return ""


def iso_to_beijing_iso(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        src = text[:-1] + "+00:00" if text.endswith("Z") else text
        dt = datetime.fromisoformat(src)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(BEIJING_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    except Exception:
        return text
