"""File-backed store for accounts, CPA auths, mail credentials, and config."""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from cpa_xai import existing_cpa_emails, parse_accounts_file
from cpa_xai.schema import credential_file_name

import proxy_pool
from . import timeutil


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.json"
ACCOUNTS_PATH = ROOT / "accounts_cli.txt"
DEFAULT_MAIL_PATH = ROOT / "mail_credentials.txt"
DEFAULT_CPA_DIR = ROOT / "cpa_auths"

_COMMENT_KEY_RE = re.compile(r"^(//|#)")
_lock = threading.RLock()
_CACHE_TTL_SEC = 2.0
_accounts_cache: dict[str, Any] = {"sig": None, "at": 0.0, "value": []}
_cpa_index_cache: dict[str, Any] = {"sig": None, "at": 0.0, "value": {}}
_mail_rows_cache: dict[str, Any] = {"sig": None, "at": 0.0, "value": ([], "")}
_overview_cache: dict[str, Any] = {"at": 0.0, "value": None}


def _utc_now() -> str:
    return timeutil.now_iso()


def _is_comment_key(key: Any) -> bool:
    return isinstance(key, str) and bool(_COMMENT_KEY_RE.match(key))


def _clear_store_caches(*names: str) -> None:
    wanted = set(names or ("accounts", "cpa", "mail", "overview"))
    with _lock:
        if "accounts" in wanted:
            _accounts_cache.update({"sig": None, "at": 0.0, "value": []})
        if "cpa" in wanted:
            _cpa_index_cache.update({"sig": None, "at": 0.0, "value": {}})
        if "mail" in wanted:
            _mail_rows_cache.update({"sig": None, "at": 0.0, "value": ([], "")})
        if "overview" in wanted:
            _overview_cache.update({"at": 0.0, "value": None})


def _path_sig(path: Path) -> tuple[str, int, int]:
    try:
        st = path.stat()
        return (str(path), int(st.st_mtime_ns), int(st.st_size))
    except FileNotFoundError:
        return (str(path), 0, 0)


def _cached_copy_list(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(item) for item in items]


def _cpa_dirs_sig(config: dict[str, Any]) -> tuple:
    dirs = [cpa_dir(config)]
    hot = hotload_dir(config)
    if hot and hot not in dirs:
        dirs.append(hot)
    parts = []
    for directory in dirs:
        if not directory.is_dir():
            parts.append((str(directory), 0, 0, 0))
            continue
        count = 0
        max_mtime = 0
        total_size = 0
        try:
            for path in directory.glob("xai-*.json"):
                try:
                    st = path.stat()
                except OSError:
                    continue
                count += 1
                max_mtime = max(max_mtime, int(st.st_mtime_ns))
                total_size += int(st.st_size)
        except Exception:
            pass
        parts.append((str(directory), count, max_mtime, total_size))
    return tuple(parts)


def _mail_cache_sig(cfg: dict[str, Any]) -> tuple:
    try:
        max_aliases = max(1, int(cfg.get("hotmail_max_aliases_per_account", 5) or 5))
    except Exception:
        max_aliases = 5
    return (
        _path_sig(mail_file(cfg)),
        _path_sig(EMAIL_USED_PATH),
        _path_sig(EMAIL_ERROR_PATH),
        max_aliases,
    )


def load_config_raw(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or CONFIG_PATH
    if not cfg_path.is_file():
        example = ROOT / "config.example.json"
        if example.is_file():
            text = example.read_text(encoding="utf-8")
        else:
            return {}
    else:
        text = cfg_path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not re.match(r'^\s*"(?://|#)', line)]
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError as exc:
        raise ValueError(f"config.json 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if not _is_comment_key(k)}


def save_config(data: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or CONFIG_PATH
    cleaned = {k: v for k, v in data.items() if not _is_comment_key(k)}
    with _lock:
        cfg_path.write_text(
            json.dumps(cleaned, ensure_ascii=False, indent=4) + "\n",
            encoding="utf-8",
        )
    _clear_store_caches()
    return cleaned


def resolve_path(value: str | Path | None, default: Path) -> Path:
    raw = str(value or "").strip()
    if not raw:
        return default
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    return path


def accounts_file(config: dict[str, Any] | None = None) -> Path:
    return ACCOUNTS_PATH


def mail_file(config: dict[str, Any] | None = None) -> Path:
    cfg = config if config is not None else load_config_raw()
    return resolve_path(cfg.get("hotmail_accounts_file"), DEFAULT_MAIL_PATH)


def cpa_dir(config: dict[str, Any] | None = None) -> Path:
    cfg = config if config is not None else load_config_raw()
    return resolve_path(cfg.get("cpa_auth_dir"), DEFAULT_CPA_DIR)


def hotload_dir(config: dict[str, Any] | None = None) -> Path | None:
    cfg = config if config is not None else load_config_raw()
    raw = str(cfg.get("cpa_hotload_dir") or "").strip()
    if not raw:
        return Path.home() / ".cli-proxy-api"
    return resolve_path(raw, Path.home() / ".cli-proxy-api")


def _cached_accounts(config: dict[str, Any]) -> list[Any]:
    path = accounts_file(config)
    sig = _path_sig(path)
    now = time.monotonic()
    with _lock:
        if (
            _accounts_cache.get("sig") == sig
            and now - float(_accounts_cache.get("at") or 0) < _CACHE_TTL_SEC
        ):
            return list(_accounts_cache.get("value") or [])
    accounts = parse_accounts_file(path)
    with _lock:
        _accounts_cache.update({"sig": sig, "at": now, "value": list(accounts)})
    return accounts


def _mask_secret(value: str, keep: int = 6) -> str:
    text = str(value or "")
    if len(text) <= keep * 2:
        return "*" * len(text) if text else ""
    return f"{text[:keep]}…{text[-keep:]}"


def list_cpa_index(config: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    cfg = config if config is not None else load_config_raw()
    sig = _cpa_dirs_sig(cfg)
    now = time.monotonic()
    with _lock:
        if (
            _cpa_index_cache.get("sig") == sig
            and now - float(_cpa_index_cache.get("at") or 0) < _CACHE_TTL_SEC
        ):
            return {k: dict(v) for k, v in (_cpa_index_cache.get("value") or {}).items()}
    dirs = [cpa_dir(cfg)]
    hot = hotload_dir(cfg)
    if hot and hot not in dirs:
        dirs.append(hot)

    index: dict[str, dict[str, Any]] = {}
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("xai-*.json")):
            email = ""
            mint_method = ""
            expired = ""
            disabled = False
            priority = 0
            managed = False
            managed_tier = ""
            cool_until = ""
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                email = str(payload.get("email") or "").strip().lower()
                mint_method = str(payload.get("mint_method") or payload.get("type") or "")
                expired = str(payload.get("expired") or payload.get("expires_at") or "")
                disabled = payload.get("disabled") is True
                try:
                    priority = int(payload.get("priority") or 0)
                except (TypeError, ValueError):
                    priority = 0
                pool_meta = payload.get("_cpa_pool")
                if isinstance(pool_meta, dict):
                    managed = bool(pool_meta.get("managed"))
                    managed_tier = str(pool_meta.get("tier") or pool_meta.get("status") or "").strip().lower()
                    cool_until = str(pool_meta.get("cool_until") or "")
            except Exception:
                payload = {}
            if not email:
                email = path.name[len("xai-") : -len(".json")].lower()
            if not email:
                continue
            prev = index.get(email)
            item = {
                "email": email,
                "path": str(path),
                "filename": path.name,
                "mint_method": mint_method,
                "expired": expired,
                "disabled": disabled,
                "priority": priority,
                "pool_managed": managed,
                "pool_tier": managed_tier,
                "cool_until": cool_until,
                "mtime": path.stat().st_mtime,
                "location": "hotload" if hot and path.parent.resolve() == hot.resolve() else "auth_dir",
                "size": path.stat().st_size,
            }
            if prev is None or item["mtime"] >= prev["mtime"]:
                index[email] = item
    with _lock:
        _cpa_index_cache.update(
            {
                "sig": sig,
                "at": now,
                "value": {k: dict(v) for k, v in index.items()},
            }
        )
    return index


def list_accounts(
    *,
    query: str = "",
    status: str = "all",
    page: int = 1,
    page_size: int = 50,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = config if config is not None else load_config_raw()
    accounts = _cached_accounts(cfg)
    cpa_index = list_cpa_index(cfg)
    q = query.strip().lower()
    rows: list[dict[str, Any]] = []
    for acc in accounts:
        email = acc.email.strip()
        email_l = email.lower()
        cpa = cpa_index.get(email_l)
        has_sso = bool(acc.sso)
        has_cpa = cpa is not None
        if has_sso and has_cpa:
            row_status = "ready"
        elif has_sso:
            row_status = "sso_only"
        else:
            row_status = "incomplete"
        if q and q not in email_l and q not in row_status:
            continue
        if status not in ("", "all") and status != row_status:
            continue
        rows.append(
            {
                "email": email,
                "password": acc.password,
                "has_sso": has_sso,
                "sso_preview": _mask_secret(acc.sso, 8) if has_sso else "",
                "status": row_status,
                "cpa": bool(has_cpa),
                "cpa_path": (cpa or {}).get("path", ""),
                "cpa_method": (cpa or {}).get("mint_method", ""),
                "cpa_location": (cpa or {}).get("location", ""),
                "line_no": acc.line_no,
            }
        )

    total = len(rows)
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": rows[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "metrics": {
            "total": len(accounts),
            "with_sso": sum(1 for a in accounts if a.sso),
            "with_cpa": sum(1 for a in accounts if a.email.lower() in cpa_index),
            "sso_only": sum(
                1 for a in accounts if a.sso and a.email.lower() not in cpa_index
            ),
            "incomplete": sum(1 for a in accounts if not a.sso),
        },
    }


def delete_accounts(emails: list[str]) -> int:
    wanted = {e.strip().lower() for e in emails if str(e).strip()}
    if not wanted:
        return 0
    path = accounts_file()
    if not path.is_file():
        return 0
    with _lock:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        kept: list[str] = []
        deleted = 0
        for line in lines:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                kept.append(line)
                continue
            email = raw.split("----", 1)[0].strip().lower()
            if email in wanted:
                deleted += 1
                continue
            kept.append(line)
        path.write_text("".join(kept), encoding="utf-8")
    _clear_store_caches("accounts", "overview")
    return deleted


def export_accounts(emails: list[str] | None = None) -> str:
    accounts = parse_accounts_file(accounts_file())
    wanted = {e.strip().lower() for e in (emails or []) if str(e).strip()}
    lines: list[str] = []
    for acc in accounts:
        if wanted and acc.email.lower() not in wanted:
            continue
        lines.append(acc.raw)
    return "\n".join(lines) + ("\n" if lines else "")


def list_cpa(
    *,
    query: str = "",
    scan_status: str = "all",
    scan_results: dict[str, dict[str, Any]] | None = None,
    page: int = 1,
    page_size: int = 50,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = config if config is not None else load_config_raw()
    items = list(list_cpa_index(cfg).values())
    items.sort(key=lambda x: x.get("mtime") or 0, reverse=True)
    q = query.strip().lower()
    if q:
        items = [
            item
            for item in items
            if q in item["email"]
            or q in str(item.get("mint_method") or "").lower()
            or q in str(item.get("location") or "").lower()
        ]
    scan_results = {str(k).lower(): dict(v) for k, v in (scan_results or {}).items()}
    st = str(scan_status or "all").strip().lower()
    if st and st != "all":
        def _row_scan_status(item: dict[str, Any]) -> str:
            email = str(item.get("email") or "").lower()
            result = scan_results.get(email) or {}
            return str(result.get("status") or "unchecked").strip().lower() or "unchecked"

        def _match_status(item: dict[str, Any]) -> bool:
            row_status = _row_scan_status(item)
            email = str(item.get("email") or "").lower()
            result = scan_results.get(email) or {}
            tier = str(result.get("tier") or "candidate").strip().lower()
            if st == "unchecked":
                return row_status == "unchecked"
            if st == "quota":
                return row_status in {"quota", "account_quota", "cooling"} or tier == "cooling"
            if st == "bad":
                return row_status not in {"ok", "quota", "account_quota", "cooling", "upstream_busy", "unchecked"}
            if st in {"main", "reserve", "candidate", "observe", "cooling", "quarantine", "manual_disabled"}:
                return tier == st
            if st == "upstream_busy":
                return str(result.get("health_status") or row_status) == "upstream_busy"
            return row_status == st

        items = [item for item in items if _match_status(item)]
    total = len(items)
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    end = start + page_size
    page_items = []
    for item in items[start:end]:
        row = dict(item)
        scan = scan_results.get(str(row.get("email") or "").lower()) or {}
        row["scan_status"] = str(scan.get("status") or "unchecked")
        row["scan_reason"] = str(scan.get("reason") or "")
        row["scan_checked_at"] = str(scan.get("checked_at") or "")
        row["scan_action"] = str(scan.get("action") or "")
        row["pool_tier"] = str(scan.get("tier") or "candidate")
        row["health_status"] = str(scan.get("health_status") or row["scan_status"])
        row["confidence"] = int(scan.get("confidence") or 0)
        row["desired_priority"] = scan.get("desired_priority")
        row["actual_priority"] = scan.get("actual_priority")
        row["actual_disabled"] = scan.get("actual_disabled")
        row["expired"] = timeutil.iso_to_beijing_display(row.get("expired")) or row.get("expired", "")
        row["scan_checked_at"] = timeutil.iso_to_beijing_display(row.get("scan_checked_at")) or row.get("scan_checked_at", "")
        row["mtime_iso"] = timeutil.timestamp_display(item["mtime"])
        page_items.append(row)
    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "auth_dir": str(cpa_dir(cfg)),
        "hotload_dir": str(hotload_dir(cfg) or ""),
    }


def delete_cpa(emails: list[str], config: dict[str, Any] | None = None) -> int:
    cfg = config if config is not None else load_config_raw()
    wanted = {e.strip().lower() for e in emails if str(e).strip()}
    if not wanted:
        return 0
    deleted = 0
    dirs = [cpa_dir(cfg)]
    hot = hotload_dir(cfg)
    if hot:
        dirs.append(hot)
    with _lock:
        for directory in dirs:
            if not directory.is_dir():
                continue
            for path in list(directory.glob("xai-*.json")):
                email = ""
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    email = str(payload.get("email") or "").strip().lower()
                except Exception:
                    email = path.name[len("xai-") : -len(".json")].lower()
                if email in wanted or path.stem[len("xai-") :].lower() in wanted:
                    path.unlink(missing_ok=True)
                    deleted += 1
    if deleted:
        _clear_store_caches("cpa", "overview")
    return deleted


def cpa_download_path(email: str, config: dict[str, Any] | None = None) -> Path:
    cfg = config if config is not None else load_config_raw()
    email_l = email.strip().lower()
    index = list_cpa_index(cfg)
    item = index.get(email_l)
    if item:
        return Path(item["path"])
    # fallback by conventional name
    candidate = cpa_dir(cfg) / credential_file_name(email=email)
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"未找到 CPA 文件: {email}")


def parse_mail_credentials(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----")
        if len(parts) < 4:
            raise ValueError(f"第 {line_no} 行格式错误，需要 邮箱----密码----ClientID----Token")
        email, password, client_id, token = [p.strip() for p in parts[:4]]
        if not email or "@" not in email:
            raise ValueError(f"第 {line_no} 行邮箱无效")
        rows.append(
            {
                "email": email,
                "password": password,
                "client_id": client_id,
                "token": token,
                "raw": f"{email}----{password}----{client_id}----{token}",
            }
        )
    return rows


# ── 邮箱消耗账本（emails_used.txt / emails_error.txt，与注册流程同一套）──

EMAIL_USED_PATH = ROOT / "emails_used.txt"
EMAIL_ERROR_PATH = ROOT / "emails_error.txt"


def _load_email_ledgers() -> set[str]:
    emails: set[str] = set()
    for path in (EMAIL_USED_PATH, EMAIL_ERROR_PATH):
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                addr = s.split("----", 1)[0].strip().lower()
                if addr:
                    emails.add(addr)
        except Exception:
            continue
    return emails


def _is_alias_of(email_addr: str, main_email: str) -> bool:
    local, _, domain = email_addr.lower().rpartition("@")
    mlocal, _, mdomain = main_email.lower().rpartition("@")
    if not local or not mlocal or domain != mdomain:
        return False
    return local == mlocal or local.startswith(mlocal + "+")


def _mail_status(consumed: int, max_aliases: int) -> str:
    if consumed <= 0:
        return "available"
    if consumed < max_aliases:
        return "partial"
    return "exhausted"


def _mail_rows_with_status(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """读取凭证文件并附带消耗状态。返回 (rows, path)。"""
    sig = _mail_cache_sig(cfg)
    now = time.monotonic()
    with _lock:
        if (
            _mail_rows_cache.get("sig") == sig
            and now - float(_mail_rows_cache.get("at") or 0) < _CACHE_TTL_SEC
        ):
            rows, cached_path = _mail_rows_cache.get("value") or ([], "")
            return _cached_copy_list(rows), str(cached_path)

    path = mail_file(cfg)
    if not path.is_file():
        return [], str(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        rows = parse_mail_credentials(text)
    except ValueError:
        # 容忍部分损坏文件
        rows = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split("----")
            if len(parts) < 4:
                continue
            rows.append(
                {
                    "email": parts[0].strip(),
                    "password": parts[1].strip(),
                    "client_id": parts[2].strip(),
                    "token": parts[3].strip(),
                    "raw": s,
                }
            )
    try:
        max_aliases = max(1, int(cfg.get("hotmail_max_aliases_per_account", 5) or 5))
    except Exception:
        max_aliases = 5
    ledger = _load_email_ledgers()
    consumed_by_main: dict[str, int] = {}
    for addr in ledger:
        local, _, domain = addr.lower().rpartition("@")
        if not local or not domain:
            continue
        # Hotmail/Outlook aliases are main+suffix@domain.  Exact main address
        # also counts as consumed.
        base_local = local.split("+", 1)[0]
        key = f"{base_local}@{domain}"
        consumed_by_main[key] = consumed_by_main.get(key, 0) + 1

    items = []
    for row in rows:
        consumed = consumed_by_main.get(str(row["email"]).lower(), 0)
        status = _mail_status(consumed, max_aliases)
        items.append(
            {
                "email": row["email"],
                "client_id": row["client_id"],
                "token_preview": _mask_secret(row["token"], 8),
                "has_token": bool(row["token"]),
                "has_password": bool(row["password"]),
                "auth_type": "oauth" if row["client_id"] and row["token"] else "password",
                "consumed": consumed,
                "max_aliases": max_aliases,
                "remaining": max(0, max_aliases - consumed),
                "status": status,
            }
        )
    with _lock:
        _mail_rows_cache.update(
            {
                "sig": sig,
                "at": now,
                "value": (_cached_copy_list(items), str(path)),
            }
        )
    return items, str(path)


def _mail_metrics(items: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(items),
        "available": sum(1 for i in items if i["status"] == "available"),
        "partial": sum(1 for i in items if i["status"] == "partial"),
        "exhausted": sum(1 for i in items if i["status"] == "exhausted"),
    }


def list_mail_credentials(
    *,
    query: str = "",
    status: str = "all",
    page: int = 1,
    page_size: int = 50,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = config if config is not None else load_config_raw()
    items, path = _mail_rows_with_status(cfg)
    metrics = _mail_metrics(items)
    q = query.strip().lower()
    if q:
        items = [i for i in items if q in i["email"].lower()]
    if status not in ("", "all"):
        items = [i for i in items if i["status"] == status]
    total = len(items)
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "metrics": metrics,
        "path": path,
    }


def mail_ids_by_status(query: str = "", status: str = "all", cap: int = 5000) -> dict[str, Any]:
    cfg = load_config_raw()
    items, _ = _mail_rows_with_status(cfg)
    q = query.strip().lower()
    if q:
        items = [i for i in items if q in i["email"].lower()]
    if status not in ("", "all"):
        items = [i for i in items if i["status"] == status]
    return {"emails": [i["email"] for i in items[:cap]], "total": len(items)}


def account_ids_by_filter(query: str = "", status: str = "all", cap: int = 5000) -> dict[str, Any]:
    """跨页收集符合条件的账号邮箱（用于"选择全部某状态"）。"""
    emails: list[str] = []
    page = 1
    total = 0
    while len(emails) < cap:
        data = list_accounts(query=query, status=status, page=page, page_size=200)
        total = data["total"]
        for item in data["items"]:
            emails.append(item["email"])
            if len(emails) >= cap:
                break
        if page >= data["total_pages"]:
            break
        page += 1
    return {"emails": emails, "total": total}


def import_mail_credentials(text: str, *, mode: str = "append", config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config if config is not None else load_config_raw()
    path = mail_file(cfg)
    incoming = parse_mail_credentials(text)
    with _lock:
        existing: list[dict[str, str]] = []
        if mode != "replace" and path.is_file():
            try:
                existing = parse_mail_credentials(path.read_text(encoding="utf-8-sig", errors="replace"))
            except ValueError:
                existing = []
        by_email = {row["email"].lower(): row for row in existing}
        added = updated = 0
        for row in incoming:
            key = row["email"].lower()
            if key in by_email:
                updated += 1
            else:
                added += 1
            by_email[key] = row
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(item["raw"] for item in by_email.values())
        if body:
            body += "\n"
        path.write_text(body, encoding="utf-8")
    _clear_store_caches("mail", "overview")
    return {"added": added, "updated": updated, "total": len(by_email), "path": str(path)}


def delete_mail_credentials(emails: list[str], config: dict[str, Any] | None = None) -> int:
    cfg = config if config is not None else load_config_raw()
    path = mail_file(cfg)
    wanted = {e.strip().lower() for e in emails if str(e).strip()}
    if not wanted or not path.is_file():
        return 0
    with _lock:
        rows = []
        try:
            rows = parse_mail_credentials(path.read_text(encoding="utf-8-sig", errors="replace"))
        except ValueError:
            return 0
        kept = [row for row in rows if row["email"].lower() not in wanted]
        deleted = len(rows) - len(kept)
        body = "\n".join(row["raw"] for row in kept)
        if body:
            body += "\n"
        path.write_text(body, encoding="utf-8")
    _clear_store_caches("mail", "overview")
    return deleted


# ── 代理池（委托 proxy_pool 模块）──


def list_proxies() -> dict[str, Any]:
    return proxy_pool.list_proxies()


def import_proxies(text: str, mode: str = "append") -> dict[str, Any]:
    if mode not in ("append", "replace"):
        mode = "append"
    result = proxy_pool.import_proxies(text, mode=mode)
    _clear_store_caches("overview")
    return result


def delete_proxies(keys: list[str]) -> int:
    deleted = proxy_pool.delete_proxies(keys)
    if deleted:
        _clear_store_caches("overview")
    return deleted


def check_proxies(
    keys: list[str] | None = None,
    *,
    workers: int = 8,
    timeout: float = 12.0,
) -> list[dict[str, Any]]:
    return proxy_pool.check_pool(keys=keys or None, workers=workers, timeout=timeout)


def overview(config: dict[str, Any] | None = None) -> dict[str, Any]:
    if config is None:
        now = time.monotonic()
        with _lock:
            cached = _overview_cache.get("value")
            if cached is not None and now - float(_overview_cache.get("at") or 0) < _CACHE_TTL_SEC:
                payload = dict(cached)
                payload["updated_at"] = _utc_now()
                return payload

    cfg = config if config is not None else load_config_raw()
    accounts = _cached_accounts(cfg)
    cpa_index = list_cpa_index(cfg)
    mail_items, _ = _mail_rows_with_status(cfg)
    cpa_items = cpa_index.values()
    hotload_count = sum(1 for item in cpa_items if item.get("location") == "hotload")
    account_emails_with_cpa = {email.lower() for email in cpa_index}
    accounts_total = len(accounts)
    accounts_with_sso = sum(1 for a in accounts if a.sso)
    accounts_with_cpa = sum(1 for a in accounts if a.email.lower() in account_emails_with_cpa)
    payload = {
        "accounts_total": accounts_total,
        "accounts_with_sso": accounts_with_sso,
        "accounts_with_cpa": accounts_with_cpa,
        "accounts_sso_only": sum(
            1 for a in accounts if a.sso and a.email.lower() not in account_emails_with_cpa
        ),
        "cpa_total": len(cpa_index),
        "cpa_hotload": hotload_count,
        "cpa_auth_dir": len(cpa_index) - hotload_count,
        "mail_total": len(mail_items),
        "proxy_total": proxy_pool.list_proxies()["total"],
        "email_provider": str(cfg.get("email_provider") or ""),
        "proxy": str(cfg.get("proxy") or ""),
        "cpa_proxy": str(cfg.get("cpa_proxy") or ""),
        "register_headless": bool(cfg.get("register_headless", False)),
        "protocol_register": bool(cfg.get("protocol_register", False)),
        "protocol_only": bool(cfg.get("protocol_only", False)),
        "protocol_register_fallback_browser": bool(
            cfg.get("protocol_register_fallback_browser", True)
        ),
        "cpa_export_enabled": bool(cfg.get("cpa_export_enabled", True)),
        "cpa_protocol_flow": str(cfg.get("cpa_protocol_flow") or "pkce"),
        "updated_at": _utc_now(),
    }
    if config is None:
        with _lock:
            _overview_cache.update({"at": time.monotonic(), "value": dict(payload)})
    return payload


PUBLIC_CONFIG_KEYS = [
    "email_provider",
    "defaultDomains",
    "gpt_agent_enabled",
    "sub2api_enabled",
    "sub2api_base",
    "sub2api_api_key",
    "sub2api_group_id",
    "sub2api_format",
    "sub2api_concurrency",
    "sub2api_priority",
    "hotmail_accounts_file",
    "hotmail_protocol",
    "hotmail_graph_folders",
    "hotmail_alias_mode",
    "hotmail_alias_random_length",
    "hotmail_max_aliases_per_account",
    "hotmail_poll_interval",
    "hotmail_recent_seconds",
    "cloudmail_url",
    "cloudmail_admin_email",
    "cloudmail_password",
    "cloudflare_api_base",
    "cloudflare_domain_select",
    "cloudflare_domain_cooldown_sec",
    "cloudflare_domain_otp_strikes",
    "cloudflare_api_key",
    "cloudflare_admin_password",
    "cloudflare_auth_mode",
    "cloudflare_path_domains",
    "cloudflare_path_accounts",
    "cloudflare_path_token",
    "cloudflare_path_messages",
    "duckmail_api_key",
    "yyds_api_key",
    "yyds_jwt",
    "mailnest_api_key",
    "mailnest_project_code",
    "proxy",
    "cpa_proxy",
    "register_headless",
    "user_agent",
    "register_count",
    "register_threads",
    "thread_start_interval",
    "register_max_attempts",
    "protocol_register",
    "protocol_only",
    "protocol_register_fallback_browser",
    "protocol_solver_url",
    "protocol_solver_pass_proxy",
    "protocol_solver_locale",
    "protocol_solver_accept_language",
    "protocol_solver_timezone",
    "protocol_impersonate",
    "protocol_register_max_attempts",
    "protocol_solver_poll_timeout",
    "protocol_solver_poll_interval",
    "turnstile_solver_provider",
    "turnstile_site_key",
    "yescaptcha_key",
    "twocaptcha_enabled",
    "twocaptcha_key",
    "twocaptcha_pass_proxy",
    "twocaptcha_timeout",
    "twocaptcha_poll_interval",
    "twocaptcha_api_base",
    "twocaptcha_action",
    "twocaptcha_data",
    "twocaptcha_pagedata",
    "twocaptcha_user_agent",
    "protocol_email_tempmail_fallback",
    "account_hard_timeout",
    "browser_timezone",
    "mail_timeout",
    "mail_poll_interval",
    "mail_retry_count",
    "enable_nsfw",
    "grok2api_auto_add_local",
    "grok2api_local_token_file",
    "grok2api_auto_add_remote",
    "grok2api_remote_base",
    "grok2api_remote_app_key",
    "grok2api_pool_name",
    "cpa_export_enabled",
    "cpa_auth_dir",
    "cpa_copy_to_hotload",
    "cpa_hotload_dir",
    "cpa_base_url",
    "cpa_headless",
    "cpa_force_standalone",
    "cpa_mint_timeout_sec",
    "cpa_mint_required",
    "cpa_probe_after_write",
    "cpa_probe_required",
    "cpa_probe_chat",
    "cpa_mint_workers",
    "cpa_mint_queue_max",
    "cpa_prefer_protocol",
    "cpa_protocol_flow",
    "cpa_protocol_only",
    "cpa_allow_device_flow_fallback",
    "cpa_protocol_poll_timeout_sec",
    "cpa_pkce_network_retries",
    "cpa_pkce_network_retry_delay_sec",
    "cpa_mint_cookie_inject",
    "cpa_gui_close_mint_browser",
    "cpa_mint_browser_reuse",
    "cpa_mint_browser_recycle_every",
    "cpa_pool_auto_scan",
    "cpa_pool_scan_interval_sec",
    "cpa_pool_scan_workers",
    "cpa_pool_probe_timeout_sec",
    "cpa_pool_probe_chat",
    "cpa_pool_refresh_before_probe",
    "cpa_pool_refresh_skew_sec",
    "cpa_pool_max_items_per_scan",
    "cpa_pool_probe_proxy",
    "cpa_pool_scheduler_tick_sec",
    "cpa_pool_adaptive_batch_size",
    "cpa_pool_healthy_check_interval_sec",
    "cpa_pool_observe_check_interval_sec",
    "cpa_pool_candidate_check_interval_sec",
    "cpa_pool_independent_failure_interval_sec",
    "cpa_pool_recovery_success_threshold",
    "cpa_pool_chat_sample_percent",
    "cpa_pool_models_probe_rate_per_sec",
    "cpa_pool_chat_probe_rate_per_sec",
    "cpa_pool_breaker_window_sec",
    "cpa_pool_breaker_min_samples",
    "cpa_pool_breaker_min_errors",
    "cpa_pool_breaker_error_ratio",
    "cpa_pool_breaker_open_sec",
    "cpa_pool_history_limit",
    "cpa_pool_scan_history_limit",
    "cpa_pool_observation_retention_days",
    "cpa_pool_governance_action_retention_days",
    "cpa_pool_apply_policy",
    "cpa_pool_auto_refill",
    "cpa_pool_refill_target_active",
    "cpa_pool_refill_max_per_scan",
    "cpa_pool_refill_workers",
    "cpa_pool_refill_probe_chat",
    "cpa_pool_refill_controller_interval_sec",
    "cpa_pool_refill_emergency_threshold_percent",
    "cpa_pool_quarantine_dir",
    "cpa_pool_move_with_backup",
    "cpa_pool_hard_bad_threshold",
    "cpa_pool_refresh_failed_threshold",
    "cpa_pool_invalid_threshold",
    "cpa_pool_no_grok45_threshold",
    "cpa_pool_soft_fail_threshold",
    "cpa_pool_quota_threshold",
    "cpa_pool_quota_cooldown_sec",
    "cpa_pool_governance_max_downgrades_per_scan",
    "cpa_pool_governance_max_downgrade_percent",
    "cpa_pool_main_low_water_percent",
    "cpa_pool_reserve_target_percent",
    "cpa_pool_refill_max_inventory",
    "cpa_pool_refill_low_water_hold_sec",
    "cpa_pool_refill_low_water_rounds",
    "cpa_pool_refill_min_baseline_percent",
    "cpa_pool_refill_cooling_grace_sec",
    "cpa_pool_refill_expected_yield_percent",
    "cpa_pool_refill_daily_limit",
    "cpa_pool_cli_management_enabled",
    "cpa_pool_cli_management_url",
    "cpa_pool_cli_management_key",
    "cpa_pool_cli_management_timeout_sec",
    "cpa_pool_cli_management_cache_sec",
    "cpa_pool_file_fallback_enabled",
    "cpa_pool_file_fallback_grace_sec",
    "cpa_pool_hard_bad_action",
    "cpa_pool_refresh_failed_action",
    "cpa_pool_invalid_action",
    "cpa_pool_no_grok45_action",
    "cpa_pool_soft_fail_action",
    "cpa_pool_quota_action",
]

PUBLIC_CONFIG_DEFAULTS = {
    "protocol_solver_pass_proxy": True,
    "protocol_solver_locale": "",
    "protocol_solver_accept_language": "",
    "protocol_solver_timezone": "",
    "twocaptcha_enabled": True,
    "twocaptcha_pass_proxy": True,
    "twocaptcha_timeout": 120,
    "twocaptcha_poll_interval": 5,
    "twocaptcha_api_base": "https://api.2captcha.com",
    "twocaptcha_key": "",
    "protocol_solver_submit_timeout": 10,
    "turnstile_solver_provider": "local",
    "browser_timezone": "",
    "cpa_pool_auto_scan": False,
    "cpa_pool_scan_interval_sec": 300,
    "cpa_pool_scan_workers": 16,
    "cpa_pool_probe_timeout_sec": 30,
    "cpa_pool_probe_chat": False,
    "cpa_pool_refresh_before_probe": True,
    "cpa_pool_refresh_skew_sec": 2700,
    "cpa_pool_max_items_per_scan": 0,
    "cpa_pool_probe_proxy": "direct",
    "cpa_pool_scheduler_tick_sec": 300,
    "cpa_pool_adaptive_batch_size": 200,
    "cpa_pool_healthy_check_interval_sec": 43200,
    "cpa_pool_observe_check_interval_sec": 720,
    "cpa_pool_candidate_check_interval_sec": 1200,
    "cpa_pool_independent_failure_interval_sec": 600,
    "cpa_pool_recovery_success_threshold": 2,
    "cpa_pool_chat_sample_percent": 5,
    "cpa_pool_models_probe_rate_per_sec": 8,
    "cpa_pool_chat_probe_rate_per_sec": 2,
    "cpa_pool_breaker_window_sec": 300,
    "cpa_pool_breaker_min_samples": 30,
    "cpa_pool_breaker_min_errors": 10,
    "cpa_pool_breaker_error_ratio": 0.3,
    "cpa_pool_breaker_open_sec": 180,
    "cpa_pool_history_limit": 8,
    "cpa_pool_scan_history_limit": 100,
    "cpa_pool_observation_retention_days": 7,
    "cpa_pool_governance_action_retention_days": 90,
    "cpa_pool_apply_policy": False,
    "cpa_pool_auto_refill": False,
    "cpa_pool_refill_target_active": 0,
    "cpa_pool_refill_max_per_scan": 200,
    "cpa_pool_refill_workers": -1,
    "cpa_pool_refill_probe_chat": False,
    "cpa_pool_refill_controller_interval_sec": 30,
    "cpa_pool_refill_emergency_threshold_percent": 90,
    "cpa_pool_quarantine_dir": "cpa_quarantine",
    "cpa_pool_move_with_backup": True,
    "cpa_pool_hard_bad_threshold": 1,
    "cpa_pool_refresh_failed_threshold": 2,
    "cpa_pool_invalid_threshold": 1,
    "cpa_pool_no_grok45_threshold": 2,
    "cpa_pool_soft_fail_threshold": 3,
    "cpa_pool_quota_threshold": 1,
    "cpa_pool_quota_cooldown_sec": 86400,
    "cpa_pool_governance_max_downgrades_per_scan": 50,
    "cpa_pool_governance_max_downgrade_percent": 1,
    "cpa_pool_main_low_water_percent": 90,
    "cpa_pool_reserve_target_percent": 10,
    "cpa_pool_refill_max_inventory": 4000,
    "cpa_pool_refill_low_water_hold_sec": 1800,
    "cpa_pool_refill_low_water_rounds": 2,
    "cpa_pool_refill_min_baseline_percent": 100,
    "cpa_pool_refill_cooling_grace_sec": 86400,
    "cpa_pool_refill_expected_yield_percent": 80,
    "cpa_pool_refill_daily_limit": 200,
    "cpa_pool_cli_management_enabled": False,
    "cpa_pool_cli_management_url": "http://127.0.0.1:8317/v0/management",
    "cpa_pool_cli_management_key": "",
    "cpa_pool_cli_management_timeout_sec": 5,
    "cpa_pool_cli_management_cache_sec": 10,
    "cpa_pool_file_fallback_enabled": True,
    "cpa_pool_file_fallback_grace_sec": 60,
    "cpa_pool_hard_bad_action": "quarantine",
    "cpa_pool_refresh_failed_action": "quarantine",
    "cpa_pool_invalid_action": "quarantine",
    "cpa_pool_no_grok45_action": "quarantine",
    "cpa_pool_soft_fail_action": "keep",
    "cpa_pool_quota_action": "keep",
}

SECRET_CONFIG_KEYS = {
    "cloudmail_password",
    "cloudflare_api_key",
    "cloudflare_admin_password",
    "sub2api_api_key",
    "duckmail_api_key",
    "yyds_api_key",
    "yyds_jwt",
    "cpa_pool_cli_management_key",
    "mailnest_api_key",
    "grok2api_remote_app_key",
    "yescaptcha_key",
    "twocaptcha_key",
}


def public_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config if config is not None else load_config_raw()
    effective_cfg = {**PUBLIC_CONFIG_DEFAULTS, **cfg}
    out: dict[str, Any] = {}
    for key in PUBLIC_CONFIG_KEYS:
        if key not in effective_cfg:
            continue
        value = effective_cfg[key]
        if key in SECRET_CONFIG_KEYS and value:
            out[key] = ""
            out[f"{key}__set"] = True
        else:
            out[key] = value
            if key in SECRET_CONFIG_KEYS:
                out[f"{key}__set"] = False
    out["_all"] = {k: v for k, v in effective_cfg.items() if k not in SECRET_CONFIG_KEYS}
    for key in SECRET_CONFIG_KEYS:
        if key in effective_cfg and effective_cfg[key]:
            out["_all"][key] = ""
            out["_all"][f"{key}__set"] = True
    return out


def merge_config_update(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_config_raw()
    incoming = dict(payload or {})
    # allow raw full config via `_raw`
    if isinstance(incoming.get("_raw"), dict):
        incoming = dict(incoming["_raw"])
    for key, value in list(incoming.items()):
        if key.endswith("__set") or key == "_all":
            continue
        if key in SECRET_CONFIG_KEYS and (value is None or str(value) == ""):
            # keep existing secret when blank
            continue
        current[key] = value
    return save_config(current)


__all__ = [
    "ROOT",
    "accounts_file",
    "cpa_dir",
    "cpa_download_path",
    "delete_accounts",
    "delete_cpa",
    "delete_mail_credentials",
    "export_accounts",
    "hotload_dir",
    "import_mail_credentials",
    "list_accounts",
    "list_cpa",
    "list_mail_credentials",
    "load_config_raw",
    "mail_file",
    "merge_config_update",
    "overview",
    "public_config",
    "save_config",
]
