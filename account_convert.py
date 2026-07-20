#!/usr/bin/env python3
"""Multi-platform account format converter.

Supported hubs:
  - sub2api JSON (common interchange)
  - Grok/xAI CPA: xai-*.json / dir / zip
  - OpenAI/Codex: codex-*.json / dir / zip

Auto direction:
  - native (cpa/codex) -> sub2api
  - sub2api -> native packs by platform
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CPA_KEYS = [
    "access_token",
    "auth_kind",
    "base_url",
    "disabled",
    "email",
    "expired",
    "expires_in",
    "id_token",
    "last_refresh",
    "redirect_uri",
    "refresh_token",
    "sub",
    "token_endpoint",
    "token_type",
    "type",
]
CODEX_KEYS = [
    "access_token",
    "account_id",
    "disabled",
    "email",
    "expired",
    "id_token",
    "last_refresh",
    "refresh_token",
    "type",
]

DEFAULT_EXPIRES_IN = 21600
DEFAULT_REDIRECT = "http://127.0.0.1:56121/callback"
DEFAULT_TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token"
DEFAULT_BASE_URL = "https://api.x.ai/v1"
DEFAULT_GROK_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
DEFAULT_GROK_SCOPE = "openid profile email offline_access grok-cli:access api:access"
OPENAI_AUTH_CLAIM = "https://api.openai.com/auth"


class ConvertError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_utc_ms(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_dt(value: str | int | float | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        # seconds vs ms
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return parse_dt(int(text))
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def b64url_json(segment: str) -> dict[str, Any]:
    pad = "=" * ((4 - len(segment) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(segment + pad))
    if not isinstance(data, dict):
        raise ConvertError("JWT payload is not an object")
    return data


def jwt_payload(token: str) -> dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}
    try:
        return b64url_json(token.split(".")[1])
    except Exception:
        return {}


def extract_sub(access_token: str, id_token: str = "") -> str:
    for token in (access_token, id_token):
        payload = jwt_payload(token)
        sub = payload.get("sub") or payload.get("principal_id")
        if sub:
            return str(sub)
    return ""


def sanitize_note(note: str) -> str:
    note = note.strip()
    if not note:
        return "export"
    note = re.sub(r'[\\/:*?"<>|]+', "_", note)
    note = re.sub(r"\s+", "_", note)
    return note[:80] or "export"


def stamp_name(prefix: str, count: int, note: str, ext: str, when: datetime | None = None) -> str:
    ts = (when or utc_now()).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{count}条_{ts}_{sanitize_note(note)}{ext}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: Any, pretty: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if pretty:
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    else:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    path.write_text(text, encoding="utf-8")


def account_email(account: dict[str, Any]) -> str:
    cred = account.get("credentials") or {}
    email = (cred.get("email") or account.get("email") or account.get("name") or "").strip()
    if not email:
        raise ConvertError(f"account missing email: keys={list(account.keys())}")
    return email


def account_platform(account: dict[str, Any]) -> str:
    platform = (account.get("platform") or "").strip().lower()
    if platform in {"grok", "xai"}:
        return "grok"
    if platform in {"openai", "chatgpt", "codex", "gpt"}:
        return "openai"
    # infer from credentials
    cred = account.get("credentials") or {}
    if isinstance(cred, dict):
        if cred.get("chatgpt_account_id") or cred.get("session_token"):
            return "openai"
        base = str(cred.get("base_url") or "")
        if "x.ai" in base:
            return "grok"
    raise ConvertError(f"cannot detect platform for account: {account.get('name') or account.get('email')}")


def normalize_sub2api(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ConvertError("sub2api root must be object")
    accounts = payload.get("accounts")
    if not isinstance(accounts, list):
        raise ConvertError("sub2api.accounts must be list")
    return {
        "type": payload.get("type") or "sub2api-data",
        "version": payload.get("version") or 1,
        "exported_at": payload.get("exported_at") or fmt_utc(utc_now()),
        "proxies": payload.get("proxies") if isinstance(payload.get("proxies"), list) else [],
        "accounts": accounts,
    }


def detect_native_kind(item: dict[str, Any]) -> str:
    if not isinstance(item, dict):
        raise ConvertError("native item must be object")
    t = str(item.get("type") or "").lower()
    if t == "xai" or item.get("auth_kind") == "oauth" and str(item.get("base_url") or "").find("x.ai") >= 0:
        return "cpa"
    if t == "codex":
        return "codex"
    if item.get("chatgpt_account_id") or item.get("session_token") or item.get("chatgpt_plan_type"):
        return "codex"
    if item.get("access_token") and item.get("refresh_token") and item.get("email") and (
        item.get("token_endpoint") or item.get("auth_kind") or item.get("sub")
    ):
        # bare xai-like
        return "cpa"
    if item.get("access_token") and item.get("email") and (item.get("account_id") or item.get("refresh_token")):
        return "codex"
    raise ConvertError(f"unsupported native item keys={sorted(item.keys())}")


def openai_auth_from_token(access_token: str) -> dict[str, Any]:
    payload = jwt_payload(access_token)
    auth = payload.get(OPENAI_AUTH_CLAIM)
    return auth if isinstance(auth, dict) else {}


def cpa_from_sub2_account(account: dict[str, Any]) -> dict[str, Any]:
    if account_platform(account) != "grok":
        raise ConvertError(f"{account_email(account)}: not a grok account, cannot export CPA")
    cred = account.get("credentials") or {}
    if not isinstance(cred, dict):
        raise ConvertError("credentials must be object")
    email = account_email(account)
    access_token = cred.get("access_token") or ""
    refresh_token = cred.get("refresh_token") or ""
    if not access_token or not refresh_token:
        raise ConvertError(f"{email}: missing access_token/refresh_token")
    id_token = cred.get("id_token") or ""
    expires_in = int(cred.get("expires_in") or DEFAULT_EXPIRES_IN)
    expires_at = parse_dt(cred.get("expires_at"))
    if expires_at is None:
        last_refresh = utc_now()
        expires_at = last_refresh + timedelta(seconds=expires_in)
    else:
        expires_at = ensure_aware(expires_at)
        last_refresh = expires_at - timedelta(seconds=expires_in)
    return {
        "access_token": access_token,
        "auth_kind": "oauth",
        "base_url": cred.get("base_url") or DEFAULT_BASE_URL,
        "disabled": False,
        "email": email,
        "expired": fmt_utc(expires_at),
        "expires_in": expires_in,
        "id_token": id_token,
        "last_refresh": fmt_utc(last_refresh),
        "redirect_uri": DEFAULT_REDIRECT,
        "refresh_token": refresh_token,
        "sub": extract_sub(access_token, id_token),
        "token_endpoint": DEFAULT_TOKEN_ENDPOINT,
        "token_type": cred.get("token_type") or "Bearer",
        "type": "xai",
    }


def sub2_account_from_cpa(cpa: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(cpa, dict):
        raise ConvertError("cpa item must be object")
    email = (cpa.get("email") or "").strip()
    access_token = cpa.get("access_token") or ""
    refresh_token = cpa.get("refresh_token") or ""
    if not email or not access_token or not refresh_token:
        raise ConvertError("cpa missing email/access_token/refresh_token")
    expires_at = cpa.get("expired") or cpa.get("expires_at")
    return {
        "name": email,
        "platform": "grok",
        "type": "oauth",
        "credentials": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": cpa.get("id_token") or "",
            "token_type": cpa.get("token_type") or "Bearer",
            "expires_at": expires_at,
            "client_id": cpa.get("client_id") or DEFAULT_GROK_CLIENT_ID,
            "scope": cpa.get("scope") or DEFAULT_GROK_SCOPE,
            "email": email,
            "base_url": cpa.get("base_url") or DEFAULT_BASE_URL,
        },
        "extra": {"email": email},
        "concurrency": 1,
        "priority": 50,
    }


def codex_from_sub2_account(account: dict[str, Any]) -> dict[str, Any]:
    if account_platform(account) != "openai":
        raise ConvertError(f"{account_email(account)}: not an openai account, cannot export codex")
    cred = account.get("credentials") or {}
    if not isinstance(cred, dict):
        raise ConvertError("credentials must be object")
    email = account_email(account)
    access_token = cred.get("access_token") or ""
    if not access_token:
        raise ConvertError(f"{email}: missing access_token")
    refresh_token = cred.get("refresh_token") or ""
    session_token = cred.get("session_token") or ""
    if not refresh_token and not session_token:
        raise ConvertError(f"{email}: missing refresh_token/session_token")
    id_token = cred.get("id_token") or ""
    auth = openai_auth_from_token(access_token)
    account_id = (
        cred.get("chatgpt_account_id")
        or auth.get("chatgpt_account_id")
        or (account.get("extra") or {}).get("account_id")
        or ""
    )
    expires_at = parse_dt(cred.get("expires_at") or account.get("expires_at"))
    last_refresh = parse_dt((account.get("extra") or {}).get("last_refresh") or cred.get("last_refresh"))
    if expires_at is None:
        exp = jwt_payload(access_token).get("exp")
        expires_at = parse_dt(exp) or (utc_now() + timedelta(seconds=DEFAULT_EXPIRES_IN))
    expires_at = ensure_aware(expires_at)
    if last_refresh is None:
        iat = jwt_payload(access_token).get("iat")
        last_refresh = parse_dt(iat) or (expires_at - timedelta(seconds=DEFAULT_EXPIRES_IN))
    last_refresh = ensure_aware(last_refresh)

    # Prefer compact oauth-style codex export when refresh_token exists.
    if refresh_token:
        return {
            "access_token": access_token,
            "account_id": str(account_id),
            "disabled": bool(account.get("disabled") or False),
            "email": email,
            "expired": expires_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "id_token": id_token,
            "last_refresh": last_refresh.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "refresh_token": refresh_token,
            "type": "codex",
        }

    plan = cred.get("plan_type") or auth.get("chatgpt_plan_type") or "unknown"
    return {
        "type": "codex",
        "account_id": str(account_id),
        "chatgpt_account_id": str(account_id),
        "email": email,
        "name": email,
        "plan_type": plan,
        "chatgpt_plan_type": plan,
        "id_token": id_token,
        "access_token": access_token,
        "session_token": session_token,
        "last_refresh": fmt_utc_ms(last_refresh),
        "expired": fmt_utc_ms(expires_at),
        "disabled": bool(account.get("disabled") or False),
    }


def sub2_account_from_codex(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ConvertError("codex item must be object")
    email = (item.get("email") or item.get("name") or "").strip()
    access_token = item.get("access_token") or ""
    refresh_token = item.get("refresh_token") or ""
    session_token = item.get("session_token") or ""
    if not email or not access_token:
        raise ConvertError("codex missing email/access_token")
    if not refresh_token and not session_token:
        raise ConvertError(f"{email}: codex missing refresh_token/session_token")

    auth = openai_auth_from_token(access_token)
    account_id = (
        item.get("account_id")
        or item.get("chatgpt_account_id")
        or auth.get("chatgpt_account_id")
        or ""
    )
    user_id = item.get("chatgpt_user_id") or auth.get("chatgpt_user_id") or ""
    plan = item.get("plan_type") or item.get("chatgpt_plan_type") or auth.get("chatgpt_plan_type") or ""
    expires_at = parse_dt(item.get("expired") or item.get("expires_at"))
    last_refresh = parse_dt(item.get("last_refresh"))
    claims = jwt_payload(access_token)
    if expires_at is None and claims.get("exp") is not None:
        expires_at = parse_dt(claims.get("exp"))
    if last_refresh is None and claims.get("iat") is not None:
        last_refresh = parse_dt(claims.get("iat"))
    expires_in = None
    if claims.get("exp") is not None and claims.get("iat") is not None:
        expires_in = int(claims["exp"]) - int(claims["iat"])
    elif expires_at is not None and last_refresh is not None:
        expires_in = int((ensure_aware(expires_at) - ensure_aware(last_refresh)).total_seconds())

    cred: dict[str, Any] = {
        "access_token": access_token,
        "email": email,
    }
    if refresh_token:
        cred["refresh_token"] = refresh_token
    if session_token:
        cred["session_token"] = session_token
    if item.get("id_token"):
        cred["id_token"] = item.get("id_token")
    if account_id:
        cred["chatgpt_account_id"] = str(account_id)
    if user_id:
        cred["chatgpt_user_id"] = str(user_id)
    if plan:
        cred["plan_type"] = str(plan)
    if expires_at is not None:
        cred["expires_at"] = fmt_utc_ms(ensure_aware(expires_at))
    if expires_in is not None and expires_in > 0:
        cred["expires_in"] = int(expires_in)
    if claims.get("client_id"):
        cred["client_id"] = claims.get("client_id")

    account: dict[str, Any] = {
        "name": email,
        "platform": "openai",
        "type": "oauth" if refresh_token else "session",
        "credentials": cred,
        "extra": {
            "email": email,
            "name": email,
            "source": "codex_oauth" if refresh_token else "codex_session",
            "account_id": str(account_id) if account_id else "",
            "last_refresh": fmt_utc_ms(ensure_aware(last_refresh)) if last_refresh else "",
            "plan_type": str(plan) if plan else "",
            "original_type": item.get("type") or "codex",
        },
        "concurrency": 10,
        "priority": 1,
        "auto_pause_on_expired": True,
    }
    if expires_at is not None:
        account["expires_at"] = int(ensure_aware(expires_at).timestamp())
    return account


def sub2_account_from_native(item: dict[str, Any]) -> dict[str, Any]:
    kind = detect_native_kind(item)
    if kind == "cpa":
        return sub2_account_from_cpa(item)
    if kind == "codex":
        return sub2_account_from_codex(item)
    raise ConvertError(f"unsupported native kind: {kind}")


def load_json_items_from_zip(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    with zipfile.ZipFile(path, "r") as zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".json") and not n.endswith("/")]
        if not names:
            raise ConvertError(f"zip has no json: {path}")
        for name in sorted(names):
            data = json.loads(zf.read(name).decode("utf-8-sig"))
            if not isinstance(data, dict):
                raise ConvertError(f"invalid json in zip: {name}")
            items.append(data)
    return items


def load_native_items(path: Path) -> list[dict[str, Any]]:
    if path.is_file() and path.suffix.lower() == ".zip":
        return load_json_items_from_zip(path)
    if path.is_file() and path.suffix.lower() == ".json":
        data = read_json(path)
        if isinstance(data, list):
            if not data:
                raise ConvertError("empty json list")
            if not all(isinstance(x, dict) for x in data):
                raise ConvertError("json list must contain objects")
            return data
        if isinstance(data, dict) and isinstance(data.get("accounts"), list):
            raise ConvertError("single json looks like sub2api; use --to cpa/codex or auto from sub2")
        if isinstance(data, dict):
            return [data]
        raise ConvertError(f"unsupported json root: {type(data).__name__}")
    if path.is_dir():
        files = sorted(path.glob("xai-*.json"))
        if not files:
            files = sorted(path.glob("codex-*.json"))
        if not files:
            files = sorted(path.glob("*.json"))
        if not files:
            raise ConvertError(f"no json in dir: {path}")
        return [read_json(f) for f in files]
    raise ConvertError(f"path not found or unsupported: {path}")


# Backward-compatible alias used by older tests/callers.
def load_cpa_items(path: Path) -> list[dict[str, Any]]:
    return load_native_items(path)


def dedupe_emails(emails: list[str], label: str) -> None:
    if not emails:
        raise ConvertError(f"no accounts in {label}")
    if len(emails) != len(set(emails)):
        raise ConvertError(f"duplicate emails in {label}")


def write_sub2(accounts: list[dict[str, Any]], output_dir: Path, note: str) -> dict[str, Any]:
    emails = [account_email(a).lower() for a in accounts]
    dedupe_emails(emails, "sub2api")
    payload = {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": fmt_utc(utc_now()),
        "proxies": [],
        "accounts": accounts,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / stamp_name("sub2api", len(accounts), note, ".json")
    write_json(out, payload, pretty=True)
    return {"count": len(accounts), "json": str(out), "note": sanitize_note(note)}


def export_cpa_pack(
    accounts: list[dict[str, Any]],
    output_dir: Path,
    note: str,
    keep_dir: bool = True,
    when: datetime | None = None,
) -> dict[str, Any]:
    if not accounts:
        raise ConvertError("no grok accounts for CPA export")
    when = when or utc_now()
    base = output_dir / stamp_name("CPA", len(accounts), note, "", when)
    cpa_dir = Path(str(base) + "_json")
    zip_path = Path(str(base) + ".zip")
    if cpa_dir.exists():
        for old in cpa_dir.glob("*"):
            if old.is_file():
                old.unlink()
    else:
        cpa_dir.mkdir(parents=True, exist_ok=True)

    emails: list[str] = []
    for account in accounts:
        cpa = cpa_from_sub2_account(account)
        email = cpa["email"]
        emails.append(email.lower())
        write_json(cpa_dir / f"xai-{email}.json", cpa, pretty=False)
    dedupe_emails(emails, "cpa")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(cpa_dir.glob("xai-*.json")):
            zf.write(f, arcname=f.name)

    if not keep_dir:
        for f in cpa_dir.glob("*"):
            f.unlink()
        cpa_dir.rmdir()

    return {
        "platform": "grok",
        "count": len(accounts),
        "zip": str(zip_path),
        "dir": str(cpa_dir) if keep_dir else None,
        "note": sanitize_note(note),
    }


def export_codex_pack(
    accounts: list[dict[str, Any]],
    output_dir: Path,
    note: str,
    keep_dir: bool = True,
    when: datetime | None = None,
) -> dict[str, Any]:
    if not accounts:
        raise ConvertError("no openai accounts for codex export")
    when = when or utc_now()
    base = output_dir / stamp_name("CODEX", len(accounts), note, "", when)
    codex_dir = Path(str(base) + "_json")
    zip_path = Path(str(base) + ".zip")
    if codex_dir.exists():
        for old in codex_dir.glob("*"):
            if old.is_file():
                old.unlink()
    else:
        codex_dir.mkdir(parents=True, exist_ok=True)

    emails: list[str] = []
    for account in accounts:
        item = codex_from_sub2_account(account)
        email = (item.get("email") or "").strip()
        emails.append(email.lower())
        # Keep filename filesystem-safe but still recognizable.
        safe = re.sub(r'[\\/:*?"<>|]+', "_", email)
        write_json(codex_dir / f"codex-{safe}.json", item, pretty=True)
    dedupe_emails(emails, "codex")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(codex_dir.glob("codex-*.json")):
            zf.write(f, arcname=f.name)

    if not keep_dir:
        for f in codex_dir.glob("*"):
            f.unlink()
        codex_dir.rmdir()

    return {
        "platform": "openai",
        "count": len(accounts),
        "zip": str(zip_path),
        "dir": str(codex_dir) if keep_dir else None,
        "note": sanitize_note(note),
    }


def sub2_to_cpa(
    sub2_path: Path,
    output_dir: Path,
    note: str = "cpa",
    keep_dir: bool = True,
) -> dict[str, Any]:
    payload = normalize_sub2api(read_json(sub2_path))
    accounts = [a for a in payload["accounts"] if account_platform(a) == "grok"]
    if not accounts:
        raise ConvertError("no grok accounts in sub2api")
    return export_cpa_pack(accounts, output_dir, note=note, keep_dir=keep_dir)


def cpa_to_sub2(
    cpa_path: Path,
    output_dir: Path,
    note: str = "sub2api",
) -> dict[str, Any]:
    items = load_native_items(cpa_path)
    accounts = [sub2_account_from_native(item) for item in items]
    return write_sub2(accounts, output_dir, note=note)


def codex_to_sub2(
    codex_path: Path,
    output_dir: Path,
    note: str = "sub2api",
) -> dict[str, Any]:
    items = load_native_items(codex_path)
    accounts = [sub2_account_from_codex(item) for item in items]
    return write_sub2(accounts, output_dir, note=note)


def sub2_to_codex(
    sub2_path: Path,
    output_dir: Path,
    note: str = "codex",
    keep_dir: bool = True,
) -> dict[str, Any]:
    payload = normalize_sub2api(read_json(sub2_path))
    accounts = [a for a in payload["accounts"] if account_platform(a) == "openai"]
    if not accounts:
        raise ConvertError("no openai accounts in sub2api")
    return export_codex_pack(accounts, output_dir, note=note, keep_dir=keep_dir)


def sub2_to_native(
    sub2_path: Path,
    output_dir: Path,
    note: str = "export",
    keep_dir: bool = True,
) -> dict[str, Any]:
    payload = normalize_sub2api(read_json(sub2_path))
    accounts = payload["accounts"]
    if not accounts:
        raise ConvertError("no accounts in sub2api")
    by_platform: dict[str, list[dict[str, Any]]] = {}
    for account in accounts:
        by_platform.setdefault(account_platform(account), []).append(account)

    when = utc_now()
    packs: list[dict[str, Any]] = []
    if "grok" in by_platform:
        packs.append(
            export_cpa_pack(by_platform["grok"], output_dir, note=note, keep_dir=keep_dir, when=when)
        )
    if "openai" in by_platform:
        packs.append(
            export_codex_pack(by_platform["openai"], output_dir, note=note, keep_dir=keep_dir, when=when)
        )
    if not packs:
        raise ConvertError(f"unsupported platforms in sub2api: {sorted(by_platform)}")
    return {
        "count": len(accounts),
        "packs": packs,
        "note": sanitize_note(note),
    }


def native_to_sub2(
    path: Path,
    output_dir: Path,
    note: str = "sub2api",
) -> dict[str, Any]:
    items = load_native_items(path)
    accounts = [sub2_account_from_native(item) for item in items]
    return write_sub2(accounts, output_dir, note=note)


def detect_input_kind(path: Path) -> str:
    if path.is_dir():
        if any(path.glob("xai-*.json")):
            return "cpa"
        if any(path.glob("codex-*.json")):
            return "codex"
        # fallback: inspect first json
        files = sorted(path.glob("*.json"))
        if not files:
            raise ConvertError(f"no json in dir: {path}")
        return detect_native_kind(read_json(files[0]))
    if path.suffix.lower() == ".zip":
        items = load_json_items_from_zip(path)
        kinds = {detect_native_kind(x) for x in items}
        if kinds == {"cpa"}:
            return "cpa"
        if kinds == {"codex"}:
            return "codex"
        if kinds <= {"cpa", "codex"}:
            return "native-mixed"
        raise ConvertError(f"unsupported zip contents: {sorted(kinds)}")
    if path.suffix.lower() != ".json":
        raise ConvertError(f"unsupported input: {path}")
    data = read_json(path)
    if isinstance(data, dict) and isinstance(data.get("accounts"), list):
        return "sub2"
    if isinstance(data, list):
        if not data:
            raise ConvertError("empty json list")
        kinds = {detect_native_kind(x) for x in data if isinstance(x, dict)}
        if kinds == {"cpa"}:
            return "cpa"
        if kinds == {"codex"}:
            return "codex"
        if kinds <= {"cpa", "codex"}:
            return "native-mixed"
        raise ConvertError("cannot detect list item format")
    if isinstance(data, dict):
        return detect_native_kind(data)
    raise ConvertError("cannot detect format; pass --to")


def detect_mode(path: Path) -> str:
    """Backward-compatible mode detector used by older tests."""
    kind = detect_input_kind(path)
    if kind == "sub2":
        return "sub2-to-cpa"
    if kind in {"cpa", "codex", "native-mixed"}:
        return "cpa-to-sub2"
    raise ConvertError("cannot detect format; pass --mode")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path, help="sub2api / cpa / codex json|dir|zip")
    p.add_argument("-o", "--output-dir", type=Path, default=None, help="output directory")
    p.add_argument("--note", default="", help="filename note, e.g. 今日outlook")
    p.add_argument(
        "--to",
        choices=["auto", "sub2", "cpa", "codex", "native"],
        default="auto",
        help="target format (auto: native->sub2, sub2->native packs)",
    )
    p.add_argument(
        "--mode",
        choices=["auto", "sub2-to-cpa", "cpa-to-sub2"],
        default="auto",
        help="legacy alias: sub2-to-cpa / cpa-to-sub2",
    )
    p.add_argument(
        "--keep-dir",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="keep unpacked native json dir when exporting zip",
    )
    return p


def resolve_target(src: Path, args: argparse.Namespace) -> str:
    # Legacy --mode wins only when --to stays default auto and mode is explicit.
    if args.mode != "auto" and args.to == "auto":
        if args.mode == "sub2-to-cpa":
            return "cpa"
        if args.mode == "cpa-to-sub2":
            return "sub2"
    if args.to != "auto":
        return args.to
    kind = detect_input_kind(src)
    if kind == "sub2":
        return "native"
    return "sub2"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    src: Path = args.input
    if not src.exists():
        raise SystemExit(f"input not found: {src}")
    out_dir: Path = args.output_dir or (src.parent if src.is_file() else src)
    note = args.note or src.stem
    target = resolve_target(src, args)

    if target == "sub2":
        result = native_to_sub2(src, out_dir, note=note)
    elif target == "cpa":
        result = sub2_to_cpa(src, out_dir, note=note, keep_dir=args.keep_dir)
    elif target == "codex":
        result = sub2_to_codex(src, out_dir, note=note, keep_dir=args.keep_dir)
    elif target == "native":
        result = sub2_to_native(src, out_dir, note=note, keep_dir=args.keep_dir)
    else:
        raise SystemExit(f"unsupported target: {target}")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
