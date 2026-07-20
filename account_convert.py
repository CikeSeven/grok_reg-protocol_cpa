#!/usr/bin/env python3
"""Convert Sub2API account bundles and CLIProxyAPI auth JSON files.

The converter intentionally uses content signatures before filenames. It accepts
single JSON files, JSON arrays, Sub2API API response/import wrappers, directories,
and nested ZIP bundles. Known providers receive a semantic field mapping while
unknown CLIProxyAPI plugin providers are preserved as generic auth records.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, unquote, urlsplit


DEFAULT_EXPIRES_IN = 21600
DEFAULT_REDIRECT = "http://127.0.0.1:56121/callback"
DEFAULT_TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token"
DEFAULT_BASE_URL = "https://api.x.ai/v1"
DEFAULT_GROK_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
DEFAULT_GROK_SCOPE = "openid profile email offline_access grok-cli:access api:access"
OPENAI_AUTH_CLAIM = "https://api.openai.com/auth"
BEIJING_TZ = timezone(timedelta(hours=8))

MAX_JSON_FILES = 5000
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2

PROVIDER_ALIASES = {
    "cpa": "xai",
    "grok": "xai",
    "x-ai": "xai",
    "xai": "xai",
    "chatgpt": "codex",
    "gpt": "codex",
    "openai": "codex",
    "codex": "codex",
    "anthropic": "claude",
    "claude-code": "claude",
    "claude": "claude",
    "google": "gemini",
    "gemini-cli": "gemini",
    "gemini": "gemini",
    "antigravity": "antigravity",
    "moonshot": "kimi",
    "kimi": "kimi",
    "qwen-code": "qwen",
    "qwen": "qwen",
    "iflow": "iflow",
    "vertex-ai": "vertex",
    "vertex": "vertex",
    "kiro": "kiro",
}

PROVIDER_INFO: dict[str, dict[str, Any]] = {
    "xai": {"platform": "grok", "prefix": "xai", "archive": "CPA", "concurrency": 1, "priority": 50},
    "codex": {"platform": "openai", "prefix": "codex", "archive": "CODEX", "concurrency": 10, "priority": 1},
    "claude": {"platform": "anthropic", "prefix": "claude", "archive": "CLAUDE", "concurrency": 5, "priority": 20},
    "gemini": {"platform": "gemini", "prefix": "gemini", "archive": "GEMINI", "concurrency": 5, "priority": 20},
    "antigravity": {"platform": "antigravity", "prefix": "antigravity", "archive": "ANTIGRAVITY", "concurrency": 5, "priority": 20},
    "kimi": {"platform": "kimi", "prefix": "kimi", "archive": "KIMI", "concurrency": 5, "priority": 20},
    "qwen": {"platform": "qwen", "prefix": "qwen", "archive": "QWEN", "concurrency": 5, "priority": 20},
    "iflow": {"platform": "iflow", "prefix": "iflow", "archive": "IFLOW", "concurrency": 5, "priority": 20},
    "vertex": {"platform": "gemini", "prefix": "vertex", "archive": "VERTEX", "concurrency": 5, "priority": 20},
    "kiro": {"platform": "kiro", "prefix": "kiro", "archive": "KIRO", "concurrency": 5, "priority": 20},
}

SUB2_PLATFORM_PROVIDER = {
    "grok": "xai",
    "xai": "xai",
    "openai": "codex",
    "chatgpt": "codex",
    "codex": "codex",
    "anthropic": "claude",
    "claude": "claude",
    "gemini": "gemini",
    "google": "gemini",
    "antigravity": "antigravity",
    "kimi": "kimi",
    "moonshot": "kimi",
    "qwen": "qwen",
    "iflow": "iflow",
    "vertex": "vertex",
    "kiro": "kiro",
}

SUB2_RUNTIME_PROVIDERS = {"codex", "claude", "gemini", "antigravity"}
RESERVED_ACCOUNT_TYPES = {"oauth", "session", "apikey", "api-key", "setup-token", "upstream", "bedrock"}
CONTROL_FIELDS = {
    "disabled",
    "excluded_models",
    "headers",
    "model_aliases",
    "prefix",
    "proxy_url",
}


class ConvertError(ValueError):
    pass


@dataclass
class NativeRecord:
    provider: str
    item: dict[str, Any]
    source: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class LoadedInput:
    kind: str
    payload: dict[str, Any] | None = None
    records: list[NativeRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_count: int = 0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_utc(dt: datetime) -> str:
    return ensure_aware(dt).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_utc_ms(dt: datetime) -> str:
    return ensure_aware(dt).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_dt(value: str | int | float | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1e12:
            timestamp /= 1000.0
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return parse_dt(float(text)) if re.fullmatch(r"-?\d+(?:\.\d+)?", text) else datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def ensure_aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _rfc3339(value: Any, default: datetime | None = None) -> str:
    parsed = parse_dt(value)
    if parsed is None:
        parsed = default
    return fmt_utc(parsed) if parsed is not None else ""


def b64url_json(segment: str) -> dict[str, Any]:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(segment + padding))
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
        subject = payload.get("sub") or payload.get("principal_id")
        if subject:
            return str(subject)
    return ""


def openai_auth_from_token(access_token: str) -> dict[str, Any]:
    auth = jwt_payload(access_token).get(OPENAI_AUTH_CLAIM)
    return auth if isinstance(auth, dict) else {}


def sanitize_note(note: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|]+', "_", str(note or "").strip())
    cleaned = re.sub(r"\s+", "_", cleaned)
    return cleaned[:80] or "export"


def _safe_segment(value: Any, fallback: str = "account") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9@._+-]+", "-", str(value or "").strip())
    return cleaned.strip("-.")[:120] or fallback


def stamp_name(prefix: str, count: int, note: str, ext: str, when: datetime | None = None) -> str:
    stamp = ensure_aware(when or utc_now()).astimezone(BEIJING_TZ).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{count}条_{stamp}_{sanitize_note(note)}{ext}"


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConvertError(f"无法读取 JSON {path.name}: {exc}") from exc


def write_json(path: Path, payload: Any, pretty: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if pretty:
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    else:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    path.write_text(text, encoding="utf-8")


def canonical_provider(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    if not raw:
        return ""
    return PROVIDER_ALIASES.get(raw, raw)


def provider_info(provider: str) -> dict[str, Any]:
    provider = canonical_provider(provider)
    if provider in PROVIDER_INFO:
        return PROVIDER_INFO[provider]
    safe = _safe_segment(provider, "plugin").lower()
    return {"platform": safe, "prefix": safe, "archive": safe.upper(), "concurrency": 5, "priority": 20}


def _first_string(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _nested_dict(item: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = item.get(key)
        if isinstance(value, dict):
            return value
    return {}


def infer_email(item: dict[str, Any]) -> str:
    nested = _nested_dict(item, "credentials", "tokens", "token", "token_data", "claudeAiOauth")
    direct = _first_string(item.get("email"), nested.get("email"), nested.get("email_address"))
    if "@" in direct:
        return direct
    tokens = [
        item.get("id_token"),
        item.get("access_token"),
        nested.get("id_token"),
        nested.get("idToken"),
        nested.get("access_token"),
        nested.get("accessToken"),
    ]
    for raw in tokens:
        if not isinstance(raw, str):
            continue
        claims = jwt_payload(raw)
        email = _first_string(claims.get("email"), claims.get("preferred_username"))
        if "@" in email:
            return email
        profile = claims.get("https://api.openai.com/profile")
        if isinstance(profile, dict):
            email = _first_string(profile.get("email"))
            if "@" in email:
                return email
    return ""


def _record_fingerprint(provider: str, item: dict[str, Any]) -> str:
    raw = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return f"{provider}-{hashlib.sha256(raw).hexdigest()[:10]}"


def _record_identity(provider: str, item: dict[str, Any]) -> str:
    email = infer_email(item)
    if email:
        return email
    for key in ("name", "account_id", "chatgpt_account_id", "project_id", "sub", "profile_arn", "device_id"):
        value = item.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return _record_fingerprint(provider, item)


def _provider_from_source(source: str) -> str:
    name = Path(source.split("!")[-1]).name.lower()
    for alias in sorted(PROVIDER_ALIASES, key=len, reverse=True):
        if name.startswith(alias + "-") or name.startswith(alias + "_"):
            return canonical_provider(alias)
    if name in {"auth.json", "codex-auth.json"}:
        return "codex"
    if "claude" in name and name.endswith(".json"):
        return "claude"
    if name in {"oauth_creds.json", "google_accounts.json"} or name.startswith("gemini"):
        return "gemini"
    return ""


def detect_native_provider(item: dict[str, Any], source: str = "") -> str:
    if not isinstance(item, dict):
        raise ConvertError("CLIProxyAPI 账号必须是 JSON 对象")

    raw_type = str(item.get("type") or "").strip().lower().replace("_", "-")
    if raw_type == "service-account":
        return "vertex"
    if raw_type and raw_type not in RESERVED_ACCOUNT_TYPES and not raw_type.startswith("sub2api-"):
        return canonical_provider(raw_type)

    if isinstance(item.get("claudeAiOauth"), dict):
        return "claude"
    if isinstance(item.get("tokens"), dict):
        return "codex"
    if isinstance(item.get("service_account"), dict) or {"private_key", "client_email", "project_id"} <= set(item):
        return "vertex"

    source_provider = _provider_from_source(source)
    if source_provider:
        return source_provider

    base_url = str(item.get("base_url") or item.get("resource_url") or "").lower()
    token_endpoint = str(item.get("token_endpoint") or "").lower()
    scope = str(item.get("scope") or "").lower()
    if "x.ai" in base_url or "auth.x.ai" in token_endpoint or "grok-cli:access" in scope:
        return "xai"
    if item.get("profile_arn") or item.get("auth_method") or item.get("start_url"):
        return "kiro"
    if item.get("device_id"):
        return "kimi"
    if item.get("resource_url"):
        return "qwen"
    if item.get("cookie") and item.get("api_key"):
        return "iflow"
    if item.get("project_id") and item.get("timestamp"):
        return "antigravity"
    if item.get("project_id") and isinstance(item.get("token"), dict):
        return "gemini"
    if item.get("expiry_date") or "generative-language" in scope or "cloud-platform" in scope:
        return "gemini"
    if "user:inference" in scope or "anthropic" in base_url:
        return "claude"
    if item.get("account_id") or item.get("chatgpt_account_id") or item.get("session_token"):
        return "codex"

    access_token = str(item.get("access_token") or "")
    if openai_auth_from_token(access_token):
        return "codex"
    keys = ", ".join(sorted(item.keys()))
    raise ConvertError(f"无法识别 CLIProxyAPI provider，字段: {keys}")


def _camel_oauth_to_flat(raw: dict[str, Any]) -> dict[str, Any]:
    mapped = copy.deepcopy(raw)
    aliases = {
        "accessToken": "access_token",
        "refreshToken": "refresh_token",
        "idToken": "id_token",
        "expiresAt": "expired",
        "expiryDate": "expiry_date",
        "accountId": "account_id",
        "subscriptionType": "plan_type",
    }
    for old, new in aliases.items():
        if old in mapped and new not in mapped:
            mapped[new] = mapped[old]
    return mapped


def normalize_native_item(item: dict[str, Any], source: str = "") -> NativeRecord:
    provider = detect_native_provider(item, source)
    original_type = str(item.get("type") or "").strip().lower().replace("_", "-")
    normalized = copy.deepcopy(item)
    warnings: list[str] = []

    if provider == "vertex" and original_type == "service-account":
        service_account = copy.deepcopy(item)
        normalized = {
            "type": "vertex",
            "service_account": service_account,
            "project_id": item.get("project_id") or "",
            "email": item.get("client_email") or "",
        }
    elif provider == "codex" and isinstance(item.get("tokens"), dict):
        normalized = _camel_oauth_to_flat(item["tokens"])
        for key in CONTROL_FIELDS | {"email", "name"}:
            if key in item and key not in normalized:
                normalized[key] = copy.deepcopy(item[key])
        if item.get("OPENAI_API_KEY") and not normalized.get("api_key"):
            normalized["api_key"] = item["OPENAI_API_KEY"]
        warnings.append("已识别 Codex CLI auth.json 并展开 tokens")
    elif provider == "claude" and isinstance(item.get("claudeAiOauth"), dict):
        normalized = _camel_oauth_to_flat(item["claudeAiOauth"])
        for key in CONTROL_FIELDS | {"email", "name"}:
            if key in item and key not in normalized:
                normalized[key] = copy.deepcopy(item[key])
        warnings.append("已识别 Claude Code 凭证并展开 claudeAiOauth")
    elif provider in {"codex", "claude"} and isinstance(item.get("token_data"), dict):
        token_data = _camel_oauth_to_flat(item["token_data"])
        normalized.update({key: value for key, value in token_data.items() if key not in normalized})

    normalized = _camel_oauth_to_flat(normalized)
    normalized["type"] = provider
    email = infer_email(normalized)
    if email and not normalized.get("email"):
        normalized["email"] = email

    expiry = normalized.get("expired") or normalized.get("expires_at") or normalized.get("expiry") or normalized.get("expiry_date")
    if expiry:
        normalized["expired"] = _rfc3339(expiry) or str(expiry)
    if provider == "xai":
        normalized.setdefault("auth_kind", "oauth")

    if provider in {"xai", "codex", "claude", "gemini", "antigravity", "kimi", "qwen", "iflow", "kiro"}:
        nested = _nested_dict(normalized, "token")
        access = _first_string(normalized.get("access_token"), nested.get("access_token"))
        refresh = _first_string(normalized.get("refresh_token"), nested.get("refresh_token"))
        if not access and not normalized.get("api_key"):
            warnings.append("未找到 access_token/api_key，输出后可能无法直接使用")
        if access and not refresh and provider not in {"iflow", "kiro"}:
            warnings.append("未找到 refresh_token，账号无法自动续期")

    return NativeRecord(provider=provider, item=normalized, source=source, warnings=warnings)


def detect_native_kind(item: dict[str, Any]) -> str:
    provider = detect_native_provider(item)
    return "cpa" if provider == "xai" else provider


def _looks_sub2_account(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("credentials"), dict) and bool(str(value.get("platform") or "").strip())


def _unwrap_sub2_payload(payload: Any) -> Any:
    current = payload
    for _ in range(3):
        if isinstance(current, dict) and not isinstance(current.get("accounts"), list):
            child = current.get("data")
            if isinstance(child, (dict, list)):
                current = child
                continue
        break
    return current


def normalize_sub2api(payload: Any) -> dict[str, Any]:
    payload = _unwrap_sub2_payload(payload)
    if isinstance(payload, list) and all(_looks_sub2_account(value) for value in payload):
        payload = {"accounts": payload, "proxies": []}
    if not isinstance(payload, dict):
        raise ConvertError("Sub2API 根节点必须是对象")
    accounts = payload.get("accounts")
    if not isinstance(accounts, list):
        raise ConvertError("Sub2API accounts 必须是数组")
    normalized_accounts: list[dict[str, Any]] = []
    for index, raw in enumerate(accounts, 1):
        if not isinstance(raw, dict):
            raise ConvertError(f"Sub2API 第 {index} 个账号不是对象")
        account = copy.deepcopy(raw)
        credentials = account.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise ConvertError(f"Sub2API 第 {index} 个账号缺少 credentials")
        platform = str(account.get("platform") or "").strip().lower()
        if not platform:
            raise ConvertError(f"Sub2API 第 {index} 个账号缺少 platform")
        account["platform"] = platform
        account.setdefault("name", infer_email(credentials) or _record_fingerprint(platform, credentials))
        if not str(account.get("type") or "").strip():
            account["type"] = "apikey" if credentials.get("api_key") and not credentials.get("access_token") else "oauth"
        account.setdefault("concurrency", 5)
        account.setdefault("priority", 20)
        normalized_accounts.append(account)
    proxies = payload.get("proxies")
    return {
        "type": payload.get("type") or "sub2api-data",
        "version": payload.get("version") or 1,
        "exported_at": payload.get("exported_at") or fmt_utc(utc_now()),
        "proxies": copy.deepcopy(proxies) if isinstance(proxies, list) else [],
        "accounts": normalized_accounts,
    }


def _proxy_key(proxy: dict[str, Any]) -> str:
    existing = str(proxy.get("proxy_key") or "").strip()
    if existing:
        return existing
    return "|".join(
        [
            str(proxy.get("protocol") or "").strip(),
            str(proxy.get("host") or "").strip(),
            str(proxy.get("port") or "").strip(),
            str(proxy.get("username") or "").strip(),
            str(proxy.get("password") or "").strip(),
        ]
    )


def _proxy_to_url(proxy: dict[str, Any]) -> str:
    protocol = str(proxy.get("protocol") or "").strip().lower()
    host = str(proxy.get("host") or "").strip()
    try:
        port = int(proxy.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if protocol not in {"http", "https", "socks5", "socks5h"} or not host or not 1 <= port <= 65535:
        return ""
    username = str(proxy.get("username") or "")
    password = str(proxy.get("password") or "")
    auth = ""
    if username or password:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{protocol}://{auth}{host_part}:{port}"


def _proxy_from_url(value: Any) -> dict[str, Any] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        protocol = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port or 0
    except ValueError:
        return None
    if protocol not in {"http", "https", "socks5", "socks5h"} or not host or not 1 <= port <= 65535:
        return None
    proxy = {
        "name": f"imported-{protocol}-{host}-{port}",
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "status": "active",
    }
    proxy["proxy_key"] = _proxy_key(proxy)
    return proxy


def _accounts_with_proxy_urls(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    proxies = {_proxy_key(proxy): proxy for proxy in payload.get("proxies", []) if isinstance(proxy, dict)}
    accounts: list[dict[str, Any]] = []
    warnings: list[str] = []
    for raw in payload["accounts"]:
        account = copy.deepcopy(raw)
        key = str(account.get("proxy_key") or "").strip()
        if key:
            proxy = proxies.get(key)
            proxy_url = _proxy_to_url(proxy) if proxy else ""
            if proxy_url:
                extra = account.setdefault("extra", {})
                if not isinstance(extra, dict):
                    extra = {}
                    account["extra"] = extra
                cliproxy = extra.setdefault("_cliproxy", {})
                if not isinstance(cliproxy, dict):
                    cliproxy = {}
                    extra["_cliproxy"] = cliproxy
                metadata = cliproxy.setdefault("metadata", {})
                if not isinstance(metadata, dict):
                    metadata = {}
                    cliproxy["metadata"] = metadata
                metadata["proxy_url"] = proxy_url
            else:
                warnings.append(f"账号 {account.get('name') or '-'} 的 proxy_key 无对应有效代理")
        accounts.append(account)
    return accounts, warnings


def account_provider(account: dict[str, Any]) -> str:
    extra = account.get("extra") if isinstance(account.get("extra"), dict) else {}
    cliproxy = extra.get("_cliproxy") if isinstance(extra.get("_cliproxy"), dict) else {}
    explicit = canonical_provider(cliproxy.get("provider"))
    if explicit:
        return explicit
    platform = str(account.get("platform") or "").strip().lower()
    credentials = account.get("credentials") if isinstance(account.get("credentials"), dict) else {}
    if platform == "gemini" and isinstance(credentials.get("service_account"), dict):
        return "vertex"
    provider = SUB2_PLATFORM_PROVIDER.get(platform)
    if provider:
        return provider
    if platform:
        return canonical_provider(platform)
    try:
        return detect_native_provider(credentials)
    except ConvertError as exc:
        raise ConvertError(f"账号 {account.get('name') or '-'} 无法识别平台: {exc}") from exc


def account_platform(account: dict[str, Any]) -> str:
    return provider_info(account_provider(account))["platform"]


def account_email(account: dict[str, Any]) -> str:
    credentials = account.get("credentials") if isinstance(account.get("credentials"), dict) else {}
    email = infer_email({"credentials": credentials, "email": account.get("email"), "name": account.get("name")})
    if not email:
        raise ConvertError(f"账号缺少 email: {account.get('name') or '-'}")
    return email


def _decode_json_bytes(raw: bytes, source: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise ConvertError(f"JSON 文件过大: {source}")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConvertError(f"JSON 解析失败 {source}: {exc}") from exc


def _iter_zip_json(raw: bytes, label: str, depth: int, budget: dict[str, int]) -> Iterator[tuple[str, Any]]:
    if depth > MAX_ARCHIVE_DEPTH:
        raise ConvertError(f"ZIP 嵌套超过 {MAX_ARCHIVE_DEPTH} 层: {label}")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except zipfile.BadZipFile as exc:
        raise ConvertError(f"ZIP 文件损坏: {label}") from exc
    with archive:
        for info in sorted(archive.infolist(), key=lambda value: value.filename):
            if info.is_dir() or info.filename.startswith("__MACOSX/"):
                continue
            lower = info.filename.lower()
            if not (lower.endswith(".json") or lower.endswith(".zip")):
                continue
            budget["files"] += 1
            budget["bytes"] += max(0, info.file_size)
            if budget["files"] > MAX_JSON_FILES:
                raise ConvertError(f"压缩包文件数超过 {MAX_JSON_FILES}")
            if budget["bytes"] > MAX_ARCHIVE_BYTES:
                raise ConvertError("压缩包解压后总大小超过 512MB")
            child_label = f"{label}!{info.filename}"
            try:
                child = archive.read(info)
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                raise ConvertError(f"无法读取 ZIP 条目: {child_label}") from exc
            if lower.endswith(".zip"):
                yield from _iter_zip_json(child, child_label, depth + 1, budget)
            else:
                yield child_label, _decode_json_bytes(child, child_label)


def _iter_json_documents(path: Path) -> Iterator[tuple[str, Any]]:
    if not path.exists():
        raise ConvertError(f"输入不存在: {path}")
    if path.is_dir():
        files = sorted(value for value in path.rglob("*.json") if value.is_file())
        if not files:
            raise ConvertError(f"目录中没有 JSON: {path}")
        if len(files) > MAX_JSON_FILES:
            raise ConvertError(f"目录 JSON 数量超过 {MAX_JSON_FILES}")
        total_size = sum(file_path.stat().st_size for file_path in files)
        if total_size > MAX_ARCHIVE_BYTES:
            raise ConvertError("目录 JSON 总大小超过 512MB")
        for file_path in files:
            if file_path.stat().st_size > MAX_JSON_BYTES:
                raise ConvertError(f"JSON 文件过大: {file_path.name}")
            yield str(file_path.relative_to(path)), read_json(file_path)
        return
    suffix = path.suffix.lower()
    if suffix == ".json":
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ConvertError(f"JSON 文件过大: {path.name}")
        yield path.name, read_json(path)
        return
    if suffix == ".zip":
        raw = path.read_bytes()
        yield from _iter_zip_json(raw, path.name, 0, {"files": 0, "bytes": 0})
        return
    raise ConvertError("仅支持 .json、.zip 或 JSON 目录")


def _document_is_sub2(data: Any) -> bool:
    candidate = _unwrap_sub2_payload(data)
    if isinstance(candidate, list):
        return bool(candidate) and all(_looks_sub2_account(value) for value in candidate)
    if not isinstance(candidate, dict) or not isinstance(candidate.get("accounts"), list):
        return False
    accounts = candidate["accounts"]
    return not accounts or all(_looks_sub2_account(value) for value in accounts)


def _native_objects(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        for key in ("auths", "credentials_files", "items"):
            values = data.get(key)
            if isinstance(values, list) and values and all(isinstance(value, dict) for value in values):
                return values
        return [data]
    if isinstance(data, list) and data and all(isinstance(value, dict) for value in data):
        return data
    raise ConvertError("不是账号对象或账号数组")


def load_input(path: Path) -> LoadedInput:
    sub2_payloads: list[dict[str, Any]] = []
    records: list[NativeRecord] = []
    warnings: list[str] = []
    source_count = 0
    direct_file = path.is_file() and path.suffix.lower() == ".json"

    for source, data in _iter_json_documents(path):
        source_count += 1
        if _document_is_sub2(data):
            sub2_payloads.append(normalize_sub2api(data))
            continue
        accepted = 0
        try:
            objects = _native_objects(data)
        except ConvertError as exc:
            if direct_file:
                raise
            warnings.append(f"已跳过 {source}: {exc}")
            continue
        for index, item in enumerate(objects, 1):
            item_source = source if len(objects) == 1 else f"{source}#{index}"
            try:
                records.append(normalize_native_item(item, item_source))
                accepted += 1
            except ConvertError as exc:
                if direct_file:
                    raise
                warnings.append(f"已跳过 {item_source}: {exc}")
        if not accepted and direct_file:
            raise ConvertError("未识别到可转换账号")

    if sub2_payloads and records:
        raise ConvertError("输入同时包含 Sub2API 账号包和 CLIProxyAPI auth 文件，请分开转换")
    if sub2_payloads:
        accounts: list[dict[str, Any]] = []
        proxies: list[dict[str, Any]] = []
        proxy_seen: set[str] = set()
        for payload in sub2_payloads:
            accounts.extend(payload["accounts"])
            for proxy in payload["proxies"]:
                key = json.dumps(proxy, sort_keys=True, ensure_ascii=False)
                if key not in proxy_seen:
                    proxy_seen.add(key)
                    proxies.append(proxy)
        if not accounts:
            raise ConvertError("Sub2API 账号包为空")
        payload = {
            "type": "sub2api-data",
            "version": 1,
            "exported_at": fmt_utc(utc_now()),
            "proxies": proxies,
            "accounts": accounts,
        }
        return LoadedInput(kind="sub2", payload=payload, warnings=warnings, source_count=source_count)
    if records:
        return LoadedInput(kind="native", records=records, warnings=warnings, source_count=source_count)
    raise ConvertError("未识别到可转换的账号 JSON")


def load_native_items(path: Path) -> list[dict[str, Any]]:
    loaded = load_input(path)
    if loaded.kind != "native":
        raise ConvertError("输入是 Sub2API 账号包，不是 CLIProxyAPI auth 文件")
    return [record.item for record in loaded.records]


def load_json_items_from_zip(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() != ".zip":
        raise ConvertError("输入不是 ZIP")
    return load_native_items(path)


def load_cpa_items(path: Path) -> list[dict[str, Any]]:
    return load_native_items(path)


def inspect_input(path: Path) -> dict[str, Any]:
    loaded = load_input(path)
    warnings = list(loaded.warnings)
    type_counts: Counter[str] = Counter()
    if loaded.kind == "sub2":
        assert loaded.payload is not None
        providers = Counter(account_provider(account) for account in loaded.payload["accounts"])
        type_counts.update(str(account.get("type") or "unknown") for account in loaded.payload["accounts"])
        account_count = len(loaded.payload["accounts"])
        for provider, count in providers.items():
            if provider not in SUB2_RUNTIME_PROVIDERS:
                warnings.append(f"{provider} 共 {count} 个：Sub2API 当前无原生运行支持，但可转换/往返保存")
        input_format = "Sub2API 账号包"
        direction = "将按账号平台拆分为 CLIProxyAPI auth 包"
        available_targets = ["auto", "native", *providers.keys()]
    else:
        providers = Counter(record.provider for record in loaded.records)
        type_counts.update("oauth" if record.item.get("access_token") or record.item.get("token") else "apikey" for record in loaded.records)
        account_count = len(loaded.records)
        for record in loaded.records:
            warnings.extend(record.warnings)
        for provider, count in providers.items():
            if provider not in SUB2_RUNTIME_PROVIDERS:
                warnings.append(f"{provider} 共 {count} 个：转换到 Sub2API 后主要用于归档/往返")
        input_format = "CLIProxyAPI auth 包" if len(providers) > 1 else f"CLIProxyAPI {next(iter(providers))} auth"
        direction = "将合并为 Sub2API 账号包"
        available_targets = ["auto", "sub2"]

    unique_warnings = list(dict.fromkeys(warnings))
    return {
        "kind": loaded.kind,
        "input_format": input_format,
        "direction": direction,
        "account_count": account_count,
        "source_count": loaded.source_count,
        "providers": dict(sorted(providers.items())),
        "account_types": dict(sorted(type_counts.items())),
        "warnings": unique_warnings[:30],
        "warning_count": len(unique_warnings),
        "available_targets": list(dict.fromkeys(available_targets)),
    }


def _native_credentials(record: NativeRecord) -> dict[str, Any]:
    credentials = copy.deepcopy(record.item)
    credentials.pop("type", None)
    for key in CONTROL_FIELDS:
        credentials.pop(key, None)
    token = credentials.get("token")
    if isinstance(token, dict):
        for key in ("access_token", "refresh_token", "id_token", "token_type", "scope", "expires_in"):
            if token.get(key) not in (None, "") and credentials.get(key) in (None, ""):
                credentials[key] = copy.deepcopy(token[key])
        expiry = token.get("expiry") or token.get("expires_at") or token.get("expiry_date")
        if expiry and not credentials.get("expires_at"):
            credentials["expires_at"] = expiry
    if credentials.get("expired") and not credentials.get("expires_at"):
        credentials["expires_at"] = credentials["expired"]
    return credentials


def sub2_account_from_native(item: dict[str, Any], source: str = "") -> dict[str, Any]:
    record = normalize_native_item(item, source)
    provider = record.provider
    credentials = _native_credentials(record)
    identity = _record_identity(provider, record.item)
    metadata = {key: copy.deepcopy(record.item[key]) for key in CONTROL_FIELDS if key in record.item}
    extra: dict[str, Any] = {"_cliproxy": {"provider": provider}}
    if metadata:
        extra["_cliproxy"]["metadata"] = metadata
    if record.warnings:
        extra["_cliproxy"]["warnings"] = record.warnings

    preserved_type = str(credentials.pop("sub2api_account_type", "") or "").strip().lower()
    has_access = bool(credentials.get("access_token") or isinstance(credentials.get("token"), dict))
    account_type = preserved_type or ("oauth" if has_access else "apikey" if credentials.get("api_key") else "upstream")
    info = provider_info(provider)
    account: dict[str, Any] = {
        "name": identity,
        "platform": info["platform"],
        "type": account_type,
        "credentials": credentials,
        "extra": extra,
        "concurrency": info["concurrency"],
        "priority": info["priority"],
        "auto_pause_on_expired": True,
    }
    expires = parse_dt(credentials.get("expires_at") or credentials.get("expired"))
    if expires is not None:
        account["expires_at"] = int(ensure_aware(expires).timestamp())
    return account


def sub2_account_from_cpa(cpa: dict[str, Any]) -> dict[str, Any]:
    account = sub2_account_from_native(cpa)
    if account_provider(account) != "xai":
        raise ConvertError("输入不是 xAI/CPA 账号")
    return account


def sub2_account_from_codex(item: dict[str, Any]) -> dict[str, Any]:
    account = sub2_account_from_native(item)
    if account_provider(account) != "codex":
        raise ConvertError("输入不是 Codex 账号")
    return account


def write_sub2(
    accounts: list[dict[str, Any]],
    output_dir: Path,
    note: str,
    proxies: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    if not accounts:
        raise ConvertError("没有可写出的账号")
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": fmt_utc(utc_now()),
        "proxies": copy.deepcopy(proxies or []),
        "accounts": accounts,
    }
    out = output_dir / stamp_name("sub2api", len(accounts), note, ".json")
    write_json(out, payload, pretty=True)
    providers = Counter(account_provider(account) for account in accounts)
    return {
        "count": len(accounts),
        "json": str(out),
        "note": sanitize_note(note),
        "providers": dict(sorted(providers.items())),
        "warnings": list(dict.fromkeys(warnings or [])),
    }


def native_to_sub2(path: Path, output_dir: Path, note: str = "sub2api") -> dict[str, Any]:
    loaded = load_input(path)
    if loaded.kind != "native":
        raise ConvertError("输入已是 Sub2API 账号包")
    accounts = [sub2_account_from_native(record.item, record.source) for record in loaded.records]
    warnings = loaded.warnings + [warning for record in loaded.records for warning in record.warnings]
    proxies: list[dict[str, Any]] = []
    proxy_keys: set[str] = set()
    for account, record in zip(accounts, loaded.records, strict=True):
        proxy_url = record.item.get("proxy_url")
        proxy = _proxy_from_url(proxy_url)
        if proxy is None:
            if proxy_url:
                warnings.append(f"{record.source} 的 proxy_url 无效，已保留在 extra 中")
            continue
        key = proxy["proxy_key"]
        account["proxy_key"] = key
        if key not in proxy_keys:
            proxy_keys.add(key)
            proxies.append(proxy)
    return write_sub2(accounts, output_dir, note=note, proxies=proxies, warnings=warnings)


def cpa_to_sub2(cpa_path: Path, output_dir: Path, note: str = "sub2api") -> dict[str, Any]:
    return native_to_sub2(cpa_path, output_dir, note)


def codex_to_sub2(codex_path: Path, output_dir: Path, note: str = "sub2api") -> dict[str, Any]:
    return native_to_sub2(codex_path, output_dir, note)


def _account_metadata(account: dict[str, Any]) -> dict[str, Any]:
    extra = account.get("extra") if isinstance(account.get("extra"), dict) else {}
    cliproxy = extra.get("_cliproxy") if isinstance(extra.get("_cliproxy"), dict) else {}
    metadata = cliproxy.get("metadata") if isinstance(cliproxy.get("metadata"), dict) else {}
    return copy.deepcopy(metadata)


def _account_expired(account: dict[str, Any], credentials: dict[str, Any], expires_in: int = DEFAULT_EXPIRES_IN) -> str:
    value = credentials.get("expired") or credentials.get("expires_at") or account.get("expires_at")
    parsed = parse_dt(value)
    if parsed is None:
        access_claims = jwt_payload(str(credentials.get("access_token") or ""))
        parsed = parse_dt(access_claims.get("exp"))
    if parsed is None:
        parsed = utc_now() + timedelta(seconds=expires_in)
    return fmt_utc(parsed)


def _base_native(account: dict[str, Any], provider: str) -> tuple[dict[str, Any], dict[str, Any]]:
    credentials = copy.deepcopy(account.get("credentials") or {})
    if not isinstance(credentials, dict) or not credentials:
        raise ConvertError(f"{account.get('name') or provider}: credentials 为空")
    item = credentials.copy()
    item.update(_account_metadata(account))
    item["type"] = provider
    if account.get("disabled") is not None:
        item["disabled"] = bool(account.get("disabled"))
    email = infer_email({"credentials": credentials, "name": account.get("name")})
    if email:
        item["email"] = email
    return item, credentials


def native_from_sub2_account(account: dict[str, Any], provider: str | None = None) -> dict[str, Any]:
    provider = canonical_provider(provider or account_provider(account))
    actual = account_provider(account)
    if provider != actual:
        raise ConvertError(f"{account.get('name') or '-'} 属于 {actual}，不能转为 {provider}")
    item, credentials = _base_native(account, provider)
    access = _first_string(credentials.get("access_token"), _nested_dict(credentials, "token").get("access_token"))
    refresh = _first_string(credentials.get("refresh_token"), _nested_dict(credentials, "token").get("refresh_token"))
    account_type = str(account.get("type") or "oauth").lower()
    if account_type != "oauth":
        item["sub2api_account_type"] = account_type
    if account_type == "oauth" and provider != "vertex" and not access:
        raise ConvertError(f"{account.get('name') or provider}: OAuth 账号缺少 access_token")

    if provider == "xai":
        expires_in = int(credentials.get("expires_in") or DEFAULT_EXPIRES_IN)
        expired = _account_expired(account, credentials, expires_in)
        last_refresh = _rfc3339(credentials.get("last_refresh"))
        if not last_refresh:
            last_refresh = fmt_utc(parse_dt(expired) - timedelta(seconds=expires_in))
        item.update({
            "access_token": access,
            "refresh_token": refresh,
            "id_token": credentials.get("id_token") or "",
            "token_type": credentials.get("token_type") or "Bearer",
            "expires_in": expires_in,
            "expired": expired,
            "last_refresh": last_refresh,
            "sub": credentials.get("sub") or extract_sub(access, str(credentials.get("id_token") or "")),
            "base_url": credentials.get("base_url") or DEFAULT_BASE_URL,
            "redirect_uri": credentials.get("redirect_uri") or DEFAULT_REDIRECT,
            "token_endpoint": credentials.get("token_endpoint") or DEFAULT_TOKEN_ENDPOINT,
            "auth_kind": "oauth",
            "type": "xai",
        })
    elif provider == "codex":
        auth = openai_auth_from_token(access)
        account_id = credentials.get("account_id") or credentials.get("chatgpt_account_id") or auth.get("chatgpt_account_id") or ""
        item.update({
            "type": "codex",
            "access_token": access,
            "refresh_token": refresh,
            "id_token": credentials.get("id_token") or "",
            "account_id": str(account_id),
            "expired": _account_expired(account, credentials),
            "last_refresh": _rfc3339(credentials.get("last_refresh"), utc_now()) or fmt_utc(utc_now()),
        })
        if credentials.get("session_token"):
            item["session_token"] = credentials["session_token"]
    elif provider == "claude":
        item.update({
            "type": "claude",
            "access_token": access,
            "refresh_token": refresh,
            "id_token": credentials.get("id_token") or "",
            "expired": _account_expired(account, credentials),
            "last_refresh": _rfc3339(credentials.get("last_refresh"), utc_now()) or fmt_utc(utc_now()),
        })
    elif provider == "gemini":
        token = copy.deepcopy(credentials.get("token")) if isinstance(credentials.get("token"), dict) else {}
        token.update({key: value for key, value in {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": credentials.get("token_type") or "Bearer",
            "scope": credentials.get("scope"),
        }.items() if value not in (None, "")})
        token.setdefault("expiry", _account_expired(account, credentials))
        for key in ("access_token", "refresh_token", "token_type", "scope", "expiry", "expiry_date", "expires_at"):
            item.pop(key, None)
        item.update({
            "type": "gemini",
            "token": token,
            "project_id": credentials.get("project_id") or item.get("project_id") or "",
            "auto": bool(credentials.get("auto", item.get("auto", True))),
            "checked": bool(credentials.get("checked", item.get("checked", False))),
        })
    elif provider == "antigravity":
        expires_in = int(credentials.get("expires_in") or DEFAULT_EXPIRES_IN)
        item.update({
            "type": "antigravity",
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": expires_in,
            "expired": _account_expired(account, credentials, expires_in),
            "timestamp": int(credentials.get("timestamp") or utc_now().timestamp() * 1000),
            "project_id": credentials.get("project_id") or "",
        })
    elif provider == "kimi":
        item.update({
            "type": "kimi",
            "access_token": access,
            "refresh_token": refresh,
            "token_type": credentials.get("token_type") or "Bearer",
            "expired": _account_expired(account, credentials),
        })
    elif provider == "qwen":
        item.update({
            "type": "qwen",
            "access_token": access,
            "refresh_token": refresh,
            "resource_url": credentials.get("resource_url") or "",
            "expired": _account_expired(account, credentials),
            "last_refresh": _rfc3339(credentials.get("last_refresh"), utc_now()) or fmt_utc(utc_now()),
        })
    elif provider == "iflow":
        item.update({
            "type": "iflow",
            "access_token": access,
            "refresh_token": refresh,
            "token_type": credentials.get("token_type") or "Bearer",
            "expired": _account_expired(account, credentials),
            "last_refresh": _rfc3339(credentials.get("last_refresh"), utc_now()) or fmt_utc(utc_now()),
        })
    elif provider == "vertex":
        service_account = credentials.get("service_account")
        if not isinstance(service_account, dict):
            raise ConvertError(f"{account.get('name') or provider}: Vertex 账号缺少 service_account")
        item.update({
            "type": "vertex",
            "service_account": copy.deepcopy(service_account),
            "project_id": credentials.get("project_id") or service_account.get("project_id") or "",
            "email": credentials.get("email") or service_account.get("client_email") or "",
        })
    elif provider == "kiro":
        item.update({
            "type": "kiro",
            "access_token": access,
            "refresh_token": refresh,
            "expires_at": credentials.get("expires_at") or _account_expired(account, credentials),
        })
    else:
        item["type"] = provider

    if provider in {"xai", "codex", "claude", "antigravity", "kimi", "qwen", "iflow"}:
        item.pop("expires_at", None)
    return {key: value for key, value in item.items() if value is not None}


def cpa_from_sub2_account(account: dict[str, Any]) -> dict[str, Any]:
    return native_from_sub2_account(account, "xai")


def codex_from_sub2_account(account: dict[str, Any]) -> dict[str, Any]:
    return native_from_sub2_account(account, "codex")


def export_provider_pack(
    accounts: list[dict[str, Any]],
    provider: str,
    output_dir: Path,
    note: str,
    keep_dir: bool = True,
    when: datetime | None = None,
) -> dict[str, Any]:
    provider = canonical_provider(provider)
    if not accounts:
        raise ConvertError(f"没有 {provider} 账号可导出")
    info = provider_info(provider)
    when = when or utc_now()
    base = output_dir / stamp_name(info["archive"], len(accounts), note, "", when)
    json_dir = Path(str(base) + "_json")
    zip_path = Path(str(base) + ".zip")
    json_dir.mkdir(parents=True, exist_ok=True)
    for old in json_dir.glob("*.json"):
        old.unlink()

    used_names: Counter[str] = Counter()
    for account in accounts:
        item = native_from_sub2_account(account, provider)
        identity = _safe_segment(_record_identity(provider, item), provider)
        used_names[identity] += 1
        suffix = f"-{used_names[identity]}" if used_names[identity] > 1 else ""
        filename = f"{info['prefix']}-{identity}{suffix}.json"
        write_json(json_dir / filename, item, pretty=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for json_file in sorted(json_dir.glob("*.json")):
            archive.write(json_file, arcname=json_file.name)

    if not keep_dir:
        for json_file in json_dir.glob("*.json"):
            json_file.unlink()
        json_dir.rmdir()
    return {
        "provider": provider,
        "platform": info["platform"],
        "count": len(accounts),
        "zip": str(zip_path),
        "dir": str(json_dir) if keep_dir else None,
        "note": sanitize_note(note),
    }


def export_cpa_pack(accounts: list[dict[str, Any]], output_dir: Path, note: str, keep_dir: bool = True, when: datetime | None = None) -> dict[str, Any]:
    return export_provider_pack(accounts, "xai", output_dir, note, keep_dir, when)


def export_codex_pack(accounts: list[dict[str, Any]], output_dir: Path, note: str, keep_dir: bool = True, when: datetime | None = None) -> dict[str, Any]:
    return export_provider_pack(accounts, "codex", output_dir, note, keep_dir, when)


def _load_sub2(path: Path) -> tuple[dict[str, Any], list[str]]:
    loaded = load_input(path)
    if loaded.kind != "sub2" or loaded.payload is None:
        raise ConvertError("输入不是 Sub2API 账号包")
    return loaded.payload, loaded.warnings


def sub2_to_provider(sub2_path: Path, output_dir: Path, provider: str, note: str = "export", keep_dir: bool = True) -> dict[str, Any]:
    payload, warnings = _load_sub2(sub2_path)
    provider = canonical_provider(provider)
    resolved_accounts, proxy_warnings = _accounts_with_proxy_urls(payload)
    accounts = [account for account in resolved_accounts if account_provider(account) == provider]
    result = export_provider_pack(accounts, provider, output_dir, note, keep_dir)
    result["warnings"] = warnings + proxy_warnings
    return result


def sub2_to_cpa(sub2_path: Path, output_dir: Path, note: str = "cpa", keep_dir: bool = True) -> dict[str, Any]:
    return sub2_to_provider(sub2_path, output_dir, "xai", note, keep_dir)


def sub2_to_codex(sub2_path: Path, output_dir: Path, note: str = "codex", keep_dir: bool = True) -> dict[str, Any]:
    return sub2_to_provider(sub2_path, output_dir, "codex", note, keep_dir)


def sub2_to_native(sub2_path: Path, output_dir: Path, note: str = "export", keep_dir: bool = True) -> dict[str, Any]:
    payload, warnings = _load_sub2(sub2_path)
    resolved_accounts, proxy_warnings = _accounts_with_proxy_urls(payload)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for account in resolved_accounts:
        grouped.setdefault(account_provider(account), []).append(account)
    when = utc_now()
    packs = [
        export_provider_pack(accounts, provider, output_dir, note, keep_dir, when)
        for provider, accounts in sorted(grouped.items())
    ]
    return {
        "count": len(payload["accounts"]),
        "packs": packs,
        "providers": {pack["provider"]: pack["count"] for pack in packs},
        "warnings": warnings + proxy_warnings,
        "note": sanitize_note(note),
    }


def detect_input_kind(path: Path) -> str:
    loaded = load_input(path)
    if loaded.kind == "sub2":
        return "sub2"
    providers = {record.provider for record in loaded.records}
    if len(providers) > 1:
        return "native-mixed"
    provider = next(iter(providers))
    return "cpa" if provider == "xai" else provider


def detect_mode(path: Path) -> str:
    return "sub2-to-cpa" if detect_input_kind(path) == "sub2" else "cpa-to-sub2"


def convert_path(
    src: Path,
    output_dir: Path,
    target: str = "auto",
    note: str = "export",
    keep_dir: bool = False,
) -> dict[str, Any]:
    target = str(target or "auto").strip().lower()
    aliases = {"cliproxy": "native", "cpa": "xai"}
    target = aliases.get(target, target)
    if target == "auto":
        target = "native" if detect_input_kind(src) == "sub2" else "sub2"
    if target == "sub2":
        return native_to_sub2(src, output_dir, note)
    if target == "native":
        return sub2_to_native(src, output_dir, note, keep_dir)
    provider = canonical_provider(target)
    if provider:
        return sub2_to_provider(src, output_dir, provider, note, keep_dir)
    raise ConvertError(f"不支持的目标格式: {target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Sub2API / CLIProxyAPI JSON、目录或 ZIP")
    parser.add_argument("-o", "--output-dir", type=Path, default=None, help="输出目录")
    parser.add_argument("--note", default="", help="输出文件名备注")
    parser.add_argument(
        "--to",
        default="auto",
        choices=["auto", "sub2", "native", "cliproxy", "cpa", *PROVIDER_INFO.keys()],
        help="目标格式；auto 根据内容自动选择方向",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "sub2-to-cpa", "cpa-to-sub2"],
        default="auto",
        help="旧版兼容参数",
    )
    parser.add_argument("--keep-dir", action=argparse.BooleanOptionalAction, default=True, help="保留解包后的 JSON 目录")
    parser.add_argument("--inspect", action="store_true", help="仅识别并输出安全概览，不转换")
    return parser


def resolve_target(src: Path, args: argparse.Namespace) -> str:
    if args.mode != "auto" and args.to == "auto":
        return "xai" if args.mode == "sub2-to-cpa" else "sub2"
    if args.to != "auto":
        return args.to
    return "native" if detect_input_kind(src) == "sub2" else "sub2"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    src: Path = args.input
    if args.inspect:
        print(json.dumps(inspect_input(src), ensure_ascii=False, indent=2))
        return 0
    output_dir: Path = args.output_dir or (src.parent if src.is_file() else src)
    result = convert_path(
        src,
        output_dir,
        target=resolve_target(src, args),
        note=args.note or src.stem,
        keep_dir=args.keep_dir,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
