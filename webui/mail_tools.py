"""Microsoft mailbox import, protocol detection, and OTP inspection tools."""

from __future__ import annotations

import csv
import imaplib
import json
import re
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.policy import default as email_policy
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Iterable

import requests

import proxy_pool
from . import store, timeutil


MAIL_TOOL_STATE_PATH = store.ROOT / "mail_tool_state.json"
MAIL_TOOL_STATE_VERSION = 1

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_CLIENT_ID_RE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$",
    re.I,
)
_FIELD_ALIASES = {
    "email": {"email", "mail", "address", "username", "account", "邮箱", "账号"},
    "password": {"password", "pass", "passwd", "pwd", "密码"},
    "client_id": {
        "client_id",
        "clientid",
        "client",
        "app_id",
        "appid",
        "application_id",
        "应用id",
    },
    "refresh_token": {
        "refresh_token",
        "refreshtoken",
        "refresh",
        "token",
        "oauth_token",
        "令牌",
    },
}
_AUTH_ERROR_MARKERS = (
    "invalid_grant",
    "interaction_required",
    "unauthorized_client",
    "invalid_client",
    "aadsts",
    "authenticate failed",
    "authenticationfailed",
    "authfailed",
    "login failed",
    "logondenied",
    "401",
    "403",
)

_IMAP_TOKEN_ATTEMPTS = (
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
        "imap_new",
    ),
    (
        "https://login.live.com/oauth20_token.srf",
        "wl.imap wl.offline_access",
        "imap_old_scope",
    ),
    ("https://login.live.com/oauth20_token.srf", "", "imap_old_default"),
)
_GRAPH_TOKEN_ATTEMPTS = (
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
        "graph_consumers",
    ),
    (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "https://graph.microsoft.com/.default",
        "graph_common",
    ),
    ("https://login.microsoftonline.com/common/oauth2/v2.0/token", "", "graph_default"),
)
_IMAP_HOSTS = ("outlook.live.com", "outlook.office365.com")
_IMAP_MAILBOXES = (
    "INBOX",
    "Junk",
    '"Junk Email"',
    "Junk Email",
    "Spam",
    "Deleted Items",
    "Archive",
)
_GRAPH_FOLDERS = ("inbox", "junkemail", "deleteditems", "archive")


def _normalized_key(value: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(value or "").strip().lower())


def _field_value(mapping: dict[str, Any], field_name: str) -> str:
    aliases = _FIELD_ALIASES[field_name]
    for key, value in mapping.items():
        if _normalized_key(key) in aliases and value is not None:
            return str(value).strip()
    return ""


def _looks_client_id(value: str) -> bool:
    return bool(_CLIENT_ID_RE.fullmatch(str(value or "").strip()))


def _looks_refresh_token(value: str) -> bool:
    text = str(value or "").strip()
    return len(text) >= 40 or text.startswith(("M.", "0.A", "1.A", "EwB", "MC"))


def _mask(value: str, keep: int = 5) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}...{text[-keep:]}"


def _safe_error(value: Any, *, secrets: Iterable[str] = ()) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "***")
    text = re.sub(
        r"(?i)(access_token|refresh_token|client_secret|password)(\s*[=:]\s*)([^\s,&]+)",
        r"\1\2***",
        text,
    )
    return text[:320]


@dataclass(slots=True)
class MailCredential:
    email: str
    password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    source_format: str = "text"
    source_line: int = 0

    @property
    def auth_type(self) -> str:
        if self.client_id and self.refresh_token:
            return "oauth"
        if self.password:
            return "password"
        return "incomplete"

    def normalized_line(self) -> str:
        return f"{self.email}----{self.password}----{self.client_id}----{self.refresh_token}"

    def safe_preview(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "auth_type": self.auth_type,
            "client_id": _mask(self.client_id, 6),
            "token": _mask(self.refresh_token, 6),
            "has_password": bool(self.password),
            "source_format": self.source_format,
            "source_line": self.source_line,
        }


@dataclass(slots=True)
class MailImportResult:
    records: list[MailCredential] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    formats: dict[str, int] = field(default_factory=dict)
    duplicates: int = 0

    def public_dict(self) -> dict[str, Any]:
        return {
            "valid": len(self.records),
            "invalid": len(self.issues),
            "duplicates": self.duplicates,
            "formats": dict(self.formats),
            "preview": [record.safe_preview() for record in self.records[:50]],
            "issues": list(self.issues[:50]),
        }


def _credential_from_mapping(
    mapping: dict[str, Any],
    *,
    source_format: str,
    source_line: int,
) -> MailCredential:
    flattened = dict(mapping)
    for key in ("credentials", "credential", "oauth", "auth"):
        nested = mapping.get(key)
        if isinstance(nested, dict):
            flattened.update(nested)
    return MailCredential(
        email=_field_value(flattened, "email").lower(),
        password=_field_value(flattened, "password"),
        client_id=_field_value(flattened, "client_id"),
        refresh_token=_field_value(flattened, "refresh_token"),
        source_format=source_format,
        source_line=source_line,
    )


def _credential_from_parts(
    parts: list[str],
    *,
    source_format: str,
    source_line: int,
) -> MailCredential:
    values = [str(part or "").strip() for part in parts]
    if len(values) == 2:
        return MailCredential(values[0].lower(), password=values[1], source_format=source_format, source_line=source_line)
    if len(values) == 3:
        email, second, third = values
        if _looks_client_id(second):
            return MailCredential(email.lower(), client_id=second, refresh_token=third, source_format=source_format, source_line=source_line)
        if _looks_client_id(third) and _looks_refresh_token(second):
            return MailCredential(email.lower(), client_id=third, refresh_token=second, source_format=source_format, source_line=source_line)
        raise ValueError("三段格式需要包含 client_id 和 refresh_token")
    if len(values) != 4:
        raise ValueError("字段数量应为 2、3 或 4")

    email, *credentials = values
    client_indexes = [index for index, value in enumerate(credentials) if _looks_client_id(value)]
    if len(client_indexes) == 1:
        client_index = client_indexes[0]
        client_id = credentials[client_index]
        remaining = [(index, value) for index, value in enumerate(credentials) if index != client_index]
        token_candidates = [(index, value) for index, value in remaining if _looks_refresh_token(value)]
        if token_candidates:
            token_index, refresh_token = max(token_candidates, key=lambda item: len(item[1]))
            password = next((value for index, value in remaining if index != token_index), "")
            return MailCredential(
                email.lower(),
                password=password,
                client_id=client_id,
                refresh_token=refresh_token,
                source_format=source_format,
                source_line=source_line,
            )
    return MailCredential(
        email.lower(),
        password=credentials[0],
        client_id=credentials[1],
        refresh_token=credentials[2],
        source_format=source_format,
        source_line=source_line,
    )


def _validate_credential(record: MailCredential) -> None:
    if not _EMAIL_RE.fullmatch(record.email):
        raise ValueError("邮箱格式无效")
    if bool(record.client_id) != bool(record.refresh_token):
        raise ValueError("client_id 与 refresh_token 必须同时存在")
    if not record.password and not (record.client_id and record.refresh_token):
        raise ValueError("缺少密码或 OAuth 凭证")


def _json_records(payload: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return
        if _field_value(value, "email"):
            found.append(value)
            return
        matched_wrapper = False
        for key in ("accounts", "data", "items", "results", "mailboxes", "emails"):
            if key in value:
                matched_wrapper = True
                walk(value[key])
        if matched_wrapper:
            return
        for key, item in value.items():
            if isinstance(item, dict) and _EMAIL_RE.fullmatch(str(key).strip()):
                found.append({"email": str(key).strip(), **item})
            elif isinstance(item, (dict, list)):
                walk(item)

    walk(payload)
    return found


def _line_delimiter(line: str) -> tuple[str, str]:
    if "----" in line:
        return "----", "four-dash"
    for delimiter, label in (("\t", "tsv"), ("|", "pipe"), (";", "semicolon"), (",", "csv")):
        if delimiter in line:
            return delimiter, label
    if line.count(":") in {1, 2, 3}:
        return ":", "colon"
    return "", "text"


def _split_line(line: str, delimiter: str) -> list[str]:
    if delimiter == "----":
        return line.split("----")
    if delimiter:
        return next(csv.reader([line], delimiter=delimiter, skipinitialspace=True))
    return [line]


def _header_mapping(parts: list[str]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for index, value in enumerate(parts):
        key = _normalized_key(value)
        for field_name, aliases in _FIELD_ALIASES.items():
            if key in aliases:
                mapping[index] = field_name
                break
    return mapping if "email" in mapping.values() else {}


def parse_mail_import(text: str) -> MailImportResult:
    raw = str(text or "").strip().removeprefix("\ufeff")
    result = MailImportResult()
    if not raw:
        result.issues.append({"line": 0, "error": "没有可导入的内容"})
        return result

    candidates: list[MailCredential] = []
    if raw[:1] in {"{", "["}:
        try:
            payload = json.loads(raw)
            objects = _json_records(payload)
            if not objects:
                raise ValueError("JSON 中未找到邮箱记录")
            for index, mapping in enumerate(objects, start=1):
                candidates.append(
                    _credential_from_mapping(mapping, source_format="json", source_line=index)
                )
        except Exception as exc:
            result.issues.append({"line": 1, "error": _safe_error(exc)})
    else:
        lines = [
            (line_no, line.strip())
            for line_no, line in enumerate(raw.splitlines(), start=1)
            if line.strip() and not line.lstrip().startswith(("#", "//"))
        ]
        header: dict[int, str] = {}
        header_delimiter = ""
        if lines:
            delimiter, _ = _line_delimiter(lines[0][1])
            parts = _split_line(lines[0][1], delimiter)
            header = _header_mapping(parts)
            if header:
                header_delimiter = delimiter
                lines = lines[1:]
        for line_no, line in lines:
            try:
                if line.startswith("{"):
                    mapping = json.loads(line)
                    if not isinstance(mapping, dict):
                        raise ValueError("JSON 行必须是对象")
                    candidates.append(
                        _credential_from_mapping(mapping, source_format="jsonl", source_line=line_no)
                    )
                    continue
                delimiter, label = _line_delimiter(line)
                if header:
                    delimiter = header_delimiter
                    label = "header-csv"
                parts = _split_line(line, delimiter)
                if header:
                    row_mapping = {
                        field_name: parts[index]
                        for index, field_name in header.items()
                        if index < len(parts)
                    }
                    candidates.append(
                        _credential_from_mapping(row_mapping, source_format=label, source_line=line_no)
                    )
                else:
                    candidates.append(
                        _credential_from_parts(parts, source_format=label, source_line=line_no)
                    )
            except Exception as exc:
                result.issues.append({"line": line_no, "error": _safe_error(exc)})

    deduplicated: dict[str, MailCredential] = {}
    for record in candidates:
        try:
            _validate_credential(record)
        except Exception as exc:
            result.issues.append({"line": record.source_line, "email": record.email, "error": _safe_error(exc)})
            continue
        key = record.email.lower()
        if key in deduplicated:
            result.duplicates += 1
            deduplicated.pop(key)
        deduplicated[key] = record
    result.records = list(deduplicated.values())
    for record in result.records:
        result.formats[record.source_format] = result.formats.get(record.source_format, 0) + 1
    return result


class MicrosoftMailboxProbe:
    """Validate a Microsoft mailbox using a real IMAP or Graph mailbox request."""

    def __init__(
        self,
        account: dict[str, str],
        *,
        proxy: str = "",
        timeout: float = 20.0,
        cancel_check: Callable[[], bool] | None = None,
        request_func: Callable[..., Any] = requests.request,
        imap_factory: Callable[..., Any] = imaplib.IMAP4_SSL,
    ) -> None:
        self.account = {
            "email": str(account.get("email") or "").strip().lower(),
            "password": str(account.get("password") or ""),
            "client_id": str(account.get("client_id") or "").strip(),
            "refresh_token": str(account.get("token") or account.get("refresh_token") or "").strip(),
        }
        self.proxy = str(proxy or "").strip()
        self.timeout = max(5.0, min(float(timeout or 20.0), 60.0))
        self.cancel_check = cancel_check
        self.request_func = request_func
        self.imap_factory = imap_factory
        self.errors: list[str] = []
        self._rotated_refresh_token = ""
        self._imap_access_token = ""
        self._imap_host = ""
        self._graph_access_token = ""

    @property
    def secrets(self) -> tuple[str, ...]:
        return (
            self.account.get("password", ""),
            self.account.get("client_id", ""),
            self.account.get("refresh_token", ""),
            self._rotated_refresh_token,
            self._imap_access_token,
            self._graph_access_token,
            self.proxy,
        )

    def _cancelled(self) -> bool:
        return bool(self.cancel_check and self.cancel_check())

    def _check_cancelled(self) -> None:
        if self._cancelled():
            raise RuntimeError("检测已停止")

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        self._check_cancelled()
        if self.proxy:
            kwargs.setdefault("proxies", {"http": self.proxy, "https": self.proxy})
        kwargs.setdefault("timeout", self.timeout)
        return self.request_func(method, url, **kwargs)

    def _token_candidates(self, protocol: str) -> Iterable[tuple[str, str]]:
        attempts = _IMAP_TOKEN_ATTEMPTS if protocol == "imap" else _GRAPH_TOKEN_ATTEMPTS
        refresh_token = self._rotated_refresh_token or self.account["refresh_token"]
        seen_tokens: set[str] = set()
        for endpoint, scope, label in attempts:
            self._check_cancelled()
            payload = {
                "client_id": self.account["client_id"],
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
            if scope:
                payload["scope"] = scope
            try:
                response = self._request("POST", endpoint, data=payload)
                try:
                    body = response.json() if getattr(response, "content", b"") else {}
                except Exception:
                    body = {}
                if int(getattr(response, "status_code", 0) or 0) >= 400:
                    error_code = str(body.get("error") or "").strip()
                    error_description = str(body.get("error_description") or "").strip()
                    detail = ": ".join(part for part in (error_code, error_description) if part)
                    if not detail:
                        detail = getattr(response, "text", "")
                    self.errors.append(f"{label}: {_safe_error(detail, secrets=self.secrets)}")
                    continue
                access_token = str(body.get("access_token") or "").strip()
                if not access_token:
                    detail = body.get("error_description") or body.get("error") or "未返回 access_token"
                    self.errors.append(f"{label}: {_safe_error(detail, secrets=self.secrets)}")
                    continue
                new_refresh = str(body.get("refresh_token") or "").strip()
                if new_refresh and new_refresh != refresh_token:
                    refresh_token = new_refresh
                    self._rotated_refresh_token = new_refresh
                if access_token in seen_tokens:
                    continue
                seen_tokens.add(access_token)
                yield access_token, label
            except Exception as exc:
                self.errors.append(f"{label}: {_safe_error(exc, secrets=self.secrets)}")

    @staticmethod
    def _oauth_auth_string(email: str, access_token: str) -> bytes:
        return f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")

    def _open_imap_oauth(self, access_token: str) -> tuple[Any, str]:
        last_error = ""
        for host in _IMAP_HOSTS:
            self._check_cancelled()
            connection = None
            try:
                connection = self.imap_factory(host, 993, timeout=self.timeout)
                auth = self._oauth_auth_string(self.account["email"], access_token)
                connection.authenticate("XOAUTH2", lambda _: auth)
                return connection, host
            except Exception as exc:
                last_error = _safe_error(exc, secrets=self.secrets)
                if connection is not None:
                    try:
                        connection.logout()
                    except Exception:
                        pass
        raise RuntimeError(last_error or "IMAP OAuth 登录失败")

    def _open_imap_password(self) -> tuple[Any, str]:
        last_error = ""
        for host in _IMAP_HOSTS:
            self._check_cancelled()
            connection = None
            try:
                connection = self.imap_factory(host, 993, timeout=self.timeout)
                connection.login(self.account["email"], self.account["password"])
                return connection, host
            except Exception as exc:
                last_error = _safe_error(exc, secrets=self.secrets)
                if connection is not None:
                    try:
                        connection.logout()
                    except Exception:
                        pass
        raise RuntimeError(last_error or "IMAP 密码登录失败")

    @staticmethod
    def _close_imap(connection: Any) -> None:
        if connection is None:
            return
        try:
            connection.logout()
        except Exception:
            pass

    def _graph_mailbox_ok(self, access_token: str) -> tuple[bool, str]:
        try:
            response = self._request(
                "GET",
                "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages",
                params={"$top": 1, "$select": "id"},
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            status = int(getattr(response, "status_code", 0) or 0)
            if 200 <= status < 300:
                return True, ""
            return False, f"Graph HTTP {status}: {_safe_error(getattr(response, 'text', ''), secrets=self.secrets)}"
        except Exception as exc:
            return False, _safe_error(exc, secrets=self.secrets)

    def _base_result(self, started: float) -> dict[str, Any]:
        errors = [error for error in self.errors if error]
        combined = "；".join(errors[-4:])
        lowered = combined.lower()
        health = "invalid" if any(marker in lowered for marker in _AUTH_ERROR_MARKERS) else "error"
        return {
            "email": self.account["email"],
            "protocol": "unknown",
            "provider": "",
            "health": health,
            "reason": combined or "未找到可用的邮箱接码协议",
            "checked_at": timeutil.now_iso(),
            "latency_ms": int((time.monotonic() - started) * 1000),
            "_refresh_token": self._rotated_refresh_token,
        }

    def detect(self) -> dict[str, Any]:
        started = time.monotonic()
        email = self.account["email"]
        if not _EMAIL_RE.fullmatch(email):
            self.errors.append("邮箱格式无效")
            return self._base_result(started)

        has_oauth = bool(self.account["client_id"] and self.account["refresh_token"])
        if has_oauth:
            for access_token, label in self._token_candidates("imap"):
                connection = None
                try:
                    connection, host = self._open_imap_oauth(access_token)
                    self._imap_access_token = access_token
                    self._imap_host = host
                    return {
                        "email": email,
                        "protocol": "imap",
                        "provider": label,
                        "health": "ok",
                        "reason": f"XOAUTH2 登录成功 · {host}",
                        "checked_at": timeutil.now_iso(),
                        "latency_ms": int((time.monotonic() - started) * 1000),
                        "_refresh_token": self._rotated_refresh_token,
                    }
                except Exception as exc:
                    self.errors.append(f"{label}: {_safe_error(exc, secrets=self.secrets)}")
                finally:
                    self._close_imap(connection)

            for access_token, label in self._token_candidates("graph"):
                ok, error = self._graph_mailbox_ok(access_token)
                if ok:
                    self._graph_access_token = access_token
                    return {
                        "email": email,
                        "protocol": "graph",
                        "provider": label,
                        "health": "ok",
                        "reason": "Microsoft Graph Mail.Read 可用",
                        "checked_at": timeutil.now_iso(),
                        "latency_ms": int((time.monotonic() - started) * 1000),
                        "_refresh_token": self._rotated_refresh_token,
                    }
                self.errors.append(f"{label}: {error}")
            return self._base_result(started)

        if self.account["password"]:
            connection = None
            try:
                connection, host = self._open_imap_password()
                self._imap_host = host
                return {
                    "email": email,
                    "protocol": "imap",
                    "provider": "password_imap",
                    "health": "ok",
                    "reason": f"IMAP 密码登录成功 · {host}",
                    "checked_at": timeutil.now_iso(),
                    "latency_ms": int((time.monotonic() - started) * 1000),
                    "_refresh_token": "",
                }
            except Exception as exc:
                self.errors.append(f"password_imap: {_safe_error(exc, secrets=self.secrets)}")
            finally:
                self._close_imap(connection)
        else:
            self.errors.append("缺少密码或 OAuth 凭证")
        return self._base_result(started)

    @staticmethod
    def _decode_header(value: Any) -> str:
        try:
            return str(make_header(decode_header(str(value or ""))))
        except Exception:
            return str(value or "")

    @staticmethod
    def _message_text(message: Any) -> str:
        chunks: list[str] = []
        parts = message.walk() if message.is_multipart() else [message]
        for part in parts:
            if part.get_content_maintype() == "multipart" or part.get_filename():
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = str(part.get_payload() or "")
            chunks.append(text)
        merged = " ".join(chunks)
        merged = re.sub(r"<[^>]+>", " ", merged)
        return re.sub(r"\s+", " ", merged).strip()

    @staticmethod
    def _extract_code(text: str) -> str:
        source = str(text or "")
        patterns = (
            r"(?is)(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|authentication\s+code|验证码|校验码|动态码|認證碼|驗證碼)[^0-9]{0,40}(\d(?:[\s-]*\d){5})",
            r"(?is)\bcode\b[^0-9]{0,20}(\d(?:[\s-]*\d){5})",
        )
        for pattern in patterns:
            match = re.search(pattern, source)
            if match:
                code = re.sub(r"\D", "", match.group(1))
                if len(code) == 6:
                    return code
        return ""

    @staticmethod
    def _timestamp(value: Any) -> float:
        text = str(value or "").strip()
        if not text:
            return 0.0
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except Exception:
            try:
                parsed = parsedate_to_datetime(text)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.timestamp()
            except Exception:
                return 0.0

    def _scan_imap_code(self, *, recent_seconds: int) -> dict[str, Any]:
        connection = None
        candidates: list[dict[str, Any]] = []
        cutoff = time.time() - max(60, int(recent_seconds or 900))
        try:
            if self.account["client_id"] and self.account["refresh_token"]:
                if not self._imap_access_token:
                    raise RuntimeError("缺少 IMAP access token")
                connection, _ = self._open_imap_oauth(self._imap_access_token)
            else:
                connection, _ = self._open_imap_password()
            for mailbox in _IMAP_MAILBOXES:
                self._check_cancelled()
                try:
                    selected, _ = connection.select(mailbox, readonly=True)
                except Exception:
                    continue
                if selected != "OK":
                    continue
                status, data = connection.uid("search", None, "ALL")
                if status != "OK" or not data or not data[0]:
                    continue
                for message_id in data[0].split()[-30:]:
                    try:
                        status, payload = connection.uid("fetch", message_id, "(RFC822)")
                        if status != "OK" or not payload:
                            continue
                        raw = next(
                            (item[1] for item in payload if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes)),
                            b"",
                        )
                        if not raw:
                            continue
                        message = message_from_bytes(raw, policy=email_policy)
                        timestamp = self._timestamp(message.get("Date"))
                        if timestamp and timestamp < cutoff:
                            continue
                        subject = self._decode_header(message.get("Subject"))
                        sender = self._decode_header(message.get("From"))
                        code = self._extract_code(f"{subject}\n{self._message_text(message)}")
                        if code:
                            candidates.append(
                                {"code": code, "subject": subject, "sender": sender, "message_at": timestamp}
                            )
                    except Exception:
                        continue
        finally:
            self._close_imap(connection)
        return max(candidates, key=lambda item: float(item.get("message_at") or 0), default={})

    def _scan_graph_code(self, *, recent_seconds: int) -> dict[str, Any]:
        if not self._graph_access_token:
            raise RuntimeError("缺少 Graph access token")
        cutoff = time.time() - max(60, int(recent_seconds or 900))
        candidates: list[dict[str, Any]] = []
        for folder in _GRAPH_FOLDERS:
            self._check_cancelled()
            try:
                response = self._request(
                    "GET",
                    f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages",
                    params={
                        "$top": 20,
                        "$select": "id,subject,from,receivedDateTime,bodyPreview,body",
                        "$orderby": "receivedDateTime desc",
                    },
                    headers={
                        "Authorization": f"Bearer {self._graph_access_token}",
                        "Accept": "application/json",
                        "Prefer": "outlook.body-content-type='text'",
                    },
                )
            except Exception:
                continue
            status = int(getattr(response, "status_code", 0) or 0)
            if status >= 400:
                continue
            try:
                payload = response.json() if getattr(response, "content", b"") else {}
            except Exception:
                payload = {}
            for item in payload.get("value") or []:
                timestamp = self._timestamp(item.get("receivedDateTime"))
                if timestamp and timestamp < cutoff:
                    continue
                subject = str(item.get("subject") or "")
                sender = str((((item.get("from") or {}).get("emailAddress") or {}).get("address") or ""))
                body = str((item.get("body") or {}).get("content") or "")
                preview = str(item.get("bodyPreview") or "")
                code = self._extract_code(f"{subject}\n{preview}\n{body}")
                if code:
                    candidates.append(
                        {"code": code, "subject": subject, "sender": sender, "message_at": timestamp}
                    )
        return max(candidates, key=lambda item: float(item.get("message_at") or 0), default={})

    def latest_code(self, *, recent_seconds: int = 900) -> dict[str, Any]:
        started = time.monotonic()
        result = self.detect()
        if result.get("health") != "ok":
            return result
        try:
            if result.get("protocol") == "imap":
                code_result = self._scan_imap_code(recent_seconds=recent_seconds)
            else:
                code_result = self._scan_graph_code(recent_seconds=recent_seconds)
            result.update(code_result)
            result["reason"] = "已读取最近验证码" if code_result.get("code") else "邮箱可用，最近邮件中没有验证码"
        except Exception as exc:
            result["reason"] = f"邮箱可用，读取邮件失败: {_safe_error(exc, secrets=self.secrets)}"
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return result


class MailToolManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._results: dict[str, dict[str, Any]] = {}
        self._logs: deque[str] = deque(maxlen=400)
        self._task: dict[str, Any] = {}
        self._running = False
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._load_state()

    def _load_state(self) -> None:
        if not MAIL_TOOL_STATE_PATH.is_file():
            return
        try:
            payload = json.loads(MAIL_TOOL_STATE_PATH.read_text(encoding="utf-8"))
            results = payload.get("results") or {}
            if isinstance(results, dict):
                self._results = {
                    str(email).lower(): dict(row)
                    for email, row in results.items()
                    if isinstance(row, dict)
                }
            task = payload.get("task") or {}
            if isinstance(task, dict):
                self._task = dict(task)
                if self._task.get("status") == "running":
                    self._task["status"] = "interrupted"
                    self._task["finished_at"] = timeutil.now_iso()
                    self._task["error"] = "服务重启，检测任务已中断"
            logs = payload.get("logs") or []
            if isinstance(logs, list):
                self._logs.extend(str(line) for line in logs if isinstance(line, str))
        except Exception:
            return

    def _save_state(self) -> bool:
        try:
            with self._write_lock:
                with self._lock:
                    persisted_results = {
                        email: {key: value for key, value in row.items() if key != "code"}
                        for email, row in self._results.items()
                    }
                    payload = {
                        "state_version": MAIL_TOOL_STATE_VERSION,
                        "results": persisted_results,
                        "task": dict(self._task),
                        "logs": list(self._logs),
                    }
                encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
                MAIL_TOOL_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
                tmp = MAIL_TOOL_STATE_PATH.with_name(f".{MAIL_TOOL_STATE_PATH.name}.tmp")
                tmp.write_text(encoded, encoding="utf-8")
                tmp.replace(MAIL_TOOL_STATE_PATH)
            return True
        except Exception:
            return False

    def _log(self, message: str) -> None:
        with self._lock:
            self._logs.append(f"[{timeutil.now_clock()}] {str(message).rstrip()}")

    @staticmethod
    def inspect_import(text: str) -> dict[str, Any]:
        if len(str(text or "").encode("utf-8")) > 20 * 1024 * 1024:
            raise ValueError("邮箱导入内容过大（>20MB）")
        return parse_mail_import(text).public_dict()

    def ensure_idle(self) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError("邮箱检测任务运行中，请先停止任务")

    def import_accounts(self, text: str, *, mode: str = "append") -> dict[str, Any]:
        self.ensure_idle()
        if len(str(text or "").encode("utf-8")) > 20 * 1024 * 1024:
            raise ValueError("邮箱导入内容过大（>20MB）")
        parsed = parse_mail_import(text)
        if not parsed.records:
            detail = parsed.issues[0]["error"] if parsed.issues else "没有有效邮箱"
            raise ValueError(detail)
        normalized = "\n".join(record.normalized_line() for record in parsed.records) + "\n"
        result = store.import_mail_credentials(normalized, mode=mode)
        if mode == "replace":
            with self._lock:
                self._results = {}
            self._save_state()
        else:
            self.forget({record.email for record in parsed.records})
        return {
            **result,
            "imported": len(parsed.records),
            "invalid": len(parsed.issues),
            "duplicates": parsed.duplicates,
            "formats": parsed.formats,
            "issues": parsed.issues[:50],
        }

    def forget(self, emails: set[str] | list[str]) -> None:
        wanted = {str(email).strip().lower() for email in emails if str(email).strip()}
        with self._lock:
            for email in wanted:
                self._results.pop(email, None)
        self._save_state()

    @staticmethod
    def _safe_account_row(account: dict[str, str], result: dict[str, Any]) -> dict[str, Any]:
        checked_at = result.get("checked_at") or ""
        message_at = result.get("message_at") or 0
        return {
            "email": account["email"],
            "auth_type": "oauth" if account.get("client_id") and account.get("token") else "password",
            "has_password": bool(account.get("password")),
            "client_id": _mask(account.get("client_id", ""), 6),
            "token_preview": _mask(account.get("token", ""), 7),
            "protocol": result.get("protocol") or "unchecked",
            "provider": result.get("provider") or "",
            "health": result.get("health") or "unchecked",
            "reason": result.get("reason") or "",
            "checked_at": timeutil.iso_to_beijing_display(checked_at) if checked_at else "",
            "latency_ms": result.get("latency_ms"),
            "code": result.get("code") or "",
            "subject": result.get("subject") or "",
            "sender": result.get("sender") or "",
            "message_at": timeutil.timestamp_display(message_at) if message_at else "",
        }

    def list_accounts(
        self,
        *,
        query: str = "",
        protocol: str = "all",
        health: str = "all",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        accounts = store.read_mail_credentials()
        with self._lock:
            results = {email: dict(row) for email, row in self._results.items()}
        items = [
            self._safe_account_row(account, results.get(account["email"].lower(), {}))
            for account in accounts
        ]
        metrics = {
            "total": len(items),
            "imap": sum(1 for item in items if item["protocol"] == "imap"),
            "graph": sum(1 for item in items if item["protocol"] == "graph"),
            "ok": sum(1 for item in items if item["health"] == "ok"),
            "failed": sum(1 for item in items if item["health"] in {"invalid", "error"}),
            "unchecked": sum(1 for item in items if item["health"] == "unchecked"),
        }
        q = str(query or "").strip().lower()
        if q:
            items = [
                item
                for item in items
                if q in item["email"].lower()
                or q in str(item["provider"]).lower()
                or q in str(item["reason"]).lower()
            ]
        if protocol not in {"", "all"}:
            items = [item for item in items if item["protocol"] == protocol]
        if health not in {"", "all"}:
            items = [item for item in items if item["health"] == health]
        total = len(items)
        page_size = max(1, min(int(page_size or 50), 200))
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(int(page or 1), total_pages))
        start = (page - 1) * page_size
        return {
            "items": items[start : start + page_size],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "metrics": metrics,
            "path": str(store.mail_file()),
        }

    @staticmethod
    def _resolve_proxy(mode: str) -> str:
        if str(mode or "direct").strip().lower() != "config":
            return ""
        cfg = store.load_config_raw()
        raw = str(cfg.get("proxy") or "").strip()
        return proxy_pool.resolve_special(raw) or proxy_pool.effective_url(raw)

    def start_check(
        self,
        *,
        emails: list[str] | None = None,
        action: str = "detect",
        workers: int = 4,
        proxy_mode: str = "direct",
        recent_seconds: int = 900,
    ) -> dict[str, Any]:
        action = str(action or "detect").strip().lower()
        if action not in {"detect", "code"}:
            raise ValueError("未知邮箱任务")
        selected = {str(email).strip().lower() for email in (emails or []) if str(email).strip()}
        accounts = store.read_mail_credentials(selected or None)
        if not accounts:
            raise ValueError("没有可检测的邮箱")
        workers = max(1, min(int(workers or 4), 8, len(accounts)))
        recent_seconds = max(60, min(int(recent_seconds or 900), 86400))
        with self._lock:
            if self._running:
                return {"started": False, "running": True, "task": dict(self._task)}
            self._running = True
            self._cancel.clear()
            self._task = {
                "id": uuid.uuid4().hex[:10],
                "status": "running",
                "action": action,
                "proxy_mode": proxy_mode,
                "workers": workers,
                "total": len(accounts),
                "done": 0,
                "ok": 0,
                "failed": 0,
                "codes": 0,
                "started_at": timeutil.now_iso(),
                "finished_at": "",
                "current": "",
                "error": "",
            }
            task = dict(self._task)
        self._log(
            f"微软邮箱任务开始：id={task['id']} action={action} total={len(accounts)} "
            f"workers={workers} proxy={proxy_mode}"
        )
        self._save_state()
        thread = threading.Thread(
            target=self._run_check,
            args=(accounts,),
            kwargs={"action": action, "workers": workers, "proxy_mode": proxy_mode, "recent_seconds": recent_seconds},
            daemon=True,
            name="mail-tool-check",
        )
        self._thread = thread
        thread.start()
        return {"started": True, "running": True, "task": task}

    def _run_check(
        self,
        accounts: list[dict[str, str]],
        *,
        action: str,
        workers: int,
        proxy_mode: str,
        recent_seconds: int,
    ) -> None:
        started = time.monotonic()

        def run_one(account: dict[str, str]) -> dict[str, Any]:
            probe = MicrosoftMailboxProbe(
                account,
                proxy=self._resolve_proxy(proxy_mode),
                cancel_check=self._cancel.is_set,
            )
            if action == "code":
                return probe.latest_code(recent_seconds=recent_seconds)
            return probe.detect()

        try:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mail-check") as executor:
                futures = {executor.submit(run_one, account): account for account in accounts}
                for future in as_completed(futures):
                    account = futures[future]
                    if self._cancel.is_set():
                        for queued in futures:
                            queued.cancel()
                        break
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "email": account["email"],
                            "protocol": "unknown",
                            "health": "error",
                            "reason": _safe_error(exc),
                            "checked_at": timeutil.now_iso(),
                            "latency_ms": None,
                        }
                    rotated = str(result.pop("_refresh_token", "") or "")
                    if rotated:
                        store.update_mail_refresh_token(
                            account["email"],
                            rotated,
                            expected_refresh_token=str(account.get("token") or ""),
                        )
                    email = str(result.get("email") or account["email"]).lower()
                    with self._lock:
                        self._results[email] = dict(result)
                        self._task["done"] = int(self._task.get("done") or 0) + 1
                        self._task["current"] = email
                        if result.get("health") == "ok":
                            self._task["ok"] = int(self._task.get("ok") or 0) + 1
                        else:
                            self._task["failed"] = int(self._task.get("failed") or 0) + 1
                        if result.get("code"):
                            self._task["codes"] = int(self._task.get("codes") or 0) + 1
                        done = int(self._task["done"])
                        total = int(self._task["total"])
                    protocol = result.get("protocol") or "unknown"
                    if result.get("health") != "ok":
                        self._log(f"{email} -> {protocol}/失败：{result.get('reason') or '-'}")
                    elif done <= 5 or done % 20 == 0 or done == total:
                        self._log(f"进度 {done}/{total}：{email} -> {protocol}")
                    if done % 10 == 0:
                        self._save_state()
        except Exception as exc:
            with self._lock:
                self._task["error"] = _safe_error(exc)
            self._log(f"邮箱检测任务异常：{exc}")
        finally:
            with self._lock:
                cancelled = self._cancel.is_set()
                self._running = False
                self._task["status"] = "stopped" if cancelled else ("failed" if self._task.get("error") else "completed")
                self._task["finished_at"] = timeutil.now_iso()
                self._task["elapsed_sec"] = round(time.monotonic() - started, 2)
                summary = dict(self._task)
            self._log(
                f"微软邮箱任务{('已停止' if cancelled else '完成')}：done={summary.get('done')}/"
                f"{summary.get('total')} ok={summary.get('ok')} failed={summary.get('failed')}"
            )
            self._save_state()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if self._running:
                self._cancel.set()
                self._task["stop_requested_at"] = timeutil.now_iso()
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            task = dict(self._task)
            running = self._running
            logs = list(self._logs)[-120:]
        for key in ("started_at", "finished_at", "stop_requested_at"):
            if task.get(key):
                task[key] = timeutil.iso_to_beijing_display(task[key])
        return {"running": running, "task": task, "logs": logs}


mail_tool_manager = MailToolManager()


__all__ = [
    "MAIL_TOOL_STATE_PATH",
    "MailCredential",
    "MailImportResult",
    "MailToolManager",
    "MicrosoftMailboxProbe",
    "mail_tool_manager",
    "parse_mail_import",
]
