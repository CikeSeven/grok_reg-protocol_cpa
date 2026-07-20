# -*- coding: utf-8 -*-
"""纯协议注册：curl_cffi + 现有邮箱配置 → SSO（不走浏览器填表）。

复用本项目已有邮箱通道：
  get_email_and_token() / get_oai_code()

Turnstile：
  单选 provider) local / yescaptcha / 2captcha（turnstile_solver_provider）
  注意：不做 provider 链式回退，失败即返回失败，避免多路验证任务互相污染。

邮箱：
  主路径) 项目 config.email_provider（推荐 hotmail + mail_credentials.txt）
  回退)  TempMail.lol（仅 provider=tempmail 或主邮箱凭证缺失/失败时）

成功产物与浏览器路径一致：
  email----password----sso  → accounts_cli.txt
  可选：继续走 cpa_export（协议 mint SSO→OIDC）
"""

from __future__ import annotations

import os
import random
import re
import secrets
import string
import struct
import threading
import time
from typing import Any, Callable, Mapping, Optional
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from curl_cffi import requests as cf_requests

import grok_register_ttk as reg

LogFn = Callable[[str], None]
SITE_URL = "https://accounts.x.ai"
SITE_KEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
DEFAULT_STATE_TREE = (
    '%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C'
    '%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C'
    '%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
)
DEFAULT_IMPERSONATE = "chrome110"


def _tempmail_create(log: LogFn | None = None) -> tuple[str, str]:
    """Free TempMail.lol fallback when project email pool not configured."""
    import requests as std_requests
    base = (str(_cfg().get("tempmail_base_url") or os.getenv("TEMPMAIL_LOL_BASE_URL") or "https://api.tempmail.lol")).rstrip("/")
    proxies = _proxy_dict() or None
    last = ""
    for attempt in range(1, 9):
        try:
            r = std_requests.post(
                base + "/v2/inbox/create",
                timeout=20,
                proxies=proxies,
                headers={
                    "Accept": "application/json",
                    "User-Agent": f"Mozilla/5.0 protocol-register/{attempt}",
                    "Origin": "https://tempmail.lol",
                    "Referer": "https://tempmail.lol/",
                },
            )
            if r.status_code in (200, 201):
                data = r.json()
                email = (data.get("address") or data.get("email") or "").lower()
                token = data.get("token") or data.get("jwt")
                if not email or not token:
                    raise RuntimeError(f"tempmail create missing fields: {r.text[:160]}")
                return email, f"tempmail::{token}"
            last = f"HTTP {r.status_code}: {r.text[:160]}"
            if r.status_code == 429:
                wait = min(12.0, 1.2 * attempt + random.uniform(0.3, 1.2))
                _log(log, f"[protocol] TempMail 限流，退避 {wait:.1f}s ({attempt}/8)")
                time.sleep(wait)
                continue
            time.sleep(0.8)
        except Exception as e:
            last = str(e)
            time.sleep(0.8)
    raise RuntimeError(f"tempmail create failed: {last}")


def _tempmail_fetch_code(dev_token: str, email: str, timeout: int = 90, poll: float = 1.5, log: LogFn | None = None) -> str:
    import requests as std_requests
    if not str(dev_token).startswith("tempmail::"):
        return ""
    token = str(dev_token).split("::", 1)[1]
    base = (str(_cfg().get("tempmail_base_url") or os.getenv("TEMPMAIL_LOL_BASE_URL") or "https://api.tempmail.lol")).rstrip("/")
    proxies = _proxy_dict() or None
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = std_requests.get(base + "/v2/inbox", params={"token": token}, timeout=20, proxies=proxies)
        if r.status_code == 200:
            data = r.json()
            emails = data.get("emails") or data.get("messages") or []
            if isinstance(data, list):
                emails = data
            for item in emails:
                subject = item.get("subject") or ""
                body = item.get("body") or item.get("text") or item.get("html") or ""
                blob = f"{subject}\n{body}"
                m = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{2,3})\b", blob, re.I)
                if m:
                    return m.group(1).upper()
                m = re.search(r"\b([A-Z0-9]{5,6})\b", blob, re.I)
                if m and ("xai" in blob.lower() or "confirmation" in blob.lower()):
                    return m.group(1).upper()
        time.sleep(poll)
        if log and int(time.time()) % 8 == 0:
            _log(log, f"[protocol] tempmail waiting code for {email}...")
    return ""



# CLI flags (set by register_cli)
FORCE_PROTOCOL = False
PROTOCOL_ONLY = False

# process-level cache
_ACTION_ID: Optional[str] = None
_ACTION_ID_TS: float = 0.0
_LOCAL_SOLVER_TASKS: set[str] = set()
_LOCAL_SOLVER_TASKS_LOCK = threading.Lock()


def _log(log: LogFn | None, msg: str) -> None:
    if log:
        log(msg)
    else:
        print(msg, flush=True)


def _sleep_with_cancel(seconds: float, cancel: Callable[[], bool] | None = None) -> bool:
    """Sleep in short slices. Return False when cancelled."""
    deadline = time.time() + max(0.0, float(seconds or 0))
    while time.time() < deadline:
        if cancel and cancel():
            return False
        time.sleep(min(0.25, max(0.0, deadline - time.time())))
    return not (cancel and cancel())


def _track_local_solver_task(task_id: str) -> None:
    if not task_id:
        return
    with _LOCAL_SOLVER_TASKS_LOCK:
        _LOCAL_SOLVER_TASKS.add(task_id)


def _untrack_local_solver_task(task_id: str) -> None:
    if not task_id:
        return
    with _LOCAL_SOLVER_TASKS_LOCK:
        _LOCAL_SOLVER_TASKS.discard(task_id)


def _cancel_local_solver_task(
    std_requests: Any,
    solver: str,
    task_id: str,
    log: LogFn | None = None,
) -> None:
    if not task_id:
        return
    try:
        std_requests.get(
            f"{solver.rstrip('/')}/cancel",
            params={"id": task_id},
            timeout=3,
        )
        _log(log, f"[protocol] local solver 已取消 task={task_id[:8]}")
    except Exception as exc:
        _log(log, f"[protocol] local solver 取消失败 task={task_id[:8]}: {exc}")


def cancel_active_local_solver_tasks(
    *,
    config: Mapping[str, Any] | None = None,
    log: LogFn | None = None,
) -> int:
    """Cancel local-solver tasks submitted by this process.

    WebUI 停止任务时调用，避免已提交给 127.0.0.1:5072 的 Turnstile
    任务在注册线程停止后继续排队/跑 Chrome。
    """
    import requests as std_requests

    solver = _solver_url(config).rstrip("/")
    with _LOCAL_SOLVER_TASKS_LOCK:
        task_ids = list(_LOCAL_SOLVER_TASKS)
    for task_id in task_ids:
        _cancel_local_solver_task(std_requests, solver, task_id, log=log)
    if task_ids:
        _log(log, f"[protocol] 已请求取消 local solver 任务 {len(task_ids)} 个")
    return len(task_ids)


def _release_or_mark_email(email: str, reason: str, password: str = "") -> None:
    """Persist only hard mailbox failures; release aliases for transient flow failures."""
    if not email:
        return
    try:
        should_mark = bool(reg.should_persist_email_error(reason))
    except Exception:
        should_mark = False
    try:
        if should_mark:
            reg.mark_error(email, password or "", reason=str(reason)[:120])
        else:
            reg.release_email(email)
    except Exception:
        pass


def _cfg(config_override: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    if config_override is not None:
        return config_override
    return getattr(reg, "config", {}) or {}


def _thread_proxy_url() -> str:
    try:
        return str(reg.get_thread_proxy() or "").strip()
    except Exception:
        return ""


def _set_thread_proxy_once(raw: str) -> None:
    if not raw or _thread_proxy_url():
        return
    try:
        reg.set_thread_proxy(raw)
    except Exception:
        pass


def _resolve_proxy_url(raw: str | None, *, pin_pool_random: bool = False) -> str:
    """Resolve config proxy value to an actual HTTP client proxy URL.

    `pool:random` is a config sentinel, not a real proxy. Protocol register
    passes a config mapping into this module, so it cannot rely on
    reg.get_effective_proxy() alone; resolve the sentinel here and pin the
    selected proxy to the current worker thread so registration HTTP, solver
    and 2Captcha use the same egress for this account.
    """
    raw = str(raw or "").strip()
    if not raw:
        return ""
    try:
        import proxy_pool

        pool_random = getattr(proxy_pool, "POOL_RANDOM", "pool:random")
        if raw == pool_random:
            pinned = _thread_proxy_url()
            if pinned:
                return pinned
            resolved = proxy_pool.resolve_special(raw)
            url = (
                proxy_pool.effective_url(resolved)
                or proxy_pool.normalize_proxy_url(resolved)
                or ""
            )
            if pin_pool_random and url:
                _set_thread_proxy_once(url)
            return url
        return (
            proxy_pool.effective_url(raw)
            or proxy_pool.normalize_proxy_url(raw)
            or raw
        )
    except Exception:
        if raw == "pool:random":
            return ""
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw


def _proxy_dict(config_override: Mapping[str, Any] | None = None) -> dict:
    """curl_cffi proxies dict from project config."""
    raw = _thread_proxy_url()
    if not raw:
        raw = str(_cfg(config_override).get("proxy") or "").strip()
    if not raw and config_override is None:
        try:
            raw = str(reg.get_effective_proxy() or "").strip()
        except Exception:
            raw = ""
    if not raw:
        raw = (
            os.getenv("HTTPS_PROXY")
            or os.getenv("https_proxy")
            or os.getenv("HTTP_PROXY")
            or os.getenv("http_proxy")
            or ""
        ).strip()
    if not raw:
        return {}
    proxy_url = _resolve_proxy_url(raw, pin_pool_random=True)
    if not proxy_url:
        return {}
    return {"http": proxy_url, "https": proxy_url}


def _solver_proxy_url(config_override: Mapping[str, Any] | None = None) -> str:
    """Proxy URL to pass to the local Turnstile solver.

    This intentionally follows the registration proxy (thread-pinned proxy pool
    entry > config.proxy). Environment proxies are not included here because the
    goal is to make Turnstile use the same per-account egress as registration.
    """
    cfg = _cfg(config_override)
    if cfg.get("protocol_solver_pass_proxy") is False:
        return ""

    raw = ""
    try:
        raw = str(reg.get_thread_proxy() or "").strip()
    except Exception:
        raw = ""
    if not raw:
        raw = str(cfg.get("proxy") or "").strip()
    if not raw and config_override is None:
        try:
            raw = str(reg.get_effective_proxy() or "").strip()
        except Exception:
            raw = ""
    if not raw and config_override is None:
        try:
            proxies = reg.get_proxies() or {}
            if isinstance(proxies, dict):
                raw = str(proxies.get("https") or proxies.get("http") or "").strip()
        except Exception:
            raw = ""
    return _resolve_proxy_url(raw, pin_pool_random=True)


def _mask_proxy(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        u = urlsplit(raw if "://" in raw else "http://" + raw)
        netloc = u.hostname or ""
        if u.port:
            netloc += f":{u.port}"
        if u.username:
            netloc = f"***:***@{netloc}"
        return urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment))
    except Exception:
        return "***"


def _impersonate(config_override: Mapping[str, Any] | None = None) -> str:
    return str(
        _cfg(config_override).get("protocol_impersonate") or DEFAULT_IMPERSONATE
    ).strip() or DEFAULT_IMPERSONATE


def _ua(config_override: Mapping[str, Any] | None = None) -> str:
    configured = str(_cfg(config_override).get("user_agent") or "").strip()
    if configured:
        return configured
    try:
        return reg.get_user_agent()
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/110.0.0.0 Safari/537.36"
        )


def _encode_grpc_string(field_id: int, value: str) -> bytes:
    key = (field_id << 3) | 2
    b = value.encode("utf-8")
    return struct.pack("B", key) + struct.pack("B", len(b)) + b


def _encode_grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_create_email_code(email: str) -> bytes:
    return _encode_grpc_frame(_encode_grpc_string(1, email))


def encode_verify_email_code(email: str, code: str) -> bytes:
    payload = _encode_grpc_string(1, email) + _encode_grpc_string(2, code)
    return _encode_grpc_frame(payload)


def fetch_action_id(
    session: cf_requests.Session,
    log: LogFn | None = None,
    force: bool = False,
    *,
    site_url: str = SITE_URL,
) -> str:
    """Scan sign-up page JS for next-action id (7f...)."""
    global _ACTION_ID, _ACTION_ID_TS
    # cache 30 min
    if not force and _ACTION_ID and (time.time() - _ACTION_ID_TS) < 1800:
        return _ACTION_ID

    start_url = f"{site_url}/sign-up?redirect=grok-com"
    html = session.get(start_url, timeout=20).text
    js_urls = [
        urljoin(start_url, m.group(1))
        for m in re.finditer(r'''<script[^>]+src=["']([^"']*_next/static/[^"']+)["']''', html, re.I)
    ]
    for js_url in js_urls:
        try:
            js_content = session.get(js_url, timeout=15).text
            m = re.search(r"7f[a-fA-F0-9]{40}", js_content)
            if m:
                _ACTION_ID = m.group(0)
                _ACTION_ID_TS = time.time()
                _log(log, f"[protocol] Action ID: {_ACTION_ID}")
                return _ACTION_ID
        except Exception as e:
            _log(log, f"[protocol] 读取 JS 失败: {e}")
            continue
    raise RuntimeError("未找到 Action ID（网站结构可能已变）")


def send_email_code(
    session: cf_requests.Session,
    email: str,
    log: LogFn | None = None,
    *,
    site_url: str = SITE_URL,
) -> bool:
    url = f"{site_url}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
    headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": site_url,
        "referer": f"{site_url}/sign-up?redirect=grok-com",
    }
    res = session.post(url, data=encode_create_email_code(email), headers=headers, timeout=20)
    if res.status_code != 200:
        _log(log, f"[protocol] 发送验证码失败 HTTP {res.status_code}")
        return False
    grpc_status = res.headers.get("grpc-status")
    if grpc_status not in (None, "0", 0, "0"):
        msg = res.headers.get("grpc-message", "")
        _log(log, f"[protocol] 发送验证码被拒 grpc-status={grpc_status} {msg}")
        return False
    return True


def verify_email_code(
    session: cf_requests.Session,
    email: str,
    code: str,
    log: LogFn | None = None,
    *,
    site_url: str = SITE_URL,
) -> bool:
    url = f"{site_url}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
    headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": site_url,
        "referer": f"{site_url}/sign-up?redirect=grok-com",
    }
    # normalize code: WAHWKH or 5LJ-IXR
    code_n = (code or "").replace("-", "").strip()
    # API often wants original form; try raw first then normalized
    for candidate in (code, code_n):
        if not candidate:
            continue
        res = session.post(
            url,
            data=encode_verify_email_code(email, candidate),
            headers=headers,
            timeout=20,
        )
        grpc_status = res.headers.get("grpc-status")
        if res.status_code == 200 and grpc_status in (None, "0", 0, "0"):
            return True
        _log(log, f"[protocol] 验证码校验未过 status={res.status_code} grpc={grpc_status}")
    return False


def _yescaptcha_key(config_override: Mapping[str, Any] | None = None) -> str:
    return (
        str(_cfg(config_override).get("yescaptcha_key") or "").strip()
        or os.getenv("YESCAPTCHA_KEY", "").strip()
    )


def _twocaptcha_key(config_override: Mapping[str, Any] | None = None) -> str:
    return (
        str(_cfg(config_override).get("twocaptcha_key") or "").strip()
        or os.getenv("TWOCAPTCHA_KEY", "").strip()
        or os.getenv("TWO_CAPTCHA_KEY", "").strip()
        or os.getenv("CAPTCHA_2CAPTCHA_KEY", "").strip()
    )


def _twocaptcha_enabled(config_override: Mapping[str, Any] | None = None) -> bool:
    cfg = _cfg(config_override)
    if cfg.get("twocaptcha_enabled") is False:
        return False
    return bool(_twocaptcha_key(config_override))


def _twocaptcha_api_base(config_override: Mapping[str, Any] | None = None) -> str:
    return (
        str(_cfg(config_override).get("twocaptcha_api_base") or "").strip()
        or os.getenv("TWOCAPTCHA_API_BASE", "").strip()
        or "https://api.2captcha.com"
    ).rstrip("/")


def _turnstile_solver_provider(config_override: Mapping[str, Any] | None = None) -> str:
    raw = (
        str(_cfg(config_override).get("turnstile_solver_provider") or "").strip()
        or os.getenv("TURNSTILE_SOLVER_PROVIDER", "").strip()
        or "local"
    ).lower()
    raw = raw.replace("_", "-").replace(" ", "")
    aliases = {
        "local": "local",
        "solver": "local",
        "localsolver": "local",
        "local-solver": "local",
        "yes": "yescaptcha",
        "yescaptcha": "yescaptcha",
        "2captcha": "2captcha",
        "twocaptcha": "2captcha",
        "two-captcha": "2captcha",
    }
    return aliases.get(raw, "local")


def _twocaptcha_proxy_fields(raw: str | None) -> dict[str, Any]:
    """Convert a URL proxy into 2Captcha TurnstileTask proxy fields."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    if "://" not in raw:
        raw = "http://" + raw
    u = urlsplit(raw)
    host = u.hostname or ""
    port = u.port
    if not host or not port:
        return {}
    scheme = (u.scheme or "http").lower()
    if scheme in {"http", "https"}:
        proxy_type = "http"
    elif scheme in {"socks4", "socks4a"}:
        proxy_type = "socks4"
    elif scheme in {"socks", "socks5", "socks5h"}:
        proxy_type = "socks5"
    else:
        return {}
    fields: dict[str, Any] = {
        "proxyType": proxy_type,
        "proxyAddress": host,
        "proxyPort": int(port),
    }
    if u.username:
        fields["proxyLogin"] = unquote(u.username)
    if u.password:
        fields["proxyPassword"] = unquote(u.password)
    return fields


def _solver_url(config_override: Mapping[str, Any] | None = None) -> str:
    return (
        str(_cfg(config_override).get("protocol_solver_url") or "").strip()
        or os.getenv("SOLVER_URL", "").strip()
        or "http://127.0.0.1:5072"
    )


def _solve_twocaptcha(
    std_requests: Any,
    *,
    cfg: Mapping[str, Any],
    siteurl: str,
    sitekey: str,
    log: LogFn | None = None,
    config: Mapping[str, Any] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> Optional[str]:
    key = _twocaptcha_key(config)
    if not key:
        return None
    api_base = _twocaptcha_api_base(config)
    pass_proxy = cfg.get("twocaptcha_pass_proxy", True) is not False
    proxy_url = str(cfg.get("twocaptcha_proxy") or "").strip()
    if pass_proxy and not proxy_url:
        proxy_url = _solver_proxy_url(config)

    task: dict[str, Any] = {
        "type": "TurnstileTaskProxyless",
        "websiteURL": siteurl,
        "websiteKey": sitekey,
    }
    if pass_proxy and proxy_url:
        proxy_fields = _twocaptcha_proxy_fields(proxy_url)
        if proxy_fields:
            task["type"] = "TurnstileTask"
            task.update(proxy_fields)
            _log(log, f"[protocol] 2Captcha 使用注册代理 {_mask_proxy(proxy_url)}")
        else:
            _log(log, "[protocol] 2Captcha 代理格式无法识别，改用 proxyless")

    # Optional Cloudflare Challenge fields.  Standalone Turnstile can omit them.
    action = str(cfg.get("twocaptcha_action") or "").strip()
    if action:
        task["action"] = action
    data = str(
        cfg.get("twocaptcha_data") or cfg.get("twocaptcha_cdata") or ""
    ).strip()
    if data:
        task["data"] = data
    pagedata = str(cfg.get("twocaptcha_pagedata") or "").strip()
    if pagedata:
        task["pagedata"] = pagedata
    ua = str(cfg.get("twocaptcha_user_agent") or "").strip()
    if ua:
        task["userAgent"] = ua

    timeout_s = int(
        cfg.get("twocaptcha_timeout")
        or os.getenv("TWOCAPTCHA_TIMEOUT_SECONDS", "120")
        or "120"
    )
    poll_interval = max(
        1.0,
        float(cfg.get("twocaptcha_poll_interval") or os.getenv("TWOCAPTCHA_POLL_INTERVAL", "5") or 5),
    )

    _log(log, "[protocol] Turnstile 主路径 2Captcha")
    r = std_requests.post(
        f"{api_base}/createTask",
        json={"clientKey": key, "task": task},
        timeout=30,
    )
    data_resp = r.json()
    if data_resp.get("errorId") != 0:
        raise RuntimeError(data_resp.get("errorDescription") or data_resp)
    task_id = data_resp.get("taskId")
    if not task_id:
        raise RuntimeError(f"2Captcha no taskId: {data_resp}")

    deadline = time.time() + max(1, timeout_s)
    while time.time() < deadline:
        if not _sleep_with_cancel(poll_interval, cancel):
            _log(log, "[protocol] 2Captcha 已取消")
            return None
        rr = std_requests.post(
            f"{api_base}/getTaskResult",
            json={"clientKey": key, "taskId": task_id},
            timeout=20,
        )
        d = rr.json()
        if d.get("errorId") not in (0, None):
            raise RuntimeError(d.get("errorDescription") or d)
        if d.get("status") == "ready":
            token = str((d.get("solution") or {}).get("token") or "").strip()
            if token:
                _log(log, "[protocol] 2Captcha OK")
                return token
            raise RuntimeError(f"2Captcha ready without token: {d}")
    raise RuntimeError("2Captcha timeout")


def solve_turnstile(
    log: LogFn | None = None,
    *,
    config: Mapping[str, Any] | None = None,
    site_url: str = SITE_URL,
    cancel: Callable[[], bool] | None = None,
) -> Optional[str]:
    """Solve Turnstile using exactly one configured provider."""
    import requests as std_requests

    cfg = _cfg(config)
    siteurl = site_url
    sitekey = str(cfg.get("turnstile_site_key") or SITE_KEY)
    provider = _turnstile_solver_provider(config)
    _log(log, f"[protocol] Turnstile provider={provider}")
    if cancel and cancel():
        _log(log, "[protocol] Turnstile 已取消")
        return None

    if provider == "yescaptcha":
        key = _yescaptcha_key(config)
        if not key:
            _log(log, "[protocol] YesCaptcha 未配置 key")
            return None
        try:
            _log(log, "[protocol] Turnstile 使用 YesCaptcha")
            r = std_requests.post(
                "https://api.yescaptcha.com/createTask",
                json={
                    "clientKey": key,
                    "task": {
                        "type": "TurnstileTaskProxyless",
                        "websiteURL": siteurl,
                        "websiteKey": sitekey,
                    },
                },
                timeout=30,
            )
            data = r.json()
            if data.get("errorId") != 0:
                raise RuntimeError(data.get("errorDescription") or data)
            task_id = data.get("taskId")
            for _ in range(60):
                if not _sleep_with_cancel(2, cancel):
                    _log(log, "[protocol] YesCaptcha 已取消")
                    return None
                rr = std_requests.post(
                    "https://api.yescaptcha.com/getTaskResult",
                    json={"clientKey": key, "taskId": task_id},
                    timeout=15,
                )
                d = rr.json()
                if d.get("status") == "ready":
                    token = (d.get("solution") or {}).get("token")
                    if token:
                        _log(log, "[protocol] YesCaptcha OK")
                        return token
                    break
                if d.get("errorId") not in (0, None):
                    raise RuntimeError(d.get("errorDescription") or d)
            _log(log, "[protocol] YesCaptcha 超时")
        except Exception as e:
            _log(log, f"[protocol] YesCaptcha 失败: {e}")
        return None

    if provider == "2captcha":
        if not _twocaptcha_key(config):
            _log(log, "[protocol] 2Captcha 未配置 key")
            return None
        try:
            token = _solve_twocaptcha(
                std_requests,
                cfg=cfg,
                siteurl=siteurl,
                sitekey=sitekey,
                log=log,
                config=config,
                cancel=cancel,
            )
            if token:
                return token
            _log(log, "[protocol] 2Captcha 未返回 token")
        except Exception as e:
            _log(log, f"[protocol] 2Captcha 失败: {e}")
        return None

    solver = _solver_url(config).rstrip("/")
    task_id = ""
    try:
        _log(log, f"[protocol] Turnstile 回退本地 solver {solver}")
        params = {"url": siteurl, "sitekey": sitekey}
        solver_proxy = _solver_proxy_url(config)
        if solver_proxy:
            params["proxy"] = solver_proxy
            _log(log, f"[protocol] local solver 使用注册代理 {_mask_proxy(solver_proxy)}")
        elif cfg.get("protocol_solver_pass_proxy") is not False:
            _log(log, "[protocol] local solver 未收到注册代理，将使用 solver 默认出口")
        solver_timezone = str(
            cfg.get("protocol_solver_timezone") or cfg.get("browser_timezone") or ""
        ).strip()
        if solver_timezone:
            params["timezone"] = solver_timezone
        solver_locale = str(cfg.get("protocol_solver_locale") or "").strip()
        if solver_locale:
            params["locale"] = solver_locale
        solver_accept_language = str(
            cfg.get("protocol_solver_accept_language") or ""
        ).strip()
        if solver_accept_language:
            params["accept_language"] = solver_accept_language
        if cancel and cancel():
            _log(log, "[protocol] local solver 提交前已取消")
            return None
        submit_timeout = max(
            2,
            min(30, int(cfg.get("protocol_solver_submit_timeout") or 10)),
        )
        r = std_requests.get(
            f"{solver}/turnstile",
            params=params,
            timeout=submit_timeout,
        )
        r.raise_for_status()
        task_id = r.json().get("taskId")
        if not task_id:
            raise RuntimeError(f"local solver no taskId: {r.text[:200]}")
        task_id = str(task_id)
        _track_local_solver_task(task_id)
        timeout_s = int(
            cfg.get("protocol_solver_poll_timeout")
            or os.getenv("LOCAL_SOLVER_TIMEOUT_SECONDS", "30")
            or "30"
        )
        poll_interval = max(
            0.2, float(cfg.get("protocol_solver_poll_interval", 1.2) or 1.2)
        )
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if cancel and cancel():
                _log(log, "[protocol] local solver 已取消")
                _cancel_local_solver_task(std_requests, solver, task_id, log=log)
                return None
            if not _sleep_with_cancel(poll_interval, cancel):
                _log(log, "[protocol] local solver 已取消")
                _cancel_local_solver_task(std_requests, solver, task_id, log=log)
                return None
            rr = std_requests.get(f"{solver}/result", params={"id": task_id}, timeout=15)
            rr.raise_for_status()
            token = ((rr.json().get("solution") or {}).get("token") or "").strip()
            if token and token != "CAPTCHA_FAIL":
                _log(log, "[protocol] local solver OK")
                return token
            if token == "CAPTCHA_FAIL":
                raise RuntimeError("local solver CAPTCHA_FAIL")
        raise RuntimeError("local solver timeout")
    except Exception as e:
        _log(log, f"[protocol] local solver 失败: {e}")
        return None
    finally:
        if task_id:
            _untrack_local_solver_task(task_id)


def accept_tos(
    session: cf_requests.Session,
    sso: str,
    sso_rw: str,
    log: LogFn | None = None,
    *,
    site_url: str = SITE_URL,
) -> bool:
    url = f"{site_url}/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = _encode_grpc_frame(payload)
    headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": site_url,
        "referer": f"{site_url}/accept-tos",
    }
    # ensure cookies
    try:
        session.cookies.set("sso", sso, domain=".x.ai")
        session.cookies.set("sso-rw", sso_rw or sso, domain=".x.ai")
    except Exception:
        pass
    res = session.post(url, data=data, headers=headers, timeout=20)
    ok = res.status_code == 200 and res.headers.get("grpc-status") in (None, "0", 0, "0")
    if not ok:
        _log(log, f"[protocol] TOS 失败 status={res.status_code} grpc={res.headers.get('grpc-status')}")
    return ok


def _pick_cookie(session: cf_requests.Session, name: str) -> str:
    try:
        v = session.cookies.get(name)
        if v:
            return str(v)
    except Exception:
        pass
    try:
        for c in session.cookies.jar:  # type: ignore[attr-defined]
            if getattr(c, "name", None) == name and getattr(c, "value", None):
                return str(c.value)
    except Exception:
        pass
    return ""


def register_one_protocol(
    *,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
    mailbox_provider: Any | None = None,
    config: Mapping[str, Any] | None = None,
    site_url: str | None = None,
) -> dict[str, Any]:
    """Run one full protocol registration. Returns dict(ok, email, password, sso, ...)."""
    cfg = _cfg(config)
    target_site = (site_url or str(cfg.get("accounts_base_url") or SITE_URL)).rstrip("/")
    proxies = _proxy_dict(cfg)
    impersonate = _impersonate(cfg)
    ua = _ua(cfg)
    flow_started = time.perf_counter()

    def timing(stage: str, started: float) -> None:
        _log(log, f"[timing] registration.{stage}={time.perf_counter() - started:.3f}s")

    def cancelled() -> bool:
        return bool(cancel and cancel())

    with cf_requests.Session(impersonate=impersonate, proxies=proxies or None) as session:
        session.headers.update({"user-agent": ua})
        try:
            session.get(target_site, timeout=15)
        except Exception:
            pass

        if cancelled():
            return {"ok": False, "error": "cancelled"}

        # 1) email from existing project providers (hotmail/cloudmail/...)
        #    fallback: tempmail.lol when provider=tempmail or credentials missing
        mailbox_started = time.perf_counter()
        provider = str(cfg.get("email_provider") or "").strip().lower()
        allow_tempmail_fallback = bool(cfg.get("protocol_email_tempmail_fallback", False)) or provider in {
            "tempmail", "tempmail.lol", "lol"
        }
        use_tempmail = provider in {"tempmail", "tempmail.lol", "lol"}
        email, dev_token = "", ""
        mailbox_handle = None
        if mailbox_provider is not None:
            try:
                mailbox_handle = mailbox_provider.create_mailbox()
                email = str(mailbox_handle.email or "")
            except Exception as e:
                return {"ok": False, "error": f"mailbox_create: {e}"}
        elif not use_tempmail:
            try:
                email, dev_token = reg.get_email_and_token()
            except Exception as e:
                msg = str(e)
                _log(log, f"[protocol] 主邮箱通道失败: {msg}")
                # 仅显式开启回退，或 provider 本身就是 tempmail 时才走 TempMail
                if allow_tempmail_fallback and provider not in {"tempmail", "tempmail.lol", "lol"}:
                    _log(log, "[protocol] 已开启 protocol_email_tempmail_fallback，回退 TempMail.lol")
                    use_tempmail = True
                elif provider in {"tempmail", "tempmail.lol", "lol"}:
                    use_tempmail = True
                else:
                    return {"ok": False, "error": f"get_email_and_token: {e}"}
        if mailbox_provider is None and use_tempmail:
            try:
                email, dev_token = _tempmail_create(log=log)
                _log(log, f"[protocol] 回退邮箱 TempMail.lol: {email}")
            except Exception as e:
                return {"ok": False, "error": f"tempmail fallback: {e}"}
        email = (email or "").strip()
        if not email:
            return {"ok": False, "error": "empty email"}
        timing("mailbox_create", mailbox_started)
        _log(log, f"[protocol] 邮箱已创建: {email}")

        if cancelled():
            if mailbox_provider is None:
                _release_or_mark_email(email, "cancelled")
            return {"ok": False, "email": email, "error": "cancelled"}

        # 2) send code
        send_code_started = time.perf_counter()
        issued_after = time.time()
        if not send_email_code(session, email, log=log, site_url=target_site):
            if mailbox_provider is None:
                _release_or_mark_email(email, "send_code_fail")
            return {"ok": False, "email": email, "error": "send_email_code failed"}
        timing("send_code", send_code_started)

        # 3) fetch code via existing provider / tempmail
        mail_timeout = int(cfg.get("mail_timeout", 150) or 150)
        poll = float(cfg.get("mail_poll_interval", 1.5) or 1.5)
        poll = max(poll, 1.0)
        otp_started = time.perf_counter()
        try:
            if mailbox_provider is not None:
                code = mailbox_provider.wait_for_otp(
                    mailbox_handle,
                    issued_after=issued_after,
                    timeout=mail_timeout,
                )
            elif str(dev_token).startswith("tempmail::"):
                code = _tempmail_fetch_code(dev_token, email, timeout=mail_timeout, poll=poll, log=log)
            else:
                code = reg.get_oai_code(
                    dev_token,
                    email,
                    timeout=mail_timeout,
                    poll_interval=poll,
                    log_callback=log,
                    cancel_callback=cancel,
                    issued_after=issued_after,
                )
        except Exception as e:
            if mailbox_provider is None:
                _release_or_mark_email(email, str(e))
            return {"ok": False, "email": email, "error": f"get_oai_code: {e}"}
        if not code:
            if mailbox_provider is None:
                _release_or_mark_email(email, "no verification code")
            return {"ok": False, "email": email, "error": "no verification code"}
        timing("otp_wait", otp_started)
        _log(log, "[protocol] 验证码已收到")

        if cancelled():
            if mailbox_provider is None:
                _release_or_mark_email(email, "cancelled")
            return {"ok": False, "email": email, "error": "cancelled"}

        # 4) verify code
        verify_started = time.perf_counter()
        if not verify_email_code(session, email, code, log=log, site_url=target_site):
            if mailbox_provider is None:
                _release_or_mark_email(email, "verify_email_code failed")
            return {"ok": False, "email": email, "error": "verify_email_code failed"}
        timing("otp_verify", verify_started)

        # 5) action id + profile
        profile_started = time.perf_counter()
        try:
            action_id = fetch_action_id(session, log=log, site_url=target_site)
        except Exception as e:
            if mailbox_provider is None:
                _release_or_mark_email(email, f"action_id: {e}")
            return {"ok": False, "email": email, "error": f"action_id: {e}"}
        given_name, family_name, password = reg.build_profile()
        state_tree = str(cfg.get("protocol_state_tree") or DEFAULT_STATE_TREE)
        timing("profile_prepare", profile_started)

        max_attempts = max(1, int(cfg.get("protocol_register_max_attempts", cfg.get("turnstile_retry_limit", 3)) or 3))
        sso = ""
        sso_rw = ""
        last_err = ""

        for attempt in range(1, max_attempts + 1):
            if cancelled():
                if mailbox_provider is None:
                    _release_or_mark_email(email, "cancelled")
                return {"ok": False, "email": email, "error": "cancelled"}
            turnstile_started = time.perf_counter()
            token = solve_turnstile(
                log=log,
                config=cfg,
                site_url=target_site,
                cancel=cancelled,
            )
            timing(f"turnstile_attempt_{attempt}", turnstile_started)
            if not token:
                last_err = "turnstile solve failed"
                _log(log, f"[protocol] Turnstile 失败 ({attempt}/{max_attempts})")
                continue

            headers = {
                "user-agent": ua,
                "accept": "text/x-component",
                "content-type": "text/plain;charset=UTF-8",
                "origin": target_site,
                "referer": f"{target_site}/sign-up",
                "cookie": f"__cf_bm={_pick_cookie(session, '__cf_bm')}",
                "next-router-state-tree": state_tree,
                "next-action": action_id,
            }
            payload = [
                {
                    "emailValidationCode": str(code).replace("-", ""),
                    "createUserAndSessionRequest": {
                        "email": email,
                        "givenName": given_name,
                        "familyName": family_name,
                        "clearTextPassword": password,
                        "tosAcceptedVersion": "$undefined",
                    },
                    "turnstileToken": token,
                    "promptOnDuplicateEmail": True,
                }
            ]
            # try both dashed/undashed code if needed
            if "-" in str(code):
                payload[0]["emailValidationCode"] = str(code)

            signup_started = time.perf_counter()
            res = session.post(f"{target_site}/sign-up", json=payload, headers=headers, timeout=40)
            timing(f"signup_post_attempt_{attempt}", signup_started)
            if res.status_code != 200:
                last_err = f"sign-up HTTP {res.status_code}"
                _log(log, f"[protocol] {last_err} body={(res.text or '')[:180]}")
                # maybe action id stale
                if res.status_code in (400, 404, 409, 500):
                    try:
                        action_id = fetch_action_id(
                            session, log=log, force=True, site_url=target_site
                        )
                    except Exception:
                        pass
                continue

            m = re.search(r'(https://[^"\s]+set-cookie\?q=[^:"\s]+)1:', res.text)
            if not m:
                # some responses embed differently
                m = re.search(r'(https://[^"\s]*set-cookie\?q=[^"\s]+)', res.text)
            if not m:
                last_err = "set-cookie url not found"
                _log(log, f"[protocol] {last_err} body={(res.text or '')[:240]}")
                continue

            verify_url = m.group(1)
            # trim trailing junk if any
            verify_url = verify_url.rstrip("\\")
            session.get(verify_url, allow_redirects=True, timeout=30)
            sso = _pick_cookie(session, "sso")
            sso_rw = _pick_cookie(session, "sso-rw") or sso
            if sso:
                break
            last_err = "sso cookie missing after set-cookie"
            _log(log, f"[protocol] {last_err}")

        if not sso:
            if mailbox_provider is None:
                _release_or_mark_email(email, last_err if last_err else "no_sso", password=password or "")
            return {"ok": False, "email": email, "password": password, "error": last_err or "no sso"}

        # 6) TOS
        tos_started = time.perf_counter()
        if not accept_tos(
            session, sso, sso_rw or sso, log=log, site_url=target_site
        ):
            _log(log, "[protocol] TOS 警告：未成功，但 SSO 已拿到，继续保存")

        timing("tos", tos_started)
        profile = {
            "given_name": given_name,
            "family_name": family_name,
            "password": password,
            "email": email,
        }
        timing("total", flow_started)
        _log(log, "[protocol] 注册成功，SSO 已取得")
        try:
            if mailbox_provider is None:
                reg.mark_used(email, password)
        except Exception:
            pass

        return {
            "ok": True,
            "email": email,
            "password": password,
            "sso": sso,
            "sso_rw": sso_rw or sso,
            "profile": profile,
            "cookies": [
                {"name": "sso", "value": sso, "domain": ".x.ai"},
                {"name": "sso-rw", "value": sso_rw or sso, "domain": ".x.ai"},
            ],
            "mint_method": "protocol_register",
        }


def register_and_save(
    accounts_file: str,
    *,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
    do_mint: bool = True,
    mint_inline: bool = True,
    mint_queue=None,
) -> dict[str, Any]:
    """Register via protocol, append accounts file, optional CPA mint enqueue."""
    result = register_one_protocol(log=log, cancel=cancel)
    if not result.get("ok"):
        return result

    email = result["email"]
    password = result["password"]
    sso = result["sso"]
    line = f"{email}----{password}----{sso}\n"
    try:
        with open(accounts_file, "a", encoding="utf-8") as f:
            f.write(line)
        _log(log, f"[protocol] 已写入 {accounts_file}")
    except Exception as e:
        result["ok"] = False
        result["error"] = f"write accounts: {e}"
        return result

    # grok2api pool optional
    try:
        reg.add_token_to_grok2api_pools(sso, email=email, log_callback=log)
    except Exception as e:
        _log(log, f"[protocol] grok2api: {e}")

    job = {
        "email": email,
        "password": password,
        "sso": sso,
        "profile": result.get("profile") or {},
        "cookies": result.get("cookies") or [],
    }
    result["job"] = job

    if not do_mint:
        return result

    if mint_inline:
        try:
            import cpa_export

            mint_res = cpa_export.export_cpa_xai_for_account(
                email,
                password,
                page=None,
                cookies=job["cookies"],
                sso=sso,
                config=dict(_cfg()),
                log_callback=log,
            )
            result["cpa"] = mint_res
        except Exception as e:
            _log(log, f"[protocol] CPA mint 异常: {e}")
            result["cpa"] = {"ok": False, "error": str(e)}
    elif mint_queue is not None:
        mint_queue.put(job)
        _log(log, f"[protocol] enqueued mint for {email}")
    return result


if __name__ == "__main__":
    import argparse

    reg.load_config()
    ap = argparse.ArgumentParser(description="Protocol register (SSO) using project email providers")
    ap.add_argument("-c", "--count", type=int, default=1)
    ap.add_argument("--accounts-file", default=os.path.join(os.path.dirname(__file__), "accounts_cli.txt"))
    ap.add_argument("--no-mint", action="store_true")
    args = ap.parse_args()
    ok = 0
    for i in range(1, args.count + 1):
        print(f"\n===== protocol register {i}/{args.count} =====", flush=True)
        r = register_and_save(
            args.accounts_file,
            do_mint=not args.no_mint,
            mint_inline=True,
        )
        if r.get("ok"):
            ok += 1
            print(f"+ OK {r.get('email')} sso={str(r.get('sso'))[:20]}...", flush=True)
        else:
            print(f"- FAIL {r}", flush=True)
    print(f"\ndone success={ok}/{args.count}", flush=True)
