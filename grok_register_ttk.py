#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 DrissionPage_example.py, openai_register.py, batch_open_nsfw.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import time
import os
import sys
import queue
import secrets
import struct
import random
import re
import string
import json

from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.errors import PageDisconnectedError
from curl_cffi import requests


CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
MAX_REGISTER_THREADS = 100

DEFAULT_CONFIG = {
    "duckmail_api_key": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_admin_password": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/admin/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/parsed_mails",
    "proxy": "http://127.0.0.1:7890",
    "register_headless": False,
    "enable_nsfw": True,
    "register_count": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "grok2api_auto_add_local": True,
    "grok2api_local_token_file": "",
    "grok2api_pool_name": "ssoBasic",
    "grok2api_auto_add_remote": False,
    "grok2api_remote_base": "",
    "grok2api_remote_app_key": "",
    "register_threads": 1,
    "thread_start_interval": 0.8,
    "show_tutorial_on_start": True,
    "cloudmail_url": "",
    "cloudmail_admin_email": "",
    "cloudmail_password": "",
    "mailnest_api_key": "",
    "mailnest_project_code": "x-ai001",
    "cpa_gui_close_mint_browser": True,
    "hotmail_accounts_file": "mail_credentials.txt",
    "hotmail_alias_mode": "random",
    "hotmail_alias_random_length": 8,
    "hotmail_alias_random_max_attempts": 200,
    "hotmail_max_aliases_per_account": 5,
    "hotmail_poll_interval": 5,
    "hotmail_recent_seconds": 900,
    "hotmail_issued_after_grace_seconds": 10,
    "hotmail_oauth_network_retries": 2,
    "hotmail_oauth_retry_delay_sec": 1.0,
    "hotmail_imap_hosts": "outlook.office365.com,imap-mail.outlook.com",
    "hotmail_imap_last_n": 30,
    "hotmail_require_recipient_match": True,
    # auto: 按凭证授权自动探测（IMAP scope refresh + XOAUTH2 试登录）；imap/graph: 强制
    "hotmail_protocol": "auto",
    # Graph 收码扫描的文件夹（ChatGPT 验证码常落 Junk）
    "hotmail_graph_folders": "inbox,junkemail",
    # 注册阶段协议路径：curl_cffi 重放 accounts.x.ai 注册请求拿 SSO；失败可回退浏览器。
    "protocol_register": False,
    "protocol_only": False,
    "protocol_register_fallback_browser": True,
    "protocol_solver_url": "http://127.0.0.1:5072",
    "protocol_solver_pass_proxy": True,
    "protocol_solver_locale": "",
    "protocol_solver_accept_language": "",
    "protocol_solver_timezone": "",
    "protocol_impersonate": "chrome110",
    "protocol_register_max_attempts": 3,
    "protocol_solver_poll_timeout": 30,
    "protocol_solver_poll_interval": 1.2,
    "yescaptcha_key": "",
    "turnstile_site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
    "protocol_email_tempmail_fallback": False,
    "cpa_pkce_network_retries": 1,
    "cpa_pkce_network_retry_delay_sec": 1.5,
    # 浏览器时区覆盖（留空不覆盖；用美区代理时建议 America/New_York 等）
    "browser_timezone": "",
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0
# CloudMail 公开 token 单例（多线程共享，避免并发覆盖）
_cloudmail_public_token = None
_cloudmail_public_token_lock = threading.Lock()
_cpa_gui_export_lock = threading.Lock()
_hotmail_accounts_cache = None
_hotmail_accounts_mtime = None
_hotmail_accounts_lock = threading.Lock()
_hotmail_selection_lock = threading.Lock()
_hotmail_reserved_aliases = set()
_hotmail_token_map = {}
_hotmail_refresh_locks = {}
_hotmail_refresh_locks_lock = threading.Lock()
_hotmail_protocol_map = {}
_thread_proxy = threading.local()



# ── 邮箱追踪 ──

_EMAILS_USED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails_used.txt")
_EMAILS_ERROR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails_error.txt")
_email_track_lock = threading.Lock()
_email_issued_after_map = {}


def mark_used(email: str, password: str = ""):
    """记录成功注册的邮箱，防止重复使用。"""
    with _email_track_lock:
        with open(_EMAILS_USED_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}----{password}----ok\n")
    release_email(email)


def mark_error(email: str, password: str = "", reason: str = ""):
    """记录失败邮箱及原因，避免重试烂邮箱。"""
    with _email_track_lock:
        with open(_EMAILS_ERROR_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}----{password}----{reason}\n")
    release_email(email)


def release_email(email: str):
    """释放运行期占用的邮箱/别名，但不写入成功或失败账本。"""
    email_key = str(email or "").strip().lower()
    if email_key:
        with _email_track_lock:
            _email_issued_after_map.pop(email_key, None)
    try:
        _hotmail_release_alias(email)
    except Exception:
        pass


def remember_email_issued_after(email: str, issued_after=None):
    """记录当前邮箱本次触发发码的大致时间，用于过滤旧验证码。"""
    email_key = str(email or "").strip().lower()
    if not email_key:
        return None
    try:
        ts = float(issued_after if issued_after is not None else time.time())
    except Exception:
        ts = time.time()
    with _email_track_lock:
        _email_issued_after_map[email_key] = ts
    return ts


def get_email_issued_after(email: str):
    email_key = str(email or "").strip().lower()
    if not email_key:
        return None
    with _email_track_lock:
        return _email_issued_after_map.get(email_key)


def should_persist_email_error(reason: str) -> bool:
    """只有明确邮箱凭证/通道不可用时才永久拉黑；验证码等待超时等只释放。"""
    text = str(reason or "").strip().lower()
    if not text:
        return False
    transient_markers = (
        "未收到验证码",
        "获取验证码失败",
        "验证码阶段失败",
        "verification code",
        "no verification code",
        "get_oai_code",
        "timeout",
        "timed out",
        "cancelled",
        "用户停止",
        "turnstile",
        "sso",
        "set-cookie",
        "sign-up http",
        "verify_email_code failed",
    )
    if any(marker in text for marker in transient_markers):
        return False
    permanent_markers = (
        "graph 鉴权失败",
        "http 401",
        "http 403",
        "invalid_grant",
        "refresh token",
        "xoauth",
        "dev_token 无效",
        "账号文件",
        "凭证",
        "credential",
    )
    return any(marker in text for marker in permanent_markers)


def is_email_used(email: str) -> bool:
    """检查邮箱是否已被使用或标记为失败。"""
    email_lower = email.strip().lower()
    for fpath in (_EMAILS_USED_FILE, _EMAILS_ERROR_FILE):
        if os.path.exists(fpath):
            with open(fpath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split("----")
                        if parts and parts[0].strip().lower() == email_lower:
                            return True
    return False


# ── 页面状态快照 ──

# ── CLI / batch performance knobs (register_cli may mutate) ──
PERF_FLAGS = {
    "fast": False,           # scale down human_sleep
    "sleep_scale": 1.0,      # multiply all human_sleep means
    "skip_debug_io": False,  # skip dump_state / take_screenshot
    "cookie_snapshot": True, # save_cookies_snapshot
    "async_side_effects": True,  # grok2api / cookie snapshot in background
    "browser_reuse": True,   # clear_session instead of quit between accounts
    "browser_recycle_every": 25,  # full quit+recreate after N successful reuses
}

_side_effect_pool = None


def _get_side_effect_pool():
    global _side_effect_pool
    if _side_effect_pool is None:
        from concurrent.futures import ThreadPoolExecutor
        _side_effect_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sidefx")
    return _side_effect_pool


def configure_perf(**kwargs):
    """Update PERF_FLAGS from CLI. Unknown keys ignored."""
    for k, v in kwargs.items():
        if k in PERF_FLAGS:
            PERF_FLAGS[k] = v


_SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")


def dump_state(page, tag: str = ""):
    """打印当前页面状态：URL、可见按钮文本、输入框类型。"""
    if PERF_FLAGS.get("skip_debug_io"):
        return
    try:
        info = page.run_js("""() => {
            const btns = [...document.querySelectorAll('button')]
                .map(b => b.innerText.trim())
                .filter(t => t)
                .slice(0, 20);
            const inputs = [...document.querySelectorAll('input,textarea')]
                .map(i => (i.type || 'text') + '/' + (i.placeholder || i.name || ''))
                .slice(0, 15);
            return {url: location.href, btns: btns, inputs: inputs};
        }""")
        if not info:
            print(f"  [state:{tag}] page context not ready (None)")
            return
        print(f"  [state:{tag}] url: {info.get('url', '?')}")
        print(f"  [state:{tag}] btns: {info.get('btns', [])}")
        print(f"  [state:{tag}] inputs: {info.get('inputs', [])}")
    except Exception as e:
        print(f"  [state:{tag}] dump_state err: {e}")


def take_screenshot(page, tag: str = ""):
    """捕获当前页面截图并保存到 screenshots/ 目录。"""
    if PERF_FLAGS.get("skip_debug_io"):
        return
    try:
        os.makedirs(_SCREENSHOT_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%H%M%S")
        path = os.path.join(_SCREENSHOT_DIR, f"{ts}_{tag}.png")
        page.get_screenshot(path=path)
        print(f"  [screenshot] saved: {path}")
    except Exception as e:
        print(f"  [screenshot] err: {e}")


def save_turnstile_debug(page, tag: str = "turnstile_failed"):
    """Best-effort debug bundle for Turnstile failures."""
    if PERF_FLAGS.get("skip_debug_io"):
        return
    try:
        os.makedirs(_SCREENSHOT_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(_SCREENSHOT_DIR, f"{ts}_{tag}")
        try:
            page.get_screenshot(path=f"{base}.png")
            print(f"  [turnstile-debug] screenshot: {base}.png")
        except Exception as exc:
            print(f"  [turnstile-debug] screenshot err: {exc}")
        try:
            info = page.run_js("""() => ({
                url: location.href,
                title: document.title,
                text: (document.body && document.body.innerText || '').slice(0, 2000)
            })""")
            with open(f"{base}.txt", "w", encoding="utf-8") as f:
                json.dump(info or {}, f, ensure_ascii=False, indent=2)
            print(f"  [turnstile-debug] state: {base}.txt")
        except Exception as exc:
            print(f"  [turnstile-debug] state err: {exc}")
    except Exception as exc:
        print(f"  [turnstile-debug] err: {exc}")


# ── 超时守卫 ──

REGISTER_TIMEOUT = 180  # 单次注册总超时（秒）


class TimeoutError(Exception):
    pass


def check_timeout(start_time: float):
    """检查是否超过总超时时间。"""
    elapsed = time.time() - start_time
    if elapsed > REGISTER_TIMEOUT:
        raise TimeoutError(f"注册超时 ({REGISTER_TIMEOUT}s, 已用 {elapsed:.0f}s)")


# ── 全量 cookie 保存 ──

_COOKIE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies", "grok")


def save_cookies_snapshot(page, tag: str = "", email: str = ""):
    """保存当前浏览器上下文的全量 cookie 快照。"""
    if not PERF_FLAGS.get("cookie_snapshot", True):
        return
    try:
        browser = _get_browser()
        if not browser:
            return
        os.makedirs(_COOKIE_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        cookies = browser.cookies()
        data = {
            "ts": ts,
            "tag": tag,
            "email": email,
            "url": page.url if page else "",
            "cookies": cookies,
        }
        path = os.path.join(_COOKIE_DIR, f"full_{ts}_{tag}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"  [cookies] saved: {path} ({len(cookies)} cookies)")
    except Exception as e:
        print(f"  [cookies] save err: {e}")


# ── .env 加载 ──


def load_env():
    """从 .env 文件加载环境变量（零依赖）。
    只在 os.environ 中尚未设置该 KEY 时填入（真实环境变量优先）。
    """
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


class RegistrationCancelled(Exception):
    pass


def _load_config_json(path: str):
    """Load config JSON, ignoring template comment keys even if their values are stale."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    lines = [
        line
        for line in text.splitlines()
        if not re.match(r'^\s*"(?://|#)', line)
    ]
    return json.loads("\n".join(lines))


def load_config():
    load_env()
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            loaded = _load_config_json(CONFIG_FILE)
            # Allow "// comment" keys in config.example.json / config.json templates.
            if isinstance(loaded, dict):
                loaded = {
                    k: v
                    for k, v in loaded.items()
                    if not (isinstance(k, str) and (k.startswith("//") or k.startswith("#")))
                }
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception as e:
            print(f"load config failed, using defaults: {e}")
            config = DEFAULT_CONFIG.copy()
    return config


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()

EXTENSION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "turnstilePatch")
)


DUCKMAIL_API_BASE = "https://api.duckmail.sbs"


def set_thread_proxy(proxy_raw):
    """为当前线程钉住代理（webui 随机代理模式：每个账号一个代理）。"""
    try:
        import proxy_pool

        _thread_proxy.url = proxy_pool.effective_url(proxy_raw) or None
    except Exception:
        _thread_proxy.url = None


def clear_thread_proxy():
    _thread_proxy.url = None


def get_thread_proxy():
    return getattr(_thread_proxy, "url", None)


def get_effective_proxy():
    """当前生效代理：线程级钉住 > config.proxy。返回规范化 URL（可含账密）。"""
    pinned = get_thread_proxy()
    if pinned:
        return pinned
    raw = str(config.get("proxy", "") or "").strip()
    if not raw:
        return ""
    try:
        import proxy_pool

        # 特殊值 pool:random → 每次调用从池中随机取（注册浏览器每次启动随机）
        return proxy_pool.effective_url(proxy_pool.resolve_special(raw))
    except Exception:
        return raw


def get_proxies():
    proxy = get_effective_proxy()
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")


def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_path(key, default_path):
    raw = str(config.get(key, default_path) or default_path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def cloudflare_build_headers(content_type=False):
    headers = {"Content-Type": "application/json"} if content_type else {}
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key:
        if mode == "x-api-key":
            headers["X-API-Key"] = key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {key}"
    return headers


def cloudflare_apply_auth_params(params=None):
    merged = dict(params or {})
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key and mode == "query-key":
        merged["key"] = key
    return merged


def _pick_list_payload(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")
        if isinstance(data.get("hydra:member"), list):
            return data.get("hydra:member")
        if isinstance(data.get("data"), list):
            return data.get("data")
        if isinstance(data.get("messages"), list):
            return data.get("messages")
        if isinstance(data.get("data"), dict):
            nested = data.get("data")
            if isinstance(nested.get("messages"), list):
                return nested.get("messages")
    return []


def _mail_direct_proxy_kwargs():
    """邮箱 API 请求默认直连，不继承注册代理 / pool:random。

    注册 x.ai、CPA mint、solver 可以走代理；但 Cloudflare/CloudMail 等
    邮箱管理 API 是我们自己的基础设施，走注册代理反而会把代理 TLS 抖动
    放大成“获取邮箱失败”。
    """
    return {"proxies": {}}


def cloudflare_create_temp_address(api_base):
    global _cf_domain_index
    import random
    import string

    path = get_cloudflare_path("cloudflare_path_accounts", "/admin/new_address")
    url = f"{api_base}{path}"
    admin_password = str(config.get("cloudflare_admin_password", "") or "").strip()
    if not admin_password:
        raise Exception("Cloudflare cloudflare_admin_password 未配置")

    def random_name():
        return "".join(random.choices(string.ascii_lowercase, k=5)) + \
               "".join(random.choices(string.digits, k=random.randint(1, 3))) + \
               "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))

    payload = {"enablePrefix": True, "name": random_name()}
    domains = [x.strip() for x in re.split(r"[,，\s]+", str(config.get("defaultDomains", "") or "")) if x.strip()]
    if domains:
        payload["domain"] = _pick_cf_domain(domains)

    resp = http_post(
        url,
        json=payload,
        headers={"Content-Type": "application/json", "x-admin-auth": admin_password},
        **_mail_direct_proxy_kwargs(),
    )
    try:
        resp.raise_for_status()
    except Exception as exc:
        raise Exception(f"Cloudflare {path} 创建邮箱失败: HTTP {resp.status_code} {resp.text[:300]}") from exc
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare {path} 返回非JSON: {resp.text[:300]}")
    address = str(data.get("address") or "").strip()
    jwt = str(data.get("jwt") or "").strip()
    if not address or not jwt:
        raise Exception(f"Cloudflare {path} 缺少 address/jwt: {data}")
    return address, jwt


# MailNest-迈巢 Outlook 临时邮箱
MAILNEST_API_BASE = "https://mailnest.top"


def get_mailnest_api_key():
    mailnest_api_key = str(config.get("mailnest_api_key", "") or "").strip()
    if not mailnest_api_key:
        raise Exception(f"请在配置文件中配置 mailnest_api_key | 注册网址：{MAILNEST_API_BASE}")
    return mailnest_api_key


def get_mailnest_project_code():
    mailnest_project_code = str(config.get("mailnest_project_code", "") or "").strip()
    if not mailnest_project_code:
        raise Exception(
            "请在配置文件中配置 mailnest_project_code | 项目网址：https://mailnest.top/buy-email"
        )
    return mailnest_project_code


def mailnest_buy_email():
    resp = http_post(
        f"{MAILNEST_API_BASE}/api/v1/email/temporary/buy",
        headers={"Authorization": f"Bearer {get_mailnest_api_key()}"},
        json={
            "project_code": get_mailnest_project_code(),
            "count": 1,
        },
        timeout=30,
        verify=False,
    )
    try:
        resp_json = resp.json()
    except Exception as exc:
        raise Exception(f"MailNest 购邮返回非 JSON: HTTP {resp.status_code} {resp.text[:300]}") from exc
    if str(resp_json.get("code")) != "00000":
        raise Exception(f"MailNest 购邮失败: {resp.text[:300]}")
    data = resp_json.get("data") or []
    if not data or not isinstance(data, list):
        raise Exception(f"MailNest 购邮无邮箱数据: {resp_json}")
    email = str((data[0] or {}).get("email") or "").strip()
    if not email:
        raise Exception(f"MailNest 购邮缺少 email: {resp_json}")
    print(f"获取到邮箱 | email={email}")
    return email


def mailnest_receive_email(email):
    resp = http_post(
        f"{MAILNEST_API_BASE}/api/v1/email/receive",
        headers={"Authorization": f"Bearer {get_mailnest_api_key()}"},
        json={"email": email},
        timeout=30,
        verify=False,
    )
    try:
        resp_json = resp.json()
    except Exception as exc:
        raise Exception(f"MailNest 收件返回非 JSON: HTTP {resp.status_code} {resp.text[:300]}") from exc
    if str(resp_json.get("code")) != "00000":
        raise Exception(f"MailNest 收件失败: {resp.text[:300]}")
    return resp_json.get("data") or []


def mailnest_get_code(
    email,
    timeout=90,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    deadline = time.time() + max(1, int(timeout or 90))
    attempt = 0
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        attempt += 1
        msg = f"第 {attempt} 次收件 (MailNest)"
        if log_callback:
            log_callback(msg)
        else:
            print(msg)
        try:
            mails = mailnest_receive_email(email)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] MailNest 收件失败: {exc}")
            mails = []
        if mails:
            preview = str((mails[0] or {}).get("body_preview") or "")
            subject = str((mails[0] or {}).get("subject") or "")
            code = extract_verification_code(preview, subject=subject)
            if code:
                return code
            # 有邮件但未解析到验证码时继续轮询，避免偶发空预览直接失败
            if log_callback:
                log_callback("[Debug] MailNest 有邮件但未解析到验证码，继续等待")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"MailNest 在 {timeout}s 内未收到验证码: {email}")


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def resolve_grok2api_local_token_file():
    configured = str(config.get("grok2api_local_token_file", "") or "").strip()
    if configured:
        return configured
    return r"D:\注册机\3255d5ee6e702db9220a897df64635a1ec9df644\vendor\grok2api\data\token.json"


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def add_token_to_grok2api_local_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    token_file = resolve_grok2api_local_token_file()
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip()
    if not pool_name:
        pool_name = "ssoBasic"
    os.makedirs(os.path.dirname(token_file), exist_ok=True)
    data = {}
    if os.path.exists(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    pool = data.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token in existing:
        if log_callback:
            log_callback(f"[*] grok2api 本地池已存在 token: {pool_name}")
        return True
    entry = {"token": token, "tags": ["auto-register"], "note": email}
    pool.append(entry)
    data[pool_name] = pool
    with open(token_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 本地池: {pool_name} ({token_file})")
    return True


def add_token_to_grok2api_remote_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    base = str(config.get("grok2api_remote_base", "") or "").strip().rstrip("/")
    app_key = str(os.environ.get("GROK2API_APP_KEY") or config.get("grok2api_remote_app_key", "") or "").strip()
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    if not base or not app_key:
        if log_callback:
            log_callback("[Debug] grok2api 远端未配置 base/app_key，跳过")
        return False
    headers = {"Content-Type": "application/json"}
    query = {"app_key": app_key, "auto_nsfw": "true"}
    pool_map = {"ssoBasic": "basic", "ssoSuper": "super"}
    remote_pool = pool_map.get(pool_name, "basic")
    # 优先使用 add 接口，避免全量覆盖远端池
    try:
        add_payload = {"tokens": [token], "pool": remote_pool, "tags": ["auto-register"]}
        resp_add = http_post(
            f"{base}/tokens/add",
            headers=headers,
            params=query,
            json=add_payload,
            timeout=8,
            proxies={},
        )
        resp_add.raise_for_status()
        if log_callback:
            log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({base}/tokens/add)")
        return True
    except Exception as add_exc:
        if log_callback:
            log_callback(f"[Debug] /tokens/add 写入失败，尝试 /tokens 全量模式: {add_exc}")

    # 兜底：旧版全量保存接口
    current = {}
    try:
        resp = http_get(f"{base}/tokens", headers=headers, params=query, timeout=6, proxies={})
        if resp.status_code == 200:
            payload = resp.json()
            current = payload.get("tokens", {}) if isinstance(payload, dict) else {}
    except Exception:
        current = {}
    if not isinstance(current, dict):
        current = {}
    pool = current.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token not in existing:
        pool.append({"token": token, "tags": ["auto-register"], "note": email})
    current[pool_name] = pool
    resp2 = http_post(f"{base}/tokens", headers=headers, params=query, json=current, timeout=8, proxies={})
    resp2.raise_for_status()
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({base}/tokens)")
    return True


def _add_token_to_grok2api_pools_sync(raw_token, email="", log_callback=None):
    # SSO 账本只写 accounts_cli.txt；不再本地备份 tokens/grok/
    if config.get("grok2api_auto_add_local", True):
        try:
            add_token_to_grok2api_local_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 本地池失败: {exc}")
    if config.get("grok2api_auto_add_remote", False):
        try:
            add_token_to_grok2api_remote_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 远端池失败: {exc}")


def add_token_to_grok2api_pools(raw_token, email="", log_callback=None):
    """Push SSO into grok2api pools. Async by default so register path never blocks on dead :8000."""
    if PERF_FLAGS.get("async_side_effects", True):
        def _job():
            try:
                _add_token_to_grok2api_pools_sync(raw_token, email=email, log_callback=log_callback)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] grok2api side-effect 异常: {exc}")
        try:
            _get_side_effect_pool().submit(_job)
            if log_callback:
                log_callback("[*] grok2api 池写入已异步提交")
            return
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 异步提交失败，同步写入: {exc}")
    _add_token_to_grok2api_pools_sync(raw_token, email=email, log_callback=log_callback)


CHROMIUM_SLIM_FLAGS = [
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-images",
    "--mute-audio",
    "--disable-background-networking",
    "--no-first-run",
]


def _apply_register_headless_options(options) -> bool:
    """Apply optional headless mode for the registration browser."""
    headless = _config_bool(config.get("register_headless", False), False)
    if not headless:
        try:
            options.headless(False)
        except Exception:
            pass
        return False

    try:
        options.headless(True)
    except Exception:
        options.set_argument("--headless=new")
    options.set_argument("--window-size=1280,900")
    print("  [browser] register_headless=true")
    return True


_SCREEN_PROFILES = ((1920, 1080), (1600, 900), (1536, 864), (1440, 900), (1366, 768))


def _installed_chrome_version():
    """读取本机 Chrome 真实版本（UA 必须与其一致，否则 CF 对验 userAgentData 穿帮）。"""
    import subprocess

    for path in (
        "/usr/bin/google-chrome-stable",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ):
        if os.path.isfile(path):
            try:
                out = subprocess.check_output(
                    [path, "--version"], timeout=5, text=True, stderr=subprocess.DEVNULL
                )
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out or "")
                if m:
                    return m.group(1)
            except Exception:
                continue
    return ""


def _fingerprint_ua():
    """生成与本地 Chrome 一致的 (user_agent, platform, platform_version, full_version)。

    config.user_agent 仅在主版本与本地 Chrome 一致时沿用。
    """
    import platform as _plat

    version = _installed_chrome_version()
    major = version.split(".")[0] if version else ""
    ua_cfg = str(config.get("user_agent") or "").strip()
    m = re.search(r"Chrome/(\d+)", ua_cfg)
    if ua_cfg and m and major and m.group(1) == major:
        platform_name = (
            "Windows" if "Windows" in ua_cfg else ("macOS" if "Mac OS" in ua_cfg else "Linux")
        )
        plat_ver = "15.0.0" if platform_name == "Windows" else (_plat.release().split("-")[0] or "6.0.0")
        full = re.search(r"Chrome/([\d.]+)", ua_cfg).group(1)
        return ua_cfg, platform_name, plat_ver, full
    full = version or "138.0.0.0"
    if os.name == "nt":
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{full} Safari/537.36"
        )
        return ua, "Windows", "15.0.0", full
    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{full} Safari/537.36"
    )
    return ua, "Linux", (_plat.release().split("-")[0] or "6.0.0"), full


def apply_page_fingerprint(page, log_callback=None):
    """CDP 级指纹对齐（参考 grok_oauth）：UA 元数据 / 屏幕 / locale / 硬件 / navigator 补丁。

    仅设置 UA 字符串会被 CF 用 sec-ch-ua / navigator.userAgentData 对验识破，
    必须通过 Network.setUserAgentOverride 带上 userAgentMetadata。
    """
    try:
        ua, platform_name, plat_ver, full_version = _fingerprint_ua()
        major = full_version.split(".")[0]
        brands = [
            {"brand": "Chromium", "version": major},
            {"brand": "Google Chrome", "version": major},
            {"brand": "Not_A Brand", "version": "99"},
        ]
        random.shuffle(brands)
        full_list = [
            (
                {"brand": b["brand"], "version": full_version}
                if b["brand"] != "Not_A Brand"
                else {"brand": b["brand"], "version": "99.0.0.0"}
            )
            for b in brands
        ]
        width, height = random.choice(_SCREEN_PROFILES)
        hw = random.choice((4, 8, 12, 16))
        nav_platform = "Linux x86_64" if platform_name == "Linux" else "Win32"
        ua_platform = "Linux x86_64" if platform_name == "Linux" else platform_name
        try:
            page.run_cdp(
                "Network.setUserAgentOverride",
                userAgent=ua,
                acceptLanguage="en-US,en;q=0.9",
                platform=ua_platform,
                userAgentMetadata={
                    "brands": brands,
                    "fullVersionList": full_list,
                    "fullVersion": full_version,
                    "platform": platform_name,
                    "platformVersion": plat_ver,
                    "architecture": "x86",
                    "model": "",
                    "mobile": False,
                    "bitness": "64",
                    "wow64": False,
                },
            )
            page.run_cdp(
                "Emulation.setDeviceMetricsOverride",
                width=width,
                height=height,
                deviceScaleFactor=1,
                mobile=False,
                screenWidth=width,
                screenHeight=height,
            )
            page.run_cdp("Emulation.setLocaleOverride", locale="en-US")
            page.run_cdp("Emulation.setHardwareConcurrencyOverride", hardwareConcurrency=hw)
            tz = str(config.get("browser_timezone") or "").strip()
            if tz:
                page.run_cdp("Emulation.setTimezoneOverride", timezoneId=tz)
        except Exception:
            pass
        src = f"""
(() => {{
  const define = (t, n, v) => {{ try {{ Object.defineProperty(t, n, {{get: () => v, configurable: true}}); }} catch (e) {{}} }};
  define(Navigator.prototype, 'webdriver', false);
  define(Navigator.prototype, 'platform', '{nav_platform}');
  define(Navigator.prototype, 'languages', Object.freeze(['en-US','en']));
  define(Navigator.prototype, 'hardwareConcurrency', {hw});
  define(Navigator.prototype, 'deviceMemory', 8);
  define(Navigator.prototype, 'maxTouchPoints', 0);
}})();
"""
        page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source=src)
        if log_callback:
            log_callback(f"[*] 指纹对齐: Chrome/{major} {platform_name} {width}x{height}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 指纹对齐失败: {exc}")


def create_browser_options():
    options = ChromiumOptions()
    options.auto_port()
    options.set_timeouts(base=1)
    headless_enabled = _config_bool(config.get("register_headless", False), False)
    for flag in CHROMIUM_SLIM_FLAGS:
        # 无头下保留图像/软件光栅：Turnstile 风控依赖 canvas/WebGL 渲染指纹
        if headless_enabled and flag in ("--disable-images", "--disable-software-rasterizer"):
            continue
        options.set_argument(flag)
    options.set_argument("--disable-blink-features=AutomationControlled")
    options.set_argument("--force-device-scale-factor=1")
    _apply_register_headless_options(options)
    # 无头模式下 Chrome UA 带 HeadlessChrome 标记，accounts.x.ai 直接 CF 硬拦截；
    # 且 UA 必须与真实 Chrome 主版本/userAgentData 一致（CF 会对验），
    # 用 _fingerprint_ua 生成（config.user_agent 仅在主版本匹配时沿用）。
    ua, _, _, _ = _fingerprint_ua()
    try:
        options.set_user_agent(ua)
    except Exception:
        pass
    if os.path.exists(EXTENSION_PATH):
        options.add_extension(EXTENSION_PATH)
    # Apply effective proxy (thread-pinned > config "proxy") to Chromium.
    # 带账密或 socks5 的代理由 proxy_relay 起本地无认证中继；http 无认证直连。
    proxy = get_effective_proxy()
    if proxy:
        try:
            import proxy_relay

            chrome_proxy = proxy_relay.chromium_proxy_for(proxy)
        except Exception:
            chrome_proxy = ""
        if chrome_proxy:
            try:
                options.set_argument(f"--proxy-server={chrome_proxy}")
            except Exception as e:
                print(f"  [proxy] set browser proxy failed: {e}")
    return options


def attach_proxy_auth(page, proxy_raw=None, log_callback=None):
    """若生效代理带账密，通过 CDP Fetch 域自动应答 407 代理认证。

    需要在每个 tab 创建后调用一次（Chromium --proxy-server 不支持内嵌账密）。
    """
    try:
        import proxy_pool

        proxy = (
            proxy_pool.normalize_proxy_url(proxy_raw)
            if proxy_raw
            else get_effective_proxy()
        )
        parsed = proxy_pool.parse_proxy(proxy) if proxy else None
    except Exception:
        parsed = None
    if not parsed or not parsed.get("user"):
        return False
    try:
        user, password = parsed["user"], parsed["password"]

        def _on_auth(**params):
            request_id = params.get("requestId")
            if not request_id:
                return
            try:
                page.run_cdp(
                    "Fetch.continueWithAuth",
                    requestId=request_id,
                    authChallengeResponse={
                        "response": "ProvideCredentials",
                        "username": user,
                        "password": password,
                    },
                )
            except Exception:
                pass

        page.run_cdp("Fetch.enable", handleAuthRequests=True)
        page.driver.set_callback("Fetch.authRequired", _on_auth)
        if log_callback:
            import proxy_pool

            log_callback(f"[*] 已挂载代理认证: {proxy_pool.mask_proxy(proxy)}")
        return True
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 代理认证挂载失败: {exc}")
        return False


def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    try:
        return requests.get(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        # 代理不可用时自动回退为直连，避免整个流程直接失败
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.get(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_post(url, **kwargs):
    try:
        return requests.post(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.post(url, **_build_request_kwargs(**retry_kwargs))
        raise


def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("用户停止注册")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = time.time() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def human_sleep(mean_seconds, cancel_callback=None):
    """高斯分布人类化延迟，sigma=mean*0.3，clamp [mean*0.5, mean*2.0]。

    PERF_FLAGS sleep_scale / fast 可压缩批量注册等待。
    """
    scale = float(PERF_FLAGS.get("sleep_scale", 1.0) or 1.0)
    if PERF_FLAGS.get("fast"):
        scale = min(scale, 0.15)
    mean_seconds = max(0.0, float(mean_seconds) * scale)
    if mean_seconds <= 0.01:
        raise_if_cancelled(cancel_callback)
        return
    try:
        delay = random.gauss(mean_seconds, mean_seconds * 0.3)
    except Exception:
        delay = mean_seconds
    delay = max(mean_seconds * 0.5, min(mean_seconds * 2.0, delay))
    sleep_with_cancel(delay, cancel_callback)



def get_domains(api_key=None):
    headers = {}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = http_get(f"{DUCKMAIL_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def create_account(address, password, api_key=None, expires_in=0):
    headers = {"Content-Type": "application/json"}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = {"address": address, "password": password, "expiresIn": expires_in}
    resp = http_post(f"{DUCKMAIL_API_BASE}/accounts", json=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_token(address, password):
    data = {"address": address, "password": password}
    resp = http_post(f"{DUCKMAIL_API_BASE}/token", json=data)
    resp.raise_for_status()
    return resp.json().get("token")


def get_messages(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def get_message_detail(token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_domains(api_base, api_key=None):
    # 使用 x-admin-auth 认证
    admin_password = config.get("cloudflare_admin_password", "")
    headers = {"Content-Type": "application/json"}
    if admin_password:
        headers["x-admin-auth"] = admin_password
    path = get_cloudflare_path("cloudflare_path_domains", "/api/domains")
    resp = http_get(f"{api_base}{path}", headers=headers, **_mail_direct_proxy_kwargs())
    resp.raise_for_status()
    return _pick_list_payload(resp.json())


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    payload = {"address": address, "password": password, "expiresIn": expires_in}
    path = get_cloudflare_path("cloudflare_path_accounts", "/accounts")
    params = cloudflare_apply_auth_params()
    resp = http_post(
        f"{api_base}{path}",
        json=payload,
        headers=headers,
        params=params,
        **_mail_direct_proxy_kwargs(),
    )
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_token(api_base, address, password, api_key=None):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_token", "/token")
    resp = http_post(
        f"{api_base}{path}",
        json={"address": address, "password": password},
        headers=headers,
        params=cloudflare_apply_auth_params(),
        **_mail_direct_proxy_kwargs(),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("token"):
            return data.get("token")
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            return data["data"].get("token")
    return None


_cf_domain_index = 0
_cf_domain_cooldowns: dict = {}
_cf_domain_cooldown_lock = threading.Lock()
_cf_domain_deck: list = []

CF_DOMAIN_COOLDOWN_DEFAULT_SEC = 600


def cf_domain_cooldown_remaining(domain: str) -> float:
    with _cf_domain_cooldown_lock:
        until = float(_cf_domain_cooldowns.get((domain or "").lower(), 0) or 0)
    return max(0.0, until - time.time())


def mark_cf_domain_cooldown(domain: str, seconds: float | None = None, log_callback=None) -> None:
    """标记域名进入冷却（仅 registration_disallowed 等业务拒绝时调用）。

    注意：网络错误 / sentinel 失败 / OTP 超时都不应调用本函数，避免误伤域名。
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    if seconds is None:
        try:
            seconds = float(config.get("cloudflare_domain_cooldown_sec", CF_DOMAIN_COOLDOWN_DEFAULT_SEC) or CF_DOMAIN_COOLDOWN_DEFAULT_SEC)
        except Exception:
            seconds = CF_DOMAIN_COOLDOWN_DEFAULT_SEC
    until = time.time() + max(30.0, float(seconds))
    with _cf_domain_cooldown_lock:
        _cf_domain_cooldowns[domain] = until
    if log_callback:
        log_callback(f"[!] 域名 {domain} 进入冷却 {int(max(30.0, seconds))}s")


_cf_otp_strikes: dict = {}


def _cf_pool_domains() -> list:
    raw = str(config.get("defaultDomains", "") or "")
    return [x.strip().lower() for x in re.split(r"[,，\s]+", raw) if x.strip()]


def cf_note_otp_success(domain: str) -> None:
    """收码成功：重置该域名的连续超时计数。"""
    with _cf_domain_cooldown_lock:
        _cf_otp_strikes.pop((domain or "").strip().lower(), None)


def cf_note_otp_failure(domain: str, log_callback=None) -> bool:
    """收码超时/失败：累计连续次数，达到阈值则冷却该域名。

    只统计域名池（defaultDomains）内的域名；hotmail 等外部域不计（避免误伤整个池）。
    返回 True 表示已触发冷却。
    """
    domain = (domain or "").strip().lower()
    if not domain or domain not in _cf_pool_domains():
        return False
    try:
        threshold = max(1, int(config.get("cloudflare_domain_otp_strikes", 3) or 3))
    except Exception:
        threshold = 3
    with _cf_domain_cooldown_lock:
        strikes = int(_cf_otp_strikes.get(domain, 0)) + 1
        _cf_otp_strikes[domain] = strikes
    if strikes >= threshold:
        with _cf_domain_cooldown_lock:
            _cf_otp_strikes[domain] = 0
        if log_callback:
            log_callback(f"[!] 域名 {domain} 连续 {strikes} 次收码超时，进入冷却")
        mark_cf_domain_cooldown(domain)
        return True
    if log_callback:
        log_callback(f"[Debug] 域名 {domain} 连续收码超时 {strikes}/{threshold}")
    return False


def _pick_cf_domain(domains, log_callback=None, cancel_callback=None):
    """域名池抽取：cloudflare_domain_select = random（随机）| round_robin（轮换，默认）。

    冷却中的域名跳过；全部冷却时自动暂停等待最早解冻（可取消）。
    """
    available = [d for d in domains if cf_domain_cooldown_remaining(d) <= 0]
    if not available:
        # 域名池全部冷却：暂停注册，等待最早解冻的域名
        wait_map = {d: cf_domain_cooldown_remaining(d) for d in domains}
        earliest = min(wait_map, key=wait_map.get)
        wait_s = max(1.0, wait_map[earliest])
        if log_callback:
            log_callback(
                f"[!] 域名池全部冷却中（{len(domains)} 个），暂停 {int(wait_s)}s 等待 {earliest} 解冻"
            )
        deadline = time.time() + wait_s + 1
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            if cf_domain_cooldown_remaining(earliest) <= 0:
                break
            sleep_with_cancel(2, cancel_callback)
        available = [d for d in domains if cf_domain_cooldown_remaining(d) <= 0] or domains

    mode = str(config.get("cloudflare_domain_select", "round_robin") or "round_robin").strip().lower()
    if mode == "random":
        return random.choice(available)
    if mode == "shuffle":
        # 洗牌轮换：每个域名各用一遍后才重新洗牌，避免真随机重复
        global _cf_domain_deck
        with _cf_domain_cooldown_lock:
            if not _cf_domain_deck:
                _cf_domain_deck = available[:]
                random.shuffle(_cf_domain_deck)
            return _cf_domain_deck.pop(0)
    global _cf_domain_index
    domain = available[_cf_domain_index % len(available)]
    _cf_domain_index += 1
    return domain


def cloudflare_get_messages(api_base, token):
    headers = {"Authorization": f"Bearer {token}"}
    configured_path = get_cloudflare_path("cloudflare_path_messages", "/api/parsed_mails")
    candidates = []
    for path in (configured_path, "/api/parsed_mails", "/api/mails"):
        if path not in candidates:
            candidates.append(path)
    last_err = None
    for path in candidates:
        try:
            resp = http_get(
                f"{api_base}{path}",
                headers=headers,
                params={"limit": 20, "offset": 0},
                **_mail_direct_proxy_kwargs(),
            )
            if resp.status_code == 404:
                last_err = f"{path} HTTP 404"
                continue
            resp.raise_for_status()
            try:
                data = resp.json()
            except Exception:
                raise Exception(f"Cloudflare {path} 返回非JSON: {resp.text[:300]}")
            return _pick_list_payload(data)
        except Exception as exc:
            last_err = exc
            if "404" in str(exc):
                continue
            raise
    raise Exception(f"Cloudflare 拉取邮件列表失败: {last_err}")


def cloudflare_get_message_detail(api_base, token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    configured_path = get_cloudflare_path("cloudflare_path_messages", "/api/parsed_mails").rstrip("/")
    candidates = [
        f"{api_base}/api/parsed_mail/{message_id}",
        f"{api_base}/api/mail/{message_id}",
        f"{api_base}{configured_path}/{message_id}",
        f"{api_base}/api/mails/{message_id}",
    ]
    last_err = None
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = http_get(url, headers=headers, **_mail_direct_proxy_kwargs())
            if resp.status_code in (404, 405):
                last_err = f"{url} HTTP {resp.status_code}"
                continue
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            last_err = exc
            continue
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


YYDS_API_BASE = "https://maliapi.215.im/v1"


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def yyds_get_domains(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []) if data.get("success") else []


def yyds_create_account(address=None, domain=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    payload = {}
    if address:
        payload["address"] = address
    if domain:
        payload["domain"] = domain
    elif key or token:
        payload["autoDomainStrategy"] = "prefer_owned"
    resp = http_post(f"{YYDS_API_BASE}/accounts", json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 创建邮箱失败: {data}")


def yyds_get_token(address, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_post(
        f"{YYDS_API_BASE}/token", json={"address": address}, headers=headers
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("token")
    raise Exception(f"YYDS 获取token失败: {data}")


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(
        f"{YYDS_API_BASE}/messages",
        params={"address": address},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("messages", [])
    return []


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 获取邮件详情失败: {data}")


def yyds_generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def yyds_pick_domain(api_key=None, jwt=None):
    domains = yyds_get_domains(api_key=api_key, jwt=jwt)
    if not domains:
        raise Exception("YYDS 没有返回任何可用域名")
    private = [d for d in domains if d.get("isVerified") and not d.get("isPublic")]
    if private:
        return private[0]["domain"]
    public = [d for d in domains if d.get("isVerified") and d.get("isPublic")]
    if public:
        return public[0]["domain"]
    verified = [d for d in domains if d.get("isVerified")]
    if verified:
        return verified[0]["domain"]
    raise Exception("YYDS 无已验证域名可用")


def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        address=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def yyds_get_oai_code(
    token,
    address,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    jwt=None,
    cancel_callback=None,
):
    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = yyds_get_messages(address, token=token, jwt=jwt)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] YYDS 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            to_addrs = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if address.lower() not in to_addrs:
                continue
            try:
                detail = yyds_get_message_detail(msg_id, token=token, jwt=jwt)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] YYDS 获取邮件详情失败: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] YYDS 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] YYDS 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"YYDS 在 {timeout}s 内未收到验证码邮件")


def generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def pick_domain(api_key=None):
    domains = get_domains(api_key=api_key)
    if not domains:
        raise Exception("DuckMail 没有返回任何可用域名")
    private = [d for d in domains if d.get("ownerId")]
    verified_private = [d for d in private if d.get("isVerified")]
    if verified_private:
        return verified_private[0]["domain"]
    public = [d for d in domains if d.get("isVerified")]
    if public:
        return public[0]["domain"]
    raise Exception("DuckMail 无已验证域名可用")


# ──────────────────────── CloudMail (maillab/cloud-mail) ────────────────────────
# API 前缀: /api/（所有接口均挂载在 /api/ 下）
# 认证格式: Authorization: <token>（不带 Bearer 前缀）
# 公开 token 通过 /api/public/genToken 获取（需管理员账号）

def get_cloudmail_url():
    return str(os.environ.get("CLOUDMAIL_URL") or config.get("cloudmail_url", "") or "").rstrip("/")


def get_cloudmail_password():
    return os.environ.get("CLOUDMAIL_PASSWORD") or config.get("cloudmail_password", "")


def get_cloudmail_admin_email():
    return str(os.environ.get("CLOUDMAIL_ADMIN_EMAIL") or config.get("cloudmail_admin_email", "") or "").strip()


def cloudmail_login(url, email, password):
    """POST /api/login -> JWT string"""
    resp = http_post(
        f"{url}/api/login",
        json={"email": email, "password": password},
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") == 200:
        token_data = data.get("data", {})
        if isinstance(token_data, dict):
            jwt = token_data.get("token")
            if jwt:
                return jwt
    raise Exception(f"CloudMail 登录失败: {str(data)[:200]}")


def cloudmail_register(url, email, password, turnstile_token=""):
    """POST /api/register -> 注册用户+账号"""
    payload = {"email": email, "password": password}
    if turnstile_token:
        payload["token"] = turnstile_token
    resp = http_post(
        f"{url}/api/register",
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") != 200:
        raise Exception(f"CloudMail 注册失败: {data.get('message', str(data))}")
    return data


def cloudmail_gen_public_token(url, admin_email, admin_password):
    """POST /api/public/genToken -> 公开 API token (UUID)"""
    resp = http_post(
        f"{url}/api/public/genToken",
        json={"email": admin_email, "password": admin_password},
        headers={"Content-Type": "application/json"},
        proxies={},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") == 200:
        token_data = data.get("data", {})
        if isinstance(token_data, dict):
            return token_data.get("token")
    raise Exception(f"CloudMail 获取公开 token 失败: {str(data)[:200]}")


def cloudmail_public_email_list(url, public_token, to_email="", size=20):
    """POST /api/public/emailList -> 公开邮件查询（需公开 token，Authorization: <token>）"""
    payload = {"size": size}
    if to_email:
        payload["toEmail"] = to_email
    resp = http_post(
        f"{url}/api/public/emailList",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": public_token,
        },
        proxies={},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("code") == 200:
            return data.get("data", [])
        raise Exception(f"CloudMail 邮件查询失败: {data.get('message', str(data))}")
    return []


def _cloudmail_get_shared_token(force_refresh=False):
    """获取或刷新共享的公开 token（线程安全单例）"""
    global _cloudmail_public_token
    with _cloudmail_public_token_lock:
        if _cloudmail_public_token and not force_refresh:
            return _cloudmail_public_token
        url = get_cloudmail_url()
        admin_email = get_cloudmail_admin_email()
        admin_password = get_cloudmail_password()
        if not url or not admin_email or not admin_password:
            raise Exception("CloudMail 配置不完整")
        token = cloudmail_gen_public_token(url, admin_email, admin_password)
        if not token:
            raise Exception("CloudMail 公开 token 为空")
        _cloudmail_public_token = token
        return token


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=300,
    poll_interval=None,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    # 使用配置的 mail_poll_interval，默认 0.3s
    if poll_interval is None:
        poll_interval = max(0.1, float(config.get("mail_poll_interval", 0.3) or 0.3))
    url = get_cloudmail_url()
    if not url:
        raise Exception("CloudMail URL 未配置")
    # 获取共享公开 token（所有线程共用同一个，避免并发覆盖）
    try:
        public_token = _cloudmail_get_shared_token()
    except Exception as exc:
        raise Exception(f"CloudMail 获取公开 token 失败: {exc}")
    if log_callback:
        log_callback("[Debug] CloudMail 公开 token 获取成功")
    deadline = time.time() + timeout
    seen_attempts = {}
    next_resend_at = time.time() + 60
    round_no = 0
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        round_no += 1
        # 日志节流：0.3s 短轮询高频，仅首轮与每 40 轮输出一次
        verbose = round_no == 1 or round_no % 40 == 0
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 60
        # 统一使用 poll_interval（0.3s 短轮询，无需前加速）
        current_interval = poll_interval
        # 用完整邮箱地址查询（公开 API 的 toEmail 需要完整地址）
        try:
            messages = cloudmail_public_email_list(url, public_token, to_email=email, size=20)
        except Exception as exc:
            err_msg = str(exc)
            if log_callback:
                log_callback(f"[Debug] CloudMail 邮件查询失败: {err_msg}")
            # token 失效时，刷新共享 token（加锁，多线程只刷新一次）
            if "token" in err_msg.lower() or "401" in err_msg:
                try:
                    public_token = _cloudmail_get_shared_token(force_refresh=True)
                    if log_callback:
                        log_callback("[Debug] CloudMail 公开 token 已刷新")
                except Exception:
                    pass
            sleep_with_cancel(current_interval, cancel_callback)
            continue
        if verbose and log_callback:
            log_callback(f"[Debug] CloudMail 本轮邮件数量: {len(messages)}（第 {round_no} 轮）")
        for msg in messages:
            msg_id = msg.get("emailId") or msg.get("id") or msg.get("messageId")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            # 提取邮件内容（公开接口返回 content 字段，为完整 HTML）
            parts = []
            for field in ("content", "text", "textContent", "text_content", "body", "snippet", "intro"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_val = msg.get("html") or msg.get("htmlContent") or msg.get("html_content")
            if isinstance(html_val, str):
                parts.append(re.sub(r"<[^>]+>", " ", html_val))
            elif isinstance(html_val, list):
                for h in html_val:
                    if isinstance(h, str):
                        parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            if log_callback:
                log_callback(f"[Debug] CloudMail 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] CloudMail 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(current_interval, cancel_callback)
    raise Exception(f"CloudMail 在 {timeout}s 内未收到验证码邮件")


# ──────────────────────── Hotmail / Outlook OAuth2 收码（IMAP + Graph 双协议） ────────────────────────
# 导入格式兼容 grok-register：邮箱----密码----ClientID----Token
# 其中 Token 为 Microsoft OAuth2 refresh_token。
# 协议取决于 refresh_token 的授权 scope：
#   - 含 outlook.office.com/IMAP.AccessAsUser.All → XOAUTH2 IMAP（outlook.office365.com）
#   - 仅含 graph.microsoft.com/Mail.Read（多数接码工具签发的格式）→ Microsoft Graph API
# hotmail_protocol = auto 时自动探测（IMAP scope 刷新 + 真实 XOAUTH2 试登录）。

HOTMAIL_IMAP_TOKEN_ENDPOINTS = [
    # IMAP XOAUTH2 needs an Outlook resource token. Graph Mail.Read tokens can
    # refresh successfully but then fail at IMAP with "authenticated but not connected".
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        {"scope": "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"},
    ),
    (
        "https://login.live.com/oauth20_token.srf",
        {"scope": "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"},
    ),
]

# Legacy default-scope refresh：老格式 refresh_token（wl.* scope）可能签出可用 IMAP token。
HOTMAIL_LEGACY_TOKEN_ENDPOINTS = [
    ("https://login.live.com/oauth20_token.srf", {}),
]

HOTMAIL_GRAPH_TOKEN_ENDPOINTS = [
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        {
            "scope": (
                "offline_access https://graph.microsoft.com/Mail.Read "
                "https://graph.microsoft.com/User.Read"
            )
        },
    ),
]

# 兼容旧引用：IMAP 优先，Graph 兜底
HOTMAIL_TOKEN_ENDPOINTS = (
    HOTMAIL_IMAP_TOKEN_ENDPOINTS
    + HOTMAIL_LEGACY_TOKEN_ENDPOINTS
    + HOTMAIL_GRAPH_TOKEN_ENDPOINTS
)


def _config_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "y", "on"):
            return True
        if v in ("0", "false", "no", "n", "off"):
            return False
    return default


def _resolve_project_path(path_value, default_name="mail_credentials.txt"):
    raw = str(path_value or default_name).strip()
    if not raw:
        raw = default_name
    if os.path.isabs(raw):
        return raw
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), raw)


def get_hotmail_accounts_file():
    return _resolve_project_path(config.get("hotmail_accounts_file", "mail_credentials.txt"))


def _hotmail_release_alias(email):
    if not email:
        return
    with _hotmail_selection_lock:
        _hotmail_reserved_aliases.discard(email.strip().lower())


def _hotmail_split_credential_line(line):
    parts = line.rstrip("\n").split("----", 3)
    if len(parts) < 4:
        return None
    email_addr = parts[0].strip()
    password = parts[1].strip()
    client_id = parts[2].strip()
    refresh_token = parts[3].strip()
    if not email_addr or "@" not in email_addr or not client_id or not refresh_token:
        return None
    return {
        "email": email_addr,
        "password": password,
        "client_id": client_id,
        "refresh_token": refresh_token,
    }


def _hotmail_load_accounts(force=False):
    global _hotmail_accounts_cache, _hotmail_accounts_mtime
    path = get_hotmail_accounts_file()
    if not os.path.exists(path):
        raise Exception(f"Hotmail/Outlook 账号文件不存在: {path}")
    mtime = os.path.getmtime(path)
    with _hotmail_accounts_lock:
        if (
            not force
            and _hotmail_accounts_cache is not None
            and _hotmail_accounts_mtime == mtime
        ):
            return _hotmail_accounts_cache
        accounts = []
        seen_emails = set()
        with open(path, "r", encoding="utf-8-sig") as f:
            for line_no, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                item = _hotmail_split_credential_line(raw)
                if not item:
                    print(f"[Hotmail] 跳过无效账号行 {line_no}: {line[:80]}")
                    continue
                email_key = item["email"].strip().lower()
                if email_key in seen_emails:
                    print(f"[Hotmail] 跳过重复主邮箱行 {line_no}: {item['email']}")
                    continue
                seen_emails.add(email_key)
                item["line_no"] = line_no
                accounts.append(item)
        if not accounts:
            raise Exception(f"Hotmail/Outlook 账号文件无有效记录: {path}")
        _hotmail_accounts_cache = accounts
        _hotmail_accounts_mtime = mtime
        return _hotmail_accounts_cache


def _hotmail_split_email_addr(email_addr):
    raw = str(email_addr or "").strip().lower()
    if "@" not in raw:
        return "", ""
    local, domain = raw.rsplit("@", 1)
    return local, domain


def _hotmail_is_alias_of_main(email_addr, main_email):
    local, domain = _hotmail_split_email_addr(email_addr)
    main_local, main_domain = _hotmail_split_email_addr(main_email)
    if not local or not main_local or domain != main_domain:
        return False
    if local == main_local:
        return True
    # 凭证本身可能已含 + 别名（如 user+HAaBDZ@outlook.de），
    # 按第一个 + 之前的基础名判断归属，避免漏计/错计配额。
    base = main_local.split("+", 1)[0]
    return local.startswith(base + "+")


def _hotmail_iter_tracked_emails():
    """Yield emails already persisted in success/error ledgers."""
    for fpath in (_EMAILS_USED_FILE, _EMAILS_ERROR_FILE):
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    email_addr = line.split("----", 1)[0].strip()
                    if email_addr:
                        yield email_addr
        except Exception:
            continue


def _hotmail_count_consumed_for_main(main_email):
    """Count used/failed/reserved aliases belonging to one Hotmail main mailbox."""
    consumed = set()
    for email_addr in _hotmail_iter_tracked_emails():
        if _hotmail_is_alias_of_main(email_addr, main_email):
            consumed.add(email_addr.strip().lower())
    for email_addr in _hotmail_reserved_aliases:
        if _hotmail_is_alias_of_main(email_addr, main_email):
            consumed.add(email_addr.strip().lower())
    return len(consumed)


def _hotmail_alias_available(alias_email):
    alias_key = alias_email.strip().lower()
    return alias_key and alias_key not in _hotmail_reserved_aliases and not is_email_used(alias_email)


def _hotmail_random_suffix(main_local):
    try:
        configured_len = int(config.get("hotmail_alias_random_length", 8) or 8)
    except Exception:
        configured_len = 8
    # Outlook local-part max is 64 chars; keep suffix valid even for long usernames.
    max_len = max(1, 64 - len(str(main_local or "")) - 1)
    length = max(1, min(configured_len, max_len))
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _hotmail_make_alias(main_email, alias_index, *, randomize=False):
    if alias_index <= 0:
        return main_email
    local, domain = main_email.split("@", 1)
    # 凭证已含 + 别名时，回退到基础名再生成单层别名：
    # 双层 plus（user+a+b@）在微软/发件方侧经常收不到信。
    base = local.split("+", 1)[0]
    if randomize:
        return f"{base}+{_hotmail_random_suffix(base)}@{domain}"
    return f"{base}+{alias_index}@{domain}"


def hotmail_get_email_and_token():
    accounts = _hotmail_load_accounts()
    try:
        max_aliases = int(config.get("hotmail_max_aliases_per_account", 5) or 5)
    except Exception:
        max_aliases = 5
    max_aliases = max(1, max_aliases)
    alias_mode = str(config.get("hotmail_alias_mode", "random") or "random").strip().lower()
    random_mode = alias_mode in ("random", "rand", "随机")
    try:
        random_max_attempts = int(config.get("hotmail_alias_random_max_attempts", 200) or 200)
    except Exception:
        random_max_attempts = 200
    random_max_attempts = max(10, random_max_attempts)

    with _hotmail_selection_lock:
        for acc in accounts:
            main_email = acc["email"].strip()
            if "@" not in main_email:
                continue
            if _hotmail_count_consumed_for_main(main_email) >= max_aliases:
                continue

            candidate = None
            # 原邮箱仍优先尝试一次；之后 random 模式使用随机 plus alias。
            if _hotmail_alias_available(main_email):
                candidate = main_email
            elif random_mode:
                for _ in range(random_max_attempts):
                    if _hotmail_count_consumed_for_main(main_email) >= max_aliases:
                        break
                    alias_email = _hotmail_make_alias(main_email, 1, randomize=True)
                    if _hotmail_alias_available(alias_email):
                        candidate = alias_email
                        break
            else:
                for alias_index in range(1, max_aliases):
                    alias_email = _hotmail_make_alias(main_email, alias_index)
                    if _hotmail_alias_available(alias_email):
                        candidate = alias_email
                        break

            if not candidate:
                continue

            alias_key = candidate.lower()
            _hotmail_reserved_aliases.add(alias_key)
            token_key = "hotmail:" + secrets.token_urlsafe(18)
            _hotmail_token_map[token_key] = {
                "account": acc,
                "email": candidate,
                "created_at": time.time(),
            }
            return candidate, token_key
    raise Exception(
        "Hotmail/Outlook 可用别名已耗尽：请增加 hotmail_max_aliases_per_account、"
        "补充 mail_credentials.txt，或清理 emails_used.txt / emails_error.txt"
    )


def _hotmail_get_refresh_lock(email_addr):
    key = email_addr.strip().lower()
    with _hotmail_refresh_locks_lock:
        lock = _hotmail_refresh_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _hotmail_refresh_locks[key] = lock
        return lock


def _hotmail_update_refresh_token_file(email_addr, new_refresh_token, log_callback=None):
    path = get_hotmail_accounts_file()
    if not new_refresh_token or not os.path.exists(path):
        return
    with _hotmail_accounts_lock:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                lines = f.readlines()
            changed = False
            out_lines = []
            for raw in lines:
                item = _hotmail_split_credential_line(raw)
                if item and item["email"].lower() == email_addr.lower():
                    newline = (
                        f"{item['email']}----{item['password']}----"
                        f"{item['client_id']}----{new_refresh_token}\n"
                    )
                    out_lines.append(newline)
                    changed = True
                else:
                    out_lines.append(raw)
            if changed:
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(out_lines)
                global _hotmail_accounts_mtime
                _hotmail_accounts_mtime = os.path.getmtime(path)
                if log_callback:
                    log_callback(f"[*] Hotmail refresh_token 已回写: {email_addr}")
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Hotmail refresh_token 回写失败: {exc}")


def _hotmail_is_transient_oauth_error(exc) -> bool:
    """Network/proxy/TLS errors worth retrying before declaring OAuth refresh failed."""
    text = str(exc or "").lower()
    if not text:
        return False
    markers = (
        "curl: (35)",
        "tls connect",
        "ssl",
        "openssl",
        "proxy",
        "could not connect",
        "connection reset",
        "connection refused",
        "connection closed",
        "connection timed out",
        "timeout",
        "timed out",
        "broken pipe",
        "unexpected eof",
        "network is unreachable",
        "failed to connect",
        "failed to perform",
    )
    return any(marker in text for marker in markers)


def _hotmail_oauth_retry_settings() -> tuple[int, float]:
    try:
        retries = int(config.get("hotmail_oauth_network_retries", 2) or 0)
    except Exception:
        retries = 2
    try:
        delay = float(config.get("hotmail_oauth_retry_delay_sec", 1.0) or 0)
    except Exception:
        delay = 1.0
    return max(0, retries), max(0.0, delay)


def _hotmail_oauth_post_with_retries(url, data, *, timeout=30, log_callback=None):
    retries, delay = _hotmail_oauth_retry_settings()
    attempts = 1 + retries
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return http_post(url, data=data, timeout=timeout)
        except Exception as exc:
            last_exc = exc
            if attempt >= attempts or not _hotmail_is_transient_oauth_error(exc):
                raise
            if log_callback:
                log_callback(
                    f"[Debug] Hotmail OAuth2 网络/TLS 错误，重试 {attempt}/{retries}: {exc}"
                )
            if delay > 0:
                time.sleep(delay)
    raise last_exc or Exception("Hotmail OAuth2 refresh network retry failed")


def _hotmail_refresh_token_with_endpoints(account, endpoints, log_callback=None):
    """按指定端点刷新 access_token；成功回写新 refresh_token。全部失败抛异常。"""
    email_addr = account["email"]
    lock = _hotmail_get_refresh_lock(email_addr)
    with lock:
        refresh_token = account.get("refresh_token", "")
        last_error = None
        for url, extra in endpoints:
            try:
                data = {
                    "client_id": account["client_id"],
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    **extra,
                }
                resp = _hotmail_oauth_post_with_retries(
                    url,
                    data,
                    timeout=30,
                    log_callback=log_callback,
                )
                try:
                    token_data = resp.json()
                except Exception:
                    token_data = {}
                access_token = token_data.get("access_token")
                if access_token:
                    new_refresh = token_data.get("refresh_token") or refresh_token
                    if new_refresh and new_refresh != refresh_token:
                        account["refresh_token"] = new_refresh
                        _hotmail_update_refresh_token_file(
                            email_addr, new_refresh, log_callback=log_callback
                        )
                    if log_callback:
                        log_callback(f"[*] Hotmail OAuth2 access_token 刷新成功: {email_addr}")
                    return access_token
                last_error = token_data.get("error_description") or token_data.get("error") or resp.text[:200]
            except Exception as exc:
                last_error = exc
                continue
        raise Exception(f"Hotmail OAuth2 refresh 失败: {last_error}")


def _hotmail_try_refresh_any(account, endpoints):
    """静默版刷新：任一端点成功即返回 access_token，否则返回 None。"""
    email_addr = account["email"]
    lock = _hotmail_get_refresh_lock(email_addr)
    with lock:
        refresh_token = account.get("refresh_token", "")
        for url, extra in endpoints:
            try:
                data = {
                    "client_id": account["client_id"],
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    **extra,
                }
                resp = _hotmail_oauth_post_with_retries(url, data, timeout=30)
                token_data = resp.json()
                access_token = token_data.get("access_token")
                if access_token:
                    new_refresh = token_data.get("refresh_token") or refresh_token
                    if new_refresh and new_refresh != refresh_token:
                        account["refresh_token"] = new_refresh
                        _hotmail_update_refresh_token_file(email_addr, new_refresh)
                    return access_token
            except Exception:
                continue
        return None


def hotmail_refresh_access_token(account, log_callback=None):
    return _hotmail_refresh_token_with_endpoints(
        account, HOTMAIL_TOKEN_ENDPOINTS, log_callback=log_callback
    )


def _hotmail_try_imap_auth(mailbox_email, access_token):
    """真实 XOAUTH2 试登录，任一 IMAP host 成功即 True。"""
    import imaplib

    for host in _hotmail_get_imap_hosts():
        imap = None
        try:
            imap = imaplib.IMAP4_SSL(host, 993, timeout=30)
            auth_string = f"user={mailbox_email}\x01auth=Bearer {access_token}\x01\x01"
            imap.authenticate("XOAUTH2", lambda _: auth_string.encode())
            return True
        except Exception:
            continue
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    pass
    return False


def hotmail_detect_protocol(account, log_callback=None):
    """探测凭证可用的收码协议：imap / graph。结果按主邮箱缓存。

    config hotmail_protocol 可强制指定（auto/imap/graph）。
    """
    email_key = account["email"].strip().lower()
    forced = str(config.get("hotmail_protocol", "auto") or "auto").strip().lower()
    if forced in ("imap", "graph"):
        _hotmail_protocol_map[email_key] = forced
        return forced
    cached = _hotmail_protocol_map.get(email_key)
    if cached:
        return cached

    # IMAP：scoped 刷新 + legacy 刷新，拿到 token 后必须真实 XOAUTH2 试登录确认。
    for endpoints in (HOTMAIL_IMAP_TOKEN_ENDPOINTS, HOTMAIL_LEGACY_TOKEN_ENDPOINTS):
        token = _hotmail_try_refresh_any(account, endpoints)
        if token and _hotmail_try_imap_auth(account["email"], token):
            _hotmail_protocol_map[email_key] = "imap"
            if log_callback:
                log_callback(f"[*] Hotmail 收码协议探测: {email_key} -> imap")
            return "imap"

    _hotmail_protocol_map[email_key] = "graph"
    if log_callback:
        log_callback(f"[*] Hotmail 收码协议探测: {email_key} -> graph（凭证未授权 IMAP scope）")
    return "graph"


def _hotmail_decode_header(value):
    if not value:
        return ""
    try:
        from email.header import decode_header, make_header

        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _hotmail_message_body(msg):
    import html as html_lib
    import re as re_lib

    def decode_part(part):
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="ignore")

    if msg.is_multipart():
        text_body = ""
        html_body = ""
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not text_body:
                text_body = decode_part(part)
            elif content_type == "text/html" and not html_body:
                html_body = decode_part(part)
        if text_body:
            return text_body
        return re_lib.sub(r"\s+", " ", re_lib.sub(r"<[^>]+>", " ", html_lib.unescape(html_body))).strip()
    return decode_part(msg)


def _hotmail_get_imap_hosts():
    raw = config.get("hotmail_imap_hosts", "outlook.office365.com,imap-mail.outlook.com")
    if isinstance(raw, (list, tuple)):
        hosts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        hosts = [x.strip() for x in re.split(r"[,，\\s]+", str(raw or "")) if x.strip()]
    out = []
    for host in hosts or ["outlook.office365.com", "imap-mail.outlook.com"]:
        if host not in out:
            out.append(host)
    return out


def _hotmail_effective_filter_after(recent_seconds, issued_after=None):
    try:
        recent_after = time.time() - max(60, int(recent_seconds or 900))
    except Exception:
        recent_after = time.time() - 900
    if issued_after is None:
        return recent_after
    try:
        issued_ts = float(issued_after)
    except Exception:
        return recent_after
    try:
        grace = float(config.get("hotmail_issued_after_grace_seconds", 10) or 10)
    except Exception:
        grace = 10.0
    return max(recent_after, issued_ts - max(0.0, grace))


def _hotmail_imap_get_code(mailbox_email, target_email, access_token, log_callback=None, host=None, issued_after=None):
    import email as email_lib
    import imaplib
    from datetime import timezone
    from email.utils import parsedate_to_datetime

    try:
        recent_seconds = int(config.get("hotmail_recent_seconds", 900) or 900)
    except Exception:
        recent_seconds = 900
    try:
        last_n = int(config.get("hotmail_imap_last_n", 30) or 30)
    except Exception:
        last_n = 30
    require_recipient = _config_bool(
        config.get("hotmail_require_recipient_match", True), default=True
    )
    filter_after_ts = int(_hotmail_effective_filter_after(recent_seconds, issued_after) * 1000)
    target_lower = (target_email or "").strip().lower()
    keywords = ["x.ai", "xai", "grok", "verification", "code", "confirm", "验证码", "确认"]

    host = host or "outlook.office365.com"
    if log_callback:
        log_callback(f"[Debug] Hotmail/Outlook IMAP 连接: host={host} user={mailbox_email}")
    imap = imaplib.IMAP4_SSL(host, 993, timeout=45)
    auth_string = f"user={mailbox_email}\x01auth=Bearer {access_token}\x01\x01"
    imap.authenticate("XOAUTH2", lambda _: auth_string.encode())
    try:
        imap.select("INBOX")
        status, data = imap.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            return None
        msg_ids = data[0].split()[-max(1, last_n):]
        for mid in reversed(msg_ids):
            _, msg_data = imap.fetch(mid, "(RFC822)")
            if not msg_data or not msg_data[0] or not isinstance(msg_data[0][1], bytes):
                continue
            msg = email_lib.message_from_bytes(msg_data[0][1])

            date_str = msg.get("Date")
            if date_str:
                try:
                    dt = parsedate_to_datetime(date_str)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if int(dt.timestamp() * 1000) < filter_after_ts:
                        continue
                except Exception:
                    pass

            subject = _hotmail_decode_header(msg.get("Subject", ""))
            sender = _hotmail_decode_header(msg.get("From", ""))
            recipient_blob = " ".join(
                _hotmail_decode_header(msg.get(h, ""))
                for h in (
                    "To",
                    "Cc",
                    "Delivered-To",
                    "X-Original-To",
                    "Original-Recipient",
                    "Envelope-To",
                )
            ).lower()
            recipient_matched = not target_lower or target_lower in recipient_blob
            if require_recipient and not recipient_matched:
                continue

            body = _hotmail_message_body(msg)
            combined = f"{subject}\n{sender}\n{recipient_blob}\n{body}"
            combined_lower = combined.lower()
            if not any(kw in combined_lower for kw in keywords):
                continue
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Hotmail/Outlook 从邮件中提取到验证码: {code}")
                return code
        return None
    finally:
        try:
            imap.close()
        except Exception:
            pass
        try:
            imap.logout()
        except Exception:
            pass


def _hotmail_graph_message_text(body_obj):
    """Graph body -> 纯文本（对齐 IMAP 路径的 html 处理方式）。"""
    import html as html_lib

    content = (body_obj or {}).get("content") or ""
    content_type = str((body_obj or {}).get("contentType") or "").lower()
    if content_type == "html":
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_lib.unescape(content))).strip()
    return content


def hotmail_graph_get_code(mailbox_email, target_email, access_token, log_callback=None, issued_after=None):
    """通过 Microsoft Graph API 拉取最新邮件并提取验证码（Mail.Read scope）。"""
    from datetime import datetime, timezone

    try:
        recent_seconds = int(config.get("hotmail_recent_seconds", 900) or 900)
    except Exception:
        recent_seconds = 900
    try:
        last_n = int(config.get("hotmail_imap_last_n", 30) or 30)
    except Exception:
        last_n = 30
    require_recipient = _config_bool(
        config.get("hotmail_require_recipient_match", True), default=True
    )
    filter_after_ts = _hotmail_effective_filter_after(recent_seconds, issued_after)
    target_lower = (target_email or "").strip().lower()
    keywords = ["x.ai", "xai", "grok", "verification", "code", "confirm", "验证码", "确认"]

    if log_callback:
        log_callback(f"[Debug] Hotmail/Outlook Graph 拉取邮件: user={mailbox_email}")
    # ChatGPT/xAI 的验证码邮件经常落进垃圾邮件文件夹，INBOX + Junk 都要扫
    raw_folders = str(config.get("hotmail_graph_folders", "inbox,junkemail") or "inbox,junkemail")
    folders = [f.strip() for f in raw_folders.replace("，", ",").split(",") if f.strip()] or ["inbox", "junkemail"]
    messages: list[dict] = []
    seen_ids: set[str] = set()
    select = "subject,from,receivedDateTime,toRecipients,ccRecipients,body"
    for folder in folders:
        url = (
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages"
            f"?$top={max(1, last_n)}&$orderby=receivedDateTime desc&$select={select}"
        )
        resp = http_get(url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
        if resp.status_code in (401, 403):
            raise Exception(f"Graph 鉴权失败 HTTP {resp.status_code}")
        if resp.status_code != 200:
            if log_callback:
                log_callback(f"[Debug] Graph {folder} 拉取失败 HTTP {resp.status_code}，跳过")
            continue
        for message in resp.json().get("value", []) or []:
            mid = str(message.get("id") or "")
            if mid and mid in seen_ids:
                continue
            if mid:
                seen_ids.add(mid)
            message["_folder"] = folder
            messages.append(message)

    messages.sort(key=lambda m: str(m.get("receivedDateTime") or ""), reverse=True)
    for message in messages:
        received = message.get("receivedDateTime") or ""
        if received:
            try:
                dt = datetime.fromisoformat(str(received).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt.timestamp() < filter_after_ts:
                    continue
            except Exception:
                pass

        recipient_blob = " ".join(
            str((r.get("emailAddress") or {}).get("address") or "")
            for r in (message.get("toRecipients") or []) + (message.get("ccRecipients") or [])
        ).lower()
        if require_recipient and target_lower and target_lower not in recipient_blob:
            continue

        subject = message.get("subject") or ""
        sender = str(((message.get("from") or {}).get("emailAddress") or {}).get("address") or "")
        body = _hotmail_graph_message_text(message.get("body"))
        combined = f"{subject}\n{sender}\n{recipient_blob}\n{body}"
        combined_lower = combined.lower()
        if not any(kw in combined_lower for kw in keywords):
            continue
        code = extract_verification_code(combined, subject)
        if code:
            if log_callback:
                log_callback(f"[*] Hotmail/Outlook 从邮件中提取到验证码: {code}")
            return code
    return None


def hotmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
    issued_after=None,
):
    token_info = _hotmail_token_map.get(dev_token)
    if not token_info:
        raise Exception("Hotmail/Outlook dev_token 无效或已过期")
    account = token_info["account"]
    mailbox_email = account["email"]
    protocol = hotmail_detect_protocol(account, log_callback=log_callback)
    try:
        configured_interval = float(config.get("hotmail_poll_interval", 5) or 5)
    except Exception:
        configured_interval = 5.0
    current_interval = max(1.0, configured_interval or float(poll_interval or 3))
    deadline = time.time() + timeout
    access_token = None
    next_resend_at = time.time() + 60
    round_no = 0

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        round_no += 1
        # 日志节流：高并发下每轮都输出会刷爆任务日志/前端，
        # 仅首轮与每 12 轮输出一次详细轮询信息；错误始终输出。
        verbose = round_no == 1 or round_no % 12 == 0
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_started = time.time()
                resend_callback()
                issued_after = resend_started
                remember_email_issued_after(email, issued_after)
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 60
        try:
            if not access_token:
                if protocol == "graph":
                    access_token = _hotmail_refresh_token_with_endpoints(
                        account, HOTMAIL_GRAPH_TOKEN_ENDPOINTS, log_callback=log_callback
                    )
                else:
                    access_token = hotmail_refresh_access_token(account, log_callback=log_callback)
            code = None
            if protocol == "graph":
                code = hotmail_graph_get_code(
                    mailbox_email,
                    email,
                    access_token,
                    log_callback=log_callback if verbose else None,
                    issued_after=issued_after,
                )
            else:
                host_errors = []
                for imap_host in _hotmail_get_imap_hosts():
                    try:
                        code = _hotmail_imap_get_code(
                            mailbox_email,
                            email,
                            access_token,
                            log_callback=log_callback,
                            host=imap_host,
                            issued_after=issued_after,
                        )
                        # 成功连接但本轮未找到码，不必再换同邮箱另一个 host 重扫。
                        break
                    except Exception as host_exc:
                        host_errors.append(f"{imap_host}: {host_exc}")
                        if log_callback:
                            log_callback(f"[Debug] Hotmail/Outlook IMAP host 失败: {imap_host}: {host_exc}")
                        continue
                if code is None and host_errors and len(host_errors) >= len(_hotmail_get_imap_hosts()):
                    raise Exception("; ".join(host_errors))
            if code:
                return code
            if verbose and log_callback:
                log_callback(f"[Debug] Hotmail/Outlook 未收到验证码（第 {round_no} 轮轮询中）: {email}")
        except Exception as exc:
            # OAuth/IMAP/Graph 临时失败时下一轮重新 refresh access_token。
            access_token = None
            if log_callback:
                log_callback(f"[Debug] Hotmail/Outlook 拉取验证码失败: {exc}")
        sleep_with_cancel(current_interval, cancel_callback)
    raise Exception(f"Hotmail/Outlook 在 {timeout}s 内未收到验证码邮件: {email}")


# ──────────────────────── 公共邮箱工具 ────────────────────────

def get_email_provider():
    return str(config.get("email_provider", "duckmail") or "duckmail").strip().lower()


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    if provider in ("hotmail", "outlook", "outlookmail", "microsoft"):
        return hotmail_get_email_and_token()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider == "cloudmail":
        # CloudMail catch-all 模式：直接生成随机邮箱，无需注册
        # Cloudflare Email Routing 会自动将所有该域名的邮件路由到 Worker
        # 支持英文逗号、中文逗号、空格分隔
        raw = str(config.get("defaultDomains", "") or "")
        domains = [x.strip() for x in re.split(r"[,，\s]+", raw) if x.strip()]
        if not domains:
            raise Exception("CloudMail 需要在 defaultDomains 中配置可用域名")
        domain = _pick_cf_domain(domains)
        username = generate_username(10)
        address = f"{username}@{domain}"
        # 返回占位 token（实际不用于邮件查询，邮件查询走公开 API）
        return address, "cloudmail_catch_all"
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        return cloudflare_create_temp_address(api_base)
    if provider == "mailnest":
        return mailnest_buy_email(), "_"
    key = api_key or get_duckmail_api_key()
    domain = pick_domain(api_key=key)
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(address, password, api_key=key, expires_in=0)
    token = get_token(address, password)
    if not token:
        raise Exception("获取 DuckMail token 失败")
    return address, token


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
    issued_after=None,
):
    provider = get_email_provider()
    if provider in ("hotmail", "outlook", "outlookmail", "microsoft"):
        return hotmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
            issued_after=issued_after,
        )
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudmail":
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "mailnest":
        return mailnest_get_code(
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def extract_verification_code(text, subject=""):
    """Extract xAI verification code from mail subject/body.

    Prefer explicit code context and subject matches.  Cloudflare parsed HTML can
    contain unrelated tokens such as ``per-100``; a blind
    ``[A-Z0-9]{3}-[A-Z0-9]{3}`` search over the whole body may otherwise pick
    those before the real code in the subject.
    """
    text = str(text or "")
    subject = str(subject or "")

    def _clean(candidate: str | None) -> str | None:
        if not candidate:
            return None
        code = str(candidate).strip().strip(".,;:()[]{}<>\"'").upper()
        if re.fullmatch(r"[A-Z0-9]{3}-[A-Z0-9]{3}", code):
            # Reject common non-code CSS/text fragments that matched only
            # because the old regex was case-insensitive.
            original = str(candidate).strip().strip(".,;:()[]{}<>\"'")
            alpha = re.sub(r"[^A-Za-z]", "", original)
            if alpha and alpha != alpha.upper():
                return None
            return code
        if re.fullmatch(r"\d{4,8}", code):
            return code
        return None

    hyphen_code = r"([A-Z0-9]{3}-[A-Z0-9]{3})"
    numeric_code = r"(\d{4,8})"

    # 1) Strong subject patterns: "SpaceXAI confirmation code: 9F0-3AK"
    #    and the older "ABC-123 xAI" subject shape.
    subject_patterns = [
        rf"(?:verification|confirm(?:ation)?|security|login)?\s*code\s*[:：#-]?\s*{hyphen_code}",
        rf"confirm(?:ation)?\s+code\s*[:：#-]?\s*{hyphen_code}",
        rf"^\s*{hyphen_code}\s+xAI\b",
        rf"\b{hyphen_code}\b",
    ]
    for pattern in subject_patterns:
        match = re.search(pattern, subject, re.IGNORECASE)
        code = _clean(match.group(1) if match else None)
        if code:
            return code

    # 2) Body with explicit context. Support both current hyphenated alnum
    #    codes and older numeric-only providers.
    context_patterns = [
        rf"(?:verification|confirm(?:ation)?|security|login)?\s*code\s*[:：#-]?\s*{hyphen_code}",
        rf"confirm(?:ation)?\s+code\s*[:：#-]?\s*{hyphen_code}",
        rf"verification\s+code\s*[:：#-]?\s*{numeric_code}",
        rf"verification\s+code\s+is\s+{numeric_code}",
        rf"(?:temporary\s+\w+\s+verification\s+)?code\s+is\s+{numeric_code}",
        rf"your\s+code\s*[:：#-]?\s*{numeric_code}",
        rf"confirm(?:ation)?\s+code\s*[:：#-]?\s*{numeric_code}",
    ]
    for pattern in context_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        code = _clean(match.group(1) if match else None)
        if code:
            return code

    # 2.5) ChatGPT/OpenAI 兜底：邮件已被关键词筛选过，纯 6 位数字即验证码
    match = re.search(r"\b(\d{6})\b", text)
    code = _clean(match.group(1) if match else None)
    if code:
        return code

    # 3) Last-resort generic body match, but keep the lowercase-fragment guard.
    for match in re.finditer(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", text):
        code = _clean(match.group(1))
        if code:
            return code
    return None


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if email.lower() not in recipients:
                continue
            try:
                detail = get_message_detail(dev_token, msg_id)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 获取邮件详情失败: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"在 {timeout}s 内未收到验证码邮件")


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    api_base = get_cloudflare_api_base()
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    deadline = time.time() + timeout
    # 同一封邮件正文可能延迟可读，允许多次重试解析，避免偶发漏码
    seen_attempts = {}
    next_resend_at = time.time() + 35
    round_no = 0
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        round_no += 1
        # 日志节流：仅首轮与每 12 轮输出轮询信息，错误始终输出
        verbose = round_no == 1 or round_no % 12 == 0
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            messages = cloudflare_get_messages(api_base, dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if verbose and log_callback:
            log_callback(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}（第 {round_no} 轮）")

        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            raw_to = msg.get("to") or []
            recipients = []
            if isinstance(raw_to, list):
                for target in raw_to:
                    if isinstance(target, dict):
                        recipients.append(str(target.get("address", "")).lower())
                    elif isinstance(target, str):
                        recipients.append(target.lower())
            elif isinstance(raw_to, str):
                recipients.append(raw_to.lower())
            msg_addr = str(msg.get("address", "")).lower()
            address_matched = True
            if recipients:
                address_matched = any(email.lower() in target for target in recipients)
            elif msg_addr:
                address_matched = email.lower() in msg_addr
            if not address_matched and log_callback:
                log_callback(f"[Debug] 跳过疑似非目标邮件 id={msg_id} address={msg_addr} to={recipients}")
                continue
            parts = []
            for field in ("text", "raw", "source", "content", "intro", "body", "snippet"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_list = msg.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            # 再尝试 detail 接口补全内容
            try:
                detail = cloudflare_get_message_detail(api_base, dev_token, msg_id)
                for field in ("text", "raw", "source", "content", "intro", "body", "snippet"):
                    value = detail.get(field)
                    if isinstance(value, str) and value.strip():
                        combined += "\n" + value
                html_list2 = detail.get("html") or []
                if isinstance(html_list2, str):
                    html_list2 = [html_list2]
                for h in html_list2:
                    combined += "\n" + re.sub(r"<[^>]+>", " ", h)
                if not subject:
                    subject = str(detail.get("subject", "") or "")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            if log_callback:
                log_callback(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def set_birth_date(session, log_callback=None):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {res.text[:200]}"
            )
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 寮傚父: {e}")
        return False


def set_tos_accepted(session, log_callback=None):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 寮傚父: {e}")
        return False


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] update_nsfw status: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 寮傚父: {e}")
        return False


def enable_nsfw_for_token(token, cf_clearance="", log_callback=None):
    proxies = get_proxies()
    user_agent = get_user_agent()
    try:
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            session.headers.update(
                {
                    "user-agent": user_agent,
                    "cookie": f"sso={token}; sso-rw={token}; cf_clearance={cf_clearance}",
                }
            )
            if not set_tos_accepted(session, log_callback):
                return False, "set_tos_accepted 澶辫触!"
            if not set_birth_date(session, log_callback):
                return False, "set_birth_date 澶辫触!"
            if not update_nsfw_settings(session, log_callback):
                return False, "update_nsfw_settings 澶辫触!"
            return True, "鎴愬姛寮€鍚疦SFW"
    except Exception as e:
        return False, f"寮傚父: {str(e)}"


SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"

_thread_ctx = threading.local()

from tab_pool import TabPool


def _get_browser():
    return TabPool.get_browser()


def _set_browser(value):
    pass  # TabPool 管理 browser，外部 setter 为 no-op


def _get_page():
    if TabPool.get_browser() is None:
        return None
    return TabPool.get_tab()


def _set_page(value):
    pass  # TabPool 管理 tab，外部 setter 为 no-op


def start_browser(log_callback=None):
    last_exc = None
    for attempt in range(1, 5):
        try:
            TabPool.init(create_browser_options, log_callback=log_callback)
            page = TabPool.get_tab()
            attach_proxy_auth(page, log_callback=log_callback if attempt == 1 else None)
            apply_page_fingerprint(page, log_callback=log_callback if attempt == 1 else None)
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return TabPool.get_browser(), page
        except Exception as exc:
            last_exc = exc
            if log_callback:
                log_callback(f"[Debug] 浏览器启动失败(第{attempt}/4次): {exc}")
            # 每线程独立浏览器，shutdown 只影响当前线程
            try:
                TabPool.release_tab()
            except Exception:
                pass
            human_sleep(min(1.5 * attempt, 4))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser():
    """Quit current-thread Chromium (full process exit + del_data)."""
    TabPool.release_tab()


def prepare_browser_for_next_account(log_callback=None, force_recycle: bool = False):
    """Between accounts: clear session (reuse) or full recycle.

    Returns (browser, page).
    """
    reuse = bool(PERF_FLAGS.get("browser_reuse", True)) and not force_recycle
    every = int(PERF_FLAGS.get("browser_recycle_every", 25) or 25)
    served = TabPool.served_count()
    if reuse and TabPool.get_browser() is not None and (every <= 0 or served < every):
        if TabPool.clear_session(log_callback=log_callback):
            TabPool.mark_served()
            return TabPool.get_browser(), _get_page()
    # full recycle
    if log_callback:
        log_callback(f"[*] 浏览器完整回收（reuse={reuse}, served={served}, every={every}）")
    TabPool.release_tab()
    return start_browser(log_callback=log_callback)


def shutdown_browser():
    """Quit all tracked Chromium instances."""
    TabPool.shutdown()


def restart_browser(log_callback=None):
    TabPool.release_tab()
    return start_browser(log_callback=log_callback)


def refresh_active_page():
    if TabPool.get_browser() is None:
        restart_browser()
    try:
        browser = TabPool.get_browser()
        tabs = browser.tab_ids
        if tabs:
            page = browser.get_tab(tabs[-1])
        else:
            page = browser.new_tab()
        page.refresh()
        TabPool.sync_tab()
    except Exception:
        restart_browser()
    return _get_page()


def click_email_signup_button(timeout=10, log_callback=None, cancel_callback=None):
    page = _get_page()
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if log_callback:
            log_callback("[Debug] 尝试查找“使用邮箱注册”按钮...")

        clicked = page.run_js(r"""
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = candidates.find((node) => {
    const text = (node.innerText || node.textContent || '').replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text.includes('使用邮箱注册') ||
        lower.includes('signupwithemail') ||
        lower.includes('continuewithemail') ||
        lower.includes('email')
    );
});
if (!target) {
    return false;
}
target.click();
return true;
        """)

        if clicked:
            if log_callback:
                log_callback("[*] 已点击「使用邮箱注册」按钮")
            human_sleep(2, cancel_callback)
            return True

        if log_callback:
            current_url = page.url if page else "none"
            log_callback(f"[Debug] 当前URL: {current_url}")

        human_sleep(1, cancel_callback)

    if log_callback:
        page_html = page.html[:500] if page else "no page"
        log_callback(f"[Debug] 页面内容片段: {page_html}")

    raise Exception("未找到「使用邮箱注册」按钮")


def open_signup_page(log_callback=None, cancel_callback=None):
    browser = _get_browser()
    page = _get_page()
    raise_if_cancelled(cancel_callback)
    if browser is None:
        browser, page = start_browser()
        if log_callback:
            log_callback("[*] 浏览器已启动")
    try:
        page = _get_page()
        page.get(SIGNUP_URL)
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        try:
            TabPool.release_tab()
            page = _get_page()
            page.get(SIGNUP_URL)
        except Exception as e2:
            if log_callback:
                log_callback(f"[Debug] 创建新标签页异常: {e2}")
            restart_browser()
            page = _get_page()
            page.get(SIGNUP_URL)
    page.wait.doc_loaded()
    dump_state(page, "signup-loaded")
    take_screenshot(page, "signup")
    human_sleep(2, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {page.url}")
    click_email_signup_button(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    dump_state(page, "after-email-signup-click")


def has_profile_form(log_callback=None):
    page = refresh_active_page()
    try:
        return bool(
            page.run_js(
                """
const givenInput = document.querySelector('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"]');
const familyInput = document.querySelector('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"]');
const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"]');
return !!(givenInput && familyInput && passwordInput);
            """
            )
        )
    except Exception:
        return False


def fill_email_and_submit(timeout=15, log_callback=None, cancel_callback=None):
    page = _get_page()
    raise_if_cancelled(cancel_callback)
    check_timeout(time.time())
    email, dev_token = get_email_and_token()
    if not email or not dev_token:
        raise Exception("获取邮箱失败")
    if log_callback:
        log_callback(f"[*] 已创建邮箱: {email}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            """
const email = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const input = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"]')).find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input) return 'not-ready';
input.focus(); input.click();
// 清空并设置值
const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
const tracker = input._valueTracker;
if (tracker) tracker.setValue('');
if (valueSetter) valueSetter.call(input, email); else input.value = email;
// 完整事件序列，确保 React 受控组件同步
input.dispatchEvent(new Event('focus', { bubbles: true }));
input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new InputEvent('input', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
input.dispatchEvent(new Event('blur', { bubbles: true }));
// 验证：值已写入即可（不依赖 checkValidity，部分站点自定义校验会导致误判）
const current = (input.value || '').trim();
if (current === email) return 'filled';
// 兜底：尝试逐字符输入
input.value = '';
input.dispatchEvent(new Event('input', { bubbles: true }));
for (const ch of email) {
    input.dispatchEvent(new KeyboardEvent('keydown', { key: ch, bubbles: true }));
    input.value += ch;
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: ch, inputType: 'insertText' }));
    input.dispatchEvent(new KeyboardEvent('keyup', { key: ch, bubbles: true }));
}
input.dispatchEvent(new Event('change', { bubbles: true }));
if ((input.value || '').trim() === email) return 'filled';
return input.value;
            """,
            email,
        )
        if filled == "not-ready":
            human_sleep(0.5, cancel_callback)
            continue
        if filled != "filled":
            if log_callback:
                log_callback(f"[Debug] 邮箱输入框已出现，但写入失败: {filled}")
            human_sleep(0.5, cancel_callback)
            continue
        human_sleep(0.8, cancel_callback)
        issued_after = time.time()
        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const input = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"]')).find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input || !input.checkValidity() || !(input.value || '').trim()) return false;
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button')).filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true');
const submitButton = buttons.find((node) => {
    const text = (node.innerText || node.textContent || '').replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text === '注册' ||
        text.includes('注册') ||
        lower.includes('sign up') ||
        lower.includes('continue') ||
        lower.includes('next')
    );
});
if (!submitButton || submitButton.disabled) return false;
submitButton.click();
return true;
            """
        )
        if clicked:
            remember_email_issued_after(email, issued_after)
            if log_callback:
                log_callback(f"[*] 已填写邮箱并点击注册: {email}")
            dump_state(page, "email-submitted")
            take_screenshot(page, "email-submitted")
            return email, dev_token
        human_sleep(0.5, cancel_callback)
    raise Exception("未找到邮箱输入框或注册按钮")


def fill_code_and_submit(email, dev_token, timeout=180, log_callback=None, cancel_callback=None):
    page = _get_page()
    check_timeout(time.time())
    dump_state(page, "wait-code")
    take_screenshot(page, "wait-code")
    def _resend_code():
        page.run_js(
            r"""
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = nodes.find((node) => {
  const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
  return t.includes('重新发送') || t.includes('resend') || t.includes('再次发送');
});
if (target && !target.disabled) { target.click(); return true; }
return false;
            """
        )

    try:
        mail_timeout = int(config.get("mail_timeout", timeout) or timeout)
    except Exception:
        mail_timeout = timeout
    try:
        mail_poll_interval = float(config.get("mail_poll_interval", 3) or 3)
    except Exception:
        mail_poll_interval = 3

    issued_after = get_email_issued_after(email)
    code = get_oai_code(
        dev_token,
        email,
        timeout=mail_timeout,
        poll_interval=mail_poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=_resend_code,
        issued_after=issued_after,
    )
    if not code:
        raise Exception("获取验证码失败")
    clean_code = str(code).replace("-", "").strip()
    deadline = time.time() + timeout

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            """
const code = String(arguments[0] || '').trim();
if (!code) return 'empty-code';

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function setInputValue(input, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

const aggregate = Array.from(document.querySelectorAll(
  'input[data-input-otp=\"true\"], input[name=\"code\"], input[autocomplete=\"one-time-code\"], input[inputmode=\"numeric\"], input[inputmode=\"text\"]'
)).find((node) => isVisible(node) && !node.disabled && !node.readOnly && Number(node.maxLength || 6) > 1);

if (aggregate) {
    aggregate.focus();
    aggregate.click();
    setInputValue(aggregate, code);
    return String(aggregate.value || '').replace(/\\s+/g, '') ? 'filled-aggregate' : 'aggregate-failed';
}

const otpBoxes = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const maxLength = Number(node.maxLength || 0);
    const ac = String(node.autocomplete || '').toLowerCase();
    return maxLength === 1 || ac === 'one-time-code';
});

if (otpBoxes.length >= code.length) {
    for (let i = 0; i < code.length; i += 1) {
        const ch = code[i] || '';
        const box = otpBoxes[i];
        box.focus();
        box.click();
        setInputValue(box, ch);
        box.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ch }));
        box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ch }));
    }
    const merged = otpBoxes.slice(0, code.length).map((x) => String(x.value || '').trim()).join('');
    return merged.length ? 'filled-boxes' : 'boxes-failed';
}

return 'not-ready';
            """,
            clean_code,
        )

        if filled == "not-ready":
            human_sleep(0.5, cancel_callback)
            continue
        if "failed" in str(filled):
            if log_callback:
                log_callback(f"[Debug] 验证码填写失败: {filled}")
            human_sleep(0.5, cancel_callback)
            continue

        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const buttons = Array.from(document.querySelectorAll('button[type=\"submit\"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});

const btn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return (
        t.includes('确认邮箱') ||
        t.includes('继续') ||
        t.includes('下一步') ||
        t.includes('confirm') ||
        t.includes('continue') ||
        t.includes('next')
    );
});

if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
            """
        )

        if clicked == "clicked" or clicked == "no-button":
            if log_callback:
                log_callback(f"[*] 已填写验证码并提交: {code}")
            human_sleep(1.5, cancel_callback)
            return code

        human_sleep(0.5, cancel_callback)

    raise Exception("验证码已获取，但自动填写/提交失败")


def getTurnstileToken(log_callback=None, cancel_callback=None):
    page = _get_page()
    if page is None:
        raise Exception("页面未就绪，无法执行 Turnstile")

    try:
        page.run_js(
            "try { if (window.turnstile && typeof turnstile.reset === 'function') turnstile.reset(); } catch(e) {}"
        )
    except Exception:
        pass

    for _ in range(0, 20):
        raise_if_cancelled(cancel_callback)
        try:
            token = page.run_js(
                """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
                """
            )
            token = str(token or "").strip()
            if len(token) >= 80:
                if log_callback:
                    log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
                return token

            challenge_input = page.ele("@name=cf-turnstile-response")
            if challenge_input:
                wrapper = challenge_input.parent()
                iframe = None
                try:
                    iframe = wrapper.shadow_root.ele("tag:iframe")
                except Exception:
                    iframe = None
                if iframe:
                    try:
                        iframe.run_js(
                            """
window.dtp = 1;
function getRandomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
let sx = getRandomInt(800, 1200);
let sy = getRandomInt(400, 700);
Object.defineProperty(MouseEvent.prototype, 'screenX', { value: sx });
Object.defineProperty(MouseEvent.prototype, 'screenY', { value: sy });
                            """
                        )
                    except Exception:
                        pass
                    try:
                        body_sr = iframe.ele("tag:body").shadow_root
                        btn = body_sr.ele("tag:input")
                        if btn:
                            btn.click()
                    except Exception:
                        pass
            else:
                # 兜底：尝试触发页面上可见的 Turnstile 容器
                page.run_js(
                    """
const nodes = Array.from(document.querySelectorAll('div,span,iframe')).filter((n) => {
  const txt = (n.className || '') + ' ' + (n.id || '') + ' ' + (n.getAttribute?.('src') || '');
  return String(txt).toLowerCase().includes('turnstile');
});
if (nodes.length && typeof nodes[0].click === 'function') nodes[0].click();
                    """
                )
        except Exception:
            pass
        human_sleep(1, cancel_callback)

    save_turnstile_debug(page)
    raise Exception("Turnstile 获取 token 失败")


def build_profile():
    given_name_pool = [
        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",
        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",
        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",
        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",
        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",
        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",
        "Aaron", "Damian",
    ]
    family_name_pool = [
        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",
        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",
        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",
        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",
        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",
        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",
        "Wei", "Xiong",
    ]
    given_name = random.choice(given_name_pool)
    family_name = random.choice(family_name_pool)
    password = "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)
    return given_name, family_name, password


def fill_profile_and_submit(timeout=120, log_callback=None, cancel_callback=None):
    page = _get_page()
    check_timeout(time.time())
    dump_state(page, "profile-form")
    take_screenshot(page, "profile-form")
    given_name, family_name, password = build_profile()
    # 预热 Turnstile：等 2 秒让 iframe 初始化，插件会自动点击 checkbox
    if log_callback:
        log_callback("[*] 预热 Turnstile...")
    human_sleep(2, cancel_callback)
    deadline = time.time() + timeout
    form_filled_once = False
    wait_cf_since = None
    last_cf_retry_at = 0.0

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if not form_filled_once:
            filled = page.run_js(
                """
const givenName = arguments[0];
const familyName = arguments[1];
const password = arguments[2];

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function pickInput(selector) {
    return Array.from(document.querySelectorAll(selector)).find((node) => {
        return isVisible(node) && !node.disabled && !node.readOnly;
    }) || null;
}

function setInputValue(input, value) {
    if (!input) return false;
    input.focus();
    input.click();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.blur();
    return String(input.value || '').trim() === String(value || '').trim();
}

const givenInput = pickInput('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"], input[aria-label*="名"]');
const familyInput = pickInput('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"], input[aria-label*="姓"]');
const passwordInput = pickInput('input[data-testid="password"], input[name="password"], input[type="password"], input[autocomplete="new-password"]');

if (!givenInput || !familyInput || !passwordInput) return 'not-ready';

const ok1 = setInputValue(givenInput, givenName);
const ok2 = setInputValue(familyInput, familyName);
const ok3 = setInputValue(passwordInput, password);

if (!ok1 || !ok2 || !ok3) return 'fill-failed';

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('sign up') || t.includes('createaccount');
});

// 必须等待 Cloudflare 校验通过后再提交
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

if (submitBtn) {
    return 'ready-to-submit';
}
return 'filled-no-submit';
            """,
                given_name,
                family_name,
                password,
            )

            if isinstance(filled, str) and filled.startswith("wait-cloudflare"):
                form_filled_once = True
                if log_callback:
                    token_len = filled.split(":", 1)[1] if ":" in filled else "0"
                    log_callback(f"[*] 资料已填写，等待 Cloudflare 人机验证通过... 当前token长度={token_len}")
                now = time.time()
                if wait_cf_since is None:
                    wait_cf_since = now
                # 卡住后自动二次复用 Turnstile 组件
                if now - wait_cf_since >= 12 and now - last_cf_retry_at >= 8:
                    if log_callback:
                        log_callback("[*] Cloudflare 验证卡住，开始二次复用 Turnstile...")
                    try:
                        token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                        if token:
                            synced = page.run_js(
                                """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                                """,
                                token,
                            )
                            if log_callback:
                                log_callback(f"[*] Turnstile 二次复用完成，回填长度={synced}")
                    except Exception as cf_exc:
                        if log_callback:
                            log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                    last_cf_retry_at = now
                human_sleep(0.8, cancel_callback)
                continue

            if filled in ("ready-to-submit", "filled-no-submit"):
                form_filled_once = True
            elif filled == "fill-failed" and log_callback:
                log_callback("[Debug] 资料输入失败，重试中...")
                human_sleep(0.5, cancel_callback)
                continue
            elif filled == "not-ready":
                human_sleep(0.5, cancel_callback)
                continue

        submit_state = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('sign up') || t.includes('createaccount');
});
if (!submitBtn) return 'no-submit-button';
submitBtn.focus();
submitBtn.click();
return 'submitted';
            """
        )

        if isinstance(submit_state, str) and submit_state.startswith("wait-cloudflare"):
            if log_callback:
                token_len = submit_state.split(":", 1)[1] if ":" in submit_state else "0"
                log_callback(f"[*] 等待 Cloudflare 人机验证通过后再提交... 当前token长度={token_len}")
            now = time.time()
            if wait_cf_since is None:
                wait_cf_since = now
            if now - wait_cf_since >= 12 and now - last_cf_retry_at >= 8:
                if log_callback:
                    log_callback("[*] 提交前仍卡住，自动再次复用 Turnstile...")
                try:
                    token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                    if token:
                        synced = page.run_js(
                            """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                            """,
                            token,
                        )
                        if log_callback:
                            log_callback(f"[*] Turnstile 二次复用完成，回填长度={synced}")
                except Exception as cf_exc:
                    if log_callback:
                        log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                last_cf_retry_at = now
            human_sleep(0.8, cancel_callback)
            continue

        if submit_state == "submitted":
            if log_callback:
                log_callback(f"[*] 已填写注册资料并提交: {given_name} {family_name}")
            return {"given_name": given_name, "family_name": family_name, "password": password}
        wait_cf_since = None
        if submit_state == "no-submit-button" and log_callback:
            log_callback("[Debug] 未找到提交按钮，继续等待页面稳定...")

        human_sleep(0.5, cancel_callback)

    raise Exception("最终注册页资料填写失败")


# ── NSFW 自动开启（从 AaronL725 移植） ──


def generate_random_birthdate():
    """生成随机生日（20-40 岁）。"""
    import datetime as dt
    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def set_birth_date(session, log_callback=None):
    """设置生日。"""
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_birth_date status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        return False, f"set_birth_date HTTP {res.status_code}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None):
    """同意 TOS。"""
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        return False, f"set_tos_accepted HTTP {res.status_code}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    """编码 NSFW 设置 gRPC 请求体。"""
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    """更新 NSFW 设置。"""
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] update_nsfw status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        return False, f"update_nsfw_settings HTTP {res.status_code}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"


def enable_nsfw(sso_cookie, log_callback=None):
    """使用 sso cookie 自动开启 NSFW（生日 + TOS + NSFW 设置）。"""
    from curl_cffi import requests as cf_requests
    session = cf_requests.Session()
    session.cookies.set("sso", sso_cookie, domain="grok.com")
    session.cookies.set("sso", sso_cookie, domain="accounts.x.ai")

    results = {}

    # 1. 设置生日
    ok, msg = set_birth_date(session, log_callback=log_callback)
    results["set_birth_date"] = {"ok": ok, "msg": msg}

    # 2. 同意 TOS
    ok, msg = set_tos_accepted(session, log_callback=log_callback)
    results["set_tos_accepted"] = {"ok": ok, "msg": msg}

    # 3. 开启 NSFW
    ok, msg = update_nsfw_settings(session, log_callback=log_callback)
    results["update_nsfw_settings"] = {"ok": ok, "msg": msg}

    if log_callback:
        all_ok = all(r["ok"] for r in results.values())
        log_callback(f"[*] NSFW 设置: {'全部成功' if all_ok else results}")

    return results


# ── wait_for_sso_cookie ──


def wait_for_sso_cookie(timeout=120, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    last_seen_names = set()
    last_submit_retry = 0.0
    last_cf_retry_at = 0.0

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            page = _get_page()
            if page is None:
                human_sleep(1, cancel_callback)
                continue

            # 仍停留在“完成注册”页时，若 Cloudflare 已通过，周期性重试点击提交
            now = time.time()
            if now - last_submit_retry >= 2.5:
                retried = page.run_js(
                    r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const titleHit = !!Array.from(document.querySelectorAll('h1,h2,div,span')).find((el) => {
    const t = (el.textContent || '').replace(/\s+/g, '');
    return t.includes('完成注册');
});
if (!titleHit) return 'not-final-page';

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solved = token.length >= 80;
    if (!solved) return 'final-page-wait-cf:' + token.length;
}

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('sign up') || t.includes('createaccount');
});
if (!submitBtn) return 'final-page-no-submit';
submitBtn.focus();
submitBtn.click();
return 'final-page-clicked-submit';
                    """
                )
                last_submit_retry = now
                if log_callback and retried in ("final-page-no-submit", "final-page-clicked-submit"):
                    log_callback(f"[Debug] 最终页状态: {retried}")
                if log_callback and isinstance(retried, str) and retried.startswith("final-page-wait-cf"):
                    token_len = retried.split(":", 1)[1] if ":" in retried else "0"
                    log_callback(f"[Debug] 最终页状态: final-page-wait-cf, token长度={token_len}")
                    if now - last_cf_retry_at >= 10:
                        if log_callback:
                            log_callback("[*] 最终页 Cloudflare 卡住，自动二次复用 Turnstile...")
                        try:
                            token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                            if token:
                                synced = page.run_js(
                                    """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                                    """,
                                    token,
                                )
                                if log_callback:
                                    log_callback(f"[*] 最终页 Turnstile 二次复用完成，回填长度={synced}")
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] 最终页 Turnstile 二次复用失败: {cf_exc}")
                        last_cf_retry_at = now

            cookies = page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()

                if name:
                    last_seen_names.add(name)

                if name == "sso" and value:
                    if log_callback:
                        log_callback("[*] 已获取到 sso cookie")
                    return value
        except PageDisconnectedError:
            refresh_active_page()
        except Exception:
            pass

        human_sleep(1, cancel_callback)

    raise Exception(
        f"等待超时：未获取到 sso cookie。已看到 cookies: {sorted(last_seen_names)}"
    )


# ── 登录（非注册）获取 sso ──

LOGIN_URL = "https://accounts.x.ai/login?redirect=grok-com"


def open_login_page(log_callback=None, cancel_callback=None):
    """打开 xAI 登录页，点击「使用邮箱登录」。"""
    browser = _get_browser()
    page = _get_page()
    raise_if_cancelled(cancel_callback)
    if browser is None:
        browser, page = start_browser()
        if log_callback:
            log_callback("[*] 浏览器已启动")
    try:
        page = _get_page()
        page.get(LOGIN_URL)
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        restart_browser()
        page = _get_page()
        page.get(LOGIN_URL)
    page.wait.doc_loaded()
    human_sleep(2, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {page.url}")
    # 点击「使用邮箱登录」
    clicked = page.run_js("""
const btn = document.querySelector('button[data-testid="continue-with-email"]');
if (btn) { btn.click(); return 'clicked'; }
return 'not-found';
""")
    if clicked != 'clicked':
        raise Exception("未找到「使用邮箱登录」按钮")
    human_sleep(2, cancel_callback)
    if log_callback:
        log_callback("[*] 已点击「使用邮箱登录」")


def fill_login_and_submit(email, password, timeout=120, log_callback=None, cancel_callback=None):
    """两步登录：1.填邮箱点下一步 2.填密码处理Turnstile点登录。"""
    page = _get_page()
    deadline = time.time() + timeout
    last_cf_retry = 0.0

    # ── 步骤1：填邮箱，点「下一步」 ──
    email_submitted = False
    while time.time() < deadline and not email_submitted:
        raise_if_cancelled(cancel_callback)
        state = page.run_js("""
const emailInput = document.querySelector('input[data-testid="email"]');
if (!emailInput) return 'not-ready';
const ns = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
const tracker = emailInput._valueTracker;
if (tracker) tracker.setValue('');
if (ns) ns.call(emailInput, arguments[0]); else emailInput.value = arguments[0];
emailInput.dispatchEvent(new InputEvent('input', {bubbles:true, data:arguments[0], inputType:'insertText'}));
emailInput.dispatchEvent(new Event('change', {bubbles:true}));
emailInput.blur();
if (String(emailInput.value||'').trim() !== String(arguments[0]||'').trim()) return 'fill-failed';
const btn = document.querySelector('button[data-testid="sign-in-submit"]');
if (!btn) return 'no-btn';
if (btn.disabled || btn.getAttribute('aria-disabled') === 'true') return 'btn-disabled';
btn.click();
return 'submitted';
""", email)
        if state == 'submitted':
            email_submitted = True
            if log_callback:
                log_callback(f"[*] 已填写邮箱并提交: {email}")
        elif state == 'not-ready':
            human_sleep(0.5, cancel_callback)
        elif state == 'btn-disabled':
            human_sleep(0.5, cancel_callback)
        else:
            human_sleep(0.5, cancel_callback)
    if not email_submitted:
        raise Exception("邮箱提交超时")

    # 等密码框出现
    human_sleep(2, cancel_callback)

    # ── 步骤2：填密码，处理 Turnstile，点「登录」 ──
    pw_filled = False
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if not pw_filled:
            filled = page.run_js("""
const pwInput = document.querySelector('input[data-testid="password"]');
if (!pwInput) return 'not-ready';
const ns = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
const tracker = pwInput._valueTracker;
if (tracker) tracker.setValue('');
if (ns) ns.call(pwInput, arguments[0]); else pwInput.value = arguments[0];
pwInput.dispatchEvent(new InputEvent('input', {bubbles:true, data:arguments[0], inputType:'insertText'}));
pwInput.dispatchEvent(new Event('change', {bubbles:true}));
pwInput.blur();
if (String(pwInput.value||'').trim() !== String(arguments[0]||'').trim()) return 'fill-failed';
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    if (token.length < 80) return 'wait-cf:' + token.length;
}
return 'ready';
""", password)
            if isinstance(filled, str) and filled.startswith('wait-cf'):
                pw_filled = True
                if log_callback:
                    token_len = filled.split(':',1)[1] if ':' in filled else '0'
                    log_callback(f"[*] 已填密码，等待 Turnstile... token长度={token_len}")
                now = time.time()
                if now - last_cf_retry >= 8:
                    try:
                        token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                        if token:
                            page.run_js("""
const token = String(arguments[0]||'').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (cfInput && token) {
    const ns = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    if (ns) ns.call(cfInput, token); else cfInput.value = token;
    cfInput.dispatchEvent(new Event('input', {bubbles:true}));
    cfInput.dispatchEvent(new Event('change', {bubbles:true}));
}
""", token)
                            if log_callback:
                                log_callback("[*] Turnstile 已通过，回填完成")
                    except Exception as cf_exc:
                        if log_callback:
                            log_callback(f"[Debug] Turnstile 复用失败: {cf_exc}")
                    last_cf_retry = now
                human_sleep(1, cancel_callback)
                continue
            elif filled == 'ready':
                pw_filled = True
                if log_callback:
                    log_callback("[*] 密码已填写，准备提交")
            elif filled == 'not-ready':
                human_sleep(0.5, cancel_callback)
                continue
            elif filled == 'fill-failed':
                human_sleep(0.5, cancel_callback)
                continue

        # 提交
        state = page.run_js("""
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    if (token.length < 80) return 'wait-cf:' + token.length;
}
const btn = document.querySelector('button[data-testid="sign-in-submit"]');
if (!btn) return 'no-submit';
if (btn.disabled || btn.getAttribute('aria-disabled') === 'true') return 'btn-disabled';
btn.click();
return 'submitted';
""")
        if isinstance(state, str) and state.startswith('wait-cf'):
            if log_callback:
                token_len = state.split(':',1)[1] if ':' in state else '0'
                log_callback(f"[*] 等待 Turnstile 通过后再提交... token长度={token_len}")
            now = time.time()
            if now - last_cf_retry >= 8:
                try:
                    token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                    if token:
                        page.run_js("""
const token = String(arguments[0]||'').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (cfInput && token) {
    const ns = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    if (ns) ns.call(cfInput, token); else cfInput.value = token;
    cfInput.dispatchEvent(new Event('input', {bubbles:true}));
    cfInput.dispatchEvent(new Event('change', {bubbles:true}));
}
""", token)
                        if log_callback:
                            log_callback("[*] Turnstile 二次复用完成")
                except Exception as cf_exc:
                    if log_callback:
                        log_callback(f"[Debug] Turnstile 复用失败: {cf_exc}")
                last_cf_retry = now
            human_sleep(1, cancel_callback)
            continue
        elif state == 'submitted':
            if log_callback:
                log_callback("[*] 已点击登录，等待 sso cookie...")
            return
        elif state == 'btn-disabled':
            human_sleep(1, cancel_callback)
            continue
        human_sleep(1, cancel_callback)
    raise Exception("登录提交超时")

def login_and_get_sso(email, password, log_callback=None, cancel_callback=None):
    """完整登录流程：打开页 → 填邮箱密码 → Turnstile → 等 sso cookie。"""
    open_login_page(log_callback=log_callback, cancel_callback=cancel_callback)
    fill_login_and_submit(email, password, log_callback=log_callback, cancel_callback=cancel_callback)
    sso = wait_for_sso_cookie(timeout=120, log_callback=log_callback, cancel_callback=cancel_callback)
    return sso


def export_cpa_after_success(email, password, sso, page=None, log_callback=None):
    """GUI 成功注册后的 CPA xai-*.json 导出 hook。"""
    log = log_callback or (lambda m: print(m, flush=True))
    if not config.get("cpa_export_enabled", True):
        log("[cpa] export disabled, skip")
        return {"ok": False, "skipped": True, "reason": "disabled"}
    if not email or not password:
        log("[cpa] 缺少 email/password，跳过 CPA 导出")
        return {"ok": False, "error": "missing email/password"}
    try:
        import cpa_export
    except Exception as exc:
        log(f"[cpa] 导入 cpa_export 失败: {exc}")
        return {"ok": False, "error": f"import: {exc}"}

    cookies = []
    try:
        cookies = cpa_export.export_cookies_from_page(page) if page is not None else []
    except Exception as exc:
        log(f"[cpa] cookie 导出失败，继续用邮箱密码 mint: {exc}")
        cookies = []
    if cookies:
        log(f"[cpa] 已导出 cookie {len(cookies)} 条供 OIDC mint 注入")

    cpa_cfg = dict(config)
    if _config_bool(config.get("cpa_gui_close_mint_browser", True), default=True):
        # GUI 下优先不残留额外 Chromium：CPA mint 成功后也立即 quit。
        # CLI 仍可通过 cpa_mint_browser_reuse 保持流水线复用。
        cpa_cfg["cpa_mint_browser_reuse"] = False

    # GUI 可多线程注册；CPA mint 使用独立有头浏览器，串行可避免多个 consent 窗口互相抢焦点。
    with _cpa_gui_export_lock:
        try:
            result = cpa_export.export_cpa_xai_for_account(
                email,
                password,
                page=page,
                cookies=cookies,
                sso=sso,
                config=cpa_cfg,
                log_callback=log,
            )
        except Exception as exc:
            log(f"[cpa] CPA 导出异常: {exc}")
            if config.get("cpa_mint_required", False):
                raise
            return {"ok": False, "error": str(exc)}

    if result.get("ok"):
        log(f"[cpa] CPA 格式已导出: {result.get('path')}")
    else:
        log(f"[cpa] CPA 导出失败: {result.get('error') or result}")
    return result


class GrokRegisterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Grok 注册机")
        self.root.geometry("980x860")
        self.root.minsize(900, 760)
        self.is_running = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.stats_lock = threading.Lock()
        self._tutorial_window = None
        self.setup_ui()
        self.root.after(200, self._maybe_show_tutorial_on_start)

    def setup_ui(self):
        load_config()
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        config_frame = ttk.LabelFrame(main_frame, text="配置", padding=10)
        config_frame.pack(fill=tk.X, pady=5)
        ttk.Label(config_frame, text="邮箱服务商:").grid(row=0, column=0, sticky=tk.W)
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "duckmail"))
        self.email_provider_combo = ttk.Combobox(config_frame, textvariable=self.email_provider_var, values=["duckmail", "yyds", "cloudflare", "cloudmail", "hotmail", "outlookmail", "mailnest"], width=12, state="readonly")
        self.email_provider_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="注册数量:").grid(row=0, column=2, sticky=tk.W, padx=10)
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.count_spinbox = ttk.Spinbox(config_frame, from_=1, to=100, width=8, textvariable=self.count_var)
        self.count_spinbox.grid(row=0, column=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="并发线程:").grid(row=1, column=2, sticky=tk.W, padx=10)
        self.thread_var = tk.StringVar(value=str(config.get("register_threads", 1)))
        self.thread_spinbox = ttk.Spinbox(config_frame, from_=1, to=MAX_REGISTER_THREADS, width=8, textvariable=self.thread_var)
        self.thread_spinbox.grid(row=1, column=3, sticky=tk.W, padx=5)
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = ttk.Checkbutton(config_frame, text="注册后开启 NSFW", variable=self.nsfw_var)
        self.nsfw_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(config_frame, text="代理（可选）:").grid(row=2, column=0, sticky=tk.W)
        self.proxy_var = tk.StringVar(value=config.get("proxy", ""))
        self.proxy_entry = ttk.Entry(config_frame, textvariable=self.proxy_var, width=30)
        self.proxy_entry.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="DuckMail API Key:").grid(row=3, column=0, sticky=tk.W)
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.api_key_entry = ttk.Entry(config_frame, textvariable=self.api_key_var, width=30)
        self.api_key_entry.grid(row=3, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare API Base:").grid(row=4, column=0, sticky=tk.W)
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_base_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_api_base_var, width=30)
        self.cloudflare_api_base_entry.grid(row=4, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare API Key:").grid(row=5, column=0, sticky=tk.W)
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_api_key_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_api_key_var, width=30)
        self.cloudflare_api_key_entry.grid(row=5, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare 鉴权模式:").grid(row=6, column=0, sticky=tk.W)
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "bearer"))
        self.cloudflare_auth_mode_combo = ttk.Combobox(
            config_frame,
            textvariable=self.cloudflare_auth_mode_var,
            values=["query-key", "bearer", "x-api-key", "none"],
            width=12,
            state="readonly",
        )
        self.cloudflare_auth_mode_combo.grid(row=6, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="CF 路径(domains/accounts/token/messages):").grid(row=7, column=0, sticky=tk.W)
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/api/domains"),
                    config.get("cloudflare_path_accounts", "/admin/new_address"),
                    config.get("cloudflare_path_token", "/api/token"),
                    config.get("cloudflare_path_messages", "/api/parsed_mails"),
                ]
            )
        )
        self.cloudflare_paths_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_paths_var, width=30)
        self.cloudflare_paths_entry.grid(row=7, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail URL:").grid(row=8, column=0, sticky=tk.W)
        self.cloudmail_url_var = tk.StringVar(value=str(config.get("cloudmail_url", "")))
        self.cloudmail_url_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_url_var, width=30)
        self.cloudmail_url_entry.grid(row=8, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail 管理员邮箱:").grid(row=9, column=0, sticky=tk.W)
        self.cloudmail_admin_email_var = tk.StringVar(value=str(config.get("cloudmail_admin_email", "")))
        self.cloudmail_admin_email_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_admin_email_var, width=30)
        self.cloudmail_admin_email_entry.grid(row=9, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail 管理员密码:").grid(row=10, column=0, sticky=tk.W)
        self.cloudmail_password_var = tk.StringVar(value=str(config.get("cloudmail_password", "")))
        self.cloudmail_password_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_password_var, width=30, show="*")
        self.cloudmail_password_entry.grid(row=10, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 本地自动入池:").grid(row=11, column=0, sticky=tk.W)
        self.grok2api_local_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_local", True)))
        self.grok2api_local_auto_check = ttk.Checkbutton(config_frame, variable=self.grok2api_local_auto_var)
        self.grok2api_local_auto_check.grid(row=11, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 本地 token.json:").grid(row=12, column=0, sticky=tk.W)
        self.grok2api_local_file_var = tk.StringVar(value=str(config.get("grok2api_local_token_file", "")))
        self.grok2api_local_file_entry = ttk.Entry(config_frame, textvariable=self.grok2api_local_file_var, width=30)
        self.grok2api_local_file_entry.grid(row=12, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 池名:").grid(row=13, column=0, sticky=tk.W)
        self.grok2api_pool_name_var = tk.StringVar(value=str(config.get("grok2api_pool_name", "ssoBasic")))
        self.grok2api_pool_name_combo = ttk.Combobox(
            config_frame,
            textvariable=self.grok2api_pool_name_var,
            values=["ssoBasic", "ssoSuper"],
            width=12,
            state="readonly",
        )
        self.grok2api_pool_name_combo.grid(row=13, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端自动入池:").grid(row=14, column=0, sticky=tk.W)
        self.grok2api_remote_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_remote", False)))
        self.grok2api_remote_auto_check = ttk.Checkbutton(config_frame, variable=self.grok2api_remote_auto_var)
        self.grok2api_remote_auto_check.grid(row=14, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端 Base:").grid(row=15, column=0, sticky=tk.W)
        self.grok2api_remote_base_var = tk.StringVar(value=str(config.get("grok2api_remote_base", "")))
        self.grok2api_remote_base_entry = ttk.Entry(config_frame, textvariable=self.grok2api_remote_base_var, width=30)
        self.grok2api_remote_base_entry.grid(row=15, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端 app_key:").grid(row=16, column=0, sticky=tk.W)
        self.grok2api_remote_key_var = tk.StringVar(value=str(config.get("grok2api_remote_app_key", "")))
        self.grok2api_remote_key_entry = ttk.Entry(config_frame, textvariable=self.grok2api_remote_key_var, width=30)
        self.grok2api_remote_key_entry.grid(row=16, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="默认域名(defaultDomains):").grid(row=17, column=0, sticky=tk.W)
        self.default_domains_var = tk.StringVar(value=str(config.get("defaultDomains", "")))
        self.default_domains_entry = ttk.Entry(config_frame, textvariable=self.default_domains_var, width=30)
        self.default_domains_entry.grid(row=17, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="Hotmail账号文件:").grid(row=18, column=0, sticky=tk.W)
        self.hotmail_accounts_file_var = tk.StringVar(value=str(config.get("hotmail_accounts_file", "mail_credentials.txt")))
        self.hotmail_accounts_file_entry = ttk.Entry(config_frame, textvariable=self.hotmail_accounts_file_var, width=30)
        self.hotmail_accounts_file_entry.grid(row=18, column=1, columnspan=3, sticky=tk.W, padx=5)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        self.help_btn = ttk.Button(btn_frame, text="教程", command=self.show_tutorial)
        self.help_btn.pack(side=tk.LEFT, padx=5)
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="green")
        self.status_label.pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        ttk.Label(status_frame, textvariable=self.stats_var).pack(side=tk.RIGHT)
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=60)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        # 仅当用户当前就在底部时自动跟随，避免手动上滑后被强制拉回底部
        yview = self.log_text.yview()
        at_bottom = bool(yview) and yview[1] >= 0.999
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        if at_bottom:
            self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        self.stats_var.set(f"成功: {self.success_count} | 失败: {self.fail_count}")

    def _set_running_ui(self, running):
        self.is_running = running
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def _maybe_show_tutorial_on_start(self):
        if bool(config.get("show_tutorial_on_start", True)):
            self.show_tutorial()

    def _tutorial_text(self):
        return """欢迎使用 Grok 注册机。建议按下面顺序填写（从最关键到可选）：

【第一步：先确定邮箱后端信息从哪里来】
如果你使用 cloudflare 模式（你当前主要是这套），先去你的临时邮箱服务配置接口查信息：
- 常见接口: /open_api/settings、/api/settings、/health_check
- 重点字段:
  - api_base（对应本工具的 Cloudflare API Base）
  - domains / defaultDomains（可用域名）
  - needAuth（是否需要鉴权）
  - admin_password 或 api_key（需要鉴权时使用）
  - provider.type（应为 cloudflare_temp_email）

【第二步：先填最小可运行配置】
1) 邮箱服务商
- duckmail: 需要 DuckMail API Key
- yyds: 需要 YYDS API Key 或 JWT
- cloudflare: 需要 Cloudflare API Base（cloudflare_temp_email 临时邮箱）
- cloudmail: 需要 CloudMail URL + 密码 + defaultDomains（maillab/cloud-mail 完整邮箱）
- hotmail/outlookmail: 需要 Hotmail账号文件，格式为 邮箱----密码----ClientID----Token
- mailnest: 需要 mailnest_api_key（https://mailnest.top/account）与 project_code

2) Cloudflare API Base（cloudflare 模式必填）
- 示例: https://xxxx.pages.dev
- 填写规则: 与 settings 接口中的 api_base 保持一致

3) 默认域名(defaultDomains)
- 填写你要优先使用的域名
- 支持单域名或逗号分隔多域名轮换
- 示例: a.com,b.com

4) CF 路径(domains/accounts/token/messages)
- 必须与后端真实路由一致
- 常见新路径:
  - /api/domains,/api/new_address,/api/token,/api/mails
- 常见旧路径:
  - /domains,/accounts,/token,/messages

5) Cloudflare API Key / 鉴权模式
- needAuth=false: 通常鉴权模式选 none，key 可留空
- needAuth=true: 按后端要求填 key，并选择 bearer/x-api-key/query-key

6) CloudMail 模式配置（maillab/cloud-mail 部署）
- CloudMail URL: 你的 Worker 地址，如 https://mail.xxx.workers.dev
- CloudMail 管理员邮箱: 管理员账号，如 admin@yourdomain.com
- CloudMail 管理员密码: 管理员密码（用于获取公开 API token 查询邮件）
- defaultDomains: 必须填写可用域名，如 yourdomain.com
- 前提: CloudMail 管理面板需关闭注册验证码（Turnstile），或确保注册接口可用
- 邮件获取: 通过 /api/public/emailList 公开接口查询，自动刷新 token

7) Hotmail/Outlook 模式配置
- Hotmail账号文件默认: mail_credentials.txt
- 每行格式: your@hotmail.com----mailPassword----client-id----refresh-token
- 默认先用原邮箱，后续使用随机 plus alias（如 name+k8s2p9qa@domain）
- 成功、失败、当前运行占用的 alias 都会去重，并通过 outlook.office365.com XOAUTH2 IMAP 收验证码

8) MailNest 模式配置
- mailnest_api_key: https://mailnest.top/account 获取
- mailnest_project_code: https://mailnest.top/buy-email 获取，默认 x-ai001

【第三步：并发与稳定性】
6) 注册数量
- 本次要注册的总账号数

7) 并发线程
- 上限 100；建议先 3-6 稳定后再升高，浏览器路径不要直接拉满

8) 代理（可选）
- 不填=直连
- 示例: http://127.0.0.1:7890
- 代理不稳会影响验证码和注册稳定性

9) 注册后开启 NSFW
- 勾选后成功账号会自动调用接口开启对应设置

【第四步：grok2api 入池（可选）】
10) grok2api 本地自动入池
- 开启后把成功 sso 自动写入本地池
- 本地 token.json 填 grok2api 的 token.json 路径

11) grok2api 池名
- ssoBasic 或 ssoSuper

12) grok2api 远端自动入池
- 开启后调用远端管理接口自动加 token
- 远端 Base 示例: https://xxx/admin/api
- app_key 按远端服务配置填写

【最后：快速自检】
1) 先设置: 注册数量=1，并发线程=1
2) 点开始后看日志是否出现：
- 已创建邮箱: xxx@你的域名
- Cloudflare/CloudMail 本轮邮件数量: ...
- 从邮件中提取到验证码: ...
3) 若第一步就失败：
- cloudflare 模式: 检查 API Base / CF 路径 / 鉴权模式
- cloudmail 模式: 检查 URL / 密码 / defaultDomains / 注册接口是否可用

提示:
- 点“开始注册”会自动保存当前配置到 config.json。
- 如果关闭了启动教程，可随时点主界面的“教程”按钮重新打开。"""

    def show_tutorial(self):
        if self._tutorial_window is not None and self._tutorial_window.winfo_exists():
            self._tutorial_window.lift()
            self._tutorial_window.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._tutorial_window = win
        win.title("使用教程")
        win.geometry("760x620")
        win.minsize(680, 520)
        win.transient(self.root)

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        txt = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=26)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert("1.0", self._tutorial_text())
        txt.config(state=tk.DISABLED)

        footer = ttk.Frame(frame)
        footer.pack(fill=tk.X, pady=(8, 0))

        dont_show_var = tk.BooleanVar(value=not bool(config.get("show_tutorial_on_start", True)))
        chk = ttk.Checkbutton(
            footer,
            text="以后不再自动显示本教程",
            variable=dont_show_var,
        )
        chk.pack(side=tk.LEFT)

        def on_close():
            config["show_tutorial_on_start"] = not bool(dont_show_var.get())
            save_config()
            try:
                win.destroy()
            except Exception:
                pass

        close_btn = ttk.Button(footer, text="关闭", command=on_close)
        close_btn.pack(side=tk.RIGHT, padx=5)
        win.protocol("WM_DELETE_WINDOW", on_close)

    def should_stop(self):
        return self.stop_requested or not self.is_running

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return

        config["email_provider"] = self.email_provider_var.get().strip() or "duckmail"
        config["proxy"] = self.proxy_var.get().strip()
        config["duckmail_api_key"] = self.api_key_var.get().strip()
        config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
        config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
        config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "bearer"
        config["cloudmail_url"] = self.cloudmail_url_var.get().strip()
        config["cloudmail_admin_email"] = self.cloudmail_admin_email_var.get().strip()
        config["cloudmail_password"] = self.cloudmail_password_var.get().strip()
        config["grok2api_auto_add_local"] = bool(self.grok2api_local_auto_var.get())
        config["grok2api_local_token_file"] = self.grok2api_local_file_var.get().strip()
        config["grok2api_pool_name"] = self.grok2api_pool_name_var.get().strip() or "ssoBasic"
        config["grok2api_auto_add_remote"] = bool(self.grok2api_remote_auto_var.get())
        config["grok2api_remote_base"] = self.grok2api_remote_base_var.get().strip()
        config["grok2api_remote_app_key"] = self.grok2api_remote_key_var.get().strip()
        config["defaultDomains"] = self.default_domains_var.get().strip()
        config["hotmail_accounts_file"] = self.hotmail_accounts_file_var.get().strip() or "mail_credentials.txt"
        try:
            config["register_threads"] = max(1, min(MAX_REGISTER_THREADS, int(self.thread_var.get())))
        except Exception:
            config["register_threads"] = 1
        raw_paths = [x.strip() for x in self.cloudflare_paths_var.get().split(",") if x.strip()]
        if len(raw_paths) >= 4:
            config["cloudflare_path_domains"] = raw_paths[0] if raw_paths[0].startswith("/") else ("/" + raw_paths[0])
            config["cloudflare_path_accounts"] = raw_paths[1] if raw_paths[1].startswith("/") else ("/" + raw_paths[1])
            config["cloudflare_path_token"] = raw_paths[2] if raw_paths[2].startswith("/") else ("/" + raw_paths[2])
            config["cloudflare_path_messages"] = raw_paths[3] if raw_paths[3].startswith("/") else ("/" + raw_paths[3])
        save_config()
        if config["email_provider"] == "cloudflare" and not config["cloudflare_api_base"]:
            self.log("[!] Cloudflare 模式需要先填写 Cloudflare API Base")
            return
        if config["email_provider"] == "cloudmail":
            if not config.get("cloudmail_url"):
                self.log("[!] CloudMail 模式需要先填写 CloudMail URL")
                return
            if not config.get("cloudmail_admin_email"):
                self.log("[!] CloudMail 模式需要先填写 CloudMail 管理员邮箱")
                return
            if not config.get("cloudmail_password"):
                self.log("[!] CloudMail 模式需要先填写 CloudMail 管理员密码")
                return
        if config["email_provider"] in ("hotmail", "outlook", "outlookmail", "microsoft"):
            hotmail_path = get_hotmail_accounts_file()
            if not os.path.exists(hotmail_path):
                self.log(f"[!] Hotmail/Outlook 模式账号文件不存在: {hotmail_path}")
                return
        try:
            count = int(self.count_var.get())
        except Exception:
            self.log("[!] 注册数量无效")
            return
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.accounts_output_file = os.path.join(
            os.path.dirname(__file__), f"accounts_{now}.txt"
        )
        self.update_stats()
        self._set_running_ui(True)
        worker_count = max(1, min(config.get("register_threads", 1), count))
        self.log(f"[*] 配置已保存，开始执行。目标数量: {count}，并发线程: {worker_count}")
        self.log(f"[*] 成功账号将实时保存到: {self.accounts_output_file}")
        threading.Thread(
            target=self.run_registration,
            args=(count, worker_count),
            daemon=True,
        ).start()

    def stop_registration(self):
        self.stop_requested = True
        self.log("[!] 用户停止注册")

    def _run_single_registration(self, idx, total, logf):
        email = ""
        dev_token = ""
        code = ""
        mail_ok = False
        max_mail_retry = 3
        for mail_try in range(1, max_mail_retry + 1):
            logf(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
            open_signup_page(log_callback=logf, cancel_callback=self.should_stop)
            logf("[*] 2. 创建邮箱并提交")
            email, dev_token = fill_email_and_submit(log_callback=logf, cancel_callback=self.should_stop)
            logf(f"[*] 邮箱: {email}")
            if get_email_provider() not in ("hotmail", "outlook", "outlookmail", "microsoft"):
                try:
                    with open(os.path.join(os.path.dirname(__file__), "created_mailboxes.txt"), "a", encoding="utf-8") as f:
                        f.write(f"{email}\t{dev_token}\n")
                except Exception:
                    pass
            logf("[*] 3. 拉取验证码")
            try:
                code = fill_code_and_submit(email, dev_token, log_callback=logf, cancel_callback=self.should_stop)
                mail_ok = True
                break
            except Exception as mail_exc:
                msg = str(mail_exc)
                if email:
                    try:
                        if should_persist_email_error(msg):
                            mark_error(email, reason=msg[:120])
                        else:
                            release_email(email)
                    except Exception:
                        pass
                if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                    logf(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                    restart_browser(log_callback=logf)
                    sleep_with_cancel(1, self.should_stop)
                    continue
                raise
        if not mail_ok:
            raise Exception("验证码阶段失败，已达到最大重试次数")
        logf(f"[*] 验证码: {code}")
        try:
            logf("[*] 4. 填写资料")
            profile = fill_profile_and_submit(log_callback=logf, cancel_callback=self.should_stop)
            logf(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
            logf("[*] 5. 等待 sso cookie")
            sso = wait_for_sso_cookie(log_callback=logf, cancel_callback=self.should_stop)
        except Exception as flow_exc:
            if email:
                try:
                    if should_persist_email_error(str(flow_exc)):
                        mark_error(email, reason=str(flow_exc)[:120])
                    else:
                        release_email(email)
                except Exception:
                    pass
            raise
        password = profile.get("password", "") or ""
        result_record = {"email": email, "sso": sso, "profile": profile}
        with self.stats_lock:
            self.results.append(result_record)
            self.success_count += 1
            line = f"{email}----{password}----{sso}\n"
            try:
                with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as file_exc:
                logf(f"[Debug] 保存账号文件失败: {file_exc}")
        try:
            mark_used(email, password)
        except Exception:
            pass
        logf(f"[+] 注册成功: {email}")
        add_token_to_grok2api_pools(sso, email=email, log_callback=logf)
        try:
            page = _get_page()
        except Exception:
            page = None
        logf("[cpa] 开始自动导出 CPA xai 认证文件")
        cpa_result = export_cpa_after_success(
            email,
            password,
            sso,
            page=page,
            log_callback=logf,
        )
        result_record["cpa"] = cpa_result

    def _worker_loop(self, worker_id, total, task_queue):
        prefix = f"[T{worker_id}]"
        logf = lambda m: self.log(f"{prefix} {m}")
        try:
            start_browser(log_callback=logf)
            logf("[*] 浏览器已启动")
            while not self.should_stop():
                try:
                    idx = task_queue.get_nowait()
                except queue.Empty:
                    break
                logf(f"--- 开始第 {idx}/{total} 个账号 ---")
                try:
                    self._run_single_registration(idx, total, logf)
                except RegistrationCancelled:
                    logf("[!] 注册被用户停止")
                    break
                except Exception as exc:
                    with self.stats_lock:
                        self.fail_count += 1
                    logf(f"[-] 注册失败: {exc}")
                finally:
                    self.update_stats()
                    if self.should_stop():
                        break
                    restart_browser(log_callback=logf)
                    sleep_with_cancel(1, self.should_stop)
        except Exception as exc:
            logf(f"[!] 线程异常: {exc}")
        finally:
            stop_browser()

    def run_registration(self, count, worker_count):
        task_queue = queue.Queue()
        for i in range(1, count + 1):
            task_queue.put(i)
        workers = []
        try:
            start_interval = float(config.get("thread_start_interval", 0.8))
        except Exception:
            start_interval = 0.8
        if start_interval < 0:
            start_interval = 0.0
        for wid in range(1, worker_count + 1):
            t = threading.Thread(target=self._worker_loop, args=(wid, count, task_queue), daemon=True)
            workers.append(t)
            t.start()
            if wid < worker_count and start_interval > 0:
                sleep_with_cancel(start_interval, self.should_stop)
        for t in workers:
            t.join()
        self._set_running_ui(False)
        self.log("[*] 任务结束")

def main():
    root = tk.Tk()
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
