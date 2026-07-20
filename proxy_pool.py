"""代理池：解析、规范化、文件存储、健康检测。

支持格式：
    host:port
    host:port:user:pass
    user:pass@host:port
    scheme://[user:pass@]host:port

文件：
    proxies.txt         每行一个代理（原始格式保留）
    proxies_state.json  检测结果 {key: {ok, latency_ms, exit_ip, error, checked_at}}
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlsplit

ROOT = Path(__file__).resolve().parent
POOL_PATH = ROOT / "proxies.txt"
STATE_PATH = ROOT / "proxies_state.json"

_lock = threading.RLock()


# 配置中的特殊代理值：每次使用时从代理池随机取一个
POOL_RANDOM = "pool:random"
_ALLOWED_SCHEMES = {"http", "https", "socks5", "socks5h"}


def resolve_special(raw: str | None) -> str:
    """解析特殊代理值。pool:random → 池中随机一个的 effective_url；其他原样返回。"""
    raw = (raw or "").strip()
    if raw != POOL_RANDOM:
        return raw
    import random as _random

    pool = load_usable_pool()
    if not pool:
        return ""
    return effective_url(_random.choice(pool))


def parse_proxy(raw: str | None) -> dict | None:
    """解析代理字符串 → {scheme, host, port, user, password}；无效返回 None。"""
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        if "@" in raw:
            raw = "http://" + raw
        else:
            parts = raw.split(":")
            if len(parts) == 2:
                host, port = parts
                if not host or not port.isdigit():
                    return None
                return {"scheme": "http", "host": host, "port": int(port), "user": "", "password": ""}
            if len(parts) == 4:
                host, port, user, password = parts
                if not host or not port.isdigit():
                    return None
                return {
                    "scheme": "http",
                    "host": host,
                    "port": int(port),
                    "user": user,
                    "password": password,
                }
            return None
    try:
        u = urlparse(raw)
    except Exception:
        return None
    if not u.hostname:
        return None
    scheme = (u.scheme or "http").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None
    # HTTP 客户端侧默认远端解析 DNS，避免 socks5 本地 DNS 行为不一致。
    if scheme == "socks5":
        scheme = "socks5h"
    return {
        "scheme": scheme,
        "host": u.hostname,
        "port": u.port or (443 if scheme == "https" else 80),
        "user": unquote(u.username or ""),
        "password": unquote(u.password or ""),
    }


def _build_url(p: dict, scheme: str) -> str:
    auth = ""
    if p["user"]:
        auth = f"{quote(p['user'], safe='')}:{quote(p['password'], safe='')}@"
    return f"{scheme}://{auth}{p['host']}:{p['port']}"


def normalize_proxy_url(raw: str | None) -> str:
    """规范化为 scheme://[user:pass@]host:port（user/pass 做 URL 编码）。无效返回 ''。"""
    p = parse_proxy(raw)
    if not p:
        return ""
    return _build_url(p, p["scheme"])


def effective_url(raw: str | None) -> str:
    """实际使用 URL：四段简写默认 http，但若检测记录里有可用协议（如 socks5h）则采用。"""
    p = parse_proxy(raw)
    if not p:
        return ""
    scheme = p["scheme"]
    if scheme == "http" and "://" not in (raw or "").strip():
        st = load_state().get(normalize_proxy_url(raw)) or {}
        scheme = st.get("scheme") or "http"
    return _build_url(p, scheme)


def mask_proxy(raw: str | None) -> str:
    """脱敏展示：隐藏密码。"""
    p = parse_proxy(raw)
    if not p:
        return str(raw or "")
    auth = f"{p['user']}:***@" if p["user"] else ""
    return f"{p['scheme']}://{auth}{p['host']}:{p['port']}"


def proxy_label(raw: str | None) -> str:
    """展示用短标签：host:port。"""
    p = parse_proxy(raw)
    if not p:
        return str(raw or "")
    return f"{p['host']}:{p['port']}"


# ── 文件 CRUD ──


def load_pool(path: Path | None = None) -> list[str]:
    """读取代理池，去重（按规范化 URL），保留原始行。"""
    path = path or POOL_PATH
    if not path.is_file():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        key = normalize_proxy_url(s)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _state_recent(st: dict, max_age_seconds: float | None) -> bool:
    if not max_age_seconds or max_age_seconds <= 0:
        return True
    checked = str(st.get("checked_at") or "")
    if not checked:
        return True
    try:
        ts = time.mktime(time.strptime(checked, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return True
    return (time.time() - ts) <= max_age_seconds


def load_usable_pool(
    path: Path | None = None,
    *,
    prefer_checked_ok: bool = True,
    max_state_age_seconds: float = 24 * 3600,
) -> list[str]:
    """读取代理池；若存在近期检测成功的代理，则优先只返回成功代理。

    如果没有任何成功检测记录，则回退完整池，避免新导入但未检测的代理无法使用。
    """
    pool = load_pool(path)
    if not prefer_checked_ok:
        return pool
    state = load_state()
    ok_pool = []
    for raw in pool:
        st = state.get(normalize_proxy_url(raw)) or {}
        if st.get("ok") is True and _state_recent(st, max_state_age_seconds):
            ok_pool.append(raw)
    return ok_pool or pool


def save_pool(lines: list[str], path: Path | None = None) -> None:
    path = path or POOL_PATH
    with _lock:
        body = "\n".join(lines)
        if body:
            body += "\n"
        path.write_text(body, encoding="utf-8")


def import_proxies(text: str, mode: str = "append") -> dict:
    """批量导入。mode=append 合并去重；replace 全量替换。"""
    incoming: list[str] = []
    invalid = 0
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if normalize_proxy_url(s):
            incoming.append(s)
        else:
            invalid += 1
    if not incoming and invalid:
        raise ValueError(f"没有可识别的代理行（{invalid} 行格式无效）")
    with _lock:
        existing = [] if mode == "replace" else load_pool()
        by_key = {normalize_proxy_url(x): x for x in existing}
        added = updated = 0
        for line in incoming:
            key = normalize_proxy_url(line)
            if key in by_key:
                updated += 1
            else:
                added += 1
            by_key[key] = line
        save_pool(list(by_key.values()))
        total = len(by_key)
    return {"added": added, "updated": updated, "invalid": invalid, "total": total}


def delete_proxies(keys: list[str]) -> int:
    wanted = {normalize_proxy_url(k) for k in keys if str(k).strip()}
    wanted.discard("")
    if not wanted:
        return 0
    with _lock:
        pool = load_pool()
        kept = [p for p in pool if normalize_proxy_url(p) not in wanted]
        deleted = len(pool) - len(kept)
        if deleted:
            save_pool(kept)
    return deleted


# ── 检测状态 ──


def load_state() -> dict:
    if not STATE_PATH.is_file():
        return {}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    with _lock:
        STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _update_state(key: str, result: dict) -> None:
    state = load_state()
    state[key] = {**(state.get(key) or {}), **result}
    _save_state(state)


# ── 健康检测 ──

_CHECK_URL = "https://api.ipify.org?format=json"
_TARGET_CHECK_URLS = (
    "https://accounts.x.ai/",
    "https://auth.x.ai/.well-known/openid-configuration",
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
)


def _redact_proxy_error(message: str, proxy: str) -> str:
    text = str(message or "")
    try:
        parts = urlsplit(proxy)
        secrets = {
            value
            for value in (
                parts.username,
                parts.password,
                unquote(parts.username or ""),
                unquote(parts.password or ""),
            )
            if value
        }
        if parts.hostname and parts.port:
            text = text.replace(proxy, f"{parts.scheme}://{parts.hostname}:{parts.port}")
        for secret in sorted(secrets, key=len, reverse=True):
            text = text.replace(secret, "<redacted>")
    except Exception:
        pass
    return text[:300] or "代理测试失败"


def _try_scheme(p: dict, scheme: str, timeout: float):
    """经指定协议请求出口 IP。成功返回 (exit_ip, latency_ms)，失败返回 (None, error)。"""
    url = _build_url(p, scheme)
    start = time.time()
    try:
        from curl_cffi import requests as creq

        proxies = {"http": url, "https": url}
        resp = creq.get(
            _CHECK_URL,
            proxies=proxies,
            timeout=timeout,
            impersonate="chrome",
        )
        if resp.status_code != 200:
            return None, f"ipify HTTP {resp.status_code}"
        exit_ip = str(resp.json().get("ip", ""))
        if not exit_ip:
            return None, "ipify missing ip"
        target_timeout = max(4.0, min(float(timeout or 12.0), 10.0))
        for target_url in _TARGET_CHECK_URLS:
            target_resp = creq.get(
                target_url,
                proxies=proxies,
                timeout=target_timeout,
                impersonate="chrome",
                allow_redirects=False,
            )
            status = int(getattr(target_resp, "status_code", 0) or 0)
            # 403/429 也说明 CONNECT/TLS/HTTP 已通；只把 5xx 当作目标连通异常。
            if status >= 500:
                return None, f"{target_url} HTTP {status}"
        latency = int((time.time() - start) * 1000)
        return exit_ip, latency
    except Exception as exc:
        return None, _redact_proxy_error(f"{type(exc).__name__}: {exc}", url)


def check_proxy(raw: str, timeout: float = 12.0) -> dict:
    """单代理检测：按 记忆协议 → 显式协议 → http → socks5h 顺序探测。"""
    p = parse_proxy(raw)
    result = {"ok": False, "latency_ms": 0, "exit_ip": "", "error": "", "scheme": ""}
    if not p:
        result["error"] = "代理格式无效"
        return result
    candidates: list[str] = []
    st = load_state().get(normalize_proxy_url(raw)) or {}
    for cand in (st.get("scheme"), p["scheme"] if "://" in (raw or "") else None, "http", "socks5h"):
        if cand and cand not in candidates:
            candidates.append(cand)
    last_error = ""
    for scheme in candidates:
        ip_or_none, info = _try_scheme(p, scheme, timeout)
        if ip_or_none:
            result.update(
                {"ok": True, "exit_ip": ip_or_none, "latency_ms": info, "scheme": scheme, "error": ""}
            )
            return result
        last_error = str(info)
        result["latency_ms"] = result["latency_ms"] or 0
    result["error"] = last_error
    return result


def check_pool(keys: list[str] | None = None, workers: int = 8, timeout: float = 12.0) -> list[dict]:
    """并发检测。keys 为空则全量。返回每项 {proxy, key, ok, latency_ms, exit_ip, error, checked_at}。"""
    pool = load_pool()
    if keys:
        wanted = {normalize_proxy_url(k) for k in keys}
        pool = [p for p in pool if normalize_proxy_url(p) in wanted]
    checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(check_proxy, p, timeout): p for p in pool}
        for fut in as_completed(futs):
            raw = futs[fut]
            r = fut.result()
            key = normalize_proxy_url(raw)
            r.update({"proxy": mask_proxy(raw), "key": key, "checked_at": checked_at})
            _update_state(
                key,
                {k: r[k] for k in ("ok", "latency_ms", "exit_ip", "error", "scheme", "checked_at")},
            )
            results.append(r)
    return results


def list_proxies() -> dict:
    """池列表 + 检测状态（前端展示用）。"""
    state = load_state()
    items = []
    for raw in load_pool():
        key = normalize_proxy_url(raw)
        p = parse_proxy(raw) or {}
        st = state.get(key) or {}
        items.append(
            {
                "key": key,
                "raw": raw,
                "label": proxy_label(raw),
                "masked": mask_proxy(raw),
                "user": p.get("user", ""),
                "has_auth": bool(p.get("user")),
                "checked": bool(st),
                "ok": st.get("ok"),
                "scheme": st.get("scheme", ""),
                "latency_ms": st.get("latency_ms"),
                "exit_ip": st.get("exit_ip", ""),
                "error": st.get("error", ""),
                "checked_at": st.get("checked_at", ""),
            }
        )
    return {"items": items, "total": len(items), "path": str(POOL_PATH)}
