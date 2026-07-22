"""ChatGPT (GPT) 纯协议注册流程（无浏览器）。

依据 注册GPT.har 抓包 + 参考实现的纯算法 sentinel（sentinel_token.py）：

  1. GET  chatgpt.com（初始 cookies）→ GET /api/auth/csrf
  2. POST /api/auth/signin/openai?login_hint=<email>   → authorize_url
  3. GET  authorize → 302 链 → email-verification（服务端自动发 OTP）
  4. 邮箱收码（复用项目现有 provider 收码链路）
  5. POST auth.openai.com/api/accounts/email-otp/validate
  6. GET  about-you（建立页面上下文）
  7. POST auth.openai.com/api/accounts/create_account
     headers: openai-sentinel-token / openai-sentinel-so-token（纯算法生成）
  8. GET  callback/openai?code=… → GET /api/auth/session → accessToken

产物：
  accounts_gpt.txt            email----access_token（主账本，去重依据）
  gpt_auths/codex-<email>.json  Codex 格式（与格式转换工具兼容）
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import string
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

CHATGPT_HOME = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"
GPT_ACCOUNTS_FILE = "accounts_gpt.txt"
GPT_AUTHS_DIR = "gpt_auths"
SCOPE = "openid email profile offline_access model.request model.read organization.read organization.write"

LogFn = Callable[[str], None]


def _noop(msg: str) -> None:
    print(msg, flush=True)


class GptRegisterError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(f"[{stage}] {message}")
        self.stage = stage


_FIRST_NAMES = [
    "James", "Robert", "Michael", "David", "William", "Richard", "Thomas", "Chris",
    "Daniel", "Matthew", "Mark", "Steven", "Paul", "Andrew", "Joshua", "Ryan",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Susan", "Sarah", "Karen",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Wilson",
    "Anderson", "Taylor", "Moore", "Jackson", "Martin", "Lee", "White", "Hall",
]


def _gen_profile() -> tuple[str, str, str]:
    name = f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"
    year = secrets.randbelow(13) + 1988
    month = secrets.randbelow(12) + 1
    day = secrets.randbelow(28) + 1
    birthdate = f"{year:04d}-{month:02d}-{day:02d}"
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    return name, birthdate, password


def _check_cancel(cancel) -> None:
    if cancel and cancel():
        raise GptRegisterError("cancel", "任务已取消")


def _save_account(
    email: str,
    password: str,
    access_token: str,
    sess_data: dict[str, Any],
    log: LogFn,
) -> None:
    root = Path(__file__).resolve().parent
    with open(root / GPT_ACCOUNTS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{email}----{access_token}\n")
    out_dir = root / GPT_AUTHS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    account = sess_data.get("account") or {}
    plan_type = account.get("planType", "free")
    payload = {
        "type": "codex",
        "access_token": access_token,
        "session_token": sess_data.get("sessionToken", ""),
        "account_id": account.get("id", ""),
        "chatgpt_account_id": account.get("id", ""),
        "chatgpt_plan_type": plan_type,
        "plan_type": plan_type,
        "email": email,
        "name": email,
        "disabled": False,
        "expired": sess_data.get("expires", ""),
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
    }
    (out_dir / f"codex-{email}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    log(f"[*] 已落账 {GPT_ACCOUNTS_FILE} + {GPT_AUTHS_DIR}/codex-{email}.json")


async def _run_async(
    *,
    email: str,
    proxy: str | None,
    get_code: Callable[[], str],
    name: str,
    birthdate: str,
    otp_timeout: float,
    impersonate: str,
    probe: bool,
    log: LogFn,
    cancel,
    on_stage: Callable[[str], None],
) -> dict[str, Any]:
    from curl_cffi import requests as creq

    from sentinel_token import SentinelTokenProvider

    kwargs: dict[str, Any] = {"impersonate": impersonate, "timeout": 60}
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    session = creq.AsyncSession(**kwargs)
    sentinel = SentinelTokenProvider(impersonate=impersonate)
    # sentinel 与 auth 共享 session：同一出口 IP
    sentinel._session = session
    device_id = str(uuid.uuid4())

    try:
        # ── 1. 初始化：首页 cookies → csrf → signin → authorize 链 ──
        _check_cancel(cancel)
        try:
            await session.get(CHATGPT_HOME)
            csrf_resp = await session.get(f"{CHATGPT_HOME}/api/auth/csrf")
            if csrf_resp.status_code != 200:
                raise GptRegisterError("csrf", f"HTTP {csrf_resp.status_code}")
            csrf_token = csrf_resp.json()["csrfToken"]
        except GptRegisterError:
            raise
        except Exception as exc:
            raise GptRegisterError("csrf", f"获取 csrfToken 失败: {exc}") from exc
        log("1. csrf ok")

        params = urlencode({
            "prompt": "login",
            "screen_hint": "login_or_signup",
            "login_hint": email,
            "ext-oai-did": device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
        })
        try:
            signin_resp = await session.post(
                f"{CHATGPT_HOME}/api/auth/signin/openai?{params}",
                data={"callbackUrl": f"{CHATGPT_HOME}/", "csrfToken": csrf_token, "json": "true"},
                headers={"content-type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
            )
            loc = ""
            try:
                loc = signin_resp.json().get("url", "")
            except Exception:
                loc = signin_resp.headers.get("location", "")
            if not loc:
                raise GptRegisterError("signin", f"未返回 authorize url: {signin_resp.text[:200]}")
        except GptRegisterError:
            raise
        except Exception as exc:
            raise GptRegisterError("signin", f"signin/openai 失败: {exc}") from exc
        log("2. signin ok → authorize")

        # 跟随重定向链（authorize → 302 → /email-verification，自动发 OTP）
        _check_cancel(cancel)
        otp_sent_at = time.time()
        final_resp = None
        hops = 0
        while loc and hops < 6:
            hops += 1
            final_resp = await session.get(loc, allow_redirects=False)
            loc = final_resp.headers.get("location", "")
        for cookie in session.cookies.jar:
            if cookie.name == "oai-did":
                device_id = cookie.value
                break
        sentinel._cookies = {c.name: c.value for c in session.cookies.jar}
        log(f"3. authorize 链完成（{hops} 跳），device={device_id[:8]}…，等待收码")
        on_stage("prepared")

        # ── 2. 收码（同步阻塞收码函数放到线程）──
        _check_cancel(cancel)
        code = await asyncio.to_thread(get_code)
        code = re.sub(r"\D", "", str(code or ""))[:6] or str(code or "").strip()
        if not code:
            raise GptRegisterError("otp", "验证码为空")
        log(f"4. 验证码: {code}")

        # ── 3. OTP validate ──
        _check_cancel(cancel)
        resp = await session.post(
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            json={"code": code},
            headers={"referer": f"{AUTH_BASE}/email-verification", "origin": AUTH_BASE},
        )
        if resp.status_code != 200:
            raise GptRegisterError("validate", f"HTTP {resp.status_code}: {resp.text[:200]}")
        validate_data = resp.json()
        if isinstance(validate_data, dict) and validate_data.get("error"):
            raise GptRegisterError("validate", str(validate_data["error"])[:200])
        log("5. OTP 校验通过")
        on_stage("otp_ready")

        # ── 4. about-you 页面上下文 ──
        about_you_url = (validate_data.get("continue_url") or "") if isinstance(validate_data, dict) else ""
        if about_you_url:
            try:
                await session.get(about_you_url, headers={"referer": f"{AUTH_BASE}/email-verification"})
            except Exception as exc:
                log(f"[Debug] about-you 访问失败（继续）: {exc}")

        # ── 5. create_account（纯算法 sentinel 头，registration_disallowed 重试 3 次）──
        _check_cancel(cancel)
        create_data: dict[str, Any] = {}
        for attempt in range(1, 4):
            headers = {
                "accept": "application/json",
                "content-type": "application/json",
                "referer": f"{AUTH_BASE}/about-you",
                "origin": AUTH_BASE,
            }
            token = await sentinel.get_token("oauth_create_account", device_id)
            if token:
                headers["openai-sentinel-token"] = json.dumps(token)
            so_token = await sentinel.get_so_token("oauth_create_account", device_id)
            if so_token:
                headers["openai-sentinel-so-token"] = json.dumps(so_token)
            log(f"6. create_account（sentinel 已生成，第 {attempt} 次）")
            resp = await session.post(
                f"{AUTH_BASE}/api/accounts/create_account",
                json={"name": name, "birthdate": birthdate},
                headers=headers,
            )
            try:
                create_data = resp.json()
            except Exception:
                create_data = {"status": resp.status_code, "text": resp.text}
            err = (create_data.get("error") or {}) if isinstance(create_data, dict) else {}
            err_code = str(err.get("code") or "")
            if err_code == "registration_disallowed" and attempt < 3:
                log(f"[!] registration_disallowed，2s 后重试 ({attempt}/3)")
                await asyncio.sleep(2)
                continue
            if err_code:
                # 仅 registration_disallowed（OpenAI 业务拒绝）才冷却域名；
                # 网络错误/sentinel/OTP 问题不触发，避免误伤。
                if err_code == "registration_disallowed":
                    try:
                        import grok_register_ttk as reg

                        reg.mark_cf_domain_cooldown(
                            email.split("@", 1)[1] if "@" in email else email,
                            log_callback=log,
                        )
                    except Exception:
                        pass
                raise GptRegisterError("create_account", f"{err_code}: {str(err)[:200]}")
            break
        else:
            raise GptRegisterError("create_account", "registration_disallowed（3 次重试均失败）")
        on_stage("sentinel_ready")

        # ── 6. callback → session ──
        continue_url = (create_data.get("continue_url") or "") if isinstance(create_data, dict) else ""
        if not continue_url:
            raise GptRegisterError("callback", f"create_account 未返回 continue_url: {str(create_data)[:200]}")
        cb_resp = await session.get(continue_url, allow_redirects=True)
        log(f"7. callback HTTP {cb_resp.status_code}")
        on_stage("session_ready")

        sess_resp = await session.get(f"{CHATGPT_HOME}/api/auth/session")
        try:
            sess_data = sess_resp.json()
        except Exception:
            sess_data = {}
        access_token = sess_data.get("accessToken", "") if isinstance(sess_data, dict) else ""
        if probe:
            if access_token:
                on_stage("probed")
                log("[*] /api/auth/session 验证通过，accessToken 已获取")
            else:
                log(f"[Debug] session 未返回 accessToken: {sess_resp.text[:150]}")
        return {
            "ok": True,
            "email": email,
            "access_token": access_token,
            "session_data": sess_data if isinstance(sess_data, dict) else {},
            "otp_sent_at": otp_sent_at,
        }
    finally:
        try:
            await session.close()
        except Exception:
            pass


def run_gpt_register(
    *,
    email: str,
    dev_token: str,
    proxy: str | None = None,
    headless: bool = True,  # 兼容旧参数，纯协议流程忽略
    otp_timeout: float = 300,
    step_timeout: float = 240,  # 兼容旧参数
    probe: bool = True,
    impersonate: str = "firefox144",
    name: str = "",
    birthdate: str = "",
    config: dict[str, Any] | None = None,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """执行一次纯协议 GPT 注册。成功返回 {ok, email, access_token}。

    注册成功后按 config 追加产物：
      - gpt_agent_enabled（默认 True）: 注册 Codex agent 身份 → gpt_agents/agent-<email>.json
      - sub2api_enabled: 推送账号到 sub2api（x-api-key + 指定分组）
    """
    log = log or _noop
    stage_cb = on_stage or (lambda _s: None)
    cfg = config or {}
    gen_name, gen_bd, password = _gen_profile()
    name = name or gen_name
    birthdate = birthdate or gen_bd

    def get_code() -> str:
        import grok_register_ttk as reg

        return reg.get_oai_code(
            dev_token,
            email,
            timeout=otp_timeout,
            log_callback=log,
            cancel_callback=cancel,
        )

    log(f"[*] 身份: {name} / {birthdate}（纯协议，impersonate={impersonate}）")
    result = asyncio.run(
        _run_async(
            email=email,
            proxy=proxy,
            get_code=get_code,
            name=name,
            birthdate=birthdate,
            otp_timeout=otp_timeout,
            impersonate=impersonate,
            probe=probe,
            log=log,
            cancel=cancel,
            on_stage=stage_cb,
        )
    )
    if result.get("ok"):
        _save_account(email, password, result.get("access_token", ""), result.get("session_data") or {}, log)

        access_token = result.get("access_token", "")
        need_agent = bool(cfg.get("gpt_agent_enabled", True)) or (
            bool(cfg.get("sub2api_enabled"))
            and str(cfg.get("sub2api_format") or "agent").lower() == "agent"
        )
        auth_json = None
        if access_token and need_agent:
            try:
                import gpt_agent

                auth_json = gpt_agent.create_agent_identity(
                    access_token, email=email, proxy=proxy, log=log
                )
            except Exception as exc:
                log(f"[!] agent 身份注册失败（不影响注册）: {exc}")

        # sub2api 推送（配置开启时）
        if access_token and cfg.get("sub2api_enabled"):
            try:
                import gpt_agent

                gpt_agent.push_to_sub2api(
                    sess_data=result.get("session_data") or {},
                    email=email,
                    access_token=access_token,
                    cfg=cfg,
                    auth_json=auth_json,
                    proxy=proxy,
                    log=log,
                )
            except Exception as exc:
                log(f"[!] sub2api 推送失败（不影响注册）: {exc}")

        log(f"+ GPT 注册成功: {email}")
    return result


def save_gpt_account(email: str, access_token: str, sess_data: dict[str, Any], log: LogFn | None = None) -> None:
    _save_account(email, "", access_token, sess_data, log or _noop)


__all__ = ["run_gpt_register", "save_gpt_account", "GptRegisterError", "GPT_ACCOUNTS_FILE", "GPT_AUTHS_DIR"]
