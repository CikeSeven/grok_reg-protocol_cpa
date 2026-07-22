"""GPT registration workbench metadata.

The workbench intentionally stores only a redacted flow summary extracted from
the supplied HAR.  Secrets, cookies, OTPs and authorization codes are not copied
into the repository.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


GPT_REGISTER_FLOW: dict[str, Any] = {
    "source": "注册GPT.har",
    "captured_on": "2026-07-22",
    "entry_count": 638,
    "core_endpoint_count": 14,
    "primary_hosts": [
        {"host": "chatgpt.com", "count": 442},
        {"host": "auth.openai.com", "count": 7},
        {"host": "sentinel.openai.com", "count": 6},
    ],
    "steps": [
        {
            "key": "entry",
            "name": "入口预检",
            "method": "GET/POST",
            "endpoint": "chatgpt.com/backend-anon/*",
            "request": "accounts/check, me, sentinel/chat-requirements/prepare",
            "response": "accounts, anonymous profile, prepare_token",
            "note": "建立匿名会话、设备上下文与初始 Sentinel 要求。",
        },
        {
            "key": "csrf",
            "name": "NextAuth 发起",
            "method": "GET/POST",
            "endpoint": "chatgpt.com/api/auth/{providers,csrf,signin/openai}",
            "request": "callbackUrl, csrfToken, screen_hint=signup, login_hint",
            "response": "authorize url, next-auth state cookie",
            "note": "用原站 NextAuth 生成跳转到 OpenAI Auth 的授权 URL。",
        },
        {
            "key": "auth",
            "name": "OpenAI Auth",
            "method": "GET",
            "endpoint": "auth.openai.com/api/accounts/authorize → /email-verification",
            "request": "client_id, scope, redirect_uri, state, login_hint",
            "response": "login_session, oai-client-auth-session",
            "note": "进入邮箱 OTP 页面，依赖同一浏览器上下文的 Cookie。",
        },
        {
            "key": "otp",
            "name": "邮箱 OTP",
            "method": "POST",
            "endpoint": "auth.openai.com/api/accounts/email-otp/validate",
            "request": "code",
            "response": "continue_url=/about-you, page.type=about_you",
            "note": "验证码来自现有邮箱凭证/收码工具，成功后进入资料页。",
        },
        {
            "key": "sentinel",
            "name": "Sentinel 令牌",
            "method": "POST",
            "endpoint": "sentinel.openai.com/backend-api/sentinel/req",
            "request": "p, id, flow",
            "response": "token, so, turnstile, proofofwork",
            "note": "create_account 前需要 openai-sentinel-token 与 so token。",
        },
        {
            "key": "profile",
            "name": "创建资料",
            "method": "POST",
            "endpoint": "auth.openai.com/api/accounts/create_account",
            "request": "name, birthdate",
            "response": "continue_url=chatgpt callback",
            "note": "提交姓名和生日，响应里给出 ChatGPT OAuth callback。",
        },
        {
            "key": "callback",
            "name": "回调换会话",
            "method": "GET",
            "endpoint": "chatgpt.com/api/auth/callback/openai",
            "request": "code, scope, state",
            "response": "__Secure-next-auth.session-token",
            "note": "完成 ChatGPT 登录态落盘，得到后续 backend-api Authorization 上下文。",
        },
        {
            "key": "probe",
            "name": "登录态验证",
            "method": "GET/POST",
            "endpoint": "chatgpt.com/backend-api/{me,accounts/check,models,conversation/init}",
            "request": "OAI-* headers, Authorization, session cookies",
            "response": "me, accounts, models, default_model_slug",
            "note": "用于判断账号是否可进入 ChatGPT 主界面。",
        },
    ],
}


def flow_summary() -> dict[str, Any]:
    """Return a copy of the redacted GPT registration flow summary."""
    return deepcopy(GPT_REGISTER_FLOW)
