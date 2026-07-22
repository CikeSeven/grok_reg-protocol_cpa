/* ═══════════════════════════════════════════════════════════════
   Grok Reg Console — frontend
   ═══════════════════════════════════════════════════════════════ */
"use strict";

const state = {
  view: "console",
  overview: null,
  accounts: [],
  accountPage: 1,
  accountPages: 1,
  accountTotal: 0,
  accountQuery: "",
  accountStatus: "all",
  selectedAccounts: new Set(),
  cpa: [],
  cpaPage: 1,
  cpaPages: 1,
  cpaTotal: 0,
  cpaQuery: "",
  cpaStatus: "all",
  selectedCpa: new Set(),
  cpaPool: null,
  cpaPoolMap: new Map(),
  cpaScanHistory: [],
  cpaScanHistoryTotal: 0,
  cpaScanHistoryQuery: "",
  cpaScanHistoryOutcome: "all",
  cpaActions: [],
  cpaActionPage: 1,
  cpaActionPages: 1,
  cpaActionTotal: 0,
  cpaActionPageSize: 10,
  cpaQuarantine: [],
  cpaQuarantineQuery: "",
  cpaQuarantineBucket: "all",
  selectedQuarantine: new Set(),
  mail: [],
  mailPage: 1,
  mailPages: 1,
  mailTotal: 0,
  mailQuery: "",
  mailStatus: "all",
  selectedMail: new Set(),
  proxies: [],
  proxyQuery: "",
  proxyPage: 1,
  proxyPageSize: 50,
  selectedProxies: new Set(),
  proxyChecking: false,
  proxyCheckTimer: null,
  toolPage: "convert",
  mailTool: [],
  mailToolPage: 1,
  mailToolPages: 1,
  mailToolTotal: 0,
  mailToolMetrics: {},
  mailToolPath: "",
  mailToolQuery: "",
  mailToolProtocol: "all",
  mailToolHealth: "all",
  selectedMailTool: new Set(),
  mailToolTask: null,
  mailToolPollTimer: null,
  mailToolImportSeq: 0,
  mailToolImportPreview: null,
  mailReader: {
    email: "",
    folder: "all",
    page: 1,
    pageSize: 30,
    items: [],
    selectedId: "",
    total: 0,
    totalExact: false,
    hasMore: false,
    protocol: "unknown",
    provider: "",
    checkedAt: "",
    loading: false,
    error: "",
    requestSeq: 0,
    cache: {},
    fromCache: false,
  },
  gptFlow: null,
  _gptHeadlessSeeded: false,
  jobs: [],
  activeJobId: null,
  activeJobStarted: "",
  logCursor: 0,
  logCount: 0,
  config: null,
  pollTimer: null,
  clockTimer: null,
  _headlessSeeded: false,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const statusText = {
  ready: "就绪",
  sso_only: "仅 SSO",
  incomplete: "不完整",
  available: "可用",
  partial: "部分消耗",
  exhausted: "已耗尽",
  queued: "排队中",
  running: "运行中",
  completed: "已完成",
  failed: "失败",
  stopped: "已停止",
  interrupted: "已中断",
  idle: "空闲",
  quota: "额度/冷却",
  account_quota: "额度耗尽",
  upstream_busy: "上游繁忙",
  transient_error: "临时异常",
  request_error: "请求异常",
  invalid_auth: "认证失效",
  malformed: "文件损坏",
  healthy: "健康",
  main: "主力池",
  reserve: "备用池",
  candidate: "候选池",
  observe: "观察池",
  quarantine: "隔离池",
  soft_fail: "软失败",
  hard_bad: "硬坏",
  refresh_failed: "续期失败",
  invalid: "无效",
  disabled: "已禁用",
  no_grok45: "无 4.5",
  probe_failed: "探测失败",
  cooling: "冷却中",
  quarantined: "已隔离",
  deleted: "已删除",
  policy_error: "策略异常",
  manual_disabled: "手动禁用",
  unchecked: "未巡检",
};

const mailStatusPill = {
  available: "ok",
  partial: "sso_only",
  exhausted: "err",
};

function cpaPoolPill(status) {
  if (status === "ok" || status === "healthy" || status === "main") return "ok";
  if (["quota", "account_quota", "cooling", "soft_fail", "probe_failed", "transient_error", "upstream_busy", "observe"].includes(status)) return "warn";
  if (["disabled", "unchecked", "candidate", "manual_disabled"].includes(status)) return "idle";
  if (status === "reserve") return "info";
  if (status === "running") return "running";
  if (!status) return "idle";
  return "err";
}

const scanOutcomeText = {
  ok: "正常",
  warn: "有异常",
  error: "执行异常",
  cancelled: "已取消",
};

function cpaScanOutcomePill(outcome) {
  if (outcome === "ok") return "ok";
  if (outcome === "warn") return "warn";
  if (outcome === "cancelled") return "idle";
  if (outcome === "error") return "err";
  return "idle";
}

const kindText = {
  register: "批量注册",
  gpt_register: "GPT 注册工作流",
  backfill: "CPA 补 mint",
};

const PROVIDER_OPTIONS = [
  ["hotmail", "hotmail — Hotmail/Outlook 四段凭证（IMAP/Graph 自动探测）"],
  ["cloudmail", "cloudmail — 自建 CloudMail 域名池"],
  ["cloudflare", "cloudflare — Cloudflare 临时邮箱 API"],
  ["mailnest", "mailnest — MailNest 购买邮箱"],
  ["duckmail", "duckmail — DuckMail 临时邮箱"],
  ["yyds", "yyds — YYDS 临时邮箱"],
];

const TURNSTILE_SOLVER_OPTIONS = [
  ["local", "local — 本地 solver"],
  ["2captcha", "2captcha — 2Captcha 打码"],
  ["yescaptcha", "yescaptcha — YesCaptcha 打码"],
];

const POLICY_ACTION_OPTIONS = [
  ["keep", "keep — 保留不处理"],
  ["disable", "disable — 标记禁用（可恢复）"],
  ["quarantine", "quarantine — 移入隔离区（推荐）"],
  ["delete", "delete — 移入 deleted 隔离区"],
];

const GPT_FLOW_FALLBACK = {
  source: "注册GPT.har",
  entry_count: 638,
  core_endpoint_count: 14,
  steps: [
    ["entry", "入口预检", "GET/POST", "chatgpt.com/backend-anon/*", "accounts/check, me, sentinel prepare", "accounts / prepare_token", "建立匿名会话与 Sentinel 要求"],
    ["csrf", "NextAuth 发起", "GET/POST", "chatgpt.com/api/auth/{providers,csrf,signin/openai}", "callbackUrl, csrfToken, screen_hint, login_hint", "authorize url / state cookie", "原站发起 OpenAI Auth 授权"],
    ["auth", "OpenAI Auth", "GET", "auth.openai.com/api/accounts/authorize → /email-verification", "client_id, scope, redirect_uri, state", "login_session / oai-client-auth-session", "进入邮箱验证码页面"],
    ["otp", "邮箱 OTP", "POST", "auth.openai.com/api/accounts/email-otp/validate", "code", "continue_url=/about-you", "验证码成功后进入资料页"],
    ["sentinel", "Sentinel 令牌", "POST", "sentinel.openai.com/backend-api/sentinel/req", "p, id, flow", "token / so / proofofwork", "create_account 前置令牌"],
    ["profile", "创建资料", "POST", "auth.openai.com/api/accounts/create_account", "name, birthdate", "continue_url=callback", "提交资料并生成回调 URL"],
    ["callback", "回调换会话", "GET", "chatgpt.com/api/auth/callback/openai", "code, scope, state", "next-auth session-token", "落盘 ChatGPT 登录态"],
    ["probe", "登录态验证", "GET/POST", "chatgpt.com/backend-api/{me,accounts/check,models}", "OAI-* headers, Authorization", "me / accounts / models", "判断账号可进入主界面"],
  ].map(([key, name, method, endpoint, request, response, note]) => ({ key, name, method, endpoint, request, response, note })),
};

const CONFIG_FIELDS = {
  basic: [
    ["email_provider", "邮箱服务商", "select"],
    ["defaultDomains", "默认域名", "text"],
    ["proxy", "注册代理", "proxy"],
    ["cpa_proxy", "CPA 代理", "proxy"],
    ["register_headless", "注册无头", "bool"],
    ["hotmail_accounts_file", "Hotmail 凭证文件", "text"],
    ["hotmail_protocol", "收码协议 auto/imap/graph", "text"],
    ["hotmail_max_aliases_per_account", "每主邮箱最大别名", "number"],
    ["cloudmail_url", "CloudMail URL", "text"],
    ["cloudmail_admin_email", "CloudMail 管理员邮箱", "text"],
    ["cloudmail_password", "CloudMail 密码", "password"],
    ["cloudflare_api_base", "Cloudflare API", "text"],
    ["cloudflare_admin_password", "CF Admin 密码", "password"],
    ["duckmail_api_key", "DuckMail API Key", "password"],
    ["mailnest_api_key", "MailNest API Key", "password"],
    ["mailnest_project_code", "MailNest 项目代码", "text"],
    ["browser_timezone", "浏览器/solver 时区", "text"],
  ],
  cpa: [
    ["register_threads", "默认注册线程", "number"],
    ["protocol_register", "注册走纯协议", "bool"],
    ["protocol_only", "协议注册失败不回退浏览器", "bool"],
    ["protocol_register_fallback_browser", "协议失败回退浏览器", "bool"],
    ["protocol_solver_url", "注册 Turnstile Solver URL", "text"],
    ["protocol_solver_pass_proxy", "Solver 同步注册代理", "bool"],
    ["protocol_solver_locale", "Solver Locale", "text"],
    ["protocol_solver_accept_language", "Solver Accept-Language", "text"],
    ["protocol_solver_timezone", "Solver 时区", "text"],
    ["protocol_impersonate", "协议注册 TLS 指纹", "text"],
    ["protocol_register_max_attempts", "协议注册重试次数", "number"],
    ["protocol_solver_poll_timeout", "Solver 轮询超时秒", "number"],
    ["protocol_solver_poll_interval", "Solver 轮询间隔秒", "number"],
    ["turnstile_solver_provider", "Turnstile 验证方式", "turnstile_solver"],
    ["turnstile_site_key", "Turnstile sitekey", "text"],
    ["yescaptcha_key", "YesCaptcha Key", "password"],
    ["twocaptcha_enabled", "启用 2Captcha", "bool"],
    ["twocaptcha_key", "2Captcha API Key", "password"],
    ["twocaptcha_pass_proxy", "2Captcha 同步注册代理", "bool"],
    ["twocaptcha_timeout", "2Captcha 超时秒", "number"],
    ["twocaptcha_poll_interval", "2Captcha 轮询间隔秒", "number"],
    ["twocaptcha_api_base", "2Captcha API Base", "text"],
    ["twocaptcha_action", "2Captcha action 可选", "text"],
    ["twocaptcha_data", "2Captcha data/cData 可选", "text"],
    ["twocaptcha_pagedata", "2Captcha pagedata 可选", "text"],
    ["twocaptcha_user_agent", "2Captcha User-Agent 可选", "text"],
    ["protocol_email_tempmail_fallback", "主邮箱失败回退 TempMail", "bool"],
    ["cpa_export_enabled", "注册后导出 CPA", "bool"],
    ["cpa_prefer_protocol", "协议优先", "bool"],
    ["cpa_protocol_flow", "协议流程 pkce/device", "text"],
    ["cpa_protocol_only", "仅协议不回退浏览器", "bool"],
    ["cpa_allow_device_flow_fallback", "允许 Device Flow 回退", "bool"],
    ["cpa_auth_dir", "CPA 导出目录", "text"],
    ["cpa_copy_to_hotload", "移动到热加载目录", "bool"],
    ["cpa_hotload_dir", "热加载目录", "text"],
    ["cpa_base_url", "CPA Base URL", "text"],
    ["cpa_headless", "Mint 浏览器无头", "bool"],
    ["cpa_mint_workers", "Mint workers", "number"],
    ["cpa_mint_queue_max", "Mint 队列上限", "number"],
    ["cpa_mint_timeout_sec", "Mint 超时秒", "number"],
    ["cpa_probe_after_write", "写出后 probe models", "bool"],
    ["cpa_probe_chat", "写出后 probe chat", "bool"],
    ["cpa_pool_auto_scan", "CPA 号池自动巡检", "bool"],
    ["cpa_pool_scan_interval_sec", "旧版健康复检周期", "number"],
    ["cpa_pool_scheduler_tick_sec", "调度器唤醒秒", "number"],
    ["cpa_pool_adaptive_batch_size", "自适应单批账号数", "number"],
    ["cpa_pool_healthy_check_interval_sec", "健康账号复检秒", "number"],
    ["cpa_pool_observe_check_interval_sec", "观察账号复检秒", "number"],
    ["cpa_pool_candidate_check_interval_sec", "候选账号复检秒", "number"],
    ["cpa_pool_independent_failure_interval_sec", "独立失败最小间隔秒", "number"],
    ["cpa_pool_recovery_success_threshold", "恢复所需连续成功", "number"],
    ["cpa_pool_chat_sample_percent", "健康账号 Chat 抽样百分比", "number"],
    ["cpa_pool_models_probe_rate_per_sec", "Models 每秒探测数", "number"],
    ["cpa_pool_chat_probe_rate_per_sec", "Chat 每秒探测数", "number"],
    ["cpa_pool_scan_workers", "号池巡检并发", "number"],
    ["cpa_pool_probe_timeout_sec", "号池 probe 超时秒", "number"],
    ["cpa_pool_probe_chat", "号池默认 probe chat", "bool"],
    ["cpa_pool_refresh_before_probe", "号池 probe 前临期续期", "bool"],
    ["cpa_pool_refresh_skew_sec", "号池续期提前秒", "number"],
    ["cpa_pool_max_items_per_scan", "单轮最多巡检(0全量)", "number"],
    ["cpa_pool_probe_proxy", "号池 probe 代理(direct/pool)", "proxy"],
    ["cpa_pool_history_limit", "每号巡检历史条数", "number"],
    ["cpa_pool_scan_history_limit", "整轮巡检历史条数", "number"],
    ["cpa_pool_observation_retention_days", "巡检明细保留天数", "number"],
    ["cpa_pool_governance_action_retention_days", "治理记录保留天数", "number"],
    ["cpa_pool_breaker_window_sec", "熔断统计窗口秒", "number"],
    ["cpa_pool_breaker_min_samples", "熔断最少样本", "number"],
    ["cpa_pool_breaker_min_errors", "熔断最少同类错误", "number"],
    ["cpa_pool_breaker_error_ratio", "熔断错误比例", "number"],
    ["cpa_pool_breaker_open_sec", "熔断保持秒", "number"],
    ["cpa_pool_apply_policy", "号池自动治理", "bool"],
    ["cpa_pool_auto_refill", "号池自动补号（含注册）", "bool"],
    ["cpa_pool_refill_target_active", "补 CPA 目标存量(0保持巡检前)", "number"],
    ["cpa_pool_refill_max_per_scan", "单批自动补号数", "number"],
    ["cpa_pool_refill_workers", "自动补 CPA workers", "number"],
    ["cpa_pool_refill_probe_chat", "自动补 CPA probe chat", "bool"],
    ["cpa_pool_refill_controller_interval_sec", "自动续批检查秒", "number"],
    ["cpa_pool_refill_emergency_threshold_percent", "应急补号水位百分比", "number"],
    ["cpa_pool_refill_max_inventory", "最大在线库存", "number"],
    ["cpa_pool_refill_low_water_hold_sec", "低水位持续秒", "number"],
    ["cpa_pool_refill_low_water_rounds", "连续低水位轮数", "number"],
    ["cpa_pool_refill_min_baseline_percent", "补号所需基线百分比", "number"],
    ["cpa_pool_refill_cooling_grace_sec", "短期冷却保护秒", "number"],
    ["cpa_pool_refill_expected_yield_percent", "预计补号成功率百分比", "number"],
    ["cpa_pool_refill_daily_limit", "日常每日补号软限额(0不限)", "number"],
    ["cpa_pool_quarantine_dir", "号池隔离区目录", "text"],
    ["cpa_pool_move_with_backup", "隔离写 meta 记录", "bool"],
    ["cpa_pool_hard_bad_threshold", "硬坏阈值", "number"],
    ["cpa_pool_refresh_failed_threshold", "续期失败阈值", "number"],
    ["cpa_pool_invalid_threshold", "无效文件阈值", "number"],
    ["cpa_pool_no_grok45_threshold", "无4.5阈值", "number"],
    ["cpa_pool_soft_fail_threshold", "软失败阈值", "number"],
    ["cpa_pool_quota_threshold", "额度冷却阈值", "number"],
    ["cpa_pool_quota_cooldown_sec", "额度禁用冷却秒", "number"],
    ["cpa_pool_governance_max_downgrades_per_scan", "单轮最大降级账号", "number"],
    ["cpa_pool_governance_max_downgrade_percent", "单轮最大降级百分比", "number"],
    ["cpa_pool_main_low_water_percent", "主力池低水位百分比", "number"],
    ["cpa_pool_reserve_target_percent", "备用池目标百分比", "number"],
    ["cpa_pool_cli_management_enabled", "CLI 管理 API 联动", "bool"],
    ["cpa_pool_cli_management_url", "CLI 管理 API 地址", "text"],
    ["cpa_pool_cli_management_key", "CLI 管理密钥", "password"],
    ["cpa_pool_cli_management_timeout_sec", "CLI 管理请求超时秒", "number"],
    ["cpa_pool_cli_management_cache_sec", "CLI 状态缓存秒", "number"],
    ["cpa_pool_file_fallback_enabled", "管理 API 异常时文件回退", "bool"],
    ["cpa_pool_file_fallback_grace_sec", "文件回退宽限秒", "number"],
    ["cpa_pool_hard_bad_action", "硬坏动作", "policy_action"],
    ["cpa_pool_refresh_failed_action", "续期失败动作", "policy_action"],
    ["cpa_pool_invalid_action", "无效文件动作", "policy_action"],
    ["cpa_pool_no_grok45_action", "无4.5动作", "policy_action"],
    ["cpa_pool_soft_fail_action", "软失败动作", "policy_action"],
    ["cpa_pool_quota_action", "额度动作", "policy_action"],
    ["grok2api_auto_add_remote", "推远端 grok2api", "bool"],
    ["grok2api_remote_base", "grok2api Admin API", "text"],
    ["grok2api_remote_app_key", "grok2api app_key", "password"],
    ["grok2api_pool_name", "池名", "text"],
  ],
};

/* ── helpers ── */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();
  if (!response.ok) {
    const msg = (payload && payload.error) || (typeof payload === "string" ? payload : `HTTP ${response.status}`);
    throw new Error(msg);
  }
  return payload;
}

function toast(message, error = false) {
  const node = document.createElement("div");
  node.className = `toast${error ? " error" : ""}`;
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => {
    node.classList.add("leaving");
    setTimeout(() => node.remove(), 280);
  }, 3400);
}

function initials(email) {
  const name = String(email || "").split("@")[0].replace(/[^a-z0-9]/gi, "");
  return (name.slice(0, 2) || "GR").toUpperCase();
}

function debounce(fn, ms = 300) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

/* 复制文本：navigator.clipboard 仅在安全上下文（HTTPS/localhost）可用，
   HTTP 部署（如 http://IP:8787）降级为 execCommand。 */
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-999px;left:-999px;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    try {
      const ok = document.execCommand("copy");
      ta.remove();
      ok ? resolve() : reject(new Error("复制失败，请手动选择复制"));
    } catch (err) {
      ta.remove();
      reject(err);
    }
  });
}

function fmtElapsed(startedIso) {
  if (!startedIso) return "00:00";
  const start = Date.parse(startedIso);
  if (Number.isNaN(start)) return "00:00";
  let sec = Math.max(0, Math.floor((Date.now() - start) / 1000));
  const h = Math.floor(sec / 3600);
  sec -= h * 3600;
  const m = Math.floor(sec / 60);
  const s = sec - m * 60;
  const mm = String(m).padStart(2, "0");
  const ss = String(s).padStart(2, "0");
  return h > 0 ? `${String(h).padStart(2, "0")}:${mm}:${ss}` : `${mm}:${ss}`;
}

/* ── views ── */

function setToolPage(page, updateHash = true) {
  const next = ["convert", "mail"].includes(page) ? page : "convert";
  state.toolPage = next;
  $$('[data-tool-page]').forEach((button) => {
    const active = button.dataset.toolPage === next;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  $$('[data-tool-panel]').forEach((panel) => {
    panel.hidden = panel.dataset.toolPanel !== next;
  });
  if (updateHash && state.view === "tools" && location.hash !== `#tools/${next}`) {
    history.replaceState(null, "", `#tools/${next}`);
  }
  if (state.view === "tools" && next === "mail") {
    loadMailTool().catch((e) => toast(e.message, true));
    pollMailToolStatus().catch(() => {});
  }
}

function setView(view, toolPage = null) {
  state.view = view;
  closePageSettings();
  if (view === "tools" && ["convert", "mail"].includes(toolPage)) state.toolPage = toolPage;
  const nextHash = view === "tools" ? `#tools/${state.toolPage}` : `#${view}`;
  if (location.hash !== nextHash) history.replaceState(null, "", nextHash);
  $$(".nav-item[data-view]").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === view));
  $$("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== view;
  });
  if (view === "accounts") loadAccounts().catch((e) => toast(e.message, true));
  if (view === "cpa") loadCpa().catch((e) => toast(e.message, true));
  if (view === "mail") loadMail().catch((e) => toast(e.message, true));
  if (view === "proxies") loadProxies().catch((e) => toast(e.message, true));
  if (view === "gpt") loadGptFlow().catch((e) => toast(e.message, true));
  if (view === "settings") loadConfig().catch((e) => toast(e.message, true));
  if (view === "tools") setToolPage(state.toolPage, false);
}

function openJobs(open = true) {
  $("#job-drawer").classList.toggle("open", open);
  $("#job-drawer").setAttribute("aria-hidden", open ? "false" : "true");
  const settingsOpen = Boolean($("#page-settings-drawer")?.classList.contains("open"));
  $("#drawer-backdrop").hidden = !(open || settingsOpen);
  if (open) loadJobs().catch((e) => toast(e.message, true));
}

/* ── overview / pipeline / active job ── */

function setBadge(sel, value) {
  const el = $(sel);
  const n = Number(value || 0);
  el.hidden = n <= 0;
  el.textContent = n > 9999 ? "9999+" : String(n);
}

function renderOverview() {
  const o = state.overview || {};
  $("#m-accounts").textContent = o.accounts_total ?? 0;
  $("#m-sso").textContent = o.accounts_with_sso ?? 0;
  $("#m-cpa").textContent = o.accounts_with_cpa ?? 0;
  $("#m-sso-only").textContent = o.accounts_sso_only ?? 0;
  $("#m-hotload").textContent = o.cpa_hotload ?? 0;
  $("#m-mail").textContent = o.mail_total ?? 0;
  $("#m-provider").textContent = o.email_provider || "-";
  $("#provider-chip").textContent = `provider: ${o.email_provider || "-"}`;
  $("#meta-proxy").textContent = o.proxy || "-";
  $("#meta-cpa-proxy").textContent = o.cpa_proxy || "-";
  $("#meta-register-mode").textContent = o.protocol_register ? "protocol" : "browser";
  $("#meta-protocol").textContent = o.cpa_protocol_flow || "pkce";
  $("#pv-flow").textContent = (o.cpa_protocol_flow || "pkce").toUpperCase();

  setBadge("#nav-accounts-count", o.accounts_total);
  setBadge("#nav-cpa-count", o.cpa_total);
  setBadge("#nav-mail-count", o.mail_total);
  setBadge("#nav-proxies-count", o.proxy_total);

  if (typeof o.register_headless === "boolean" && !state._headlessSeeded) {
    $("#reg-headless").checked = o.register_headless;
    state._headlessSeeded = true;
  }
  if (typeof o.protocol_register === "boolean" && !state._protocolSeeded) {
    $("#reg-protocol").checked = o.protocol_register;
    $("#reg-protocol-only").checked = Boolean(
      o.protocol_register && (o.protocol_only || !o.protocol_register_fallback_browser)
    );
    syncRegisterProtocolToggles();
    state._protocolSeeded = true;
  }

  renderPipeline(o);
  renderActiveJob(o.active_job);
  renderGptOverview(o);
}

async function loadOverview() {
  state.overview = await api("/api/overview");
  renderOverview();
  return state.overview;
}

function renderPipeline(o) {
  const job = o.active_job;
  const running = job && (job.status === "running" || job.status === "queued");
  const steps = {
    mail: { value: o.mail_total ?? 0, state: (o.mail_total ?? 0) > 0 ? "done" : "" },
    register: {
      value: o.accounts_total ?? 0,
      state: running && job.kind === "register" ? "active" : (o.accounts_total ?? 0) > 0 ? "done" : "",
    },
    sso: { value: o.accounts_with_sso ?? 0, state: (o.accounts_with_sso ?? 0) > 0 ? "done" : "" },
    mint: {
      value: running
        ? (job.kind === "register"
            ? `${job.stats?.mint_success ?? 0}/${job.stats?.mint_fail ?? 0}`
            : `${job.stats?.ok ?? 0}/${job.stats?.fail ?? 0}`)
        : "-",
      state: running ? "active" : "",
    },
    cpa: { value: o.accounts_with_cpa ?? 0, state: (o.accounts_with_cpa ?? 0) > 0 ? "done" : "" },
    hotload: { value: o.cpa_hotload ?? 0, state: (o.cpa_hotload ?? 0) > 0 ? "done" : "" },
  };
  for (const [name, info] of Object.entries(steps)) {
    const el = document.querySelector(`.pstep[data-step="${name}"]`);
    if (!el) continue;
    el.classList.toggle("done", info.state === "done");
    el.classList.toggle("active", info.state === "active");
    const valueEl = el.querySelector(".pstep-value");
    if (valueEl) valueEl.textContent = info.value;
  }
}

function jobProgress(job) {
  const s = job.stats || {};
  if (job.kind === "register") {
    const done = Number(s.done || 0);
    const target = Math.max(1, Number(s.target || 1));
    return Math.min(100, (done / target) * 100);
  }
  const done = Number(s.done || 0);
  const total = Math.max(1, Number(s.total || 1));
  return Math.min(100, (done / total) * 100);
}

function statCell(label, value, cls = "") {
  return `<div class="job-stat ${cls}"><small>${label}</small><b>${value}</b></div>`;
}

function renderActiveJob(job) {
  const statusEl = $("#active-job-status");
  const stopBtn = $("#stop-active-job");
  const idleEl = $("#active-job-idle");
  const detailEl = $("#active-job-detail");
  const navActive = $("#nav-jobs-active");

  if (!job) {
    state.activeJobId = null;
    state.activeJobStarted = "";
    statusEl.className = "pill idle";
    statusEl.textContent = "空闲";
    idleEl.hidden = false;
    detailEl.hidden = true;
    stopBtn.disabled = true;
    navActive.hidden = true;
    renderGptJob(null);
    return;
  }

  state.activeJobId = job.id;
  state.activeJobStarted = job.started_at || state.activeJobStarted;
  const running = job.status === "running" || job.status === "queued";

  statusEl.className = `pill ${job.status}`;
  statusEl.textContent = statusText[job.status] || job.status;
  stopBtn.disabled = !running;
  navActive.hidden = !running;
  navActive.textContent = "1";

  idleEl.hidden = true;
  detailEl.hidden = false;
  $("#active-job-id").textContent = job.id;
  $("#active-job-kind").textContent = kindText[job.kind] || job.kind;
  $("#active-job-elapsed").textContent = fmtElapsed(state.activeJobStarted);

  const s = job.stats || {};
  if (job.kind === "register") {
    $("#active-job-stats").innerHTML =
      statCell("注册成功", s.reg_success ?? 0, "ok") +
      statCell("注册失败", s.reg_fail ?? 0, "err") +
      statCell("目标", s.target ?? 0) +
      statCell("Mint 成功", s.mint_success ?? 0, "accent") +
      statCell("Mint 失败", s.mint_fail ?? 0, (s.mint_fail ?? 0) > 0 ? "err" : "") +
      statCell("进度", `${s.done ?? 0}/${s.target ?? 0}`);
  } else if (job.kind === "gpt_register") {
    $("#active-job-stats").innerHTML =
      statCell("目标", s.target ?? 0) +
      statCell("阶段", `${s.stage_index ?? 0}/${s.steps ?? 0}`, "accent") +
      statCell("会话", s.session_ready ?? 0, (s.session_ready ?? 0) > 0 ? "ok" : "") +
      statCell("Probe", s.probed ?? 0, (s.probed ?? 0) > 0 ? "ok" : "") +
      statCell("完成步", `${s.done ?? 0}/${s.total ?? 0}`) +
      statCell("模式", job.options?.plan_only ? "预检" : "执行");
  } else {
    $("#active-job-stats").innerHTML =
      statCell("成功", s.ok ?? 0, "ok") +
      statCell("失败", s.fail ?? 0, (s.fail ?? 0) > 0 ? "err" : "") +
      statCell("进度", `${s.done ?? 0}/${s.total ?? 0}`);
  }

  const pct = jobProgress(job);
  $("#active-job-progress").style.width = `${pct}%`;
  $("#active-job-progress-text").textContent = `${Math.round(pct)}%`;
  renderGptJob(job);
}

/* ── GPT workbench ── */

function gptFlow() {
  return state.gptFlow || GPT_FLOW_FALLBACK;
}

async function loadGptFlow() {
  try {
    state.gptFlow = await api("/api/gpt/register/flow");
  } catch (err) {
    state.gptFlow = GPT_FLOW_FALLBACK;
    throw err;
  } finally {
    renderGptFlow();
    renderGptOverview(state.overview || {});
  }
}

function renderGptFlow() {
  const flow = gptFlow();
  const rows = flow.steps || [];
  const tbody = $("#gpt-flow-rows");
  if (!tbody) return;
  tbody.innerHTML = "";
  for (const step of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="pill info">${esc(step.name || step.key || "-")}</span></td>
      <td><span class="gpt-endpoint" title="${esc(step.endpoint || "")}">${esc(step.method || "-")} ${esc(step.endpoint || "-")}</span></td>
      <td><small class="table-sub">${esc(step.request || "-")}</small></td>
      <td><small class="table-sub">${esc(step.response || "-")}</small></td>
      <td><small class="table-sub">${esc(step.note || "-")}</small></td>
    `;
    tbody.append(tr);
  }
  $("#gpt-m-har-entries").textContent = flow.entry_count ?? 0;
  $("#gpt-m-core-endpoints").textContent = flow.core_endpoint_count ?? rows.length;
  $("#gpt-m-har-source").textContent = flow.source || "注册GPT.har";
}

function renderGptOverview(o = {}) {
  if (!$("#gpt-m-mail")) return;
  const proxyTotal = state.proxies.length || Number(o.proxy_total || 0);
  $("#gpt-m-mail").textContent = o.mail_total ?? 0;
  $("#gpt-m-provider").textContent = o.email_provider || "-";
  $("#gpt-m-proxies").textContent = proxyTotal;
  $("#gpt-meta-provider").textContent = o.email_provider || "-";
  $("#gpt-meta-proxy").textContent = o.proxy || "-";
  $("#gpt-meta-browser").textContent = $("#gpt-headless")?.checked ? "headless" : "headed";
  if (typeof o.register_headless === "boolean" && !state._gptHeadlessSeeded) {
    $("#gpt-headless").checked = o.register_headless;
    $("#gpt-meta-browser").textContent = o.register_headless ? "headless" : "headed";
    state._gptHeadlessSeeded = true;
  }
  renderGptPipeline(o.active_job || null);
  renderGptJob(o.active_job || null);
}

function renderGptPipeline(job) {
  const steps = (gptFlow().steps || []).map((s) => String(s.key || ""));
  const isGpt = job && job.kind === "gpt_register";
  const running = isGpt && (job.status === "running" || job.status === "queued");
  const completed = isGpt && job.status === "completed";
  const stage = isGpt ? Number(job.stats?.stage_index || 0) : 0;
  $$("#gpt-pipeline [data-gpt-step]").forEach((el, idx) => {
    const key = el.dataset.gptStep;
    const pos = Math.max(1, steps.indexOf(key) + 1 || idx + 1);
    el.classList.toggle("active", running && pos === Math.max(1, stage));
    el.classList.toggle("done", completed || (isGpt && pos < stage));
  });
}

function renderGptJob(job) {
  if (!$("#gpt-active-job-status")) return;
  const statusEl = $("#gpt-active-job-status");
  const stopBtn = $("#gpt-stop-active-job");
  const idleEl = $("#gpt-active-job-idle");
  const detailEl = $("#gpt-active-job-detail");
  const isGpt = job && job.kind === "gpt_register";
  if (!isGpt) {
    statusEl.className = "pill idle";
    statusEl.textContent = job ? `其他任务：${kindText[job.kind] || job.kind}` : "空闲";
    idleEl.hidden = false;
    detailEl.hidden = true;
    stopBtn.disabled = !(job && (job.status === "running" || job.status === "queued"));
    renderGptPipeline(null);
    return;
  }
  const running = job.status === "running" || job.status === "queued";
  const s = job.stats || {};
  statusEl.className = `pill ${job.status}`;
  statusEl.textContent = statusText[job.status] || job.status;
  stopBtn.disabled = !running;
  idleEl.hidden = true;
  detailEl.hidden = false;
  $("#gpt-active-job-id").textContent = job.id || "-";
  $("#gpt-active-job-kind").textContent = kindText[job.kind] || job.kind;
  $("#gpt-active-job-elapsed").textContent = fmtElapsed(job.started_at || state.activeJobStarted);
  $("#gpt-active-job-stats").innerHTML =
    statCell("目标", s.target ?? 0) +
    statCell("阶段", `${s.stage_index ?? 0}/${s.steps ?? 0}`, "accent") +
    statCell("OTP", s.otp_ready ?? 0, (s.otp_ready ?? 0) > 0 ? "ok" : "") +
    statCell("Sentinel", s.sentinel_ready ?? 0, (s.sentinel_ready ?? 0) > 0 ? "ok" : "") +
    statCell("Session", s.session_ready ?? 0, (s.session_ready ?? 0) > 0 ? "ok" : "") +
    statCell("进度", `${s.done ?? 0}/${s.total ?? 0}`);
  const pct = jobProgress(job);
  $("#gpt-active-job-progress").style.width = `${pct}%`;
  $("#gpt-active-job-progress-text").textContent = `${Math.round(pct)}%`;
  renderGptPipeline(job);
}

/* ── live log ── */

function classifyLog(line) {
  if (/异常|失败|未成功|error|Traceback/i.test(line) || /\] ! /.test(line)) return "err";
  if (/注册成功|CPA auth|ok ->|moved ->|完成:|\+ /.test(line)) return "ok";
  if (/背压|重试|跳过|skipped|等待|retry/i.test(line)) return "warn";
  if (/===/.test(line)) return "hl";
  if (/gpt|openai|nextauth|sentinel|otp|callback/i.test(line)) return "cpa";
  if (/cpa|mint|pkce|oidc|hotload/i.test(line)) return "cpa";
  return "";
}

function appendLogs(lines) {
  if (!lines || !lines.length) return;
  const panels = [
    { panel: $("#live-log"), autoscroll: $("#log-autoscroll") },
    { panel: $("#gpt-live-log"), autoscroll: $("#gpt-log-autoscroll") },
  ].filter((x) => x.panel);
  for (const { panel, autoscroll } of panels) {
    const placeholder = panel.querySelector(".log-line.dim");
    if (placeholder && placeholder.textContent.startsWith("//")) placeholder.remove();
    const frag = document.createDocumentFragment();
    for (const line of lines) {
      const div = document.createElement("div");
      div.className = `log-line ${classifyLog(line)}`.trim();
      const m = String(line).match(/^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$/s);
      if (m) {
        div.innerHTML = `<span class="ts">[${esc(m[1])}]</span> ${esc(m[2])}`;
      } else {
        div.textContent = line;
      }
      frag.append(div);
    }
    panel.append(frag);
    while (panel.children.length > 2000 && panel.firstChild) {
      panel.removeChild(panel.firstChild);
    }
    if (!autoscroll || autoscroll.checked) panel.scrollTop = panel.scrollHeight;
  }
  state.logCount = ($("#live-log")?.children.length || 0);
}

function resetLogs(msg = "// 等待任务启动，日志将实时输出在这里") {
  state.logCount = 1;
  $("#live-log").innerHTML = `<div class="log-line dim">${esc(msg)}</div>`;
  if ($("#gpt-live-log")) {
    $("#gpt-live-log").innerHTML = `<div class="log-line dim">${esc(msg)}</div>`;
  }
}

/* ── accounts ── */

function renderAccounts() {
  const tbody = $("#account-rows");
  tbody.innerHTML = "";
  $("#account-empty").hidden = state.accounts.length > 0;
  for (const row of state.accounts) {
    const selected = state.selectedAccounts.has(row.email);
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-email="${esc(row.email)}" ${selected ? "checked" : ""}></td>
      <td><div class="cell-main">
        <span class="avatar">${esc(initials(row.email))}</span>
        <span class="cell-email" title="${esc(row.email)}">${esc(row.email)}</span>
      </div></td>
      <td>${row.has_sso ? '<span class="pill ok">有</span>' : '<span class="pill err">无</span>'}</td>
      <td><span class="pill ${esc(row.status)}">${esc(statusText[row.status] || row.status)}</span></td>
      <td>${row.cpa ? '<span class="pill ok">有</span>' : '<span class="pill sso_only">无</span>'}</td>
      <td><span class="mono">${esc(row.cpa_method || "-")}</span></td>
      <td><span class="mono">${esc(row.cpa_location || "-")}</span></td>
    `;
    tbody.append(tr);
  }
  $("#account-count").textContent = `共 ${state.accountTotal} 个账号`;
  $("#account-page-label").textContent = `${state.accountPage} / ${state.accountPages}`;
  $("#account-selected-count").textContent = String(state.selectedAccounts.size);
  $("#account-batch").classList.toggle("active", state.selectedAccounts.size > 0);
  $("#account-select-all").checked =
    state.accounts.length > 0 && state.accounts.every((r) => state.selectedAccounts.has(r.email));
}

async function loadAccounts() {
  const params = new URLSearchParams({
    query: state.accountQuery,
    status: state.accountStatus,
    page: String(state.accountPage),
    page_size: "50",
  });
  const data = await api(`/api/accounts?${params}`);
  state.accounts = data.items || [];
  state.accountTotal = data.total || 0;
  state.accountPage = data.page || 1;
  state.accountPages = data.total_pages || 1;
  renderAccounts();
}

/* ── cpa ── */

function renderCpa() {
  const tbody = $("#cpa-rows");
  tbody.innerHTML = "";
  $("#cpa-empty").hidden = state.cpa.length > 0;
  for (const row of state.cpa) {
    const selected = state.selectedCpa.has(row.email);
    const scan = state.cpaPoolMap.get(String(row.email || "").toLowerCase()) || {};
    const scanStatus = scan.status || row.scan_status || "";
    const healthStatus = scan.health_status || row.health_status || scanStatus || "unchecked";
    const tier = scan.tier || row.pool_tier || "candidate";
    const scanReason = scan.reason || row.scan_reason || "";
    const tierPill = `<span class="pill ${cpaPoolPill(tier)}">${esc(statusText[tier] || tier)}</span>`;
    const scanPill = `<span class="pill ${cpaPoolPill(healthStatus)}" title="${esc(scanReason)}">${esc(statusText[healthStatus] || healthStatus)}</span>`;
    const expires = scan.expired || row.expired || "-";
    const refreshMark = scan.refreshed ? '<span class="chip">已续期</span>' : "";
    const actionMark = scan.action ? `<span class="chip">${esc(scan.action)}</span>` : "";
    const streak = scan.status_streak ? ` · 连续 ${scan.status_streak}` : "";
    const cool = scan.cool_until ? ` · 冷却到 ${scan.cool_until}` : "";
    const desiredPriority = scan.desired_priority ?? row.desired_priority;
    const actualPriority = scan.actual_priority ?? row.actual_priority;
    const actualDisabled = scan.actual_disabled ?? row.actual_disabled;
    const scheduleText = `${actualPriority == null ? "-" : `P${actualPriority}`} → ${desiredPriority == null ? "-" : `P${desiredPriority}`}`;
    const disabledText = actualDisabled == null ? "未同步" : (actualDisabled ? "已禁用" : "可路由");
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    const locPill = row.location === "hotload"
      ? '<span class="pill info">热加载</span>'
      : '<span class="pill idle">导出目录</span>';
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-cpa-email="${esc(row.email)}" ${selected ? "checked" : ""}></td>
      <td><div class="cell-main">
        <span class="avatar">${esc(initials(row.email))}</span>
        <span class="cell-email" title="${esc(row.email)}">${esc(row.email)}</span>
      </div></td>
      <td><span class="mono">${esc(row.mint_method || "-")}</span></td>
      <td>${locPill}</td>
      <td><div class="scan-cell"><span class="status-pair">${tierPill}${scanPill}</span>${refreshMark}${actionMark}<small>${esc((scan.reason || "") + streak + cool)}</small></div></td>
      <td><span class="mono">${esc(scheduleText)}</span><small class="table-sub">${esc(disabledText)}</small></td>
      <td><span class="mono">${esc(expires)}</span></td>
      <td><span class="mono">${esc(row.mtime_iso || "-")}</span></td>
      <td class="c-actions"><button class="link" data-download-cpa="${esc(row.email)}" type="button">下载</button></td>
    `;
    tbody.append(tr);
  }
  $("#cpa-count").textContent = `共 ${state.cpaTotal} 个文件`;
  $("#cpa-page-label").textContent = `${state.cpaPage} / ${state.cpaPages}`;
  $("#cpa-selected-count").textContent = String(state.selectedCpa.size);
  $("#cpa-batch").classList.toggle("active", state.selectedCpa.size > 0);
  $("#cpa-select-all").checked =
    state.cpa.length > 0 && state.cpa.every((r) => state.selectedCpa.has(r.email));
}

async function loadCpa() {
  const params = new URLSearchParams({
    query: state.cpaQuery,
    status: state.cpaStatus,
    page: String(state.cpaPage),
    page_size: "50",
  });
  const [data] = await Promise.all([
    api(`/api/cpa?${params}`),
    loadCpaPoolStatus().catch(() => null),
    loadCpaPoolResults().catch(() => null),
    loadCpaScanHistory().catch(() => null),
    loadCpaActions().catch(() => null),
    loadCpaQuarantine().catch(() => null),
  ]);
  state.cpa = data.items || [];
  state.cpaTotal = data.total || 0;
  state.cpaPage = data.page || 1;
  state.cpaPages = data.total_pages || 1;
  $("#cpa-dirs").textContent = `auth: ${data.auth_dir || "-"} · hotload: ${data.hotload_dir || "-"}`;
  renderCpa();
}

function renderCpaPoolStatus() {
  const data = state.cpaPool || {};
  const s = data.summary || {};
  const counts = s.counts || {};
  const progress = data.progress || {};
  const settings = data.settings || {};
  const refill = data.refill_status?.checked_at ? data.refill_status : (s.refill || {});
  const pool = data.pool || {};
  const running = Boolean(data.running);
  const resumed = running && Boolean(data.resumed);
  const total = Number(data.cpa_total ?? s.total ?? 0);
  const done = Number(progress.done ?? s.done ?? 0);
  const scanTotal = Number(progress.total ?? s.total ?? 0);
  const pct = scanTotal ? Math.min(100, (done / scanTotal) * 100) : 0;

  $("#cpa-pool-state").className = `pill ${running ? "running" : (s.finished_at || data.finished_at ? "completed" : "idle")}`;
  $("#cpa-pool-state").textContent = running ? (resumed ? "恢复巡检中" : "巡检中") : (s.finished_at || data.finished_at ? "已完成" : "未巡检");
  $("#cpa-pool-stop").disabled = !running;
  $("#cpa-pool-scan").disabled = running;
  $("#cpa-pool-total").textContent = pool.file_inventory ?? total;
  $("#cpa-pool-cli-loaded").textContent = pool.cli_loaded == null ? "-" : pool.cli_loaded;
  $("#cpa-pool-ok").textContent = pool.main_routeable ?? data.ok ?? 0;
  $("#cpa-pool-reserve").textContent = pool.reserve ?? 0;
  $("#cpa-pool-observe").textContent = Number(pool.candidate || 0) + Number(pool.observe || 0);
  $("#cpa-pool-quota").textContent = pool.cooling ?? data.quota ?? 0;
  $("#cpa-pool-quarantine").textContent = pool.quarantine ?? data.quarantine_total ?? 0;
  const upstreamOpen = (pool.upstream_state || data.upstream_state) === "open";
  $("#cpa-pool-upstream").textContent = upstreamOpen ? "熔断" : "正常";
  $("#cpa-pool-upstream-kpi").className = `pool-kpi ${upstreamOpen ? "err" : "ok"}`;
  const breaker = (pool.breakers || []).find((item) => item.state === "open" || item.state === "half_open");
  $("#cpa-pool-breaker").hidden = !breaker;
  if (breaker) {
    $("#cpa-pool-breaker-detail").textContent = `${breaker.scope || "upstream"} · ${breaker.error_count || 0}/${breaker.sample_count || 0} · ${breaker.reason || "-"}`;
  }
  const refillState = refill.waiting_for_baseline
    ? `基线${refill.baseline_percent || 0}%`
    : (refill.waiting_for_rounds
      ? `${refill.low_rounds || 0}/${refill.required_low_rounds || 0}轮`
      : (refill.waiting_for_stability
        ? "观察"
        : (refill.waiting_for_job
          ? "续批等待"
          : (refill.waiting_for_daily_budget
            ? "日常限额"
            : (refill.need ? `${refill.emergency ? "应急" : "待"}${refill.need}` : "ON")))));
  $("#cpa-pool-refill").textContent = refill.enabled
    ? (refill.started ? `+${refill.limit || refill.need || 0}` : refillState)
    : (settings.auto_refill ? "ON" : "OFF");
  $("#cpa-pool-progress").style.width = `${pct}%`;
  const next = data.next_scan_at_display
    ? `${data.next_scan_at_display} (${data.next_scan_in_sec || 0}s)`
    : (data.next_scan_in_sec != null ? `${data.next_scan_in_sec}s` : "-");
  const elapsed = s.elapsed_sec != null ? ` · 耗时 ${s.elapsed_sec}s` : "";
  const actions = s.actions ? Object.entries(s.actions).map(([k, v]) => `${k}:${v}`).join(" ") : "";
  const refillPending = refill.waiting_for_baseline
    ? `基线 ${refill.baseline_checked || 0}/${refill.baseline_total || 0}`
    : (refill.waiting_for_rounds
      ? `低水位 ${refill.low_rounds || 0}/${refill.required_low_rounds || 0}轮`
      : (refill.waiting_for_stability
        ? `稳定观察 ${refill.eligible_in_sec || 0}s`
        : (refill.waiting_for_job
          ? `等待任务 ${refill.active_job || "-"}`
          : (refill.waiting_for_daily_budget
            ? `日常软限额 ${refill.daily_used || 0}/${refill.daily_soft_limit || 0}`
            : (refill.error || `${refill.emergency ? "应急" : "待"}补 ${refill.need || 0}`)))));
  const refillMeta = refill.enabled
    ? (refill.started
      ? ` · 补号 <code>${refill.emergency ? "应急 " : ""}${esc(refill.strategy || "backfill")} gap=${esc(refill.gap || 0)} batch=${esc(refill.limit || 0)}</code>`
      : ` · 补号 <code>${esc(refillPending)}</code>`)
    : "";
  const resumeMeta = Number(data.resume_count || s.resume_count || 0) > 0
    ? ` · 任务恢复 <code>${esc(data.resume_count || s.resume_count)}次</code>`
    : "";
  $("#cpa-pool-meta").innerHTML =
    `进度 <b>${done}/${scanTotal || total}</b>${elapsed} · 下次自动检查 ${esc(next)} · ` +
    `调度 <code>${esc(settings.scheduler_tick_sec || 300)}s</code> · 健康复检 <code>${esc(settings.healthy_check_interval_sec || 43200)}s</code> · ` +
    `proxy <code>${esc(settings.probe_proxy || "-")}</code> · ` +
    `自动巡检 <code>${settings.auto_scan ? "ON" : "OFF"}</code> · ` +
    `治理 <code>${settings.apply_policy ? "ON" : "OFF"}</code> · ` +
    `自动补号 <code>${settings.auto_refill ? "ON" : "OFF"}</code>` +
    (actions ? ` · 动作 <code>${esc(actions)}</code>` : "") +
    resumeMeta +
    refillMeta;

  const logs = data.logs || [];
  const logEl = $("#cpa-pool-log");
  if (!logs.length) {
    logEl.innerHTML = '<div class="log-line dim">// 等待巡检</div>';
  } else {
    logEl.innerHTML = logs.slice(-120).map((line) => {
      const cls = classifyLog(line);
      return `<div class="log-line ${esc(cls)}">${esc(line)}</div>`;
    }).join("");
    logEl.scrollTop = logEl.scrollHeight;
  }

  if (data.settings) {
    if (!$("#cpa-pool-workers").dataset.seeded) {
      $("#cpa-pool-workers").value = data.settings.scan_workers || 16;
      $("#cpa-pool-limit").value = data.settings.max_items_per_scan || 0;
      $("#cpa-pool-refresh-before").checked = data.settings.refresh_before_probe !== false;
      $("#cpa-pool-probe-chat").checked = Boolean(data.settings.probe_chat);
      $("#cpa-pool-apply-policy").checked = Boolean(data.settings.apply_policy);
      $("#cpa-pool-auto-refill").checked = Boolean(data.settings.auto_refill);
      $("#cpa-pool-refill-target").value = data.settings.refill_target_active || 0;
      $("#cpa-pool-refill-inventory").value = data.settings.refill_max_inventory || 4000;
      $("#cpa-pool-refill-max").value = data.settings.refill_max_per_scan || 200;
      $("#cpa-pool-refill-workers").value = data.settings.refill_workers ?? -1;
      $("#cpa-pool-refill-probe-chat").checked = Boolean(data.settings.refill_probe_chat);
      $("#cpa-pool-workers").dataset.seeded = "1";
    }
  }
}

async function loadCpaPoolStatus() {
  const data = await api("/api/cpa/pool/status");
  state.cpaPool = data;
  renderCpaPoolStatus();
  return data;
}

async function loadCpaPoolResults() {
  const data = await api("/api/cpa/pool/results?page_size=10000");
  state.cpaPoolMap = new Map((data.items || []).map((r) => [String(r.email || "").toLowerCase(), r]));
  return data;
}

function compactObj(obj) {
  return Object.entries(obj || {})
    .filter(([, v]) => Number(v || 0) !== 0)
    .map(([k, v]) => `${k}:${v}`)
    .join(" ");
}

function renderCpaScanHistory() {
  const tbody = $("#cpa-scan-history-rows");
  if (!tbody) return;
  tbody.innerHTML = "";
  const items = state.cpaScanHistory || [];
  $("#cpa-scan-history-empty").hidden = items.length > 0;
  $("#cpa-scan-history-count").textContent =
    state.cpaScanHistoryTotal > items.length ? `最近 ${items.length} / 共 ${state.cpaScanHistoryTotal} 条` : `${items.length} 条`;
  for (const row of items) {
    const tr = document.createElement("tr");
    const actions = compactObj(row.actions);
    const counts = compactObj(row.counts);
    const refill = row.refill || {};
    const refillText = refill.enabled
      ? (refill.started ? `${refill.strategy === "register" ? "注册" : "补 CPA"} ${refill.limit || refill.need || 0}` : (refill.need ? `待补 ${refill.need}` : "开启"))
      : "-";
    tr.innerHTML = `
      <td><span class="pill ${cpaScanOutcomePill(row.outcome)}">${esc(scanOutcomeText[row.outcome] || row.outcome || "-")}</span></td>
      <td><span class="mono" title="${esc(row.id || "")}">${esc(row.finished_at || row.started_at || "-")}</span><small class="table-sub">${esc(row.trigger || "manual")}${row.resume_count ? ` · 恢复 ${esc(row.resume_count)}次` : ""}</small></td>
      <td><span class="mono">${esc(row.done ?? 0)}/${esc(row.total ?? 0)}</span><small class="table-sub">耗时 ${esc(row.elapsed_sec ?? "-")}s</small></td>
      <td><div class="mini-counts"><span class="ok">OK ${esc(row.ok || 0)}</span><span class="warn">额度 ${esc(row.quota || 0)}</span><span class="err">异常 ${esc(row.bad || 0)}</span></div></td>
      <td><span class="mono" title="${esc(counts)}">${esc(actions || "-")}</span><small class="table-sub">续期 ${esc(row.refreshed || 0)} · 恢复 ${esc(row.reenabled || 0)}</small></td>
      <td><span class="mono">${esc(refillText)}</span><small class="table-sub">CPA ${esc(row.cpa_total || 0)} · 隔离 ${esc(row.quarantine_total || 0)}</small></td>
      <td><span class="mono">${esc(row.proxy || "direct")}</span><small class="table-sub">并发 ${esc(row.scan_workers || "-")} · chat ${row.probe_chat ? "ON" : "OFF"}</small></td>
    `;
    tbody.append(tr);
  }
}

async function loadCpaScanHistory() {
  const params = new URLSearchParams({
    query: state.cpaScanHistoryQuery,
    outcome: state.cpaScanHistoryOutcome,
    page_size: "20",
  });
  const data = await api(`/api/cpa/pool/history?${params}`);
  state.cpaScanHistory = data.items || [];
  state.cpaScanHistoryTotal = data.total || 0;
  renderCpaScanHistory();
  return data;
}

function renderCpaActions() {
  const tbody = $("#cpa-action-rows");
  if (!tbody) return;
  tbody.innerHTML = "";
  const items = state.cpaActions || [];
  $("#cpa-actions-empty").hidden = items.length > 0;
  $("#cpa-action-count").textContent = `共 ${state.cpaActionTotal} 条`;
  $("#cpa-action-page-label").textContent = `${state.cpaActionPage} / ${state.cpaActionPages}`;
  $("#cpa-action-page-size").value = String(state.cpaActionPageSize);
  $("#cpa-action-prev").disabled = state.cpaActionPage <= 1;
  $("#cpa-action-next").disabled = state.cpaActionPage >= state.cpaActionPages;
  for (const row of items) {
    const tr = document.createElement("tr");
    const actionClass = ["disabled", "quarantined", "manual_disable", "manual_delete"].includes(row.action) ? "warn" : "ok";
    tr.innerHTML = `
      <td><span class="mono">${esc(row.action_at || "-")}</span></td>
      <td><span class="cell-email" title="${esc(row.email || "")}">${esc(row.email || "-")}</span></td>
      <td><span class="pill ${actionClass}">${esc(row.action || "-")}</span></td>
      <td><span class="mono">${esc(row.old_state || "-")} → ${esc(row.new_state || "-")}</span></td>
      <td><span class="table-clip" title="${esc(row.reason || "")}">${esc(row.reason || "-")}</span></td>
      <td><span class="mono">${esc(row.result || "-")}</span></td>
    `;
    tbody.append(tr);
  }
}

async function loadCpaActions() {
  const params = new URLSearchParams({
    page: String(state.cpaActionPage),
    page_size: String(state.cpaActionPageSize),
  });
  const data = await api(`/api/cpa/pool/actions?${params}`);
  state.cpaActions = data.items || [];
  state.cpaActionTotal = data.total || 0;
  state.cpaActionPage = data.page || 1;
  state.cpaActionPages = data.total_pages || 1;
  renderCpaActions();
  return data;
}

function renderCpaQuarantine(data = {}) {
  const tbody = $("#cpa-quarantine-rows");
  tbody.innerHTML = "";
  const items = state.cpaQuarantine || [];
  $("#cpa-quarantine-empty").hidden = items.length > 0;
  $("#cpa-quarantine-dir").textContent = data.dir ? `目录: ${data.dir}` : "-";
  for (const row of items) {
    const selected = state.selectedQuarantine.has(row.email);
    const meta = row.meta || {};
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-q-email="${esc(row.email)}" ${selected ? "checked" : ""}></td>
      <td><div class="cell-main">
        <span class="avatar">${esc(initials(row.email))}</span>
        <span class="cell-email" title="${esc(row.email)}">${esc(row.email || "-")}</span>
      </div></td>
      <td><span class="pill ${cpaPoolPill(row.bucket)}">${esc(statusText[row.bucket] || row.bucket || "-")}</span></td>
      <td><span class="mono" title="${esc((meta.source || "") + " " + (meta.reason || ""))}">${esc(meta.reason || meta.source || "-")}</span></td>
      <td><span class="mono">${esc(row.mtime_iso || "-")}</span></td>
    `;
    tbody.append(tr);
  }
  $("#cpa-quarantine-selected-count").textContent = String(state.selectedQuarantine.size);
  $("#cpa-quarantine-select-all").checked =
    items.length > 0 && items.every((r) => state.selectedQuarantine.has(r.email));
}

async function loadCpaQuarantine() {
  const params = new URLSearchParams({
    query: state.cpaQuarantineQuery,
    bucket: state.cpaQuarantineBucket,
    page: "1",
    page_size: "200",
  });
  const data = await api(`/api/cpa/pool/quarantine?${params}`);
  state.cpaQuarantine = data.items || [];
  renderCpaQuarantine(data);
  return data;
}

/* ── mail ── */

function renderMail() {
  const tbody = $("#mail-rows");
  tbody.innerHTML = "";
  $("#mail-empty").hidden = state.mail.length > 0;
  for (const row of state.mail) {
    const selected = state.selectedMail.has(row.email);
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-mail-email="${esc(row.email)}" ${selected ? "checked" : ""}></td>
      <td><div class="cell-main">
        <span class="avatar">${esc(initials(row.email))}</span>
        <span class="cell-email" title="${esc(row.email)}">${esc(row.email)}</span>
      </div></td>
      <td><span class="mono">${esc(row.client_id || "-")}</span></td>
      <td><span class="mono">${esc(row.token_preview || "-")}</span></td>
      <td><span class="pill ${mailStatusPill[row.status] || "idle"}">${esc(statusText[row.status] || row.status)}</span></td>
      <td><span class="mono">${row.consumed}/${row.max_aliases}（剩 ${row.remaining}）</span></td>
    `;
    tbody.append(tr);
  }
  $("#mail-count").textContent = `共 ${state.mailTotal} 条`;
  $("#mail-page-label").textContent = `${state.mailPage} / ${state.mailPages}`;
  $("#mail-selected-count").textContent = String(state.selectedMail.size);
  $("#mail-batch").classList.toggle("active", state.selectedMail.size > 0);
  $("#mail-select-all").checked =
    state.mail.length > 0 && state.mail.every((r) => state.selectedMail.has(r.email));
}

async function loadMail() {
  const params = new URLSearchParams({
    query: state.mailQuery,
    status: state.mailStatus,
    page: String(state.mailPage),
    page_size: "50",
  });
  const data = await api(`/api/mail-credentials?${params}`);
  state.mail = data.items || [];
  state.mailTotal = data.total || 0;
  state.mailPage = data.page || 1;
  state.mailPages = data.total_pages || 1;
  $("#mail-path").textContent = `路径: ${data.path || "-"}`;
  renderMail();
}

/* 跨页按状态全选（邮箱 / 账号通用） */
async function selectAllByStatus(kind, status) {
  if (!status) return;
  try {
    const base = kind === "mail" ? "/api/mail-credentials/ids" : "/api/accounts/ids";
    const data = await api(`${base}?status=${encodeURIComponent(status)}`);
    const set = kind === "mail" ? state.selectedMail : state.selectedAccounts;
    data.emails.forEach((e) => set.add(e));
    if (kind === "mail") renderMail();
    else renderAccounts();
    toast(`已选中 ${data.emails.length} 项（共 ${data.total} 项符合）`);
  } catch (err) {
    toast(err.message, true);
  }
}

/* 页码快速跳转 */
function bindPageJump(sel, go) {
  const el = $(sel);
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const n = Number(el.value);
    if (n >= 1) go(n);
    el.value = "";
    el.blur();
  });
}

/* ── proxies ── */

function proxyStatusPill(row) {
  if (!row.checked) return '<span class="pill idle">未检测</span>';
  if (row.ok) return '<span class="pill ok">正常</span>';
  return `<span class="pill err" title="${esc(row.error || "")}">失败</span>`;
}

function filteredProxies() {
  const q = state.proxyQuery.toLowerCase();
  if (!q) return state.proxies;
  return state.proxies.filter((p) =>
    [p.masked, p.user, p.exit_ip, p.label].some((v) => String(v || "").toLowerCase().includes(q)),
  );
}

function currentProxyRows() {
  const filtered = filteredProxies();
  const start = (state.proxyPage - 1) * state.proxyPageSize;
  return filtered.slice(start, start + state.proxyPageSize);
}

function renderProxies() {
  const tbody = $("#proxy-rows");
  tbody.innerHTML = "";
  const filtered = filteredProxies();
  const totalPages = Math.max(1, Math.ceil(filtered.length / state.proxyPageSize));
  if (state.proxyPage > totalPages) state.proxyPage = totalPages;
  const start = (state.proxyPage - 1) * state.proxyPageSize;
  const rows = filtered.slice(start, start + state.proxyPageSize);
  $("#proxy-empty").hidden = state.proxies.length > 0;
  for (const row of rows) {
    const selected = state.selectedProxies.has(row.key);
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-proxy-key="${esc(row.key)}" ${selected ? "checked" : ""}></td>
      <td><span class="cell-email mono" title="${esc(row.raw)}">${esc(row.masked)}</span></td>
      <td><span class="mono">${esc(row.user || "-")}</span></td>
      <td>${proxyStatusPill(row)}</td>
      <td><span class="mono">${esc(row.scheme || "-")}</span></td>
      <td><span class="mono">${row.checked && row.latency_ms != null ? row.latency_ms + "ms" : "-"}</span></td>
      <td><span class="mono">${esc(row.exit_ip || "-")}</span></td>
      <td><span class="mono">${esc(row.checked_at || "-")}</span></td>
      <td class="c-actions"><button class="link" data-check-proxy="${esc(row.key)}" type="button">检测</button></td>
    `;
    tbody.append(tr);
  }
  $("#proxy-count").textContent = `共 ${state.proxies.length} 个代理`;
  $("#proxy-page-label").textContent = `${state.proxyPage} / ${totalPages}`;
  const checked = state.proxies.filter((p) => p.checked);
  const healthy = checked.filter((p) => p.ok).length;
  $("#proxy-health").textContent = checked.length ? `已检测 ${checked.length} · 可用 ${healthy}` : "";
  $("#proxy-selected-count").textContent = String(state.selectedProxies.size);
  $("#proxy-batch").classList.toggle("active", state.selectedProxies.size > 0);
  $("#proxy-select-all").checked =
    rows.length > 0 && rows.every((r) => state.selectedProxies.has(r.key));
}
async function loadProxies() {
  const data = await api("/api/proxies");
  state.proxies = data.items || [];
  $("#proxy-path").textContent = `路径: ${data.path || "-"}`;
  renderProxies();
  renderProxyFixedOptions();
}

function renderProxyFixedOptions() {
  for (const sel of ["#reg-proxy-fixed", "#gpt-proxy-fixed"].map((s) => $(s)).filter(Boolean)) {
    const prev = sel.value;
    sel.innerHTML = state.proxies.length
      ? state.proxies.map((p) => `<option value="${esc(p.raw)}">${esc(p.masked)}</option>`).join("")
      : `<option value="">（代理池为空，请先导入）</option>`;
    if (prev && state.proxies.some((p) => p.raw === prev)) sel.value = prev;
  }
  renderGptOverview(state.overview || {});
}

async function checkProxies(keys = []) {
  if (state.proxyChecking) return;
  state.proxyChecking = true;
  const btn = $("#check-all-proxies");
  const oldText = btn.innerHTML;
  btn.innerHTML = "后台检测中…";
  btn.disabled = true;
  try {
    const data = await api("/api/proxies/check", {
      method: "POST",
      body: JSON.stringify({ keys }),
    });
    if (data.running && !data.started) {
      toast("已有代理检测任务在运行");
    } else {
      const total = (data.job && data.job.total) || keys.length || state.proxies.length;
      toast(`代理检测已后台启动：${total} 个`);
    }
    pollProxyCheck(oldText).catch((err) => {
      state.proxyChecking = false;
      btn.innerHTML = oldText;
      btn.disabled = false;
      toast(err.message, true);
    });
  } catch (err) {
    state.proxyChecking = false;
    btn.innerHTML = oldText;
    btn.disabled = false;
    toast(err.message, true);
  }
}

async function pollProxyCheck(oldText = "检测全部") {
  if (state.proxyCheckTimer) {
    clearTimeout(state.proxyCheckTimer);
    state.proxyCheckTimer = null;
  }
  const btn = $("#check-all-proxies");
  const tick = async () => {
    const status = await api("/api/proxies/check/status");
    if (status.status === "running") {
      btn.innerHTML = `检测中… ${status.ok || 0}/${status.total || 0}`;
      btn.disabled = true;
      // 检测状态文件是边跑边写的，轻量刷新即可看到部分结果。
      if (state.view === "proxies") loadProxies().catch(() => {});
      state.proxyCheckTimer = setTimeout(tick, 2500);
      return;
    }
    state.proxyChecking = false;
    btn.innerHTML = oldText;
    btn.disabled = false;
    if (state.view === "proxies") await loadProxies();
    if (status.status === "completed") {
      toast(`检测完成：可用 ${status.ok}/${status.total}`, status.total > 0 && status.ok === 0);
    } else if (status.status === "failed") {
      toast(`代理检测失败: ${status.error || "unknown"}`, true);
    }
  };
  await tick();
}

/* ── settings ── */

function fieldInput(key, label, type, value, isSet) {
  if (type === "bool") {
    return `<label class="switch-row"><span>${esc(label)}</span><span class="switch"><input data-config-key="${esc(key)}" type="checkbox" ${value ? "checked" : ""}><i></i></span></label>`;
  }
  if (type === "select") {
    const current = String(value ?? "");
    const options = PROVIDER_OPTIONS.map(([v, text]) =>
      `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(text)}</option>`,
    ).join("");
    const fallback = current && !PROVIDER_OPTIONS.some(([v]) => v === current)
      ? `<option value="${esc(current)}" selected>${esc(current)}（当前值）</option>`
      : "";
    return `<label><span>${esc(label)}</span><select class="select wide" data-config-key="${esc(key)}">${fallback}${options}</select></label>`;
  }
  if (type === "turnstile_solver") {
    const current = String(value ?? "local");
    const options = TURNSTILE_SOLVER_OPTIONS.map(([v, text]) =>
      `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(text)}</option>`,
    ).join("");
    const fallback = current && !TURNSTILE_SOLVER_OPTIONS.some(([v]) => v === current)
      ? `<option value="${esc(current)}" selected>${esc(current)}（当前值）</option>`
      : "";
    return `<label><span>${esc(label)}</span><select class="select wide" data-config-key="${esc(key)}">${fallback}${options}</select></label>`;
  }
  if (type === "policy_action") {
    const current = String(value ?? "keep").toLowerCase();
    const options = POLICY_ACTION_OPTIONS.map(([v, text]) =>
      `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(text)}</option>`,
    ).join("");
    const fallback = current && !POLICY_ACTION_OPTIONS.some(([v]) => v === current)
      ? `<option value="${esc(current)}" selected>${esc(current)}（当前值）</option>`
      : "";
    return `<label><span>${esc(label)}</span><select class="select wide policy-action-select" data-config-key="${esc(key)}">${fallback}${options}</select></label>`;
  }
  if (type === "proxy") {
    const current = String(value ?? "");
    const poolOptions = state.proxies.map((p) =>
      `<option value="${esc(p.raw)}" ${p.raw === current ? "selected" : ""}>${esc(p.masked)}</option>`,
    ).join("");
    const isCustom = current && current !== "pool:random" && !state.proxies.some((p) => p.raw === current);
    return `<label><span>${esc(label)}</span>
      <select class="select wide" data-config-key="${esc(key)}" data-proxy-field="1">
        <option value="" ${current === "" ? "selected" : ""}>直连（不使用代理）</option>
        <option value="pool:random" ${current === "pool:random" ? "selected" : ""}>随机轮换（每次使用从代理池随机取）</option>
        ${poolOptions}
        <option value="__custom__" ${isCustom ? "selected" : ""}>自定义…</option>
      </select>
      <input data-proxy-custom="${esc(key)}" type="text" value="${isCustom ? esc(current) : ""}"
        placeholder="host:port[:user:pass] 或 http://user:pass@host:port"
        style="margin-top:7px" ${isCustom ? "" : "hidden"}>
    </label>`;
  }
  const ph = type === "password" && isSet ? "已设置，留空保留" : "";
  const inputType = type === "password" ? "password" : type === "number" ? "number" : "text";
  return `<label><span>${esc(label)}</span><input data-config-key="${esc(key)}" type="${inputType}" value="${esc(value ?? "")}" placeholder="${ph}"></label>`;
}

/* ── 页面级配置（拆分自配置中心，就近维护） ── */

const FIELD_MAP = {};
[...(CONFIG_FIELDS.basic || []), ...(CONFIG_FIELDS.cpa || [])].forEach(([k, l, t]) => {
  FIELD_MAP[k] = [k, l, t];
});
// 配置中心未暴露但注册流程常用的键
const EXTRA_FIELDS = [
  ["thread_start_interval", "线程启动间隔秒", "number"],
  ["register_max_attempts", "单账号最大尝试", "number"],
  ["account_hard_timeout", "单账号硬超时秒", "number"],
  ["mail_timeout", "收码超时秒", "number"],
  ["mail_poll_interval", "收码轮询间隔秒", "number"],
  ["mail_retry_count", "收码换邮箱重试次数", "number"],
  ["user_agent", "浏览器 User-Agent", "text"],
  ["hotmail_alias_mode", "Hotmail 别名模式", "text"],
  ["hotmail_alias_random_length", "别名随机后缀长度", "number"],
  ["hotmail_poll_interval", "Hotmail 轮询间隔秒", "number"],
  ["hotmail_recent_seconds", "Hotmail 邮件时间窗秒", "number"],
  ["cloudflare_api_key", "Cloudflare API Key", "password"],
  ["cloudflare_auth_mode", "Cloudflare 认证方式", "text"],
  ["cloudflare_domain_select", "域名池抽取 random/round_robin", "text"],
  ["cloudflare_domain_cooldown_sec", "域名冷却秒（被拒后）", "number"],
  ["yyds_api_key", "YYDS API Key", "password"],
  ["yyds_jwt", "YYDS JWT", "password"],
  ["enable_nsfw", "注册开启 NSFW", "bool"],
  ["grok2api_auto_add_local", "推本地 grok2api", "bool"],
  ["grok2api_local_token_file", "本地 grok2api token 文件", "text"],
  ["cpa_force_standalone", "Mint 强制独立浏览器", "bool"],
  ["cpa_protocol_poll_timeout_sec", "协议轮询超时秒", "number"],
  ["cpa_mint_cookie_inject", "Mint 注入注册 cookie", "bool"],
  ["cpa_gui_close_mint_browser", "Mint 后关闭浏览器", "bool"],
  ["cpa_mint_browser_reuse", "Mint 浏览器复用", "bool"],
  ["cpa_mint_browser_recycle_every", "Mint 浏览器回收周期", "number"],
];
EXTRA_FIELDS.forEach(([k, l, t]) => { if (!FIELD_MAP[k]) FIELD_MAP[k] = [k, l, t]; });

const GPT_EXTRA_FIELDS = [
  ["gpt_agent_enabled", "注册后生成 Codex agent 身份", "bool"],
  ["sub2api_enabled", "注册后推送 sub2api", "bool"],
  ["sub2api_base", "sub2api 地址", "text"],
  ["sub2api_api_key", "sub2api 管理密钥 (x-api-key)", "password"],
  ["sub2api_group_id", "sub2api 分组（id 或名称）", "text"],
  ["sub2api_format", "推送格式 agent/oauth", "text"],
  ["sub2api_concurrency", "sub2api 账号并发", "number"],
  ["sub2api_priority", "sub2api 账号优先级", "number"],
];
GPT_EXTRA_FIELDS.forEach(([k, l, t]) => { if (!FIELD_MAP[k]) FIELD_MAP[k] = [k, l, t]; });

const PAGE_SETTINGS = {
  console: {
    title: "注册流程配置",
    eyebrow: "CONSOLE CONFIG",
    groups: [
      ["注册行为", ["register_headless", "register_threads", "thread_start_interval", "register_max_attempts", "account_hard_timeout", "mail_timeout", "mail_poll_interval", "mail_retry_count", "enable_nsfw", "user_agent"]],
      ["纯协议注册 / Turnstile Solver", ["protocol_register", "protocol_only", "protocol_register_fallback_browser", "turnstile_solver_provider", "protocol_solver_url", "protocol_solver_pass_proxy", "protocol_solver_locale", "protocol_solver_accept_language", "protocol_solver_timezone", "protocol_impersonate", "protocol_register_max_attempts", "protocol_solver_poll_timeout", "protocol_solver_poll_interval", "turnstile_site_key", "yescaptcha_key", "twocaptcha_enabled", "twocaptcha_key", "twocaptcha_pass_proxy", "twocaptcha_timeout", "twocaptcha_poll_interval", "twocaptcha_api_base", "protocol_email_tempmail_fallback"]],
      ["grok2api 推送", ["grok2api_auto_add_local", "grok2api_local_token_file", "grok2api_auto_add_remote", "grok2api_remote_base", "grok2api_remote_app_key", "grok2api_pool_name"]],
    ],
  },
  gpt: {
    title: "GPT 注册工作台配置",
    eyebrow: "GPT CONFIG",
    groups: [
      ["邮箱与收码", ["email_provider", "hotmail_accounts_file", "hotmail_protocol", "mail_timeout", "mail_poll_interval", "mail_retry_count"]],
      ["浏览器与代理", ["register_headless", "register_threads", "thread_start_interval", "proxy", "browser_timezone", "user_agent"]],
      ["Solver 预留", ["turnstile_solver_provider", "protocol_solver_url", "protocol_solver_pass_proxy", "protocol_solver_locale", "protocol_solver_accept_language", "protocol_solver_timezone"]],
      ["Agent 身份", ["gpt_agent_enabled"]],
      ["sub2api 推送", ["sub2api_enabled", "sub2api_base", "sub2api_api_key", "sub2api_group_id", "sub2api_format", "sub2api_concurrency", "sub2api_priority"]],
    ],
  },
  mail: {
    title: "邮箱与收码配置",
    eyebrow: "MAIL CONFIG",
    groups: [
      ["服务商", ["email_provider", "defaultDomains", "cloudflare_domain_select", "cloudflare_domain_cooldown_sec"]],
      ["Hotmail / Outlook", ["hotmail_accounts_file", "hotmail_protocol", "hotmail_max_aliases_per_account", "hotmail_alias_mode", "hotmail_alias_random_length", "hotmail_poll_interval", "hotmail_recent_seconds"]],
      ["CloudMail", ["cloudmail_url", "cloudmail_admin_email", "cloudmail_password"]],
      ["其他服务商", ["cloudflare_api_base", "cloudflare_api_key", "cloudflare_admin_password", "cloudflare_auth_mode", "duckmail_api_key", "mailnest_api_key", "mailnest_project_code", "yyds_api_key", "yyds_jwt"]],
    ],
  },
  proxies: {
    title: "代理配置",
    eyebrow: "PROXY CONFIG",
    groups: [
      ["全局代理", ["proxy", "cpa_proxy"]],
      ["透传与其他", ["cpa_pool_probe_proxy", "protocol_solver_pass_proxy", "twocaptcha_pass_proxy", "browser_timezone"]],
    ],
  },
  cpa: {
    title: "CPA / Mint 配置",
    eyebrow: "CPA CONFIG",
    groups: [
      ["CPA 导出", ["cpa_export_enabled", "cpa_prefer_protocol", "cpa_protocol_flow", "cpa_protocol_only", "cpa_allow_device_flow_fallback", "cpa_auth_dir", "cpa_copy_to_hotload", "cpa_hotload_dir", "cpa_base_url"]],
      ["Mint 执行", ["cpa_headless", "cpa_force_standalone", "cpa_mint_workers", "cpa_mint_queue_max", "cpa_mint_timeout_sec", "cpa_mint_cookie_inject", "cpa_gui_close_mint_browser", "cpa_mint_browser_reuse", "cpa_mint_browser_recycle_every", "cpa_probe_after_write", "cpa_probe_chat", "cpa_protocol_poll_timeout_sec"]],
      ["自适应巡检", ["cpa_pool_auto_scan", "cpa_pool_scheduler_tick_sec", "cpa_pool_adaptive_batch_size", "cpa_pool_scan_workers", "cpa_pool_probe_timeout_sec", "cpa_pool_refresh_before_probe", "cpa_pool_refresh_skew_sec", "cpa_pool_probe_proxy", "cpa_pool_healthy_check_interval_sec", "cpa_pool_observe_check_interval_sec", "cpa_pool_candidate_check_interval_sec", "cpa_pool_independent_failure_interval_sec", "cpa_pool_recovery_success_threshold", "cpa_pool_chat_sample_percent", "cpa_pool_models_probe_rate_per_sec", "cpa_pool_chat_probe_rate_per_sec", "cpa_pool_history_limit", "cpa_pool_scan_history_limit", "cpa_pool_observation_retention_days", "cpa_pool_governance_action_retention_days"]],
      ["上游熔断", ["cpa_pool_breaker_window_sec", "cpa_pool_breaker_min_samples", "cpa_pool_breaker_min_errors", "cpa_pool_breaker_error_ratio", "cpa_pool_breaker_open_sec"]],
      ["分层治理", ["cpa_pool_apply_policy", "cpa_pool_governance_max_downgrades_per_scan", "cpa_pool_governance_max_downgrade_percent", "cpa_pool_main_low_water_percent", "cpa_pool_reserve_target_percent", "cpa_pool_soft_fail_threshold", "cpa_pool_quota_cooldown_sec", "cpa_pool_quarantine_dir", "cpa_pool_move_with_backup"]],
      ["容量与补号", ["cpa_pool_auto_refill", "cpa_pool_refill_target_active", "cpa_pool_refill_max_inventory", "cpa_pool_refill_emergency_threshold_percent", "cpa_pool_refill_controller_interval_sec", "cpa_pool_refill_low_water_hold_sec", "cpa_pool_refill_low_water_rounds", "cpa_pool_refill_min_baseline_percent", "cpa_pool_refill_cooling_grace_sec", "cpa_pool_refill_expected_yield_percent", "cpa_pool_refill_daily_limit", "cpa_pool_refill_max_per_scan", "cpa_pool_refill_workers", "cpa_pool_refill_probe_chat"]],
      ["CLIProxy 联动", ["cpa_pool_cli_management_enabled", "cpa_pool_cli_management_url", "cpa_pool_cli_management_key", "cpa_pool_cli_management_timeout_sec", "cpa_pool_cli_management_cache_sec", "cpa_pool_file_fallback_enabled", "cpa_pool_file_fallback_grace_sec"]],
    ],
  },
};

let pageSettingsKey = null;

function renderCfgGroup(title, keys, cfg, anchorId = "") {
  const fields = keys
    .filter((k) => FIELD_MAP[k])
    .map((k) => {
      const [key, label, type] = FIELD_MAP[k];
      return fieldInput(key, label, type, cfg[key], cfg[`${key}__set`]);
    })
    .join("");
  if (!fields) return "";
  return `<div class="cfg-group" ${anchorId ? `id="${anchorId}"` : ""}><h3>${esc(title)}</h3><div class="cfg-group-grid">${fields}</div></div>`;
}

function renderPageSettings() {
  const def = pageSettingsKey && PAGE_SETTINGS[pageSettingsKey];
  if (!def) return;
  const cfg = state.config || {};
  $("#page-settings-title").textContent = def.title;
  $("#page-settings-eyebrow").textContent = def.eyebrow;
  $("#page-settings-body").innerHTML = def.groups
    .map(([groupTitle, keys]) => renderCfgGroup(groupTitle, keys, cfg))
    .join("");
}

async function openPageSettings(key) {
  pageSettingsKey = key;
  try {
    if (!state.config) await loadConfig();
    else if (!state.proxies.length) await loadProxies().catch(() => {});
  } catch (err) {
    toast(err.message, true);
  }
  renderPageSettings();
  $("#page-settings-drawer").classList.add("open");
  $("#page-settings-drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").hidden = false;
}

function closePageSettings() {
  pageSettingsKey = null;
  $("#page-settings-drawer").classList.remove("open");
  $("#page-settings-drawer").setAttribute("aria-hidden", "true");
  $("#page-settings-body").innerHTML = "";
  const jobsOpen = Boolean($("#job-drawer")?.classList.contains("open"));
  $("#drawer-backdrop").hidden = !jobsOpen;
}

function collectConfigScoped(root) {
  const payload = {};
  root.querySelectorAll("[data-config-key]").forEach((input) => {
    const key = input.dataset.configKey;
    if (input.dataset.proxyField) {
      if (input.value === "__custom__") {
        const custom = root.querySelector(`[data-proxy-custom="${key}"]`);
        payload[key] = (custom ? custom.value : "").trim();
      } else {
        payload[key] = input.value;
      }
    } else if (input.type === "checkbox") {
      payload[key] = input.checked;
    } else if (input.type === "number") {
      payload[key] = input.value === "" ? null : Number(input.value);
    } else {
      payload[key] = input.value;
    }
  });
  return payload;
}

function renderConfigForm() {
  const cfg = state.config || {};
  const allEl = $("#settings-all");
  const anchorsEl = $("#cfg-anchors");
  if (allEl) {
    const seen = new Set();
    const sections = [];
    const anchors = [];
    for (const [pageKey, def] of Object.entries(PAGE_SETTINGS)) {
      def.groups.forEach(([groupTitle, keys], idx) => {
        const fields = keys
          .filter((k) => FIELD_MAP[k] && !seen.has(k))
          .map((k) => {
            seen.add(k);
            const [key, label, type] = FIELD_MAP[k];
            return fieldInput(key, label, type, cfg[key], cfg[`${key}__set`]);
          })
          .join("");
        if (!fields) return;
        const id = `cfg-${pageKey}-${idx}`;
        anchors.push(`<a href="#${esc(id)}">${esc(def.title.replace("配置", ""))} · ${esc(groupTitle)}</a>`);
        sections.push(`<section class="cfg-section" id="${esc(id)}"><h3>${esc(def.title)} / ${esc(groupTitle)}</h3><div class="settings-grid">${fields}</div></section>`);
      });
    }
    allEl.innerHTML = sections.join("");
    if (anchorsEl) anchorsEl.innerHTML = anchors.join("");
  }
  const raw = { ...(cfg._all || {}) };
  for (const key of Object.keys(raw)) {
    if (key.endsWith("__set")) delete raw[key];
  }
  $("#config-raw").value = JSON.stringify(raw, null, 2);
}

async function loadConfig() {
  if (!state.proxies.length) {
    try {
      await loadProxies();
    } catch (err) {
      // 代理池为空也能正常渲染（仅有 直连/随机/自定义）
    }
  }
  state.config = await api("/api/config");
  renderConfigForm();
}

function collectConfigFromForm() {
  const payload = {};
  $$("[data-config-key]").forEach((input) => {
    const key = input.dataset.configKey;
    if (input.dataset.proxyField) {
      // 代理选择器：__custom__ 时取自定义输入框的值
      if (input.value === "__custom__") {
        const custom = document.querySelector(`[data-proxy-custom="${key}"]`);
        payload[key] = (custom ? custom.value : "").trim();
      } else {
        payload[key] = input.value;
      }
    } else if (input.type === "checkbox") {
      payload[key] = input.checked;
    } else if (input.type === "number") {
      payload[key] = input.value === "" ? null : Number(input.value);
    } else {
      payload[key] = input.value;
    }
  });
  try {
    const raw = JSON.parse($("#config-raw").value || "{}");
    payload._raw = { ...raw, ...payload };
  } catch (err) {
    throw new Error(`原始 JSON 无效: ${err.message}`);
  }
  return payload;
}

function syncRegisterProtocolToggles() {
  const protocol = $("#reg-protocol");
  const noFallback = $("#reg-protocol-only");
  if (!protocol || !noFallback) return;
  if (!protocol.checked) {
    noFallback.checked = false;
  }
  noFallback.disabled = !protocol.checked;
  noFallback.closest(".toggle")?.classList.toggle("disabled", !protocol.checked);
}

/* ── tools ── */

const convertState = {
  file: null,
  lastUrl: null,
  lastName: "",
  detected: null,
  inspectSeq: 0,
  inspecting: false,
};

function setConvertTargetAvailability(available = null) {
  const allowed = available ? new Set(available) : null;
  const select = $("#convert-to");
  for (const option of select.options) {
    option.disabled = Boolean(allowed && option.value !== "auto" && !allowed.has(option.value));
  }
  if (select.selectedOptions[0]?.disabled) select.value = "auto";
}

function renderConvertInspect(payload, error = "") {
  const panel = $("#convert-inspect");
  panel.hidden = false;
  panel.classList.toggle("error", Boolean(error));
  if (error) {
    $("#convert-detected-format").textContent = "无法识别";
    $("#convert-detected-direction").textContent = error;
    $("#convert-detected-count").textContent = "检查失败";
    $("#convert-detected-providers").innerHTML = "";
    $("#convert-detected-warnings").hidden = true;
    return;
  }
  if (!payload) {
    $("#convert-detected-format").textContent = "识别中";
    $("#convert-detected-direction").textContent = "正在检查文件结构";
    $("#convert-detected-count").textContent = "-";
    $("#convert-detected-providers").innerHTML = "";
    $("#convert-detected-warnings").hidden = true;
    return;
  }
  $("#convert-detected-format").textContent = payload.input_format || "已识别";
  $("#convert-detected-direction").textContent = payload.direction || "";
  $("#convert-detected-count").textContent = `${payload.account_count || 0} 个账号`;
  $("#convert-detected-providers").innerHTML = Object.entries(payload.providers || {})
    .map(([provider, count]) => `<span><b>${esc(provider)}</b>${esc(count)}</span>`)
    .join("");
  const warningBox = $("#convert-detected-warnings");
  const warnings = payload.warnings || [];
  warningBox.hidden = !warnings.length;
  warningBox.innerHTML = warnings.length
    ? warnings.slice(0, 4).map((warning) => `<span>${esc(warning)}</span>`).join("")
    : "";
}

async function inspectConvertFile(file) {
  const seq = ++convertState.inspectSeq;
  convertState.detected = null;
  convertState.inspecting = true;
  $("#convert-run").disabled = true;
  setConvertTargetAvailability(null);
  renderConvertInspect(null);
  const form = new FormData();
  form.append("file", file);
  try {
    const resp = await fetch("/api/tools/convert/inspect", { method: "POST", body: form });
    const payload = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(payload.error || `HTTP ${resp.status}`);
    if (seq !== convertState.inspectSeq) return;
    convertState.detected = payload;
    renderConvertInspect(payload);
    setConvertTargetAvailability(payload.available_targets || null);
  } catch (err) {
    if (seq !== convertState.inspectSeq) return;
    renderConvertInspect(null, err.message);
  } finally {
    if (seq === convertState.inspectSeq) {
      convertState.inspecting = false;
      $("#convert-run").disabled = !convertState.detected;
    }
  }
}

function convertSetFile(file) {
  convertState.file = file || null;
  convertState.detected = null;
  convertState.inspectSeq += 1;
  $("#convert-file-label").textContent = file
    ? `${file.name}（${(file.size / 1024).toFixed(1)} KB）`
    : "拖拽文件到这里，或点击选择";
  $("#convert-result").hidden = true;
  $("#convert-status").textContent = "";
  if (file) {
    inspectConvertFile(file);
  } else {
    $("#convert-inspect").hidden = true;
    $("#convert-run").disabled = false;
    setConvertTargetAvailability(null);
  }
}

function convertDownload(blob, filename) {
  if (convertState.lastUrl) URL.revokeObjectURL(convertState.lastUrl);
  const url = URL.createObjectURL(blob);
  convertState.lastUrl = url;
  convertState.lastName = filename;
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
}

function decodeConversionMeta(value) {
  if (!value) return null;
  try {
    const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
    const bytes = Uint8Array.from(atob(padded.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (_) {
    return null;
  }
}

async function runConvert() {
  if (!convertState.file) {
    toast("请先选择要转换的文件", true);
    return;
  }
  if (convertState.inspecting) {
    toast("文件仍在识别中", true);
    return;
  }
  if (!convertState.detected) {
    toast("文件格式未通过识别", true);
    return;
  }
  const btn = $("#convert-run");
  const status = $("#convert-status");
  btn.disabled = true;
  status.textContent = "转换中…";
  try {
    const form = new FormData();
    form.append("file", convertState.file);
    form.append("to", $("#convert-to").value);
    form.append("note", $("#convert-note").value.trim());
    const resp = await fetch("/api/tools/convert", { method: "POST", body: form });
    if (!resp.ok) {
      const payload = await resp.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${resp.status}`);
    }
    const disposition = resp.headers.get("content-disposition") || "";
    const match = disposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
    const filename = match
      ? decodeURIComponent(match[1].replace(/"/g, ""))
      : `converted-${Date.now()}`;
    const blob = await resp.blob();
    const meta = decodeConversionMeta(resp.headers.get("x-conversion-meta"));
    convertDownload(blob, filename);
    $("#convert-result").hidden = false;
    $("#convert-result-name").textContent = filename;
    const providerText = Object.entries(meta?.providers || {})
      .map(([provider, count]) => `${provider} ${count}`)
      .join(" · ");
    $("#convert-result-meta").textContent = [
      `${(blob.size / 1024).toFixed(1)} KB`,
      meta?.count ? `${meta.count} 个账号` : "",
      providerText,
      "已自动开始下载",
    ].filter(Boolean).join(" · ");
    status.textContent = "";
    toast("转换完成，已开始下载");
  } catch (err) {
    status.textContent = "";
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

const mailToolProtocolText = {
  imap: "IMAP",
  graph: "Graph",
  unknown: "未识别",
  unchecked: "未检测",
};

const mailToolHealthText = {
  ok: "可用",
  invalid: "凭证失效",
  error: "连接失败",
  unchecked: "未检测",
};

function mailToolHealthPill(health) {
  if (health === "ok") return "ok";
  if (health === "error") return "warn";
  if (health === "invalid") return "err";
  return "idle";
}

function mailToolProtocolPill(protocol) {
  if (protocol === "imap") return "ok";
  if (protocol === "graph") return "running";
  return "idle";
}

function renderMailTool(data = {}) {
  const tbody = $("#mail-tool-rows");
  tbody.innerHTML = "";
  $("#mail-tool-empty").hidden = state.mailTool.length > 0;
  for (const row of state.mailTool) {
    const selected = state.selectedMailTool.has(row.email);
    const tr = document.createElement("tr");
    if (selected) tr.classList.add("selected");
    const authText = row.auth_type === "oauth" ? "OAuth" : "密码";
    const codeCell = row.code
      ? `<span class="mail-code-value">${esc(row.code)}<button class="icon-btn" type="button" data-copy-mail-code="${esc(row.code)}" title="复制验证码"><svg><use href="#i-file"/></svg></button></span><small class="table-sub" title="${esc(row.subject || "")}">${esc(row.message_at || row.subject || "-")}</small>`
      : `<span class="mono">-</span><small class="table-sub">${esc(row.subject || "")}</small>`;
    tr.innerHTML = `
      <td class="c-check"><input type="checkbox" data-mail-tool-email="${esc(row.email)}" ${selected ? "checked" : ""}></td>
      <td><div class="cell-main">
        <span class="avatar">${esc(initials(row.email))}</span>
        <span><span class="cell-email" title="${esc(row.email)}">${esc(row.email)}</span><small class="table-sub mono">${esc(row.client_id || "-")}</small></span>
      </div></td>
      <td><span class="pill idle">${esc(authText)}</span><small class="table-sub">${row.has_password ? "含密码" : "无密码"}</small></td>
      <td><span class="pill ${mailToolProtocolPill(row.protocol)}">${esc(mailToolProtocolText[row.protocol] || row.protocol || "未检测")}</span><small class="table-sub mono">${esc(row.provider || "-")}</small></td>
      <td><span class="pill ${mailToolHealthPill(row.health)}">${esc(mailToolHealthText[row.health] || row.health || "未检测")}</span><small class="table-sub" title="${esc(row.reason || "")}">${esc(row.reason || "-")}</small></td>
      <td>${codeCell}</td>
      <td><span class="mono">${esc(row.checked_at || "-")}</span><small class="table-sub">${row.latency_ms == null ? "" : `${esc(row.latency_ms)} ms`}</small></td>
      <td class="c-actions"><div class="mail-tool-row-actions">
        <button class="icon-btn" type="button" data-mail-tool-messages="${esc(row.email)}" title="查看全部邮件"><svg><use href="#i-mail"/></svg></button>
        <button class="icon-btn" type="button" data-mail-tool-check="${esc(row.email)}" title="检测接码协议"><svg><use href="#i-zap"/></svg></button>
        <button class="icon-btn" type="button" data-mail-tool-code="${esc(row.email)}" title="读取最近验证码"><svg><use href="#i-key"/></svg></button>
      </div></td>
    `;
    tbody.append(tr);
  }
  const metrics = data.metrics || state.mailToolMetrics || {};
  for (const key of ["total", "imap", "graph", "ok", "failed", "unchecked"]) {
    const node = $(`#mail-tool-m-${key}`);
    if (node) node.textContent = String(metrics[key] || 0);
  }
  $("#mail-tool-count").textContent = `共 ${state.mailToolTotal} 条`;
  $("#mail-tool-page-label").textContent = `${state.mailToolPage} / ${state.mailToolPages}`;
  const path = data.path || state.mailToolPath;
  $("#mail-tool-path").textContent = path ? `路径: ${path}` : "";
  $("#mail-tool-selected-count").textContent = String(state.selectedMailTool.size);
  $("#mail-tool-batch").classList.toggle("active", state.selectedMailTool.size > 0);
  $("#mail-tool-select-all").checked =
    state.mailTool.length > 0 && state.mailTool.every((row) => state.selectedMailTool.has(row.email));
}

async function loadMailTool() {
  const params = new URLSearchParams({
    query: state.mailToolQuery,
    protocol: state.mailToolProtocol,
    health: state.mailToolHealth,
    page: String(state.mailToolPage),
    page_size: "50",
  });
  const data = await api(`/api/tools/mail/accounts?${params}`);
  state.mailTool = data.items || [];
  state.mailToolTotal = data.total || 0;
  state.mailToolPage = data.page || 1;
  state.mailToolPages = data.total_pages || 1;
  state.mailToolMetrics = data.metrics || {};
  state.mailToolPath = data.path || "";
  renderMailTool(data);
  return data;
}

function renderMailToolTask(payload = {}) {
  const task = payload.task || {};
  const running = Boolean(payload.running);
  state.mailToolTask = task;
  const panel = $("#mail-tool-task");
  panel.hidden = !task.id;
  $("#mail-tool-stop").hidden = !running;
  $("#mail-tool-check-all").disabled = running;
  $("#mail-tool-check-selected").disabled = running;
  $("#mail-tool-code-selected").disabled = running;
  $("#mail-tool-import-open").disabled = running;
  $("#mail-tool-delete").disabled = running;
  if (!task.id) return;
  const done = Number(task.done || 0);
  const total = Number(task.total || 0);
  const percent = total > 0 ? Math.min(100, (done / total) * 100) : 0;
  const action = task.action === "code" ? "读取验证码" : "检测协议";
  const statusLabel = running ? "进行中" : (statusText[task.status] || task.status || "-");
  $("#mail-tool-task-title").textContent = `${action} · ${statusLabel}`;
  $("#mail-tool-task-count").textContent = `${done} / ${total}`;
  $("#mail-tool-task-current").textContent = task.current || task.error || "";
  $("#mail-tool-task-progress").style.width = `${percent}%`;
}

async function pollMailToolStatus() {
  const wasRunning = Boolean(state.mailToolTask?.status === "running");
  const payload = await api("/api/tools/mail/check/status");
  renderMailToolTask(payload);
  if (payload.running) {
    if (!state.mailToolPollTimer) {
      state.mailToolPollTimer = setInterval(() => {
        pollMailToolStatus().catch(() => {});
      }, 1200);
    }
  } else {
    if (state.mailToolPollTimer) {
      clearInterval(state.mailToolPollTimer);
      state.mailToolPollTimer = null;
    }
    if (wasRunning) {
      await loadMailTool();
      const task = payload.task || {};
      toast(`邮箱任务完成：可用 ${task.ok || 0}，失败 ${task.failed || 0}`);
    }
  }
  return payload;
}

async function startMailToolCheck(emails = [], action = "detect") {
  const result = await api("/api/tools/mail/check", {
    method: "POST",
    body: JSON.stringify({
      emails,
      action,
      workers: Number($("#mail-tool-workers").value || 4),
      proxy_mode: $("#mail-tool-proxy").value,
      recent_seconds: Number($("#mail-tool-recent").value || 900),
    }),
  });
  renderMailToolTask({ running: true, task: result.task || {} });
  await pollMailToolStatus();
}

const mailReaderFolderText = {
  all: "全部邮件",
  inbox: "收件箱",
  junk: "垃圾邮件",
  deleted: "已删除",
  archive: "归档",
  sent: "已发送",
  drafts: "草稿",
};

function selectedMailReaderMessage() {
  return state.mailReader.items.find((item) => String(item.id) === state.mailReader.selectedId) || null;
}

function renderMailReaderMessage() {
  const message = selectedMailReaderMessage();
  $("#mail-reader-content-empty").hidden = Boolean(message);
  $("#mail-reader-message").hidden = !message;
  if (!message) return;

  $("#mail-reader-message-folder").textContent = mailReaderFolderText[message.folder] || message.folder || "邮件";
  $("#mail-reader-message-subject").textContent = message.subject || "(无主题)";
  $("#mail-reader-sender").textContent = message.sender || "-";
  $("#mail-reader-recipient").textContent = message.recipient || state.mailReader.email || "-";
  $("#mail-reader-time").textContent = message.received_at || "-";
  $("#mail-reader-body").textContent = message.body || message.preview || "(无正文)";
  $("#mail-reader-code").hidden = !message.code;
  $("#mail-reader-code-value").textContent = message.code || "";
}

function renderMailReader() {
  const reader = state.mailReader;
  $("#mail-reader-email").textContent = reader.email;
  $$('[data-mail-reader-folder]').forEach((button) => {
    const active = button.dataset.mailReaderFolder === reader.folder;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });

  const protocol = $("#mail-reader-protocol");
  protocol.className = `pill ${mailToolProtocolPill(reader.protocol)}`;
  protocol.textContent = mailToolProtocolText[reader.protocol] || reader.protocol || "未检测";
  $("#mail-reader-status").textContent = reader.loading
    ? "正在读取邮件…"
    : (reader.error || [reader.provider, reader.checkedAt, reader.fromCache ? "缓存" : ""].filter(Boolean).join(" · "));
  $("#mail-reader-status").classList.toggle("error", Boolean(reader.error));

  const list = $("#mail-reader-list");
  list.replaceChildren();
  reader.items.forEach((message, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "mail-reader-item";
    button.dataset.mailReaderIndex = String(index);
    if (String(message.id) === reader.selectedId) button.classList.add("active");
    if (message.is_read === false) button.classList.add("unread");

    const top = document.createElement("span");
    top.className = "mail-reader-item-top";
    const sender = document.createElement("strong");
    sender.textContent = message.sender || "未知发件人";
    const time = document.createElement("time");
    time.textContent = message.received_at || "";
    top.append(sender, time);

    const subject = document.createElement("span");
    subject.className = "mail-reader-item-subject";
    subject.textContent = message.subject || "(无主题)";
    const preview = document.createElement("span");
    preview.className = "mail-reader-item-preview";
    preview.textContent = message.preview || "(无正文)";
    const folder = document.createElement("small");
    folder.textContent = mailReaderFolderText[message.folder] || message.folder || "";
    button.append(top, subject, preview, folder);
    list.append(button);
  });

  $("#mail-reader-list-empty").hidden = reader.loading || reader.items.length > 0;
  $("#mail-reader-count").textContent = reader.totalExact
    ? `共 ${reader.total} 封邮件`
    : `本页 ${reader.items.length} 封邮件`;
  $("#mail-reader-page").textContent = `第 ${reader.page} 页`;
  $("#mail-reader-prev").disabled = reader.page <= 1;
  $("#mail-reader-next").disabled = !reader.hasMore;
  $("#mail-reader-refresh").disabled = reader.loading;
  renderMailReaderMessage();
}

function mailReaderCacheKey(reader) {
  const proxy = $("#mail-reader-proxy") ? $("#mail-reader-proxy").value : "";
  return `${reader.folder}|${reader.page}|${proxy}`;
}

function applyMailReaderPayload(reader, payload, fromCache) {
  reader.items = payload.items || [];
  reader.total = Number(payload.total || 0);
  reader.totalExact = Boolean(payload.total_exact);
  reader.hasMore = Boolean(payload.has_more);
  reader.protocol = payload.protocol || "unknown";
  reader.provider = payload.provider || "";
  reader.checkedAt = payload.checked_at || "";
  reader.fromCache = fromCache;
  reader.error = "";
  if (!reader.items.some((item) => String(item.id) === reader.selectedId)) {
    reader.selectedId = reader.items.length ? String(reader.items[0].id) : "";
  }
}

async function loadMailReaderMessages({ force = false } = {}) {
  const reader = state.mailReader;
  const key = mailReaderCacheKey(reader);
  // 缓存命中：秒开，不发请求（仅首次打开 / 点刷新 / 未访问过的页才走网络）
  if (!force && reader.cache[key]) {
    const seq = ++reader.requestSeq;
    reader.loading = false;
    applyMailReaderPayload(reader, reader.cache[key], true);
    renderMailReader();
    return;
  }
  const seq = ++reader.requestSeq;
  reader.loading = true;
  reader.fromCache = false;
  reader.error = "";
  renderMailReader();
  try {
    const payload = await api("/api/tools/mail/messages", {
      method: "POST",
      body: JSON.stringify({
        email: reader.email,
        folder: reader.folder,
        page: reader.page,
        page_size: reader.pageSize,
        proxy_mode: $("#mail-reader-proxy").value,
      }),
    });
    reader.cache[key] = payload;
    if (seq !== reader.requestSeq) return;
    applyMailReaderPayload(reader, payload, false);
  } catch (err) {
    if (seq !== reader.requestSeq) return;
    reader.items = [];
    reader.selectedId = "";
    reader.total = 0;
    reader.hasMore = false;
    reader.error = err.message;
    throw err;
  } finally {
    if (seq === reader.requestSeq) {
      reader.loading = false;
      renderMailReader();
    }
  }
}

async function openMailReader(email) {
  Object.assign(state.mailReader, {
    email,
    folder: "all",
    page: 1,
    items: [],
    selectedId: "",
    total: 0,
    totalExact: false,
    hasMore: false,
    protocol: "unknown",
    provider: "",
    checkedAt: "",
    error: "",
    cache: {},
    fromCache: false,
  });
  $("#mail-reader-proxy").value = $("#mail-tool-proxy").value;
  $("#mail-reader-dialog").showModal();
  renderMailReader();
  await loadMailReaderMessages();
  loadMailTool().catch(() => {});
}

function renderMailToolImportInspect(payload = null, error = "") {
  const panel = $("#mail-tool-import-inspect");
  const submit = $("#mail-tool-import-submit");
  if (!payload && !error) {
    panel.hidden = true;
    submit.disabled = true;
    return;
  }
  panel.hidden = false;
  $("#mail-tool-import-valid").textContent = String(payload?.valid || 0);
  $("#mail-tool-import-invalid").textContent = String(payload?.invalid || (error ? 1 : 0));
  $("#mail-tool-import-duplicates").textContent = String(payload?.duplicates || 0);
  $("#mail-tool-import-formats").innerHTML = Object.entries(payload?.formats || {})
    .map(([format, count]) => `<span><b>${esc(format)}</b>${esc(count)}</span>`)
    .join("");
  const issues = error ? [{ error }] : (payload?.issues || []);
  const issueBox = $("#mail-tool-import-issues");
  issueBox.hidden = issues.length === 0;
  issueBox.innerHTML = issues.slice(0, 8)
    .map((issue) => `<span>${issue.line ? `第 ${esc(issue.line)} 行 · ` : ""}${esc(issue.error || issue)}</span>`)
    .join("");
  submit.disabled = !(payload?.valid > 0);
}

async function inspectMailToolImport() {
  const text = $("#mail-tool-import-text").value;
  const seq = ++state.mailToolImportSeq;
  state.mailToolImportPreview = null;
  if (!text.trim()) {
    renderMailToolImportInspect();
    return;
  }
  try {
    const payload = await api("/api/tools/mail/inspect", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
    if (seq !== state.mailToolImportSeq) return;
    state.mailToolImportPreview = payload;
    renderMailToolImportInspect(payload);
  } catch (err) {
    if (seq !== state.mailToolImportSeq) return;
    renderMailToolImportInspect(null, err.message);
  }
}

async function submitMailToolImport() {
  if (!state.mailToolImportPreview?.valid) {
    toast("没有可导入的有效邮箱", true);
    return;
  }
  const button = $("#mail-tool-import-submit");
  button.disabled = true;
  try {
    const result = await api("/api/tools/mail/import", {
      method: "POST",
      body: JSON.stringify({
        text: $("#mail-tool-import-text").value,
        mode: $("#mail-tool-import-replace").checked ? "replace" : "append",
      }),
    });
    $("#mail-tool-import-dialog").close();
    $("#mail-tool-import-text").value = "";
    $("#mail-tool-import-file").value = "";
    $("#mail-tool-import-file-name").textContent = "TXT / CSV / JSON";
    state.mailToolImportPreview = null;
    state.selectedMailTool.clear();
    state.mailToolPage = 1;
    await loadMailTool();
    toast(`已导入 ${result.imported || 0} 条，跳过 ${result.invalid || 0} 条`);
  } finally {
    button.disabled = false;
  }
}

/* ── jobs ── */

function renderJobs() {
  const list = $("#job-list");
  list.innerHTML = "";
  if (!state.jobs.length) {
    list.innerHTML = `<div class="empty"><svg><use href="#i-history"/></svg><strong>暂无任务</strong><span>启动注册或补 mint 后会出现在这里</span></div>`;
    return;
  }
  for (const job of state.jobs) {
    const s = job.stats || {};
    const pct = jobProgress(job);
    const item = document.createElement("div");
    item.className = "job-card";
    item.innerHTML = `
      <div class="job-card-head">
        <span class="job-title">${esc(kindText[job.kind] || job.kind)}</span>
        <span class="pill ${esc(job.status)}">${esc(statusText[job.status] || job.status)}</span>
      </div>
      <div class="job-meta"><span>${esc(job.id)}</span><span>${esc(job.created_at || "")}</span></div>
      <div class="job-counts">
        ${job.kind === "register"
          ? `<span>成功 ${s.reg_success || 0}</span><span>失败 ${s.reg_fail || 0}</span><span>mint ${s.mint_success || 0}</span>`
          : job.kind === "gpt_register"
            ? `<span>target ${s.target || 0}</span><span>stage ${s.stage_index || 0}/${s.steps || 0}</span><span>${s.done || 0}/${s.total || 0}</span>`
          : `<span>ok ${s.ok || 0}</span><span>fail ${s.fail || 0}</span><span>${s.done || 0}/${s.total || 0}</span>`}
      </div>
      <div class="progress"><div class="progress-bar" style="width:${pct}%"></div></div>
      <div class="job-actions">
        <button class="link" data-focus-job="${esc(job.id)}" type="button">查看日志</button>
        ${(job.status === "running" || job.status === "queued")
          ? `<button class="link danger" data-stop-job="${esc(job.id)}" type="button">停止</button>`
          : ""}
      </div>
    `;
    list.append(item);
  }
}

async function loadJobs() {
  const data = await api("/api/jobs");
  state.jobs = data.jobs || [];
  renderJobs();
}

/* ── polling ── */

async function pollActiveJob() {
  try {
    const previousActiveId = state.activeJobId;
    state.overview = await api("/api/overview");
    renderOverview();
    if (state.view === "cpa") {
      const beforeRunning = Boolean(state.cpaPool && state.cpaPool.running);
      const status = await loadCpaPoolStatus().catch(() => null);
      if (beforeRunning && status && !status.running) {
        await loadCpaPoolResults().catch(() => {});
        await loadCpaScanHistory().catch(() => {});
        await loadCpaQuarantine().catch(() => {});
        renderCpa();
      }
    }
    const detailJobId = state.activeJobId || previousActiveId;
    if (!detailJobId) return;
    const detail = await api(`/api/jobs/${detailJobId}?after=${state.logCursor}`);
    renderActiveJob(detail);
    if (detail.logs && detail.logs.length) appendLogs(detail.logs);
    state.logCursor = detail.log_seq || state.logCursor;
    if (["completed", "failed", "stopped"].includes(detail.status)) {
      if (state.view === "accounts") loadAccounts().catch(() => {});
      if (state.view === "cpa") loadCpa().catch(() => {});
      state.activeJobId = null;
    }
  } catch (err) {
    $("#side-status-text").textContent = "连接异常，重试中…";
    setTimeout(() => { $("#side-status-text").textContent = "本地服务在线"; }, 3000);
  }
}

/* ── actions ── */

async function startRegister() {
  const proxyMode = $("#reg-proxy-mode").value;
  const body = {
    extra: Number($("#reg-extra").value || 1),
    threads: Number($("#reg-threads").value || 1),
    mint_workers: Number($("#reg-mint-workers").value || -1),
    mint_queue_max: Number($("#reg-mint-queue-max").value || -1),
    headless: $("#reg-headless").checked,
    fast: $("#reg-fast").checked,
    protocol_register: $("#reg-protocol").checked,
    protocol_no_browser_fallback: $("#reg-protocol-only").checked,
    proxy_mode: proxyMode,
    proxy_fixed: proxyMode === "fixed" ? $("#reg-proxy-fixed").value : "",
  };
  if (proxyMode === "fixed" && !body.proxy_fixed) {
    toast("请选择固定代理（或先在代理池导入）", true);
    return;
  }
  if (proxyMode === "random" && !state.proxies.length) {
    toast("代理池为空，请先在代理池页面导入", true);
    return;
  }
  const target = $("#reg-target") ? $("#reg-target").value : "grok";
  try {
    const url = target === "gpt" ? "/api/jobs/gpt-register" : "/api/jobs/register";
    const job = await api(url, { method: "POST", body: JSON.stringify(body) });
    state.activeJobId = job.id;
    state.logCursor = 0;
    resetLogs("// 任务已创建，正在初始化…");
    appendLogs([`任务已创建: ${job.id}`]);
    renderActiveJob(job);
    toast("注册任务已启动");
  } catch (err) {
    toast(err.message, true);
  }
}

async function startGptRegister() {
  const proxyMode = $("#gpt-proxy-mode").value;
  const body = {
    extra: Number($("#gpt-extra").value || 1),
    threads: Number($("#gpt-threads").value || 1),
    otp_timeout: Number($("#gpt-otp-timeout").value || 300),
    auth_entry: $("#gpt-auth-entry").value,
    headless: $("#gpt-headless").checked,
    fast: $("#gpt-fast").checked,
    auto_continue: $("#gpt-auto-continue").checked,
    probe: $("#gpt-probe").checked,
    proxy_mode: proxyMode,
    proxy_fixed: proxyMode === "fixed" ? $("#gpt-proxy-fixed").value : "",
    source: "gpt_workbench",
  };
  if (proxyMode === "fixed" && !body.proxy_fixed) {
    toast("请选择固定代理（或先在代理池导入）", true);
    return;
  }
  if (proxyMode === "random" && !state.proxies.length) {
    toast("代理池为空，请先在代理池页面导入", true);
    return;
  }
  try {
    const job = await api("/api/jobs/gpt-register", { method: "POST", body: JSON.stringify(body) });
    state.activeJobId = job.id;
    state.activeJobStarted = job.started_at || "";
    state.logCursor = 0;
    resetLogs("// GPT 工作流任务已创建，正在输出 HAR 流程预检…");
    appendLogs([`GPT 工作流任务已创建: ${job.id}`]);
    renderActiveJob(job);
    renderGptJob(job);
    toast("GPT 工作流任务已启动");
  } catch (err) {
    toast(err.message, true);
  }
}

async function stopJob(jobId) {
  if (!jobId) return;
  try {
    const job = await api(`/api/jobs/${jobId}/stop`, { method: "POST", body: "{}" });
    renderActiveJob(job);
    toast("已发送停止请求");
    loadJobs().catch(() => {});
  } catch (err) {
    toast(err.message, true);
  }
}

async function startBackfill(payload, notice) {
  try {
    const job = await api("/api/jobs/backfill", { method: "POST", body: JSON.stringify(payload) });
    state.activeJobId = job.id;
    state.logCursor = 0;
    resetLogs("// 补 mint 任务已创建…");
    appendLogs([`${notice}: ${job.id}`]);
    renderActiveJob(job);
    toast("补 CPA 任务已启动");
    setView("console");
  } catch (err) {
    toast(err.message, true);
  }
}

function backfillPayload(base, scope) {
  const workersEl = $(`#${scope}-backfill-workers`);
  const probeChatEl = $(`#${scope}-backfill-probe-chat`);
  return {
    ...base,
    workers: Number(workersEl?.value || -1),
    probe: true,
    probe_chat: Boolean(probeChatEl?.checked),
    sleep: 0,
  };
}

async function cpaPoolManualAction(action, label) {
  if (!state.selectedCpa.size) return;
  const reason = prompt(`${label} ${state.selectedCpa.size} 个 CPA 文件，原因备注：`, `manual:${action}`);
  if (reason === null) return;
  if (!confirm(`确认${label} ${state.selectedCpa.size} 个 CPA 文件？`)) return;
  try {
    const result = await api("/api/cpa/pool/action", {
      method: "POST",
      body: JSON.stringify({ action, emails: [...state.selectedCpa], reason }),
    });
    toast(`${label}完成：${result.success}/${result.total}`);
    state.selectedCpa.clear();
    await loadCpa();
  } catch (err) {
    toast(err.message, true);
  }
}

async function restoreSelectedQuarantine() {
  if (!state.selectedQuarantine.size) return;
  const overwrite = $("#cpa-quarantine-overwrite").checked;
  if (!confirm(`确认恢复 ${state.selectedQuarantine.size} 个隔离账号到热加载目录？`)) return;
  try {
    const result = await api("/api/cpa/pool/quarantine/restore", {
      method: "POST",
      body: JSON.stringify({ emails: [...state.selectedQuarantine], target: "hotload", overwrite }),
    });
    toast(`恢复完成：${result.success}/${result.total}`);
    state.selectedQuarantine.clear();
    await loadCpa();
  } catch (err) {
    toast(err.message, true);
  }
}

async function exportAccounts(emails = []) {
  try {
    const response = await fetch("/api/accounts/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emails }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `accounts-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast("导出完成");
  } catch (err) {
    toast(err.message, true);
  }
}

/* ── event bindings ── */

function bindEvents() {
  $$(".nav-item[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.view));
  });
  $$('[data-tool-page]').forEach((btn) => {
    btn.addEventListener("click", () => setToolPage(btn.dataset.toolPage));
  });
  $("#open-jobs").addEventListener("click", () => openJobs(true));
  $("#close-jobs").addEventListener("click", () => openJobs(false));
  $("#drawer-backdrop").addEventListener("click", () => {
    openJobs(false);
    closePageSettings();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if ($("#page-settings-drawer").classList.contains("open")) closePageSettings();
    else if ($("#job-drawer").classList.contains("open")) openJobs(false);
  });
  window.addEventListener("hashchange", () => {
    const [view, toolPage] = location.hash.replace(/^#/, "").split("/");
    if (view && document.querySelector(`[data-view-panel="${view}"]`)) {
      setView(view, view === "tools" ? toolPage : null);
    }
  });

  /* 页面设置抽屉 */
  $$("[data-page-settings]").forEach((btn) => {
    btn.addEventListener("click", () => openPageSettings(btn.dataset.pageSettings));
  });
  $$("[data-goto-settings]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.gotoSettings;
      setView(key === "console" ? "console" : key);
      openPageSettings(key);
    });
  });
  $("#close-page-settings").addEventListener("click", closePageSettings);
  $("#page-settings-reload").addEventListener("click", async () => {
    try {
      state.config = await api("/api/config");
      renderPageSettings();
      toast("已重新加载配置");
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#page-settings-save").addEventListener("click", async () => {
    try {
      const payload = collectConfigScoped($("#page-settings-body"));
      state.config = await api("/api/config", { method: "PUT", body: JSON.stringify(payload) });
      renderPageSettings();
      toast("页面配置已保存");
      state.overview = await api("/api/overview");
      renderOverview();
    } catch (err) {
      toast(err.message, true);
    }
  });
  // 配置中心代理选择器：选「自定义…」时展开文本框
  document.addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-proxy-field]");
    if (!sel) return;
    const custom = document.querySelector(`[data-proxy-custom="${sel.dataset.configKey}"]`);
    if (custom) custom.hidden = sel.value !== "__custom__";
  });

  /* console */
  $("#refresh-overview").addEventListener("click", () =>
    api("/api/overview").then((o) => { state.overview = o; renderOverview(); }).catch((e) => toast(e.message, true)));
  $("#start-register").addEventListener("click", startRegister);
  $("#reg-protocol").addEventListener("change", syncRegisterProtocolToggles);
  $("#reg-protocol-only").addEventListener("change", (e) => {
    if (e.target.checked) $("#reg-protocol").checked = true;
    syncRegisterProtocolToggles();
  });
  $("#stop-active-job").addEventListener("click", () => stopJob(state.activeJobId));
  $("#clear-log").addEventListener("click", () => resetLogs());

  /* GPT workbench */
  $("#gpt-refresh-flow").addEventListener("click", () =>
    loadGptFlow().then(() => toast("GPT 流程已刷新")).catch((e) => toast(`流程刷新失败，已使用内置摘要: ${e.message}`, true)));
  $("#start-gpt-register").addEventListener("click", startGptRegister);
  $("#gpt-stop-active-job").addEventListener("click", () => stopJob(state.activeJobId));
  $("#gpt-clear-log").addEventListener("click", () => resetLogs("// 等待 GPT 工作流启动，日志将同步显示在这里"));
  $("#gpt-headless").addEventListener("change", () => {
    $("#gpt-meta-browser").textContent = $("#gpt-headless").checked ? "headless" : "headed";
  });
  $("#gpt-proxy-mode").addEventListener("change", (e) => {
    $("#gpt-proxy-fixed-wrap").hidden = e.target.value !== "fixed";
    if (e.target.value === "fixed" && !state.proxies.length) {
      loadProxies().catch(() => {});
    }
  });

  /* accounts */
  $("#refresh-accounts").addEventListener("click", () => loadAccounts().catch((e) => toast(e.message, true)));
  $("#account-search").addEventListener("input", debounce((e) => {
    state.accountQuery = e.target.value.trim();
    state.accountPage = 1;
    loadAccounts().catch((err) => toast(err.message, true));
  }));
  $("#account-status").addEventListener("change", (e) => {
    state.accountStatus = e.target.value;
    state.accountPage = 1;
    loadAccounts().catch((err) => toast(err.message, true));
  });
  $("#account-prev").addEventListener("click", () => {
    if (state.accountPage > 1) { state.accountPage -= 1; loadAccounts().catch(() => {}); }
  });
  $("#account-next").addEventListener("click", () => {
    if (state.accountPage < state.accountPages) { state.accountPage += 1; loadAccounts().catch(() => {}); }
  });
  $("#account-select-all").addEventListener("change", (e) => {
    for (const row of state.accounts) {
      if (e.target.checked) state.selectedAccounts.add(row.email);
      else state.selectedAccounts.delete(row.email);
    }
    renderAccounts();
  });
  $$("[data-acc-select]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.accSelect === "page") state.accounts.forEach((r) => state.selectedAccounts.add(r.email));
      else state.selectedAccounts.clear();
      renderAccounts();
    });
  });
  $("#account-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-email]");
    if (!input) return;
    if (input.checked) state.selectedAccounts.add(input.dataset.email);
    else state.selectedAccounts.delete(input.dataset.email);
    renderAccounts();
  });
  $("#export-accounts").addEventListener("click", () => exportAccounts([]));
  $("#export-selected-accounts").addEventListener("click", () => exportAccounts([...state.selectedAccounts]));
  $("#delete-accounts").addEventListener("click", async () => {
    if (!state.selectedAccounts.size) return;
    if (!confirm(`确认删除 ${state.selectedAccounts.size} 个账号？`)) return;
    try {
      await api("/api/accounts", {
        method: "DELETE",
        body: JSON.stringify({ emails: [...state.selectedAccounts] }),
      });
      state.selectedAccounts.clear();
      toast("已删除");
      loadAccounts().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#backfill-selected").addEventListener("click", () => {
    if (!state.selectedAccounts.size) return;
    startBackfill(
      backfillPayload({ emails: [...state.selectedAccounts] }, "account"),
      "补 mint 任务已创建",
    );
  });

  /* cpa */
  $("#refresh-cpa").addEventListener("click", () => loadCpa().catch((e) => toast(e.message, true)));
  $("#cpa-pool-refresh-status").addEventListener("click", async () => {
    await loadCpaPoolStatus().catch((e) => toast(e.message, true));
    await loadCpaPoolResults().catch(() => {});
    await loadCpaScanHistory().catch(() => {});
    await loadCpaActions().catch(() => {});
    await loadCpaQuarantine().catch(() => {});
    renderCpa();
  });
  $("#refresh-cpa-scan-history").addEventListener("click", () =>
    loadCpaScanHistory().catch((e) => toast(e.message, true)));
  $("#refresh-cpa-actions").addEventListener("click", () =>
    loadCpaActions().catch((e) => toast(e.message, true)));
  $("#cpa-action-prev").addEventListener("click", () => {
    if (state.cpaActionPage > 1) {
      state.cpaActionPage -= 1;
      loadCpaActions().catch((e) => toast(e.message, true));
    }
  });
  $("#cpa-action-next").addEventListener("click", () => {
    if (state.cpaActionPage < state.cpaActionPages) {
      state.cpaActionPage += 1;
      loadCpaActions().catch((e) => toast(e.message, true));
    }
  });
  $("#cpa-action-page-size").addEventListener("change", (e) => {
    state.cpaActionPageSize = Number(e.target.value || 10);
    state.cpaActionPage = 1;
    loadCpaActions().catch((err) => toast(err.message, true));
  });
  $("#cpa-scan-history-search").addEventListener("input", debounce((e) => {
    state.cpaScanHistoryQuery = e.target.value.trim();
    loadCpaScanHistory().catch((err) => toast(err.message, true));
  }));
  $("#cpa-scan-history-outcome").addEventListener("change", (e) => {
    state.cpaScanHistoryOutcome = e.target.value;
    loadCpaScanHistory().catch((err) => toast(err.message, true));
  });
  $("#cpa-pool-scan").addEventListener("click", async () => {
    const body = {
      trigger: "manual",
      scan_workers: Number($("#cpa-pool-workers").value || 16),
      limit: Number($("#cpa-pool-limit").value || 0),
      refresh_before_probe: $("#cpa-pool-refresh-before").checked,
      probe_chat: $("#cpa-pool-probe-chat").checked,
      apply_policy: $("#cpa-pool-apply-policy").checked,
      auto_refill: $("#cpa-pool-auto-refill").checked,
      refill_target_active: Number($("#cpa-pool-refill-target").value || 0),
      refill_max_inventory: Number($("#cpa-pool-refill-inventory").value || 4000),
      refill_max_per_scan: Number($("#cpa-pool-refill-max").value || 200),
      refill_workers: Number($("#cpa-pool-refill-workers").value || -1),
      refill_probe_chat: $("#cpa-pool-refill-probe-chat").checked,
    };
    try {
      const result = await api("/api/cpa/pool/scan", { method: "POST", body: JSON.stringify(body) });
      state.cpaPool = result.status || result;
      renderCpaPoolStatus();
      toast(result.started ? "CPA 巡检已启动" : "CPA 巡检已在运行");
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#cpa-pool-stop").addEventListener("click", async () => {
    try {
      state.cpaPool = await api("/api/cpa/pool/stop", { method: "POST", body: "{}" });
      renderCpaPoolStatus();
      toast("已发送停止巡检请求");
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#cpa-search").addEventListener("input", debounce((e) => {
    state.cpaQuery = e.target.value.trim();
    state.cpaPage = 1;
    loadCpa().catch((err) => toast(err.message, true));
  }));
  $("#cpa-status").addEventListener("change", (e) => {
    state.cpaStatus = e.target.value;
    state.cpaPage = 1;
    state.selectedCpa.clear();
    loadCpa().catch((err) => toast(err.message, true));
  });
  $("#cpa-prev").addEventListener("click", () => {
    if (state.cpaPage > 1) { state.cpaPage -= 1; loadCpa().catch(() => {}); }
  });
  $("#cpa-next").addEventListener("click", () => {
    if (state.cpaPage < state.cpaPages) { state.cpaPage += 1; loadCpa().catch(() => {}); }
  });
  $$("[data-cpa-select]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.cpaSelect === "page") state.cpa.forEach((r) => state.selectedCpa.add(r.email));
      else state.selectedCpa.clear();
      renderCpa();
    });
  });
  $("#cpa-select-all").addEventListener("change", (e) => {
    for (const row of state.cpa) {
      if (e.target.checked) state.selectedCpa.add(row.email);
      else state.selectedCpa.delete(row.email);
    }
    renderCpa();
  });
  $("#cpa-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-cpa-email]");
    if (!input) return;
    if (input.checked) state.selectedCpa.add(input.dataset.cpaEmail);
    else state.selectedCpa.delete(input.dataset.cpaEmail);
    renderCpa();
  });
  $("#cpa-rows").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-download-cpa]");
    if (!btn) return;
    window.open(`/api/cpa/download?email=${encodeURIComponent(btn.dataset.downloadCpa)}`, "_blank");
  });
  $("#delete-cpa").addEventListener("click", async () => {
    if (!state.selectedCpa.size) return;
    if (!confirm(`确认删除 ${state.selectedCpa.size} 个 CPA 文件？`)) return;
    try {
      await api("/api/cpa", { method: "DELETE", body: JSON.stringify({ emails: [...state.selectedCpa] }) });
      state.selectedCpa.clear();
      toast("已删除 CPA");
      loadCpa().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#cpa-action-disable").addEventListener("click", () => cpaPoolManualAction("disable", "禁用"));
  $("#cpa-action-enable").addEventListener("click", () => cpaPoolManualAction("enable", "启用"));
  $("#cpa-action-quarantine").addEventListener("click", () => cpaPoolManualAction("quarantine", "隔离"));
  $("#refresh-cpa-quarantine").addEventListener("click", () => loadCpaQuarantine().catch((e) => toast(e.message, true)));
  $("#restore-cpa-quarantine").addEventListener("click", restoreSelectedQuarantine);
  $("#cpa-quarantine-search").addEventListener("input", debounce((e) => {
    state.cpaQuarantineQuery = e.target.value.trim();
    loadCpaQuarantine().catch((err) => toast(err.message, true));
  }));
  $("#cpa-quarantine-bucket").addEventListener("change", (e) => {
    state.cpaQuarantineBucket = e.target.value;
    loadCpaQuarantine().catch((err) => toast(err.message, true));
  });
  $("#cpa-quarantine-select-all").addEventListener("change", (e) => {
    for (const row of state.cpaQuarantine) {
      if (!row.email) continue;
      if (e.target.checked) state.selectedQuarantine.add(row.email);
      else state.selectedQuarantine.delete(row.email);
    }
    renderCpaQuarantine({ dir: $("#cpa-quarantine-dir").textContent.replace(/^目录: /, "") });
  });
  $("#cpa-quarantine-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-q-email]");
    if (!input) return;
    if (input.checked) state.selectedQuarantine.add(input.dataset.qEmail);
    else state.selectedQuarantine.delete(input.dataset.qEmail);
    renderCpaQuarantine({ dir: $("#cpa-quarantine-dir").textContent.replace(/^目录: /, "") });
  });
  $("#backfill-missing").addEventListener("click", () =>
    startBackfill(backfillPayload({ limit: 0 }, "cpa"), "补缺失 CPA 任务"));

  /* mail */
  $("#refresh-mail").addEventListener("click", () => loadMail().catch((e) => toast(e.message, true)));
  $("#mail-search").addEventListener("input", debounce((e) => {
    state.mailQuery = e.target.value.trim();
    state.mailPage = 1;
    loadMail().catch((err) => toast(err.message, true));
  }));
  $("#mail-status").addEventListener("change", (e) => {
    state.mailStatus = e.target.value;
    state.mailPage = 1;
    loadMail().catch((err) => toast(err.message, true));
  });
  $("#mail-select-by-status").addEventListener("change", (e) => {
    selectAllByStatus("mail", e.target.value);
    e.target.value = "";
  });
  $("#mail-prev").addEventListener("click", () => {
    if (state.mailPage > 1) { state.mailPage -= 1; loadMail().catch(() => {}); }
  });
  $("#mail-next").addEventListener("click", () => {
    if (state.mailPage < state.mailPages) { state.mailPage += 1; loadMail().catch(() => {}); }
  });
  bindPageJump("#mail-page-jump", (n) => {
    state.mailPage = Math.min(Math.max(1, n), state.mailPages);
    loadMail().catch(() => {});
  });
  $("#open-mail-import").addEventListener("click", () => $("#mail-import-dialog").showModal());
  $("#mail-import-form").addEventListener("submit", async (e) => {
    const submitter = e.submitter;
    if (!submitter || submitter.value !== "default") return;
    e.preventDefault();
    try {
      const text = $("#mail-import-text").value;
      const mode = $("#mail-import-replace").checked ? "replace" : "append";
      const result = await api("/api/mail-credentials/import", {
        method: "POST",
        body: JSON.stringify({ text, mode }),
      });
      $("#mail-import-dialog").close();
      $("#mail-import-text").value = "";
      toast(`导入完成：新增 ${result.added}，更新 ${result.updated}`);
      loadMail().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });
  $$("[data-mail-select]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.mailSelect === "page") state.mail.forEach((r) => state.selectedMail.add(r.email));
      else state.selectedMail.clear();
      renderMail();
    });
  });
  $("#mail-select-all").addEventListener("change", (e) => {
    for (const row of state.mail) {
      if (e.target.checked) state.selectedMail.add(row.email);
      else state.selectedMail.delete(row.email);
    }
    renderMail();
  });
  $("#mail-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-mail-email]");
    if (!input) return;
    if (input.checked) state.selectedMail.add(input.dataset.mailEmail);
    else state.selectedMail.delete(input.dataset.mailEmail);
    renderMail();
  });
  $("#delete-mail").addEventListener("click", async () => {
    if (!state.selectedMail.size) return;
    if (!confirm(`确认删除 ${state.selectedMail.size} 条邮箱凭证？`)) return;
    try {
      await api("/api/mail-credentials", {
        method: "DELETE",
        body: JSON.stringify({ emails: [...state.selectedMail] }),
      });
      state.selectedMail.clear();
      toast("已删除凭证");
      loadMail().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#account-select-by-status").addEventListener("change", (e) => {
    selectAllByStatus("accounts", e.target.value);
    e.target.value = "";
  });
  bindPageJump("#account-page-jump", (n) => {
    state.accountPage = Math.min(Math.max(1, n), state.accountPages);
    loadAccounts().catch(() => {});
  });
  bindPageJump("#cpa-page-jump", (n) => {
    state.cpaPage = Math.min(Math.max(1, n), state.cpaPages);
    loadCpa().catch(() => {});
  });
  bindPageJump("#cpa-action-page-jump", (n) => {
    state.cpaActionPage = Math.min(Math.max(1, n), state.cpaActionPages);
    loadCpaActions().catch(() => {});
  });
  bindPageJump("#proxy-page-jump", (n) => {
    const totalPages = Math.max(1, Math.ceil(filteredProxies().length / state.proxyPageSize));
    state.proxyPage = Math.min(Math.max(1, n), totalPages);
    renderProxies();
  });

  /* proxies */
  $("#refresh-proxies").addEventListener("click", () => loadProxies().catch((e) => toast(e.message, true)));
  $("#open-proxy-import").addEventListener("click", () => $("#proxy-import-dialog").showModal());
  $("#check-all-proxies").addEventListener("click", () => checkProxies([]));
  $("#check-selected-proxies").addEventListener("click", () => {
    if (state.selectedProxies.size) checkProxies([...state.selectedProxies]);
  });
  $("#proxy-import-form").addEventListener("submit", async (e) => {
    const submitter = e.submitter;
    if (!submitter || submitter.value !== "default") return;
    e.preventDefault();
    try {
      const text = $("#proxy-import-text").value;
      const mode = $("#proxy-import-replace").checked ? "replace" : "append";
      const result = await api("/api/proxies/import", {
        method: "POST",
        body: JSON.stringify({ text, mode }),
      });
      $("#proxy-import-dialog").close();
      $("#proxy-import-text").value = "";
      toast(`导入完成：新增 ${result.added}，更新 ${result.updated}${result.invalid ? `，无效 ${result.invalid}` : ""}`);
      loadProxies().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#proxy-search").addEventListener("input", debounce((e) => {
    state.proxyQuery = e.target.value.trim();
    state.proxyPage = 1;
    renderProxies();
  }));
  $$("[data-proxy-select]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.proxySelect === "page") currentProxyRows().forEach((r) => state.selectedProxies.add(r.key));
      else state.selectedProxies.clear();
      renderProxies();
    });
  });
  $("#proxy-select-all").addEventListener("change", (e) => {
    for (const row of currentProxyRows()) {
      if (e.target.checked) state.selectedProxies.add(row.key);
      else state.selectedProxies.delete(row.key);
    }
    renderProxies();
  });
  $("#proxy-prev").addEventListener("click", () => {
    if (state.proxyPage > 1) { state.proxyPage -= 1; renderProxies(); }
  });
  $("#proxy-next").addEventListener("click", () => {
    const totalPages = Math.max(1, Math.ceil(filteredProxies().length / state.proxyPageSize));
    if (state.proxyPage < totalPages) { state.proxyPage += 1; renderProxies(); }
  });
  $("#proxy-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-proxy-key]");
    if (!input) return;
    if (input.checked) state.selectedProxies.add(input.dataset.proxyKey);
    else state.selectedProxies.delete(input.dataset.proxyKey);
    renderProxies();
  });
  $("#proxy-rows").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-check-proxy]");
    if (!btn) return;
    checkProxies([btn.dataset.checkProxy]);
  });
  $("#delete-proxies").addEventListener("click", async () => {
    if (!state.selectedProxies.size) return;
    if (!confirm(`确认删除 ${state.selectedProxies.size} 个代理？`)) return;
    try {
      await api("/api/proxies", {
        method: "DELETE",
        body: JSON.stringify({ keys: [...state.selectedProxies] }),
      });
      state.selectedProxies.clear();
      toast("已删除代理");
      loadProxies().catch(() => {});
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#reg-proxy-mode").addEventListener("change", (e) => {
    $("#reg-proxy-fixed-wrap").hidden = e.target.value !== "fixed";
    if (e.target.value === "fixed" && !state.proxies.length) {
      loadProxies().catch(() => {});
    }
  });

  /* tools */
  const dropzone = $("#convert-dropzone");
  const fileInput = $("#convert-file");
  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => convertSetFile(fileInput.files[0] || null));
  ["dragenter", "dragover"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    }),
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    }),
  );
  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) convertSetFile(file);
  });
  $("#convert-run").addEventListener("click", runConvert);
  $("#convert-redownload").addEventListener("click", () => {
    if (convertState.lastUrl) {
      const a = document.createElement("a");
      a.href = convertState.lastUrl;
      a.download = convertState.lastName;
      a.click();
    }
  });

  /* mail tool */
  $("#mail-tool-refresh").addEventListener("click", () => {
    loadMailTool().catch((e) => toast(e.message, true));
    pollMailToolStatus().catch(() => {});
  });
  $("#mail-tool-search").addEventListener("input", debounce((e) => {
    state.mailToolQuery = e.target.value.trim();
    state.mailToolPage = 1;
    loadMailTool().catch((err) => toast(err.message, true));
  }));
  $("#mail-tool-protocol").addEventListener("change", (e) => {
    state.mailToolProtocol = e.target.value;
    state.mailToolPage = 1;
    loadMailTool().catch((err) => toast(err.message, true));
  });
  $("#mail-tool-health").addEventListener("change", (e) => {
    state.mailToolHealth = e.target.value;
    state.mailToolPage = 1;
    loadMailTool().catch((err) => toast(err.message, true));
  });
  $("#mail-tool-prev").addEventListener("click", () => {
    if (state.mailToolPage > 1) {
      state.mailToolPage -= 1;
      loadMailTool().catch(() => {});
    }
  });
  $("#mail-tool-next").addEventListener("click", () => {
    if (state.mailToolPage < state.mailToolPages) {
      state.mailToolPage += 1;
      loadMailTool().catch(() => {});
    }
  });
  bindPageJump("#mail-tool-page-jump", (page) => {
    state.mailToolPage = Math.min(Math.max(1, page), state.mailToolPages);
    loadMailTool().catch(() => {});
  });
  $$('[data-mail-tool-select]').forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.mailToolSelect === "page") {
        state.mailTool.forEach((row) => state.selectedMailTool.add(row.email));
      } else {
        state.selectedMailTool.clear();
      }
      renderMailTool();
    });
  });
  $("#mail-tool-select-all").addEventListener("change", (e) => {
    state.mailTool.forEach((row) => {
      if (e.target.checked) state.selectedMailTool.add(row.email);
      else state.selectedMailTool.delete(row.email);
    });
    renderMailTool();
  });
  $("#mail-tool-rows").addEventListener("change", (e) => {
    const input = e.target.closest("input[data-mail-tool-email]");
    if (!input) return;
    if (input.checked) state.selectedMailTool.add(input.dataset.mailToolEmail);
    else state.selectedMailTool.delete(input.dataset.mailToolEmail);
    renderMailTool();
  });
  $("#mail-tool-rows").addEventListener("click", (e) => {
    const copy = e.target.closest("[data-copy-mail-code]");
    if (copy) {
      copyText(copy.dataset.copyMailCode)
        .then(() => toast("验证码已复制"))
        .catch((err) => toast(err.message, true));
      return;
    }
    const messages = e.target.closest("[data-mail-tool-messages]");
    if (messages) {
      openMailReader(messages.dataset.mailToolMessages).catch((err) => toast(err.message, true));
      return;
    }
    const check = e.target.closest("[data-mail-tool-check]");
    if (check) {
      startMailToolCheck([check.dataset.mailToolCheck], "detect").catch((err) => toast(err.message, true));
      return;
    }
    const code = e.target.closest("[data-mail-tool-code]");
    if (code) {
      startMailToolCheck([code.dataset.mailToolCode], "code").catch((err) => toast(err.message, true));
    }
  });
  $("#mail-tool-check-all").addEventListener("click", () => {
    startMailToolCheck([], "detect").catch((e) => toast(e.message, true));
  });
  $("#mail-tool-check-selected").addEventListener("click", () => {
    if (!state.selectedMailTool.size) return;
    startMailToolCheck([...state.selectedMailTool], "detect").catch((e) => toast(e.message, true));
  });
  $("#mail-tool-code-selected").addEventListener("click", () => {
    if (!state.selectedMailTool.size) return;
    startMailToolCheck([...state.selectedMailTool], "code").catch((e) => toast(e.message, true));
  });
  $("#mail-tool-stop").addEventListener("click", async () => {
    try {
      const payload = await api("/api/tools/mail/check/stop", { method: "POST", body: "{}" });
      renderMailToolTask(payload);
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#mail-tool-delete").addEventListener("click", async () => {
    if (!state.selectedMailTool.size) return;
    if (!confirm(`确认删除 ${state.selectedMailTool.size} 条微软邮箱？`)) return;
    try {
      const result = await api("/api/tools/mail/accounts", {
        method: "DELETE",
        body: JSON.stringify({ emails: [...state.selectedMailTool] }),
      });
      state.selectedMailTool.clear();
      await loadMailTool();
      toast(`已删除 ${result.deleted || 0} 条邮箱`);
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#mail-tool-import-open").addEventListener("click", () => {
    renderMailToolImportInspect(state.mailToolImportPreview);
    $("#mail-tool-import-dialog").showModal();
  });
  $("#mail-tool-import-file-open").addEventListener("click", () => $("#mail-tool-import-file").click());
  $("#mail-tool-import-file").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    $("#mail-tool-import-file-name").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    $("#mail-tool-import-text").value = await file.text();
    inspectMailToolImport().catch((err) => toast(err.message, true));
  });
  $("#mail-tool-import-text").addEventListener("input", debounce(() => {
    inspectMailToolImport().catch((err) => toast(err.message, true));
  }, 350));
  $("#mail-tool-import-form").addEventListener("submit", (e) => {
    if (e.submitter?.value !== "default") return;
    e.preventDefault();
    submitMailToolImport().catch((err) => toast(err.message, true));
  });
  $("#mail-reader-close").addEventListener("click", () => $("#mail-reader-dialog").close());
  $("#mail-reader-dialog").addEventListener("close", () => {
    state.mailReader.requestSeq += 1;
    state.mailReader.loading = false;
    state.mailReader.items = [];
    state.mailReader.selectedId = "";
    state.mailReader.error = "";
    $("#mail-reader-list").replaceChildren();
    $("#mail-reader-body").textContent = "";
  });
  $("#mail-reader-refresh").addEventListener("click", () => {
    loadMailReaderMessages({ force: true }).catch((err) => toast(err.message, true));
  });
  $$('[data-mail-reader-folder]').forEach((button) => {
    button.addEventListener("click", () => {
      // 加载中也允许切换：requestSeq 保证最后一次操作生效，缓存命中则秒开
      if (state.mailReader.folder === button.dataset.mailReaderFolder) return;
      state.mailReader.folder = button.dataset.mailReaderFolder;
      state.mailReader.page = 1;
      state.mailReader.selectedId = "";
      loadMailReaderMessages().catch((err) => toast(err.message, true));
    });
  });
  $("#mail-reader-proxy").addEventListener("change", () => {
    state.mailReader.page = 1;
    state.mailReader.selectedId = "";
    loadMailReaderMessages().catch((err) => toast(err.message, true));
  });
  $("#mail-reader-list").addEventListener("click", (e) => {
    const item = e.target.closest("[data-mail-reader-index]");
    if (!item) return;
    const message = state.mailReader.items[Number(item.dataset.mailReaderIndex)];
    if (!message) return;
    state.mailReader.selectedId = String(message.id);
    renderMailReader();
  });
  $("#mail-reader-prev").addEventListener("click", () => {
    if (state.mailReader.page <= 1) return;
    state.mailReader.page -= 1;
    state.mailReader.selectedId = "";
    loadMailReaderMessages().catch((err) => toast(err.message, true));
  });
  $("#mail-reader-next").addEventListener("click", () => {
    if (!state.mailReader.hasMore) return;
    state.mailReader.page += 1;
    state.mailReader.selectedId = "";
    loadMailReaderMessages().catch((err) => toast(err.message, true));
  });
  $("#mail-reader-copy-code").addEventListener("click", () => {
    const code = selectedMailReaderMessage()?.code;
    if (!code) return;
    copyText(code)
      .then(() => toast("验证码已复制"))
      .catch((err) => toast(err.message, true));
  });

  /* settings */
  $("#reload-config").addEventListener("click", () => loadConfig().catch((e) => toast(e.message, true)));
  $("#save-config").addEventListener("click", async () => {
    try {
      // 表单字段（分组内联编辑）优先，原始 JSON 作为底合并
      const payload = collectConfigScoped($('[data-view-panel="settings"]'));
      let raw;
      try {
        raw = JSON.parse($("#config-raw").value || "{}");
      } catch (err) {
        throw new Error(`原始 JSON 无效: ${err.message}`);
      }
      payload._raw = { ...raw, ...payload };
      state.config = await api("/api/config", { method: "PUT", body: JSON.stringify(payload) });
      renderConfigForm();
      toast("配置已保存");
      state.overview = await api("/api/overview");
      renderOverview();
    } catch (err) {
      toast(err.message, true);
    }
  });

  /* jobs drawer */
  $("#job-list").addEventListener("click", (e) => {
    const stop = e.target.closest("[data-stop-job]");
    if (stop) {
      stopJob(stop.dataset.stopJob);
      return;
    }
    const focus = e.target.closest("[data-focus-job]");
    if (focus) {
      state.activeJobId = focus.dataset.focusJob;
      state.logCursor = 0;
      resetLogs("// 加载历史任务日志…");
      setView("console");
      openJobs(false);
      pollActiveJob();
    }
  });
}

/* ── boot ── */

async function boot() {
  bindEvents();
  const [hashView, hashToolPage] = location.hash.replace(/^#/, "").split("/");
  if (hashView && document.querySelector(`[data-view-panel="${hashView}"]`)) {
    setView(hashView, hashView === "tools" ? hashToolPage : null);
  }
  try {
    state.overview = await api("/api/overview");
    renderOverview();
    if (state.overview.active_job) state.activeJobId = state.overview.active_job.id;
  } catch (err) {
    toast(`加载失败: ${err.message}`, true);
    $("#side-status-text").textContent = "服务连接失败";
  }
  state.pollTimer = setInterval(pollActiveJob, 1500);
  loadProxies().catch(() => {});
  state.clockTimer = setInterval(() => {
    if (state.activeJobStarted) {
      const el = $("#active-job-elapsed");
      if (el && !$("#active-job-detail").hidden) el.textContent = fmtElapsed(state.activeJobStarted);
    }
  }, 1000);
}

boot();
