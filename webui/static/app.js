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
  selectedCpa: new Set(),
  cpaPool: null,
  cpaPoolMap: new Map(),
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
  idle: "空闲",
  quota: "额度/冷却",
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
};

const mailStatusPill = {
  available: "ok",
  partial: "sso_only",
  exhausted: "err",
};

function cpaPoolPill(status) {
  if (status === "ok") return "ok";
  if (status === "quota" || status === "cooling" || status === "soft_fail" || status === "probe_failed") return "warn";
  if (status === "disabled") return "idle";
  if (status === "running") return "running";
  if (!status) return "idle";
  return "err";
}

const kindText = {
  register: "批量注册",
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
    ["cpa_pool_scan_interval_sec", "号池巡检周期秒", "number"],
    ["cpa_pool_scan_workers", "号池巡检并发", "number"],
    ["cpa_pool_probe_timeout_sec", "号池 probe 超时秒", "number"],
    ["cpa_pool_probe_chat", "号池默认 probe chat", "bool"],
    ["cpa_pool_refresh_before_probe", "号池 probe 前临期续期", "bool"],
    ["cpa_pool_refresh_skew_sec", "号池续期提前秒", "number"],
    ["cpa_pool_max_items_per_scan", "单轮最多巡检(0全量)", "number"],
    ["cpa_pool_probe_proxy", "号池 probe 代理(direct/pool)", "proxy"],
    ["cpa_pool_history_limit", "每号巡检历史条数", "number"],
    ["cpa_pool_apply_policy", "号池自动治理", "bool"],
    ["cpa_pool_quarantine_dir", "号池隔离区目录", "text"],
    ["cpa_pool_move_with_backup", "隔离写 meta 记录", "bool"],
    ["cpa_pool_hard_bad_threshold", "硬坏阈值", "number"],
    ["cpa_pool_refresh_failed_threshold", "续期失败阈值", "number"],
    ["cpa_pool_invalid_threshold", "无效文件阈值", "number"],
    ["cpa_pool_no_grok45_threshold", "无4.5阈值", "number"],
    ["cpa_pool_soft_fail_threshold", "软失败阈值", "number"],
    ["cpa_pool_quota_threshold", "额度冷却阈值", "number"],
    ["cpa_pool_quota_cooldown_sec", "额度禁用冷却秒", "number"],
    ["cpa_pool_hard_bad_action", "硬坏动作 keep/disable/quarantine/delete", "text"],
    ["cpa_pool_refresh_failed_action", "续期失败动作", "text"],
    ["cpa_pool_invalid_action", "无效文件动作", "text"],
    ["cpa_pool_no_grok45_action", "无4.5动作", "text"],
    ["cpa_pool_soft_fail_action", "软失败动作", "text"],
    ["cpa_pool_quota_action", "额度动作", "text"],
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

function setView(view) {
  state.view = view;
  if (location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
  $$(".nav-item[data-view]").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === view));
  $$("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== view;
  });
  if (view === "accounts") loadAccounts().catch((e) => toast(e.message, true));
  if (view === "cpa") loadCpa().catch((e) => toast(e.message, true));
  if (view === "mail") loadMail().catch((e) => toast(e.message, true));
  if (view === "proxies") loadProxies().catch((e) => toast(e.message, true));
  if (view === "settings") loadConfig().catch((e) => toast(e.message, true));
}

function openJobs(open = true) {
  $("#job-drawer").classList.toggle("open", open);
  $("#job-drawer").setAttribute("aria-hidden", open ? "false" : "true");
  $("#drawer-backdrop").hidden = !open;
  if (open) loadJobs().catch((e) => toast(e.message, true));
}

/* ── overview / pipeline / active job ── */

function setBadge(sel, value) {
  const el = $(sel);
  const n = Number(value || 0);
  el.hidden = n <= 0;
  el.textContent = n > 999 ? "999+" : String(n);
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
  } else {
    $("#active-job-stats").innerHTML =
      statCell("成功", s.ok ?? 0, "ok") +
      statCell("失败", s.fail ?? 0, (s.fail ?? 0) > 0 ? "err" : "") +
      statCell("进度", `${s.done ?? 0}/${s.total ?? 0}`);
  }

  const pct = jobProgress(job);
  $("#active-job-progress").style.width = `${pct}%`;
  $("#active-job-progress-text").textContent = `${Math.round(pct)}%`;
}

/* ── live log ── */

function classifyLog(line) {
  if (/异常|失败|未成功|error|Traceback/i.test(line) || /\] ! /.test(line)) return "err";
  if (/注册成功|CPA auth|ok ->|moved ->|完成:|\+ /.test(line)) return "ok";
  if (/背压|重试|跳过|skipped|等待|retry/i.test(line)) return "warn";
  if (/===/.test(line)) return "hl";
  if (/cpa|mint|pkce|oidc|hotload/i.test(line)) return "cpa";
  return "";
}

function appendLogs(lines) {
  if (!lines || !lines.length) return;
  const panel = $("#live-log");
  const placeholder = panel.querySelector(".log-line.dim");
  if (placeholder && placeholder.textContent.startsWith("//")) placeholder.remove();
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    state.logCount += 1;
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
  while (state.logCount > 2000 && panel.firstChild) {
    panel.removeChild(panel.firstChild);
    state.logCount -= 1;
  }
  if ($("#log-autoscroll").checked) panel.scrollTop = panel.scrollHeight;
}

function resetLogs(msg = "// 等待任务启动，日志将实时输出在这里") {
  state.logCount = 1;
  $("#live-log").innerHTML = `<div class="log-line dim">${esc(msg)}</div>`;
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
    const scanStatus = scan.status || "";
    const scanPill = scanStatus
      ? `<span class="pill ${cpaPoolPill(scanStatus)}" title="${esc(scan.reason || "")}">${esc(statusText[scanStatus] || scanStatus)}</span>`
      : '<span class="pill idle">未巡检</span>';
    const expires = scan.expired || row.expired || "-";
    const refreshMark = scan.refreshed ? '<span class="chip">已续期</span>' : "";
    const actionMark = scan.action ? `<span class="chip">${esc(scan.action)}</span>` : "";
    const streak = scan.status_streak ? ` · 连续 ${scan.status_streak}` : "";
    const cool = scan.cool_until ? ` · 冷却到 ${scan.cool_until}` : "";
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
      <td><div class="scan-cell">${scanPill}${refreshMark}${actionMark}<small>${esc((scan.reason || "") + streak + cool)}</small></div></td>
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
    page: String(state.cpaPage),
    page_size: "50",
  });
  const [data] = await Promise.all([
    api(`/api/cpa?${params}`),
    loadCpaPoolStatus().catch(() => null),
    loadCpaPoolResults().catch(() => null),
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
  const running = Boolean(data.running);
  const total = Number(data.cpa_total ?? s.total ?? 0);
  const done = Number(progress.done ?? s.done ?? 0);
  const scanTotal = Number(progress.total ?? s.total ?? 0);
  const pct = scanTotal ? Math.min(100, (done / scanTotal) * 100) : 0;

  $("#cpa-pool-state").className = `pill ${running ? "running" : (s.finished_at || data.finished_at ? "completed" : "idle")}`;
  $("#cpa-pool-state").textContent = running ? "巡检中" : (s.finished_at || data.finished_at ? "已完成" : "未巡检");
  $("#cpa-pool-stop").disabled = !running;
  $("#cpa-pool-scan").disabled = running;
  $("#cpa-pool-total").textContent = total;
  $("#cpa-pool-ok").textContent = counts.ok || data.ok || 0;
  $("#cpa-pool-quota").textContent = counts.quota || data.quota || 0;
  $("#cpa-pool-bad").textContent = data.bad || 0;
  $("#cpa-pool-refreshed").textContent = s.refreshed || 0;
  $("#cpa-pool-results").textContent = data.results_total || 0;
  $("#cpa-pool-quarantine").textContent = data.quarantine_total || 0;
  $("#cpa-pool-progress").style.width = `${pct}%`;
  const next = data.next_scan_in_sec != null ? `${data.next_scan_in_sec}s` : "-";
  const elapsed = s.elapsed_sec != null ? ` · 耗时 ${s.elapsed_sec}s` : "";
  const actions = s.actions ? Object.entries(s.actions).map(([k, v]) => `${k}:${v}`).join(" ") : "";
  $("#cpa-pool-meta").innerHTML =
    `进度 <b>${done}/${scanTotal || total}</b>${elapsed} · 下次自动检查 ${esc(next)} · ` +
    `周期 <code>${esc((data.settings || {}).scan_interval_sec || 300)}s</code> · ` +
    `proxy <code>${esc((data.settings || {}).probe_proxy || "-")}</code> · ` +
    `治理 <code>${(data.settings || {}).apply_policy ? "ON" : "OFF"}</code>` +
    (actions ? ` · 动作 <code>${esc(actions)}</code>` : "");

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
  const sel = $("#reg-proxy-fixed");
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = state.proxies.length
    ? state.proxies.map((p) => `<option value="${esc(p.raw)}">${esc(p.masked)}</option>`).join("")
    : `<option value="">（代理池为空，请先导入）</option>`;
  if (prev && state.proxies.some((p) => p.raw === prev)) sel.value = prev;
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

function renderConfigForm() {
  const cfg = state.config || {};
  $("#settings-basic").innerHTML = CONFIG_FIELDS.basic
    .map(([key, label, type]) => fieldInput(key, label, type, cfg[key], cfg[`${key}__set`]))
    .join("");
  $("#settings-cpa").innerHTML = CONFIG_FIELDS.cpa
    .map(([key, label, type]) => fieldInput(key, label, type, cfg[key], cfg[`${key}__set`]))
    .join("");
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

const convertState = { file: null, lastUrl: null, lastName: "" };

function convertSetFile(file) {
  convertState.file = file || null;
  $("#convert-file-label").textContent = file
    ? `${file.name}（${(file.size / 1024).toFixed(1)} KB）`
    : "拖拽文件到这里，或点击选择";
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

async function runConvert() {
  if (!convertState.file) {
    toast("请先选择要转换的文件", true);
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
    convertDownload(blob, filename);
    $("#convert-result").hidden = false;
    $("#convert-result-name").textContent = filename;
    $("#convert-result-meta").textContent = `${(blob.size / 1024).toFixed(1)} KB · 已自动开始下载`;
    status.textContent = "";
    toast("转换完成，已开始下载");
  } catch (err) {
    status.textContent = "";
    toast(err.message, true);
  } finally {
    btn.disabled = false;
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
    state.overview = await api("/api/overview");
    renderOverview();
    if (state.view === "cpa") {
      const beforeRunning = Boolean(state.cpaPool && state.cpaPool.running);
      const status = await loadCpaPoolStatus().catch(() => null);
      if (beforeRunning && status && !status.running) {
        await loadCpaPoolResults().catch(() => {});
        await loadCpaQuarantine().catch(() => {});
        renderCpa();
      }
    }
    if (!state.activeJobId) return;
    const detail = await api(`/api/jobs/${state.activeJobId}?after=${state.logCursor}`);
    renderActiveJob(detail);
    if (detail.logs && detail.logs.length) appendLogs(detail.logs);
    state.logCursor = detail.log_seq || state.logCursor;
    if (["completed", "failed", "stopped"].includes(detail.status)) {
      if (state.view === "accounts") loadAccounts().catch(() => {});
      if (state.view === "cpa") loadCpa().catch(() => {});
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
  try {
    const job = await api("/api/jobs/register", { method: "POST", body: JSON.stringify(body) });
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
  $("#open-jobs").addEventListener("click", () => openJobs(true));
  $("#close-jobs").addEventListener("click", () => openJobs(false));
  $("#drawer-backdrop").addEventListener("click", () => openJobs(false));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $("#job-drawer").classList.contains("open")) openJobs(false);
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
    await loadCpaQuarantine().catch(() => {});
    renderCpa();
  });
  $("#cpa-pool-scan").addEventListener("click", async () => {
    const body = {
      trigger: "manual",
      scan_workers: Number($("#cpa-pool-workers").value || 16),
      limit: Number($("#cpa-pool-limit").value || 0),
      refresh_before_probe: $("#cpa-pool-refresh-before").checked,
      probe_chat: $("#cpa-pool-probe-chat").checked,
      apply_policy: $("#cpa-pool-apply-policy").checked,
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

  /* settings */
  $("#reload-config").addEventListener("click", () => loadConfig().catch((e) => toast(e.message, true)));
  $("#save-config").addEventListener("click", async () => {
    try {
      const payload = collectConfigFromForm();
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
  const hashView = location.hash.replace("#", "");
  if (hashView && document.querySelector(`[data-view-panel="${hashView}"]`)) setView(hashView);
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
