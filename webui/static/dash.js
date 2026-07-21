/* 新看板数据逻辑 —— 接本仓库自己的 API(webui/app.py):
   /api/overview, /api/cpa, /api/cpa/pool/status|scan|stop, /api/config, /api/jobs/register|backfill
   Soft UI / 漫画 两主题共用本脚本(只切 CSS,数据一致)。 */
"use strict";
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var GAUGE_C = 402.12;
  var CPA_PAGE = 1, CPA_STATUS = "all", CPA_QUERY = "";
  var lastPool = {}, lastOverview = {};

  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  function toast(msg, kind) {
    var t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.textContent = msg;
    $("toast").appendChild(t);
    setTimeout(function () { t.remove(); }, 3200);
  }
  function fmtDur(sec) {
    sec = Math.max(0, sec | 0);
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (h > 0) return h + "时" + m + "分";
    return m > 0 ? m + "分" + s + "秒" : s + "秒";
  }
  function num(v) { return v == null ? "–" : v; }
  async function api(path, opts) {
    var r = await fetch(path, opts);
    if (!r.ok) throw new Error(await r.text());
    var ct = r.headers.get("content-type") || "";
    return ct.indexOf("json") >= 0 ? r.json() : r.text();
  }

  /* 主题切换后重渲染切换器高亮 */
  window.__apcOnTheme = function () { if (window.__apcRenderViewSwitch) window.__apcRenderViewSwitch(); };

  /* 点击弹跳(漫画主题) */
  document.addEventListener("click", function (e) {
    var b = e.target.closest(".btn,.tab,.view-opt");
    if (!b) return;
    b.classList.remove("boom"); void b.offsetWidth; b.classList.add("boom");
    setTimeout(function () { b.classList.remove("boom"); }, 380);
  });

  /* ---------- 渲染:概览 ---------- */
  function renderStats(ov, pool) {
    var p = pool.pool || {};
    var defs = [
      ["文件库存", num(p.file_inventory != null ? p.file_inventory : pool.cpa_total), "c-accent"],
      ["CLI 已加载", num(p.cli_loaded), "c-new"],
      ["主力可路由", num(p.main_routeable != null ? p.main_routeable : pool.ok), "c-ok"],
      ["备用账号", num(p.reserve), "c-accent"],
      ["候选/观察", num((p.candidate || 0) + (p.observe || 0)), "c-warn"],
      ["冷却账号", num(p.cooling != null ? p.cooling : pool.quota), "c-cool"],
      ["隔离账号", num(p.quarantine != null ? p.quarantine : pool.quarantine_total), "c-bad"],
      ["上游状态", p.upstream_state === "open" ? "熔断" : "正常", p.upstream_state === "open" ? "c-bad" : "c-ok"],
    ];
    $("stats").innerHTML = defs.map(function (d) {
      return '<div class="stat ' + d[2] + '"><i class="chip"></i><div class="n">' + d[1] + '</div><div class="k">' + d[0] + "</div></div>";
    }).join("");
  }
  function renderHero(ov, pool) {
    var p = pool.pool || {};
    var okv = Number(p.main_routeable != null ? p.main_routeable : pool.ok) || 0;
    var cpaTotal = Number(p.file_inventory != null ? p.file_inventory : (pool.cpa_total != null ? pool.cpa_total : ov.cpa_total)) || 0;
    $("gOk").textContent = okv;
    $("gTotal").textContent = cpaTotal;
    $("hAccounts").textContent = num(ov.accounts_total);
    $("hHotload").textContent = num(ov.cpa_hotload);
    $("hQuar").textContent = num(pool.quarantine_total);
    var ratio = cpaTotal > 0 ? Math.min(1, okv / cpaTotal) : 0;
    $("gaugeArc").style.strokeDashoffset = (GAUGE_C * (1 - ratio)).toFixed(2);
    var hf = $("healthFill");
    hf.style.width = (ratio * 100).toFixed(0) + "%";
    hf.className = "fill " + (ratio >= 0.85 ? "good" : ratio >= 0.5 ? "mid" : "low");
    var act = $("activityText");
    act.textContent = pool.running ? "巡检中…" : (pool.last_error ? ("上次异常:" + pool.last_error) : "空闲 · 等待下次巡检");
    act.classList.toggle("busy", !!pool.running);
  }
  function renderStatusCard(ov, pool, cfg) {
    $("scanState").textContent = pool.running ? "运行中" : "空闲";
    var pg = pool.progress || {};
    $("scanProgress").textContent = (pg.total ? (pg.done || 0) + " / " + pg.total : "—");
    var p = pool.pool || {};
    $("lastSummary").textContent = "主力 " + num(p.main_routeable) + " · 备用 " + num(p.reserve) + " · 冷却 " + num(p.cooling);
    var ar = cfg ? !!cfg.cpa_pool_auto_refill : null;
    $("autoRefill").textContent = ar == null ? "—" : (ar ? "开" : "关");
    $("cpaProxy").textContent = ov.cpa_proxy || "direct";
    $("healthDot").className = "dot " + (pool.running ? "busy" : "live");
    window.__next = pool.next_scan_in_sec;
    window.__nextTs = Date.now();
    window.__busy = !!pool.running;
    var bar = $("scanBar");
    if (bar) bar.style.width = (pg.total ? Math.min(100, Math.round((pg.done || 0) / pg.total * 100)) : 0) + "%";
    $("stopBtn").disabled = !pool.running;
  }
  function renderJob(ov) {
    var job = ov.active_job;
    if (!job) {
      $("jobIdle").hidden = false; $("jobDetail").hidden = true; return;
    }
    $("jobIdle").hidden = true; $("jobDetail").hidden = false;
    var st = String(job.status || "queued");
    $("jobStatus").className = "pill " + st;
    $("jobStatus").textContent = st;
    $("jobKind").textContent = (job.kind || "") + " · " + (job.id || "").slice(0, 8);
    var stats = job.stats || {};
    var keys = Object.keys(stats).filter(function (k) { return k !== "workers"; });
    $("jobStats").innerHTML = keys.slice(0, 6).map(function (k) {
      return '<div class="job-stat"><small>' + esc(k) + "</small><b>" + esc(stats[k]) + "</b></div>";
    }).join("") || '<div class="muted">运行中…</div>';
    var done = Number(stats.done) || 0, total = Number(stats.target || stats.total) || 0;
    $("jobBar").style.width = (total ? Math.min(100, Math.round(done / total * 100)) : 8) + "%";
  }

  /* ---------- CPA 明细 ---------- */
  var CPA_TABS = [["all", "全部"], ["main", "主力"], ["reserve", "备用"], ["observe", "观察"], ["quota", "冷却"], ["bad", "异常"], ["unchecked", "未巡检"]];
  function renderCpaTabs() {
    $("cpaTabs").innerHTML = CPA_TABS.map(function (t) {
      return '<button type="button" class="tab' + (t[0] === CPA_STATUS ? " active" : "") + '" data-st="' + t[0] + '">' + t[1] + "</button>";
    }).join("");
    $("cpaTabs").querySelectorAll(".tab").forEach(function (b) {
      b.addEventListener("click", function () { CPA_STATUS = b.dataset.st; CPA_PAGE = 1; loadCpa(); });
    });
  }
  async function loadCpa() {
    renderCpaTabs();
    try {
      var d = await api("/api/cpa?page=" + CPA_PAGE + "&page_size=50&status=" + encodeURIComponent(CPA_STATUS) + "&query=" + encodeURIComponent(CPA_QUERY));
      $("cpaCount").textContent = d.total + " 个";
      $("cpaPageLabel").textContent = d.page + " / " + d.total_pages;
      $("cpaPrev").disabled = d.page <= 1;
      $("cpaNext").disabled = d.page >= d.total_pages;
      $("cpaBody").innerHTML = (d.items || []).map(function (it) {
        var scan = String(it.health_status || it.scan_status || "unchecked");
        var tier = String(it.pool_tier || "candidate");
        var cls = scan.replace(/[^a-z0-9_]/gi, "") || "unchecked";
        return "<tr><td class=email title='" + esc(it.email) + "'>" + esc(it.email) + "</td>" +
          "<td><span class='pill " + cls + "' title='" + esc(it.scan_reason || "") + "'>" + esc(tier + " / " + scan) + "</span></td>" +
          "<td>" + esc(it.mint_method || "—") + "</td>" +
          "<td>" + esc(it.location || "—") + "</td>" +
          "<td>" + esc(it.expired || "—") + "</td>" +
          "<td>" + esc(it.mtime_iso || "—") + "</td></tr>";
      }).join("") || "<tr><td colspan=6 class=muted style='padding:22px;text-align:center'>空</td></tr>";
    } catch (e) {
      $("cpaBody").innerHTML = "<tr><td colspan=6 class=muted style='padding:22px;text-align:center'>加载失败</td></tr>";
    }
  }
  window.cpaPage = function (delta) { CPA_PAGE = Math.max(1, CPA_PAGE + delta); loadCpa(); };

  /* ---------- 配置 ---------- */
  var lastCfg = null;
  async function loadConfig() {
    try {
      var c = await api("/api/config");
      lastCfg = c;
      setIfBlur("setInterval", c.cpa_pool_scan_interval_sec);
      setIfBlur("setWorkers", c.cpa_pool_scan_workers);
      setIfBlur("setRefillTarget", c.cpa_pool_refill_target_active);
      setIfBlur("setRefillMax", c.cpa_pool_refill_max_per_scan);
      if (document.activeElement !== $("setAutoScan")) $("setAutoScan").checked = !!c.cpa_pool_auto_scan;
      if (document.activeElement !== $("setAutoRefill")) $("setAutoRefill").checked = !!c.cpa_pool_auto_refill;
    } catch (e) {}
  }
  function setIfBlur(id, v) { var el = $(id); if (el && document.activeElement !== el && v != null) el.value = v; }
  window.saveConfig = async function () {
    var body = {
      cpa_pool_scan_interval_sec: +$("setInterval").value || 300,
      cpa_pool_scan_workers: +$("setWorkers").value || 16,
      cpa_pool_refill_target_active: +$("setRefillTarget").value || 0,
      cpa_pool_refill_max_per_scan: +$("setRefillMax").value || 30,
      cpa_pool_auto_scan: $("setAutoScan").checked,
      cpa_pool_auto_refill: $("setAutoRefill").checked,
    };
    try {
      await api("/api/config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      toast("设置已保存", "ok"); loadConfig();
    } catch (e) { toast("保存失败", "bad"); }
  };

  /* ---------- 操作 ---------- */
  window.doScan = async function () {
    var b = $("scanBtn"); b.disabled = true;
    try { await api("/api/cpa/pool/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ trigger: "manual" }) }); toast("已触发巡检", "ok"); }
    catch (e) { toast("触发失败(可能已在巡检)", "bad"); }
    setTimeout(function () { b.disabled = false; refreshAll(); }, 1200);
  };
  window.doStop = async function () {
    try { await api("/api/cpa/pool/stop", { method: "POST" }); toast("已请求停止", "ok"); }
    catch (e) { toast("停止失败", "bad"); }
    setTimeout(refreshStatus, 800);
  };
  window.doRegister = async function () {
    var body = { extra: +$("regExtra").value || 1, threads: +$("regThreads").value || 1 };
    try { await api("/api/jobs/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); toast("已启动注册任务", "ok"); }
    catch (e) { toast("启动失败(可能已有任务在跑)", "bad"); }
    setTimeout(refreshStatus, 900);
  };
  window.doBackfill = async function () {
    try { await api("/api/jobs/backfill", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) }); toast("已启动补 CPA 任务", "ok"); }
    catch (e) { toast("启动失败(可能已有任务在跑)", "bad"); }
    setTimeout(refreshStatus, 900);
  };

  /* ---------- 轮询 ---------- */
  async function refreshStatus() {
    try {
      var ov = await api("/api/overview");
      lastOverview = ov;
      var pool = {};
      try { pool = await api("/api/cpa/pool/status"); } catch (e) {}
      lastPool = pool;
      renderStats(ov, pool);
      renderHero(ov, pool);
      renderStatusCard(ov, pool, lastCfg);
      renderJob(ov);
      $("updated").textContent = "已更新 · " + new Date().toLocaleTimeString();
    } catch (e) {
      $("updated").textContent = "连接失败";
      $("healthDot").className = "dot";
    }
  }
  async function refreshLog() {
    try {
      var pool = await api("/api/cpa/pool/status");
      var logs = pool.logs || [];
      var text = logs.map(function (l) { return typeof l === "string" ? l : JSON.stringify(l); }).join("\n");
      var el = $("log");
      var atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 30;
      el.textContent = text || "(暂无巡检日志)";
      if (atBottom) el.scrollTop = el.scrollHeight;
    } catch (e) {}
  }
  window.refreshAll = function () { refreshStatus(); loadCpa(); refreshLog(); };

  /* CPA 搜索(防抖) */
  var searchTimer = null;
  document.addEventListener("input", function (e) {
    if (e.target && e.target.id === "cpaSearch") {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(function () { CPA_QUERY = e.target.value.trim(); CPA_PAGE = 1; loadCpa(); }, 350);
    }
  });

  /* 倒计时 tick */
  setInterval(function () {
    var el = $("countdown");
    if (window.__busy) { el.textContent = "巡检中…"; return; }
    if (window.__next == null) { el.textContent = "—"; return; }
    var left = window.__next - Math.floor((Date.now() - window.__nextTs) / 1000);
    el.textContent = left > 0 ? fmtDur(left) : "即将开始…";
  }, 1000);

  /* 启动 */
  loadConfig();
  refreshAll();
  setInterval(function () { if (!document.hidden) refreshStatus(); }, 5000);
  setInterval(function () { if (!document.hidden) loadCpa(); }, 9000);
  setInterval(function () { if (!document.hidden) refreshLog(); }, 5000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refreshAll(); });
})();
