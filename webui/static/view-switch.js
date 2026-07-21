/* 统一三选一视图切换器:原始(/) / Soft UI(/dash) / 漫画(/dash?theme=comic)。
   - 新看板 dash.html:填充内联 #viewSwitch,Soft↔漫画 同页换 data-theme。
   - 原始 index.html:app.py 注入本脚本,这里自建一个浮动切换器(自带样式,不依赖 dash.css)。
   选择持久化在 localStorage(apc_view / apc_theme),刷新保持。 */
(function () {
  "use strict";
  var IS_DASH = !!document.getElementById("apc-dashboard");
  var OPTS = [["classic", "原始"], ["softui", "Soft UI"], ["comic", "漫画"]];

  function getTheme() {
    var t = document.documentElement.getAttribute("data-theme");
    return t === "comic" ? "comic" : "softui";
  }
  function currentView() { return IS_DASH ? getTheme() : "classic"; }
  function persist(view) {
    try {
      localStorage.setItem("apc_view", view);
      if (view === "softui" || view === "comic") localStorage.setItem("apc_theme", view);
    } catch (e) {}
  }
  function go(view) {
    if (view === currentView()) return;
    if (view === "classic") { persist("classic"); location.href = "/"; return; }
    if (IS_DASH) {
      document.documentElement.setAttribute("data-theme", view);
      persist(view);
      render();
      if (typeof window.__apcOnTheme === "function") window.__apcOnTheme(view);
    } else {
      persist(view);
      location.href = "/dash?theme=" + view;
    }
  }
  function buildInto(box) {
    var cur = currentView();
    box.innerHTML = OPTS.map(function (o) {
      return '<button type="button" class="view-opt' + (o[0] === cur ? " active" : "") +
        '" data-view="' + o[0] + '">' + o[1] + "</button>";
    }).join("");
    box.querySelectorAll(".view-opt").forEach(function (b) {
      b.addEventListener("click", function () { go(b.dataset.view); });
    });
  }
  function render() {
    var inline = document.getElementById("viewSwitch");
    if (inline) buildInto(inline);
    var floating = document.getElementById("apc-vs-float");
    if (floating) buildInto(floating);
  }
  function injectFloatingStyle() {
    if (document.getElementById("apc-vs-style")) return;
    var s = document.createElement("style");
    s.id = "apc-vs-style";
    s.textContent =
      "#apc-vs-float{position:fixed;right:18px;bottom:18px;z-index:9999;display:inline-flex;gap:4px;" +
      "padding:5px;border-radius:999px;background:rgba(255,255,255,.96);border:1px solid #e4e8f4;" +
      "box-shadow:0 10px 30px rgba(29,36,56,.22);backdrop-filter:blur(10px);font-family:Inter,'PingFang SC','Microsoft YaHei',sans-serif}" +
      "#apc-vs-float .view-opt{border:0;background:transparent;font-size:12px;font-weight:700;color:#5a6684;" +
      "padding:7px 14px;border-radius:999px;cursor:pointer;letter-spacing:.4px;transition:.18s}" +
      "#apc-vs-float .view-opt:hover{color:#1c2337}" +
      "#apc-vs-float .view-opt.active{background:linear-gradient(135deg,#7c5cf0,#0ea5e9);color:#fff;" +
      "box-shadow:0 4px 12px rgba(124,92,240,.4)}" +
      "#apc-vs-float::before{content:'视图';align-self:center;padding:0 6px 0 8px;font-size:10.5px;" +
      "font-weight:700;letter-spacing:.12em;color:#92a0bd}" +
      "@media(max-width:900px){#apc-vs-float{position:static;order:9;margin:0 0 0 auto;padding:3px;gap:2px;" +
      "box-shadow:none;backdrop-filter:none;background:#fff}#apc-vs-float::before{display:none}" +
      "#apc-vs-float .view-opt{padding:6px 9px;font-size:11px;letter-spacing:0}}";
    document.head.appendChild(s);
  }
  function ensureFloating() {
    if (IS_DASH || document.getElementById("viewSwitch")) return;
    if (document.getElementById("apc-vs-float")) return;
    injectFloatingStyle();
    var box = document.createElement("div");
    box.id = "apc-vs-float";
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", "视图切换(原始 / Soft UI / 漫画)");
    (document.querySelector(".side") || document.body).appendChild(box);
  }
  function init() { ensureFloating(); render(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
  window.__apcRenderViewSwitch = render;
})();
