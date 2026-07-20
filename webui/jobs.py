"""In-process job runner for register and CPA backfill."""

from __future__ import annotations

import queue
import random
import threading
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import store


MAX_REGISTER_THREADS = 100
MAX_BACKFILL_WORKERS = 20
MAX_BACKFILL_CONFIG_WORKERS = 8
DEFAULT_BACKFILL_WORKERS = 4


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_register_protocol_options(
    cfg: dict[str, Any], options: dict[str, Any]
) -> dict[str, Any]:
    """Apply WebUI console protocol switches to a per-job config.

    Precedence rule: the registration console is authoritative for this job;
    config.json only seeds the initial checkbox state in the browser.
    """
    has_protocol = "protocol_register" in options
    has_no_fallback = "protocol_no_browser_fallback" in options
    if not has_protocol and not has_no_fallback:
        return cfg

    protocol_enabled = (
        bool(options.get("protocol_register"))
        if has_protocol
        else bool(cfg.get("protocol_register", False))
    )
    no_browser_fallback = (
        bool(options.get("protocol_no_browser_fallback"))
        if has_no_fallback
        else bool(cfg.get("protocol_only", False))
        or not bool(cfg.get("protocol_register_fallback_browser", True))
    )

    cfg["protocol_register"] = protocol_enabled
    if protocol_enabled:
        cfg["protocol_only"] = no_browser_fallback
        cfg["protocol_register_fallback_browser"] = not no_browser_fallback
    else:
        # A stale no-fallback checkbox/config must not re-enable protocol.
        cfg["protocol_only"] = False
        cfg["protocol_register_fallback_browser"] = True
    return cfg


def _rotating_proxy_picker(
    pool: list[str],
    *,
    shuffle: Callable[[list[str]], None] | None = None,
) -> Callable[[], str]:
    """Return a thread-safe picker that uses every proxy once before repeating."""
    source = [str(x).strip() for x in pool if str(x).strip()]
    if not source:
        raise ValueError("代理池为空")
    shuffle = shuffle or random.shuffle
    lock = threading.Lock()
    deck: list[str] = []

    def _refill() -> None:
        deck[:] = source[:]
        shuffle(deck)

    def _pick() -> str:
        with lock:
            if not deck:
                _refill()
            return deck.pop(0)

    return _pick


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def resolve_backfill_workers(options: dict[str, Any], config: dict[str, Any]) -> int:
    """Resolve CPA backfill concurrency.

    options.workers:
      - -1: use config.cpa_mint_workers with a conservative cap, then auto
      - 1..20: fixed backfill concurrency

    Backfill may fall back to Chromium per worker, so it intentionally has a
    lower cap than registration/mint queue workers to avoid browser storms.
    """
    raw = _coerce_int(options.get("workers", -1), -1)
    if raw >= 0:
        return max(1, min(raw or 1, MAX_BACKFILL_WORKERS))

    cfg_v = _coerce_int(config.get("cpa_mint_workers", -1), -1)
    if cfg_v >= 0:
        return max(1, min(cfg_v or 1, MAX_BACKFILL_CONFIG_WORKERS))
    return DEFAULT_BACKFILL_WORKERS


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    options: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)
    error: str = ""
    created_at: str = field(default_factory=_utc_now)
    started_at: str = ""
    finished_at: str = ""
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=2000))
    log_seq: int = 0
    log_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = field(default=None, repr=False)

    def append_log(self, message: str) -> None:
        line = str(message).rstrip()
        if not line:
            return
        with self.log_lock:
            self.log_seq += 1
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] {line}")

    def public_dict(self, *, include_logs: bool = False, after: int = 0) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "options": dict(self.options),
            "stats": dict(self.stats),
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "log_seq": self.log_seq,
            "log_count": len(self.logs),
        }
        if include_logs:
            # after is number of log lines already consumed from the start of current buffer is hard;
            # expose absolute seq window by slicing from buffer end using log_seq delta.
            with self.log_lock:
                logs = list(self.logs)
                log_seq = self.log_seq
            if after > 0 and after < log_seq:
                # best-effort: take the newest (log_seq - after) lines
                take = max(0, log_seq - after)
                logs = logs[-take:] if take else []
            elif after >= log_seq:
                logs = []
            payload["logs"] = logs
        return payload


class JobRunner:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._order: deque[str] = deque(maxlen=100)
        self._active_id: str | None = None

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._jobs[jid].public_dict() for jid in list(self._order)[::-1] if jid in self._jobs]

    def get_job(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            return job

    def active_job(self) -> Job | None:
        with self._lock:
            if not self._active_id:
                return None
            return self._jobs.get(self._active_id)

    def _register_job(self, kind: str, options: dict[str, Any]) -> Job:
        with self._lock:
            if self._active_id:
                active = self._jobs.get(self._active_id)
                if active and active.status in {"queued", "running"}:
                    raise RuntimeError(f"已有任务进行中: {active.kind} ({active.id})")
            job = Job(id=uuid.uuid4().hex[:12], kind=kind, options=options)
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._active_id = job.id
            return job

    def stop_job(self, job_id: str) -> dict[str, Any]:
        job = self.get_job(job_id)
        if job.status not in {"queued", "running"}:
            return job.public_dict()
        job.cancel_event.set()
        job.append_log("收到停止请求")
        # best-effort browser teardown
        try:
            import grok_register_ttk as reg

            reg.shutdown_browser()
        except Exception:
            pass
        try:
            from cpa_xai.browser_confirm import shutdown_mint_browsers

            shutdown_mint_browsers()
        except Exception:
            pass
        return job.public_dict()

    def start_register(self, options: dict[str, Any]) -> dict[str, Any]:
        extra = max(0, int(options.get("extra") or 0))
        count = max(0, int(options.get("count") or 0))
        if extra <= 0 and count <= 0:
            raise ValueError("请指定 extra 或 count")
        threads = max(1, min(int(options.get("threads") or 1), MAX_REGISTER_THREADS))
        mint_workers = int(options.get("mint_workers", -1))
        mint_queue_max = int(options.get("mint_queue_max", -1))
        headless = bool(options.get("headless", False))
        fast = bool(options.get("fast", True))
        protocol_register = bool(options.get("protocol_register", False))
        protocol_no_browser_fallback = bool(
            options.get("protocol_no_browser_fallback", False)
        )
        proxy_mode = str(options.get("proxy_mode") or "config").strip().lower()
        if proxy_mode not in ("config", "fixed", "random"):
            raise ValueError("proxy_mode 必须是 config/fixed/random")
        proxy_fixed = str(options.get("proxy_fixed") or "").strip()
        if proxy_mode == "fixed":
            import proxy_pool

            if not proxy_pool.normalize_proxy_url(proxy_fixed):
                raise ValueError("固定代理格式无效")
        elif proxy_mode == "random":
            import proxy_pool

            if not proxy_pool.load_pool():
                raise ValueError("代理池为空，请先在代理池页面导入代理")
        job = self._register_job(
            "register",
            {
                "extra": extra,
                "count": count,
                "threads": threads,
                "mint_workers": mint_workers,
                "mint_queue_max": mint_queue_max,
                "headless": headless,
                "fast": fast,
                "protocol_register": protocol_register,
                "protocol_no_browser_fallback": protocol_no_browser_fallback,
                "proxy_mode": proxy_mode,
                "proxy_fixed": proxy_fixed,
            },
        )
        job.stats = {
            "reg_success": 0,
            "reg_fail": 0,
            "mint_success": 0,
            "mint_fail": 0,
            "mint_skip": 0,
            "target": 0,
            "done": 0,
        }
        t = threading.Thread(target=self._run_register, args=(job,), daemon=True, name=f"job-reg-{job.id}")
        job.thread = t
        t.start()
        return job.public_dict()

    def start_backfill(self, options: dict[str, Any]) -> dict[str, Any]:
        emails = [str(e).strip() for e in (options.get("emails") or []) if str(e).strip()]
        exclude_emails = [str(e).strip().lower() for e in (options.get("exclude_emails") or []) if str(e).strip()]
        limit = max(0, int(options.get("limit") or 0))
        probe = bool(options.get("probe", True))
        probe_chat = bool(options.get("probe_chat", False))
        browser_only = bool(options.get("browser_only", False))
        workers = _coerce_int(options.get("workers", -1), -1)
        workers = -1 if workers < 0 else max(1, min(workers or 1, MAX_BACKFILL_WORKERS))
        sleep_s = float(options.get("sleep") or 0)
        job = self._register_job(
            "backfill",
            {
                "emails": emails,
                "exclude_emails": exclude_emails,
                "limit": limit,
                "probe": probe,
                "probe_chat": probe_chat,
                "browser_only": browser_only,
                "workers": workers,
                "sleep": sleep_s,
            },
        )
        job.stats = {"ok": 0, "fail": 0, "total": 0, "done": 0, "workers": 0}
        t = threading.Thread(target=self._run_backfill, args=(job,), daemon=True, name=f"job-bf-{job.id}")
        job.thread = t
        t.start()
        return job.public_dict()

    def _finish(self, job: Job, status: str, error: str = "") -> None:
        job.status = status
        job.error = error
        job.finished_at = _utc_now()
        with self._lock:
            if self._active_id == job.id:
                self._active_id = None

    def _run_register(self, job: Job) -> None:
        import register_cli as cli
        import grok_register_ttk as reg

        job.status = "running"
        job.started_at = _utc_now()
        job.append_log("注册任务启动")

        # capture logs
        original_log = cli.log

        def log_sink(worker_id: int | str, msg: str) -> None:
            line = f"[W{worker_id}] {msg}"
            job.append_log(line)
            try:
                original_log(worker_id, msg)
            except Exception:
                pass

        cli.log = log_sink  # type: ignore[assignment]

        cancel = job.cancel_event.is_set
        proxy_mode = str(job.options.get("proxy_mode") or "config")
        orig_register_one = cli.register_one
        orig_run_mint_job = cli._run_mint_job

        try:
            reg.load_config()
            cfg = dict(getattr(reg, "config", {}) or {})
            cfg.update(store.load_config_raw())
            reg.config = cfg

            # 注册控制台的开关是任务级显式覆盖（以控制台为准）；
            # 配置中心只是默认值——控制台初始值从配置读取，启动时把选择显式传回。
            apply_register_protocol_options(cfg, job.options)

            # ── 代理模式 ──
            pool: list[str] = []
            if proxy_mode == "fixed":
                import proxy_pool as pp

                fixed_url = pp.effective_url(job.options.get("proxy_fixed"))
                cfg["proxy"] = fixed_url
                cfg["cpa_proxy"] = fixed_url
                job.append_log(f"代理模式: 固定 {pp.mask_proxy(fixed_url)}")
            elif proxy_mode == "random":
                import proxy_pool as pp

                total_pool = pp.load_pool()
                pool = pp.load_usable_pool()
                pick_proxy = _rotating_proxy_picker(pool)
                job.append_log(
                    f"代理模式: 随机轮换（池 {len(total_pool)} 个，可用 {len(pool)} 个，每账号无放回）"
                )
                # 全局留空，逐线程钉住，避免串号
                cfg["proxy"] = ""
                cfg["cpa_proxy"] = ""

                def register_one_proxy(*args, **kwargs):
                    raw = pick_proxy()
                    reg.set_thread_proxy(raw)
                    log_sink(0, f"[proxy] 本账号使用 {pp.mask_proxy(raw)}")
                    try:
                        result = orig_register_one(*args, **kwargs)
                        if isinstance(result, dict):
                            result["_proxy"] = reg.get_thread_proxy()
                        return result
                    finally:
                        reg.clear_thread_proxy()
                        # 浏览器在启动时固化代理，下个账号必须全新进程
                        try:
                            reg.TabPool.release_tab()
                        except Exception:
                            pass

                def run_mint_job_proxy(worker_id, mint_job, config_):
                    px = mint_job.get("_proxy") if isinstance(mint_job, dict) else None
                    if not px:
                        return orig_run_mint_job(worker_id, mint_job, config_)
                    cfg2 = dict(config_)
                    cfg2["cpa_proxy"] = px
                    try:
                        from cpa_xai.proxyutil import set_runtime_proxy
                    except Exception:
                        set_runtime_proxy = None
                    if set_runtime_proxy:
                        set_runtime_proxy(px)
                    try:
                        return orig_run_mint_job(worker_id, mint_job, cfg2)
                    finally:
                        if set_runtime_proxy:
                            set_runtime_proxy(None)

                cli.register_one = register_one_proxy  # type: ignore[assignment]
                cli._run_mint_job = run_mint_job_proxy  # type: ignore[assignment]

            if job.options.get("headless"):
                cfg["register_headless"] = True
            else:
                # keep config value unless explicitly false via options
                if "headless" in job.options:
                    cfg["register_headless"] = bool(job.options.get("headless"))

            threads = int(job.options["threads"])
            fast = bool(job.options.get("fast", True))
            mint_workers = cli.resolve_mint_workers(
                cli_value=int(job.options.get("mint_workers", -1)),
                threads=threads,
                config=cfg,
                inline_mint=False,
            )
            do_mint_inline = mint_workers == 0
            mint_queue_cli_value = int(job.options.get("mint_queue_max", -1))
            mint_qmax = cli.resolve_mint_queue_max(
                cfg,
                mint_workers,
                cli_value=(None if mint_queue_cli_value < 0 else mint_queue_cli_value),
            )
            start_interval = cli.resolve_thread_start_interval(cfg)

            reg.configure_perf(
                fast=fast,
                sleep_scale=0.15 if fast else 1.0,
                skip_debug_io=fast,
                cookie_snapshot=not fast,
                async_side_effects=True,
                # 随机代理模式：每个账号独立浏览器进程（代理在启动时固化）
                browser_reuse=proxy_mode != "random",
                browser_recycle_every=25,
            )

            accounts_file = str(store.accounts_file(cfg))
            done_count = 0
            if Path(accounts_file).exists():
                with open(accounts_file, encoding="utf-8") as f:
                    done_count = sum(1 for line in f if line.strip())

            extra = int(job.options.get("extra") or 0)
            count = int(job.options.get("count") or 0)
            if extra > 0:
                target_total = done_count + extra
                remaining = extra
            elif count > 0:
                target_total = count
                remaining = max(0, count - done_count)
            else:
                raise ValueError("extra/count 无效")

            job.stats["target"] = remaining
            job.append_log(
                f"已有 {done_count}，目标新增 {remaining}，threads={threads}, "
                f"mint_workers={mint_workers}, mint_queue_max={mint_qmax}, "
                f"start_interval={start_interval:g}s, "
                f"protocol_register={bool(cfg.get('protocol_register', False))}"
            )
            if remaining <= 0:
                job.append_log("无需注册")
                self._finish(job, "completed")
                return

            if cancel():
                self._finish(job, "stopped")
                return

            # reset cli stats
            with cli._stats_lock:
                for k in list(cli._stats.keys()):
                    cli._stats[k] = 0

            if not cli._use_protocol_register():
                try:
                    reg.TabPool.init(reg.create_browser_options, log_callback=lambda m: log_sink(0, m))
                except Exception as exc:
                    raise RuntimeError(f"浏览器初始化失败: {exc}") from exc

            task_queue: queue.Queue = queue.Queue()
            mint_queue: queue.Queue | None = queue.Queue() if not do_mint_inline else None
            if mint_queue is not None:
                mint_queue._reg_qmax = mint_qmax  # type: ignore[attr-defined]

            cli._next_idx[0] = done_count + 1
            for i in range(done_count + 1, target_total + 1):
                task_queue.put(i)

            mint_threads: list[threading.Thread] = []
            if mint_queue is not None and mint_workers > 0:
                for i in range(1, mint_workers + 1):
                    wid = f"M{i}"
                    t = threading.Thread(
                        target=cli._mint_worker,
                        args=(wid, mint_queue, cfg),
                        daemon=True,
                        name=f"mint-{i}",
                    )
                    t.start()
                    mint_threads.append(t)

            reg_threads: list[threading.Thread] = []
            for wid in range(1, threads + 1):
                t = threading.Thread(
                    target=cli._register_worker,
                    args=(
                        wid,
                        task_queue,
                        target_total,
                        accounts_file,
                        mint_queue,
                        False,
                        do_mint_inline,
                        cancel,
                    ),
                    daemon=True,
                    name=f"reg-{wid}",
                )
                t.start()
                reg_threads.append(t)
                if wid < threads and start_interval > 0:
                    reg.sleep_with_cancel(start_interval, cancel)
                    if cancel():
                        break

            # progress poller
            while any(t.is_alive() for t in reg_threads):
                with cli._stats_lock:
                    job.stats.update(dict(cli._stats))
                    job.stats["done"] = int(cli._stats.get("reg_success", 0)) + int(
                        cli._stats.get("reg_fail", 0)
                    )
                if cancel():
                    job.append_log("停止中：等待 worker 退出")
                    break
                time.sleep(0.5)

            for t in reg_threads:
                t.join(timeout=5)

            if mint_queue is not None:
                if not cancel():
                    job.append_log("等待 mint 队列清空...")
                    # join with cancel awareness
                    while mint_queue.unfinished_tasks:  # type: ignore[attr-defined]
                        if cancel():
                            break
                        time.sleep(0.3)
                for _ in mint_threads:
                    mint_queue.put(cli._MINT_STOP)
                for t in mint_threads:
                    t.join(timeout=30)

            try:
                reg.shutdown_browser()
            except Exception:
                pass
            try:
                from cpa_xai.browser_confirm import shutdown_mint_browsers

                shutdown_mint_browsers()
            except Exception:
                pass

            with cli._stats_lock:
                job.stats.update(dict(cli._stats))
                job.stats["done"] = int(cli._stats.get("reg_success", 0)) + int(
                    cli._stats.get("reg_fail", 0)
                )

            if cancel():
                self._finish(job, "stopped")
                job.append_log("注册任务已停止")
            else:
                self._finish(job, "completed")
                job.append_log(
                    "完成: "
                    f"reg_ok={job.stats.get('reg_success', 0)} "
                    f"reg_fail={job.stats.get('reg_fail', 0)} "
                    f"mint_ok={job.stats.get('mint_success', 0)} "
                    f"mint_fail={job.stats.get('mint_fail', 0)}"
                )
        except Exception as exc:
            job.append_log(f"注册任务异常: {exc}")
            traceback.print_exc()
            self._finish(job, "failed", str(exc))
        finally:
            cli.log = original_log  # type: ignore[assignment]
            cli.register_one = orig_register_one  # type: ignore[assignment]
            cli._run_mint_job = orig_run_mint_job  # type: ignore[assignment]

    def _run_backfill(self, job: Job) -> None:
        from cpa_xai import existing_cpa_emails, mint_and_export, parse_accounts_file

        job.status = "running"
        job.started_at = _utc_now()
        job.append_log("CPA 补 mint 任务启动")
        cancel = job.cancel_event.is_set
        try:
            cfg = store.load_config_raw()
            accounts_path = store.accounts_file(cfg)
            out_dir = store.cpa_dir(cfg)
            hot_dir = store.hotload_dir(cfg)
            proxy = (cfg.get("cpa_proxy") or cfg.get("proxy") or "").strip() or None
            if proxy:
                import proxy_pool as pp

                proxy = pp.resolve_special(proxy) or None  # pool:random 等配置特殊值
            protocol_flow = str(cfg.get("cpa_protocol_flow") or "pkce").strip().lower()
            if protocol_flow not in {"pkce", "device"}:
                protocol_flow = "pkce"
            allow_device = bool(cfg.get("cpa_allow_device_flow_fallback", False))
            protocol_only = bool(cfg.get("cpa_protocol_only", False))
            protocol_poll = float(cfg.get("cpa_protocol_poll_timeout_sec", 90) or 90)
            try:
                protocol_network_retries = int(cfg.get("cpa_pkce_network_retries", 1) or 0)
            except (TypeError, ValueError):
                protocol_network_retries = 1
            try:
                protocol_network_retry_delay = float(cfg.get("cpa_pkce_network_retry_delay_sec", 1.5) or 1.5)
            except (TypeError, ValueError):
                protocol_network_retry_delay = 1.5
            timeout = float(cfg.get("cpa_mint_timeout_sec", 300) or 300)
            headless = bool(cfg.get("cpa_headless", False))

            accounts = parse_accounts_file(accounts_path)
            emails = [e.lower() for e in job.options.get("emails") or []]
            exclude_emails = {e.lower() for e in job.options.get("exclude_emails") or []}
            if emails:
                accounts = [a for a in accounts if a.email.lower() in set(emails)]

            have = set()
            if not emails:
                have |= {e.lower() for e in existing_cpa_emails(out_dir)}
                if hot_dir:
                    have |= {e.lower() for e in existing_cpa_emails(hot_dir)}

            todo = []
            for acc in accounts:
                if not emails and acc.email.lower() in exclude_emails:
                    continue
                if not emails and acc.email.lower() in have:
                    continue
                if not acc.sso and not acc.password:
                    continue
                todo.append(acc)
                limit = int(job.options.get("limit") or 0)
                if limit and len(todo) >= limit:
                    break

            job.stats["total"] = len(todo)
            out_dir.mkdir(parents=True, exist_ok=True)
            if hot_dir:
                hot_dir.mkdir(parents=True, exist_ok=True)
            workers = min(resolve_backfill_workers(job.options, cfg), max(1, len(todo) or 1))
            job.stats["workers"] = workers
            sleep_s = float(job.options.get("sleep") or 0)
            probe_enabled = bool(job.options.get("probe", True))
            probe_chat_enabled = bool(job.options.get("probe_chat", False))
            job.append_log(
                f"待处理 {len(todo)} 个账号，workers={workers}, probe={probe_enabled}, "
                f"probe_chat={probe_chat_enabled}, sleep={sleep_s:g}s, "
                f"exclude={len(exclude_emails) if not emails else 0}, out={out_dir}"
            )

            proxy_raw = (cfg.get("cpa_proxy") or cfg.get("proxy") or "").strip()
            proxy_fixed = proxy
            proxy_picker = None
            if proxy_raw:
                try:
                    import proxy_pool as pp

                    if proxy_raw == getattr(pp, "POOL_RANDOM", "pool:random"):
                        pool = pp.load_usable_pool()
                        if pool:
                            proxy_picker = _rotating_proxy_picker(pool)
                            proxy_fixed = None
                            job.append_log(f"CPA 代理: pool:random 可用 {len(pool)} 个，每账号轮换")
                        else:
                            proxy_fixed = None
                            job.append_log("CPA 代理: pool:random 但代理池为空，改为直连")
                except Exception as exc:
                    job.append_log(f"CPA 代理池解析失败，使用固定/直连: {exc}")

            work_q: queue.Queue = queue.Queue()
            for item in enumerate(todo, 1):
                work_q.put(item)
            stats_lock = threading.Lock()

            def account_proxy():
                if proxy_picker is None:
                    return proxy_fixed
                try:
                    import proxy_pool as pp

                    return pp.effective_url(proxy_picker()) or None
                except Exception:
                    return None

            def record_result(ok: bool, message: str) -> None:
                with stats_lock:
                    job.stats["done"] = int(job.stats.get("done", 0)) + 1
                    if ok:
                        job.stats["ok"] = int(job.stats.get("ok", 0)) + 1
                    else:
                        job.stats["fail"] = int(job.stats.get("fail", 0)) + 1
                if message:
                    job.append_log(message)

            def worker_loop(worker_id: int) -> None:
                try:
                    while not cancel():
                        try:
                            i, acc = work_q.get_nowait()
                        except queue.Empty:
                            break
                        try:
                            job.append_log(f"=== [B{worker_id}] [{i}/{len(todo)}] {acc.email} ===")

                            def log_cb(msg: str, _email=acc.email) -> None:
                                job.append_log(f"[B{worker_id}] [{_email}] {msg}")

                            result = mint_and_export(
                                email=acc.email,
                                password=acc.password,
                                auth_dir=str(out_dir),
                                page=None,
                                proxy=account_proxy(),
                                headless=headless,
                                probe=probe_enabled,
                                probe_chat=probe_chat_enabled,
                                browser_timeout_sec=timeout,
                                force_standalone=True,
                                sso=acc.sso or None,
                                prefer_protocol=not bool(job.options.get("browser_only", False)),
                                protocol_flow=protocol_flow,
                                allow_device_flow_fallback=allow_device,
                                protocol_only=protocol_only,
                                protocol_poll_timeout_sec=protocol_poll,
                                protocol_network_retries=protocol_network_retries,
                                protocol_network_retry_delay_sec=protocol_network_retry_delay,
                                log=log_cb,
                                cancel=cancel,
                            )
                            if result.get("ok") and result.get("path"):
                                path = Path(result["path"])
                                if hot_dir and bool(cfg.get("cpa_copy_to_hotload", True)):
                                    import os
                                    import shutil

                                    dst = hot_dir / path.name
                                    shutil.move(str(path), str(dst))
                                    try:
                                        os.chmod(dst, 0o600)
                                    except Exception:
                                        pass
                                    record_result(True, f"[B{worker_id}] moved -> {dst}")
                                else:
                                    record_result(True, f"[B{worker_id}] ok -> {path}")
                            else:
                                record_result(
                                    False,
                                    f"[B{worker_id}] fail: {result.get('error') or result}",
                                )
                        except Exception as exc:
                            record_result(False, f"[B{worker_id}] fail: {exc}")
                            traceback.print_exc()
                        finally:
                            try:
                                work_q.task_done()
                            except Exception:
                                pass
                        if sleep_s > 0 and not cancel():
                            time.sleep(sleep_s)
                finally:
                    try:
                        from cpa_xai.browser_confirm import shutdown_mint_browsers

                        shutdown_mint_browsers()
                    except Exception:
                        pass

            threads: list[threading.Thread] = []
            for wid in range(1, workers + 1):
                t = threading.Thread(target=worker_loop, args=(wid,), daemon=True, name=f"bf-mint-{wid}")
                t.start()
                threads.append(t)
            for t in threads:
                t.join()

            try:
                from cpa_xai.browser_confirm import shutdown_mint_browsers

                shutdown_mint_browsers()
            except Exception:
                pass

            if cancel():
                self._finish(job, "stopped")
            else:
                self._finish(job, "completed")
                job.append_log(
                    f"补 mint 完成 ok={job.stats.get('ok', 0)} fail={job.stats.get('fail', 0)}"
                )
        except Exception as exc:
            job.append_log(f"补 mint 异常: {exc}")
            traceback.print_exc()
            self._finish(job, "failed", str(exc))


runner = JobRunner()

__all__ = ["Job", "JobRunner", "runner"]
