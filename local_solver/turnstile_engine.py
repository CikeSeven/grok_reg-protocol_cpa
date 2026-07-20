# -*- coding: utf-8 -*-
"""
本地免费 Turnstile 引擎 v7.2（更像真人的无头/离屏方案）
关键：用系统 Chrome + CDP 连接，不要用 patchright 直接 launch（易 600010）
流程：启动/连接 Chrome(remote debugging) → 打开 accounts.x.ai → render sitekey → 点 checkbox → 取 token

模式（SOLVER_BROWSER_MODE / headless 参数）：
- headed   : 可见窗口（最稳）
- offscreen: 有头但窗口移出屏幕（推荐“无界面”，仍非 headless）
- headless : Chrome --headless=new + 人性化鼠标/指纹（成功率仍不确定）

环境变量：
- SOLVER_BROWSER_MODE=headed|offscreen|headless
- SOLVER_HEADLESS=true/false（兼容旧配置；true 约等于 headless）
- SOLVER_RESTART_CDP=true  强制重启 CDP Chrome
- SOLVER_HUMANIZE=true     启用人性化鼠标/预热（默认 true）
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform as _platform
import random
import re
import shutil
import socket
import subprocess
import time
import uuid
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse

logger = logging.getLogger("TurnstileEngine")

DEBUG_PORT = int(os.getenv("SOLVER_CDP_PORT", "9222") or "9222")
PROFILE_DIR = Path(os.getcwd()) / ".solver_chrome_cdp_profile"
HEADLESS_PROFILE_DIR = Path(os.getcwd()) / ".solver_chrome_cdp_profile_headless"
OFFSCREEN_PROFILE_DIR = Path(os.getcwd()) / ".solver_chrome_cdp_profile_offscreen"

# Prefer real residential/local app proxies over accidental local tools (e.g. mitm 8080)
_SCAN_PROXY_PORTS = (7897, 7890, 7891, 10808, 10809, 20171, 20172, 1080, 8888)
_SOLVER_SCREEN_PROFILES = ((1366, 768), (1440, 900), (1536, 864), (1600, 900), (1920, 1080))


def _normalize_mode(mode: Optional[str] = None, headless: Optional[bool] = None) -> str:
    """Return headed | offscreen | headless."""
    raw = (mode or os.getenv("SOLVER_BROWSER_MODE") or "").strip().lower()
    if raw in {"headed", "headful", "gui", "visible"}:
        return "headed"
    if raw in {"offscreen", "virtual", "hidden", "background"}:
        return "offscreen"
    if raw in {"headless", "hl"}:
        return "headless"

    # compatibility: SOLVER_HEADLESS / function arg
    if headless is None and os.getenv("SOLVER_HEADLESS") is not None:
        headless = _env_bool("SOLVER_HEADLESS", False)
    if headless is True:
        # allow SOLVER_HEADLESS=true + SOLVER_BROWSER_MODE=offscreen to prefer offscreen
        if raw == "offscreen":
            return "offscreen"
        return "headless"
    if headless is False:
        return "headed"
    return "headed"


def _profile_for_mode(mode: str) -> Path:
    if mode == "headless":
        return HEADLESS_PROFILE_DIR
    if mode == "offscreen":
        return OFFSCREEN_PROFILE_DIR
    return PROFILE_DIR


def _worker_profile(mode: str, worker_id: int) -> Path:
    base = _profile_for_mode(mode)
    return Path(str(base) + f"_w{worker_id}")


@dataclass
class ChromeWorker:
    worker_id: int
    port: int
    mode: str
    profile: Path
    proxy: Optional[str] = None
    pid: Optional[int] = None


class ChromeWorkerPool:
    """Isolated Chrome workers (one CDP port + profile each).

    Prevents concurrent tasks from sharing the same page/token state.
    """

    def __init__(self):
        self.size = 1
        self.mode = "offscreen"
        self.base_port = DEBUG_PORT
        self.proxy: Optional[str] = None
        self.workers: List[ChromeWorker] = []
        self._queue: Optional[asyncio.Queue] = None
        self._init_lock = asyncio.Lock()
        self._ready = False

    async def ensure(self, size: int, mode: str, proxy: Optional[str] = None) -> None:
        async with self._init_lock:
            size = max(1, min(int(size or 1), 16))
            mode = _normalize_mode(mode, None)
            proxy = pick_live_proxy(proxy)
            need_rebuild = (
                not self._ready
                or self.size != size
                or self.mode != mode
                or (
                    proxy
                    and proxy != self.proxy
                    and (
                        self.proxy is None
                        or _env_bool("SOLVER_REBUILD_ON_PROXY_CHANGE", False)
                    )
                )
            )
            if not need_rebuild:
                if proxy and self.proxy and proxy != self.proxy:
                    logger.warning(
                        "solver pool already bound to proxy %s; requested %s ignored "
                        "(set SOLVER_REBUILD_ON_PROXY_CHANGE=1 only for low concurrency)",
                        (parse_proxy(self.proxy) or {}).get("server"),
                        (parse_proxy(proxy) or {}).get("server"),
                    )
                alive = True
                for w in self.workers:
                    if not _probe_port("127.0.0.1", w.port) or not _pid_alive(w.pid):
                        alive = False
                        break
                if alive:
                    return

            # rebuild from clean state
            self.shutdown()
            self.size = size
            self.mode = mode
            self.proxy = proxy
            self.base_port = int(os.getenv("SOLVER_CDP_PORT", "9222") or "9222")
            self.workers = []
            # purge any leftover solver chrome before rebuild
            _cleanup_all_solver_chrome()
            for i in range(size):
                port = self.base_port + i
                profile = _worker_profile(mode, i)
                ok, pid = ensure_chrome_cdp(
                    proxy=proxy,
                    headless=(mode == "headless"),
                    mode=mode,
                    port=port,
                    profile_dir=profile,
                    worker_id=i,
                )
                if not ok:
                    logger.error("worker %s failed to start on port %s", i, port)
                    continue
                worker = ChromeWorker(
                    worker_id=i,
                    port=port,
                    mode=mode,
                    profile=profile,
                    proxy=proxy,
                    pid=pid,
                )
                self.workers.append(worker)
            if not self.workers:
                self._ready = False
                raise RuntimeError("No Chrome workers started")
            self._queue = asyncio.Queue()
            for w in self.workers:
                await self._queue.put(w)
            self._ready = True
            logger.info(
                "Chrome worker pool ready size=%s mode=%s ports=%s",
                len(self.workers),
                mode,
                [w.port for w in self.workers],
            )

    def _stop_all_workers(self) -> None:
        ports = [self.base_port + i for i in range(max(self.size, 1))]
        for w in self.workers:
            if w.port not in ports:
                ports.append(w.port)
            # Kill full tree for tracked root/listener and any descendants.
            if w.pid:
                for child in list(_collect_descendant_pids(w.pid)):
                    _kill_pid_tree(child)
                _kill_pid_tree(w.pid)
        for port in ports:
            _stop_cdp_chrome(port=port)
        self.workers = []
        self._queue = None
        self._ready = False

    def shutdown(self) -> None:
        """Public cleanup used on solver exit."""
        try:
            self._stop_all_workers()
        finally:
            # Second pass: sweep any leaked solver chrome by profile/port markers.
            _cleanup_all_solver_chrome()
            # Brief settle so ports/taskbar icons release before process exits.
            time.sleep(0.3)
            _cleanup_all_solver_chrome()
            logger.info("Chrome worker pool shutdown complete")

    async def acquire(self, timeout: float = 120.0) -> ChromeWorker:
        if not self._ready or self._queue is None:
            raise RuntimeError("Worker pool not initialized")
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError("No free Chrome worker (timeout)")

    async def release(self, worker: ChromeWorker) -> None:
        if self._queue is not None:
            await self._queue.put(worker)


_WORKER_POOL = ChromeWorkerPool()


def get_worker_pool() -> ChromeWorkerPool:
    return _WORKER_POOL


async def init_worker_pool(
    size: int = 1,
    mode: Optional[str] = None,
    proxy: Optional[str] = None,
) -> None:
    mode = _normalize_mode(mode or os.getenv("SOLVER_BROWSER_MODE"), None)
    size = int(os.getenv("SOLVER_WORKERS", str(size)) or size)
    await _WORKER_POOL.ensure(size=size, mode=mode, proxy=proxy)


def shutdown_worker_pool() -> None:
    _WORKER_POOL.shutdown()




def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _profile_dir(headless: bool) -> Path:
    return _profile_for_mode("headless" if headless else "headed")


def _chrome_cmd_contains(pid: int, needle: str) -> bool:
    try:
        import psutil  # optional

        proc = psutil.Process(pid)
        cmd = " ".join(proc.cmdline()).lower()
        return needle.lower() in cmd
    except Exception:
        pass

    if os.name != "nt":
        try:
            raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").lower()
            return needle.lower() in cmd
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["ps", "-p", str(int(pid)), "-o", "command="],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            return needle.lower() in (out or "").lower()
        except Exception:
            return False
    try:
        import subprocess as sp

        out = sp.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine",
            ],
            text=True,
            stderr=sp.DEVNULL,
            timeout=3,
        )
        return needle.lower() in (out or "").lower()
    except Exception:
        return False


def _find_listener_pids(port: int) -> List[int]:
    """Return process ids listening on a TCP port."""
    port = int(port)
    pids: List[int] = []

    def add(pid: int) -> None:
        if pid > 0 and pid not in pids:
            pids.append(pid)

    if os.name != "nt":
        # ss output example:
        # users:(("chrome",pid=1087013,fd=89))
        try:
            out = subprocess.check_output(
                ["ss", "-ltnp", f"sport = :{port}"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for m in re.finditer(r"\bpid=(\d+)", out or ""):
                add(int(m.group(1)))
        except Exception:
            pass

        # lsof -t prints one pid per line.
        if not pids:
            try:
                out = subprocess.check_output(
                    ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
                for line in (out or "").splitlines():
                    line = line.strip()
                    if line.isdigit():
                        add(int(line))
            except Exception:
                pass

        # fuser output can include the queried port; ignore that value.
        if not pids:
            try:
                out = subprocess.check_output(
                    ["fuser", "-n", "tcp", str(port)],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
                for m in re.finditer(r"\b(\d+)\b", out or ""):
                    pid = int(m.group(1))
                    if pid != port:
                        add(pid)
            except Exception:
                pass

        return pids

    try:
        import subprocess as sp

        out = sp.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"$c=Get-NetTCPConnection -LocalPort {port} -State Listen "
                    "-ErrorAction SilentlyContinue | Select-Object -First 1;"
                    "if($c){$c.OwningProcess}"
                ),
            ],
            text=True,
            stderr=sp.DEVNULL,
            timeout=3,
        ).strip()
        if out.isdigit():
            add(int(out))
    except Exception:
        pass
    return pids


def _find_listener_pid(port: int) -> Optional[int]:
    pids = _find_listener_pids(port)
    return pids[0] if pids else None


def _running_cdp_is_headless(port: Optional[int] = None) -> Optional[bool]:
    """Return True/False if we can detect current CDP chrome headless mode; else None."""
    cdp_port = int(port or DEBUG_PORT)
    pid = _find_listener_pid(cdp_port)
    if not pid:
        return None
    if _chrome_cmd_contains(pid, "--headless"):
        return True
    try:
        import subprocess as sp

        out = sp.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
                    "Select-Object -ExpandProperty CommandLine"
                ),
            ],
            text=True,
            stderr=sp.DEVNULL,
            timeout=5,
        )
        lines = [ln for ln in (out or "").splitlines() if f"--remote-debugging-port={cdp_port}" in ln]
        if not lines:
            lines = [ln for ln in (out or "").splitlines() if "--remote-debugging-port=" in ln]
        if not lines:
            return None
        joined = "\n".join(lines).lower()
        return "--headless" in joined
    except Exception:
        return None


def _stop_cdp_chrome(port: Optional[int] = None) -> None:
    """Best-effort stop Chrome that owns a CDP debug port / solver profiles."""
    port = int(port or DEBUG_PORT)
    pids = set()
    pids.update(_find_listener_pids(port))

    if os.name == "nt":
        try:
            import subprocess as sp

            out = sp.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
                        "ForEach-Object { if ($_.CommandLine -and ("
                        f"$_.CommandLine -like '*--remote-debugging-port={port}*' -or "
                        "$_.CommandLine -like '*solver_chrome_cdp_profile*'"
                        ")) { $_.ProcessId } }"
                    ),
                ],
                text=True,
                stderr=sp.DEVNULL,
                timeout=5,
            )
            for line in (out or "").splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.add(int(line))
        except Exception as e:
            logger.warning("enumerate chrome for stop failed: %s", e)

    for p in sorted(pids):
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(p), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                os.kill(p, 15)
            logger.info("stopped CDP chrome pid=%s port=%s", p, port)
        except Exception as e:
            logger.warning("stop chrome pid=%s failed: %s", p, e)

    for _ in range(20):
        if not _probe_port("127.0.0.1", port):
            break
        time.sleep(0.25)


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        if os.name == "nt":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, int(pid))
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _kill_pid_tree(pid: Optional[int]) -> None:
    if not pid:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.kill(int(pid), 15)
        logger.info("killed chrome pid tree=%s", pid)
    except Exception as e:
        logger.debug("kill pid %s failed: %s", pid, e)


def _cleanup_all_solver_chrome() -> None:
    """Kill every chrome started by this project (solver profiles / cdp ports)."""
    pids = set()
    base = int(os.getenv("SOLVER_CDP_PORT", "9222") or "9222")
    for port in range(base, base + 16):
        pids.update(_find_listener_pids(port))
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
                        "ForEach-Object { if ($_.CommandLine -and ("
                        "$_.CommandLine -like '*solver_chrome_cdp_profile*' -or "
                        "$_.CommandLine -like '*--remote-debugging-port=922*'"
                        ")) { $_.ProcessId } }"
                    ),
                ],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=6,
            )
            for line in (out or "").splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.add(int(line))
        except Exception as e:
            logger.debug("cleanup enumerate failed: %s", e)
    else:
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid=,cmd="],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=6,
            )
            watched_ports = [f"--remote-debugging-port={p}" for p in range(base, base + 16)]
            for line in (out or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                pid_s, _, cmd = line.partition(" ")
                if not pid_s.isdigit():
                    continue
                lower = cmd.lower()
                if "chrome" not in lower and "chromium" not in lower:
                    continue
                if "solver_chrome_cdp_profile" in cmd or any(marker in cmd for marker in watched_ports):
                    pids.add(int(pid_s))
        except Exception as e:
            logger.debug("cleanup enumerate failed: %s", e)
    expanded = set()
    for pid in sorted(pids):
        expanded.update(_collect_descendant_pids(pid))
        expanded.add(pid)
    for pid in sorted(expanded):
        _kill_pid_tree(pid)
    for port in range(base, base + 16):
        for _ in range(10):
            if not _probe_port("127.0.0.1", port):
                break
            time.sleep(0.15)


def _collect_descendant_pids(root_pid: int) -> set:
    """Collect process tree PIDs for a Chrome launcher root."""
    pids = {int(root_pid)}
    if os.name != "nt":
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid=,ppid="],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            children = {}
            for line in (out or "").splitlines():
                parts = line.split()
                if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
                    continue
                cpid = int(parts[0])
                ppid = int(parts[1])
                children.setdefault(ppid, []).append(cpid)
            stack = [int(root_pid)]
            while stack:
                cur = stack.pop()
                for child in children.get(cur, []):
                    if child not in pids:
                        pids.add(child)
                        stack.append(child)
        except Exception:
            pass
        return pids
    try:
        # Walk parent/child relation iteratively in Python to avoid nested-quote hell.
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Csv -NoTypeInformation",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        children = {}
        for line in (out or "").splitlines()[1:]:
            line = line.strip().strip('"')
            if not line:
                continue
            # CSV like: "123","456"
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) < 2:
                continue
            if not parts[0].isdigit():
                continue
            cpid = int(parts[0])
            ppid = int(parts[1]) if parts[1].isdigit() else -1
            children.setdefault(ppid, []).append(cpid)
        stack = [int(root_pid)]
        while stack:
            cur = stack.pop()
            for child in children.get(cur, []):
                if child not in pids:
                    pids.add(child)
                    stack.append(child)
    except Exception:
        pass
    return pids


def _hide_chrome_windows_for_pid(pid: Optional[int]) -> None:
    """Hide taskbar/windows for offscreen workers on Windows."""
    if not pid or os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        SW_HIDE = 0
        GWL_EXSTYLE = -20
        WS_EX_TOOLWINDOW = 0x00000080
        WS_EX_APPWINDOW = 0x00040000
        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        pids = _collect_descendant_pids(int(pid))

        def _cb(hwnd, _lparam):
            proc_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))
            if proc_id.value not in pids:
                return True
            # Hide both visible and cloaked/taskbar windows.
            try:
                style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                style = (style | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW
                user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
            except Exception:
                pass
            user32.ShowWindow(hwnd, SW_HIDE)
            try:
                user32.SetWindowPos(hwnd, 0, -32000, -32000, 0, 0, 0x0015)  # NOMOVE? NOSIZE+NOZORDER+NOACTIVATE+SHOWWINDOW-ish
            except Exception:
                pass
            return True

        user32.EnumWindows(EnumWindowsProc(_cb), 0)
    except Exception as e:
        logger.debug("hide chrome windows failed: %s", e)


async def _cleanup_context_pages(context, keep_blank: bool = True) -> None:
    """Close leftover pages so workers don't accumulate tabs/windows."""
    try:
        pages = list(context.pages)
    except Exception:
        return
    blank = None
    for page in pages:
        try:
            url = ""
            try:
                url = page.url or ""
            except Exception:
                url = ""
            if keep_blank and blank is None and (not url or url.startswith("about:blank")):
                blank = page
                continue
            await page.close()
        except Exception:
            pass
    if keep_blank and blank is None:
        try:
            blank = await context.new_page()
            await blank.goto("about:blank", wait_until="domcontentloaded", timeout=10000)
        except Exception:
            pass


def _probe_port(host: str, port: int, timeout: float = 0.35) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _windows_system_proxy() -> Optional[str]:
    if os.name != "nt":
        return None
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        try:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        finally:
            winreg.CloseKey(key)
        if not enable or not server:
            return None
        server = str(server).strip()
        if "=" in server:
            parts = {}
            for item in server.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    parts[k.strip().lower()] = v.strip()
            server = (
                parts.get("https")
                or parts.get("http")
                or next(iter(parts.values()), "")
            )
        if not server:
            return None
        if "://" not in server:
            server = "http://" + server
        return server
    except Exception:
        return None


def load_proxy_list() -> List[str]:
    proxies: List[str] = []

    def add(val: str):
        val = (val or "").strip().lstrip("\ufeff")
        if not val:
            return
        if "://" not in val:
            val = "http://" + val
        if val not in proxies:
            proxies.append(val)

    proxy_file = os.path.join(os.getcwd(), "proxies.txt")
    if os.path.exists(proxy_file):
        try:
            with open(proxy_file, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip().lstrip("\ufeff")
                    if not line or line.startswith("#"):
                        continue
                    add(line)
        except Exception as e:
            logger.warning("read proxies.txt failed: %s", e)

    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY"):
        add(os.getenv(key) or "")
    sys_proxy = _windows_system_proxy()
    if sys_proxy:
        add(sys_proxy)
    # scanned local ports are lowest priority and exclude common mitm/debug ports
    for port in _SCAN_PROXY_PORTS:
        if _probe_port("127.0.0.1", port):
            add(f"http://127.0.0.1:{port}")
    return proxies


def parse_proxy(proxy: Optional[str]) -> Optional[Dict[str, Any]]:
    if not proxy:
        return None
    proxy = proxy.strip().lstrip("\ufeff")
    if "://" not in proxy:
        proxy = "http://" + proxy
    try:
        u = urlparse(proxy)
        if not u.hostname or not u.port:
            return {"server": proxy}
        conf: Dict[str, Any] = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
        if u.username:
            conf["username"] = u.username
        if u.password:
            conf["password"] = u.password
        return conf
    except Exception:
        return {"server": proxy}


def chrome_proxy_server_arg(proxy_conf: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Build a Chrome --proxy-server value from a parsed proxy config.

    Requests/httpx commonly use ``socks5h://`` to mean "resolve DNS through the
    proxy". Chrome does DNS-through-proxy for SOCKS5 but does not accept the
    literal ``socks5h`` scheme, which produces net::ERR_NO_SUPPORTED_PROXIES.
    """
    server = str((proxy_conf or {}).get("server") or "").strip()
    if not server:
        return None
    try:
        raw = server if "://" in server else "http://" + server
        u = urlparse(raw)
        host = u.hostname
        port = u.port
        if not host:
            return server
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        hostport = f"{host}:{port}" if port else host
        scheme = (u.scheme or "http").lower()
        if scheme in {"http", "https"}:
            # Keep previous behavior: bare host:port means an HTTP proxy.
            return hostport
        if scheme in {"socks5h", "socks5", "socks"}:
            return f"socks5://{hostport}"
        if scheme in {"socks4a", "socks4"}:
            return f"socks4://{hostport}"
        logger.warning("unsupported proxy scheme for Chrome: %s", scheme)
        return hostport
    except Exception:
        return server


def pick_live_proxy(preferred: Optional[str] = None) -> Optional[str]:
    candidates: List[str] = []
    if preferred:
        candidates.append(preferred)
    for p in load_proxy_list():
        if p not in candidates:
            candidates.append(p)
    for raw in candidates:
        conf = parse_proxy(raw)
        if not conf:
            continue
        try:
            u = urlparse(conf["server"])
            host = u.hostname or "127.0.0.1"
            port = u.port
            if port and _probe_port(host, port, timeout=0.35):
                return raw
        except Exception:
            continue
    return None


def find_chrome() -> Optional[str]:
    env_cands = [
        os.getenv("CHROME_BIN"),
        os.getenv("GOOGLE_CHROME_SHIM"),
        os.getenv("CHROMIUM_BIN"),
    ]
    path_cands = [
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("chrome"),
    ]
    cands = env_cands + path_cands + [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def _installed_chrome_version() -> str:
    chrome = find_chrome()
    if not chrome:
        return ""
    try:
        out = subprocess.check_output(
            [chrome, "--version"],
            timeout=5,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out or "")
        if m:
            return m.group(1)
        m = re.search(r"(\d+)(?:\.\d+)*", out or "")
        if m:
            return m.group(1) + ".0.0.0"
    except Exception:
        pass
    return ""


def _env_int(name: str, default: int) -> int:
    try:
        raw = os.getenv(name)
        if raw is None or str(raw).strip() == "":
            return default
        return int(str(raw).strip())
    except Exception:
        return default


def _parse_viewport(raw: str | None) -> tuple[int, int] | None:
    if not raw:
        return None
    m = re.match(r"^\s*(\d{3,5})\s*[x,]\s*(\d{3,5})\s*$", raw)
    if not m:
        return None
    width, height = int(m.group(1)), int(m.group(2))
    if width < 800 or height < 600:
        return None
    return width, height


def build_solver_fingerprint(
    *,
    locale: Optional[str] = None,
    timezone: Optional[str] = None,
    accept_language: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a self-consistent desktop Chrome fingerprint for the solver."""
    full_version = (
        os.getenv("SOLVER_CHROME_VERSION", "").strip()
        or _installed_chrome_version()
        or "138.0.0.0"
    )
    major = (full_version.split(".")[0] or "138").strip()
    full_version = full_version if "." in full_version else f"{full_version}.0.0.0"

    platform_name = os.getenv("SOLVER_UA_PLATFORM", "").strip()
    if not platform_name:
        platform_name = "Windows" if os.name == "nt" else "Linux"
    if platform_name.lower().startswith("win"):
        platform_name = "Windows"
        navigator_platform = "Win32"
        platform_version = "15.0.0"
        ua_os = "Windows NT 10.0; Win64; x64"
        webgl_vendor = "Google Inc. (Intel)"
        webgl_renderer = "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    else:
        platform_name = "Linux"
        navigator_platform = "Linux x86_64"
        platform_version = _platform.release().split("-")[0] or "6.0.0"
        ua_os = "X11; Linux x86_64"
        webgl_vendor = "Intel Open Source Technology Center"
        webgl_renderer = "Mesa Intel(R) UHD Graphics 620 (KBL GT2)"

    ua = os.getenv("SOLVER_USER_AGENT", "").strip()
    if not ua or f"Chrome/{major}" not in ua:
        ua = (
            f"Mozilla/5.0 ({ua_os}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{full_version} Safari/537.36"
        )

    locale = (locale or os.getenv("SOLVER_LOCALE") or "en-US").strip() or "en-US"
    lang_root = locale.split("-", 1)[0]
    languages = [locale] + ([lang_root] if lang_root and lang_root != locale else [])
    accept_language = (
        accept_language
        or os.getenv("SOLVER_ACCEPT_LANGUAGE")
        or f"{locale},{lang_root};q=0.9,en;q=0.8"
    )
    timezone = (timezone or os.getenv("SOLVER_TIMEZONE") or "").strip()
    width, height = _parse_viewport(os.getenv("SOLVER_VIEWPORT")) or random.choice(_SOLVER_SCREEN_PROFILES)
    hardware = _env_int("SOLVER_HARDWARE_CONCURRENCY", random.choice((4, 8, 12)))
    memory = _env_int("SOLVER_DEVICE_MEMORY", random.choice((4, 8)))
    brands = [
        {"brand": "Chromium", "version": major},
        {"brand": "Google Chrome", "version": major},
        {"brand": "Not_A Brand", "version": "99"},
    ]
    full_version_list = [
        {"brand": "Chromium", "version": full_version},
        {"brand": "Google Chrome", "version": full_version},
        {"brand": "Not_A Brand", "version": "99.0.0.0"},
    ]
    return {
        "user_agent": ua,
        "major": major,
        "full_version": full_version,
        "platform": platform_name,
        "navigator_platform": navigator_platform,
        "platform_version": platform_version,
        "language": locale,
        "languages": languages,
        "accept_language": accept_language,
        "timezone": timezone,
        "width": width,
        "height": height,
        "hardware_concurrency": hardware,
        "device_memory": memory,
        "webgl_vendor": os.getenv("SOLVER_WEBGL_VENDOR", "").strip() or webgl_vendor,
        "webgl_renderer": os.getenv("SOLVER_WEBGL_RENDERER", "").strip() or webgl_renderer,
        "metadata": {
            "brands": brands,
            "fullVersionList": full_version_list,
            "fullVersion": full_version,
            "platform": platform_name,
            "platformVersion": platform_version,
            "architecture": "x86",
            "model": "",
            "mobile": False,
            "bitness": "64",
            "wow64": False,
        },
    }


def ensure_chrome_cdp(
    proxy: Optional[str] = None,
    headless: bool = False,
    mode: Optional[str] = None,
    port: Optional[int] = None,
    profile_dir: Optional[Path] = None,
    worker_id: Optional[int] = None,
) -> bool:
    """Ensure a real Chrome is listening on remote debugging port.

    mode:
      - headed: visible window
      - offscreen: headed but off-screen (best "no UI" compromise)
      - headless: Chrome --headless=new
    """
    mode = _normalize_mode(mode, headless)
    cdp_port = int(port or DEBUG_PORT)
    if profile_dir is None:
        if worker_id is None:
            profile_dir = _profile_for_mode(mode)
        else:
            profile_dir = _worker_profile(mode, int(worker_id))

    if _probe_port("127.0.0.1", cdp_port):
        running_headless = _running_cdp_is_headless(cdp_port)
        # offscreen is still headed chrome process
        want_headless = mode == "headless"
        mode_ok = running_headless is not None and running_headless == want_headless
        force_restart = _env_bool("SOLVER_RESTART_CDP", False)
        if mode_ok and not force_restart:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{cdp_port}/json/version", timeout=1.5
                ) as r:
                    data = json.loads(r.read().decode("utf-8", errors="replace"))
                    logger.info(
                        "reuse CDP chrome: %s running_headless=%s requested_mode=%s port=%s",
                        data.get("Browser"),
                        running_headless,
                        mode,
                        cdp_port,
                    )
                    pid = _find_listener_pid(cdp_port)
                    if mode == "offscreen":
                        _hide_chrome_windows_for_pid(pid)
                    return True, pid
            except Exception:
                pass
        else:
            logger.info(
                "restart CDP chrome (running_headless=%s requested_mode=%s force=%s)",
                running_headless,
                mode,
                force_restart,
            )
            _stop_cdp_chrome(port=cdp_port)

    chrome = find_chrome()
    if not chrome:
        logger.error("Chrome not found")
        return False, None

    profile = Path(profile_dir)
    profile.mkdir(parents=True, exist_ok=True)
    proxy_conf = parse_proxy(proxy) if proxy else parse_proxy(pick_live_proxy())
    fp = build_solver_fingerprint()

    # Keep flags conservative: extra "automation" flags can hurt Turnstile.
    args = [
        chrome,
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={str(profile)}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-popup-blocking",
        "--disable-dev-shm-usage",
        f"--lang={fp['language']}",
        f"--accept-lang={fp['accept_language']}",
        "--disable-features=TranslateUI",
        "--disable-blink-features=AutomationControlled",
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding",
        "--disable-backgrounding-occluded-windows",
        "--password-store=basic",
    ]

    if os.name != "nt" and (
        (hasattr(os, "geteuid") and os.geteuid() == 0)
        or _env_bool("SOLVER_NO_SANDBOX", False)
    ):
        args.append("--no-sandbox")

    if mode == "headless":
        args.extend(
            [
                "--headless=new",
                "--window-size=1920,1080",
                "--hide-scrollbars",
                "--mute-audio",
                # avoid --disable-gpu: can make headless more detectable / less stable
            ]
        )
    elif mode == "offscreen":
        width, height = int(fp["width"]), int(fp["height"])
        if os.getenv("DISPLAY") and _env_bool("SOLVER_OFFSCREEN_IN_XVFB_AS_HEADED", False):
            # In Xvfb there is no real desktop to hide from. Negative window
            # coordinates can leak through window.screenX/screenY, so keep it
            # as a normal headed desktop window inside the virtual display.
            args.extend([f"--window-size={width},{height}", "--window-position=40,40"])
        else:
            # Headed chrome process, but not visible to user.
            # This often bypasses headless fingerprints better than --headless=new.
            args.extend(
                [
                    f"--window-size={width},{height}",
                    "--window-position=-32000,-32000",
                    "--start-minimized",
                    "--no-startup-window",
                ]
            )
    else:
        width, height = int(fp["width"]), int(fp["height"])
        args.extend(
            [
                f"--window-size={width},{height}",
                "--window-position=40,40",
            ]
        )

    # NOTE: avoid unsupported automation flags that trigger banner and may hurt CF
    args.append("about:blank")

    if proxy_conf and proxy_conf.get("server"):
        server = chrome_proxy_server_arg(proxy_conf)
        if server:
            args.insert(-1, f"--proxy-server={server}")

    logger.info(
        "starting real Chrome CDP on port %s mode=%s profile=%s proxy=%s worker=%s",
        cdp_port,
        mode,
        profile.name,
        (proxy_conf or {}).get("server"),
        worker_id,
    )
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    pid = proc.pid
    for _ in range(50):
        time.sleep(0.4)
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{cdp_port}/json/version", timeout=1
            ) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
                # Prefer the process actually listening on CDP (child of launcher).
                listener_pid = _find_listener_pid(cdp_port) or pid
                if listener_pid and listener_pid != pid:
                    logger.info(
                        "CDP root pid=%s listener pid=%s port=%s",
                        pid,
                        listener_pid,
                        cdp_port,
                    )
                    pid = listener_pid
                logger.info(
                    "CDP ready: %s mode=%s port=%s pid=%s",
                    data.get("Browser"),
                    mode,
                    cdp_port,
                    pid,
                )
                if mode == "offscreen":
                    for _hide_try in range(3):
                        _hide_chrome_windows_for_pid(pid)
                        time.sleep(0.2)
                return True, pid
        except Exception:
            continue
    logger.error("CDP not ready (mode=%s port=%s)", mode, cdp_port)
    _kill_pid_tree(pid)
    return False, None




def _bezier_points(x0, y0, x1, y1, steps: int = 20):
    """Generate human-ish cubic bezier mouse path points."""
    # random control points
    cx1 = x0 + (x1 - x0) * random.uniform(0.15, 0.45) + random.uniform(-40, 40)
    cy1 = y0 + (y1 - y0) * random.uniform(0.05, 0.35) + random.uniform(-30, 30)
    cx2 = x0 + (x1 - x0) * random.uniform(0.55, 0.85) + random.uniform(-40, 40)
    cy2 = y0 + (y1 - y0) * random.uniform(0.65, 0.95) + random.uniform(-30, 30)
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = (
            u * u * u * x0
            + 3 * u * u * t * cx1
            + 3 * u * t * t * cx2
            + t * t * t * x1
        )
        y = (
            u * u * u * y0
            + 3 * u * u * t * cy1
            + 3 * u * t * t * cy2
            + t * t * t * y1
        )
        pts.append((x, y))
    return pts


async def human_move_to(page, x: float, y: float, steps: int = 18) -> None:
    try:
        # approximate current mouse; patchright may not expose it, start from random
        sx = random.uniform(80, 420)
        sy = random.uniform(80, 320)
        pts = _bezier_points(sx, sy, x, y, steps=max(8, steps))
        for px, py in pts:
            await page.mouse.move(px, py)
            await page.wait_for_timeout(random.randint(8, 28))
    except Exception as e:
        logger.debug("human_move_to err: %s", e)


async def human_click_box(page, box: Dict[str, float], bias_left: bool = True) -> bool:
    """Click inside a box with human path + small random offset."""
    try:
        if not box:
            return False
        if bias_left:
            # checkbox is usually near left of turnstile widget
            tx = box["x"] + min(max(12.0, box["width"] * random.uniform(0.10, 0.22)), box["width"] - 4)
        else:
            tx = box["x"] + box["width"] * random.uniform(0.35, 0.65)
        ty = box["y"] + box["height"] * random.uniform(0.40, 0.62)
        await human_move_to(page, tx, ty, steps=random.randint(14, 26))
        await page.wait_for_timeout(random.randint(60, 180))
        await page.mouse.down()
        await page.wait_for_timeout(random.randint(35, 90))
        await page.mouse.up()
        return True
    except Exception as e:
        logger.debug("human_click_box err: %s", e)
        return False


def build_stealth_init_js(fp: Mapping[str, Any] | Dict[str, Any]) -> str:
    languages = list(fp.get("languages") or ["en-US", "en"])
    language = str(fp.get("language") or languages[0] or "en-US")
    navigator_platform = str(fp.get("navigator_platform") or "Linux x86_64")
    hardware = int(fp.get("hardware_concurrency") or 8)
    memory = int(fp.get("device_memory") or 8)
    webgl_vendor = str(fp.get("webgl_vendor") or "Intel Open Source Technology Center")
    webgl_renderer = str(fp.get("webgl_renderer") or "Mesa Intel(R) UHD Graphics 620 (KBL GT2)")
    user_agent = str(fp.get("user_agent") or "")
    metadata = fp.get("metadata") or {}
    script = """
(() => {
  try {
    const fp = {
      languages: __LANGUAGES__,
      language: __LANGUAGE__,
      platform: __PLATFORM__,
      hardwareConcurrency: __HARDWARE__,
      deviceMemory: __MEMORY__,
      webglVendor: __WEBGL_VENDOR__,
      webglRenderer: __WEBGL_RENDERER__,
      userAgent: __USER_AGENT__,
      userAgentData: __UA_DATA__
    };
    const define = (target, name, value) => {
      try { Object.defineProperty(target, name, { get: () => value, configurable: true }); } catch (e) {}
    };

    Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => undefined, configurable: true });
    try { delete Object.getPrototypeOf(navigator).webdriver; } catch (e) {}

    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) {
      window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {},
        id: undefined
      };
    }

    define(navigator, 'languages', fp.languages);
    define(navigator, 'language', fp.language);
    define(navigator, 'platform', fp.platform);
    define(navigator, 'hardwareConcurrency', fp.hardwareConcurrency);
    define(navigator, 'deviceMemory', fp.deviceMemory);
    define(navigator, 'maxTouchPoints', 0);
    if (fp.userAgent) define(navigator, 'userAgent', fp.userAgent);
    if (fp.userAgentData && fp.userAgentData.brands) {
      const uaData = {
        brands: fp.userAgentData.brands,
        mobile: false,
        platform: fp.userAgentData.platform || 'Linux',
        getHighEntropyValues: async (hints) => ({
          brands: fp.userAgentData.brands,
          mobile: false,
          platform: fp.userAgentData.platform || 'Linux',
          architecture: fp.userAgentData.architecture || 'x86',
          bitness: fp.userAgentData.bitness || '64',
          model: '',
          platformVersion: fp.userAgentData.platformVersion || '',
          uaFullVersion: fp.userAgentData.fullVersion || '',
          fullVersionList: fp.userAgentData.fullVersionList || []
        }),
        toJSON: () => ({ brands: fp.userAgentData.brands, mobile: false, platform: fp.userAgentData.platform || 'Linux' })
      };
      define(navigator, 'userAgentData', uaData);
    }

    const fakePlugin = { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' };
    Object.defineProperty(navigator, 'plugins', {
      get: () => {
        const arr = [fakePlugin, fakePlugin, fakePlugin];
        arr.item = (i) => arr[i];
        arr.namedItem = () => fakePlugin;
        arr.refresh = () => {};
        return arr;
      }, configurable: true
    });

    const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
    if (originalQuery) {
      window.navigator.permissions.query = (parameters) => (
        parameters && parameters.name === 'notifications'
          ? Promise.resolve({ state: Notification.permission })
          : originalQuery(parameters)
      );
    }

    const patchWebGL = (proto) => {
      if (!proto || !proto.getParameter || proto.__solverPatched) return;
      const getParameter = proto.getParameter;
      Object.defineProperty(proto, '__solverPatched', { value: true });
      proto.getParameter = function(parameter) {
        if (parameter === 37445) return fp.webglVendor;
        if (parameter === 37446) return fp.webglRenderer;
        return getParameter.call(this, parameter);
      };
    };
    patchWebGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchWebGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);

    try {
      if (window.outerWidth === 0) define(window, 'outerWidth', window.innerWidth + 16);
      if (window.outerHeight === 0) define(window, 'outerHeight', window.innerHeight + 88);
    } catch (e) {}
  } catch (e) {}
})();
"""
    return (
        script.replace("__LANGUAGES__", json.dumps(languages, ensure_ascii=False))
        .replace("__LANGUAGE__", json.dumps(language))
        .replace("__PLATFORM__", json.dumps(navigator_platform))
        .replace("__HARDWARE__", str(hardware))
        .replace("__MEMORY__", str(memory))
        .replace("__WEBGL_VENDOR__", json.dumps(webgl_vendor))
        .replace("__WEBGL_RENDERER__", json.dumps(webgl_renderer))
        .replace("__USER_AGENT__", json.dumps(user_agent))
        .replace("__UA_DATA__", json.dumps(metadata, ensure_ascii=False))
    )

STEALTH_INIT_JS = build_stealth_init_js(build_solver_fingerprint())


async def apply_stealth(page, fp: Optional[Mapping[str, Any]] = None) -> None:
    script = build_stealth_init_js(fp or build_solver_fingerprint())
    try:
        await page.add_init_script(script)
    except Exception as e:
        logger.debug("add_init_script failed: %s", e)
    try:
        await peval(page, "() => { " + script + "; return true; }")
    except Exception:
        pass


async def apply_cdp_fingerprint(
    context,
    page,
    *,
    locale: Optional[str] = None,
    timezone: Optional[str] = None,
    accept_language: Optional[str] = None,
) -> Dict[str, Any]:
    fp = build_solver_fingerprint(
        locale=locale,
        timezone=timezone,
        accept_language=accept_language,
    )
    try:
        await page.set_extra_http_headers({"Accept-Language": fp["accept_language"]})
    except Exception as e:
        logger.debug("set extra headers failed: %s", e)
    try:
        session = await context.new_cdp_session(page)
        await session.send(
            "Network.setUserAgentOverride",
            {
                "userAgent": fp["user_agent"],
                "acceptLanguage": fp["accept_language"],
                "platform": fp.get("navigator_platform") or "Linux x86_64",
                "userAgentMetadata": fp["metadata"],
            },
        )
        await session.send("Emulation.setLocaleOverride", {"locale": fp["language"]})
        if fp.get("timezone"):
            await session.send(
                "Emulation.setTimezoneOverride",
                {"timezoneId": fp["timezone"]},
            )
        await session.send(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": int(fp["width"]),
                "height": int(fp["height"]),
                "deviceScaleFactor": 1,
                "mobile": False,
                "screenWidth": int(fp["width"]),
                "screenHeight": int(fp["height"]),
            },
        )
        await session.send(
            "Emulation.setHardwareConcurrencyOverride",
            {"hardwareConcurrency": int(fp["hardware_concurrency"])},
        )
    except Exception as e:
        logger.debug("CDP fingerprint failed: %s", e)
    return fp


async def install_proxy_auth(context, page, proxy: Optional[str]):
    """Answer authenticated-proxy challenges over CDP without exposing secrets."""
    conf = parse_proxy(proxy)
    username = str((conf or {}).get("username") or "")
    password = str((conf or {}).get("password") or "")
    if not username and not password:
        return None
    session = await context.new_cdp_session(page)

    async def continue_request(event: Dict[str, Any]) -> None:
        try:
            await session.send(
                "Fetch.continueRequest", {"requestId": event["requestId"]}
            )
        except Exception:
            pass

    async def provide_credentials(event: Dict[str, Any]) -> None:
        try:
            await session.send(
                "Fetch.continueWithAuth",
                {
                    "requestId": event["requestId"],
                    "authChallengeResponse": {
                        "response": "ProvideCredentials",
                        "username": username,
                        "password": password,
                    },
                },
            )
        except Exception:
            pass

    session.on(
        "Fetch.requestPaused",
        lambda event: asyncio.create_task(continue_request(event)),
    )
    session.on(
        "Fetch.authRequired",
        lambda event: asyncio.create_task(provide_credentials(event)),
    )
    await session.send("Fetch.enable", {"handleAuthRequests": True})
    return session


async def human_warmup(page) -> None:
    """Light human-like interactions before captcha."""
    try:
        # random short scroll + mouse wander
        await page.mouse.move(random.randint(120, 500), random.randint(140, 420))
        await page.wait_for_timeout(random.randint(200, 500))
        await page.mouse.wheel(0, random.randint(80, 260))
        await page.wait_for_timeout(random.randint(250, 700))
        await page.mouse.wheel(0, -random.randint(40, 140))
        await page.wait_for_timeout(random.randint(150, 400))
    except Exception as e:
        logger.debug("human_warmup err: %s", e)


async def peval(page, expression, arg=None):
    try:
        return await page.evaluate(expression, arg, isolated_context=False)
    except TypeError:
        return await page.evaluate(expression, arg)


async def ensure_turnstile_api(page) -> bool:
    if await peval(page, "() => !!(window.turnstile && window.turnstile.render)"):
        return True
    try:
        await page.add_script_tag(
            url="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        )
    except Exception as e:
        logger.warning("add_script_tag: %s", e)
    for _ in range(50):
        if await peval(page, "() => !!(window.turnstile && window.turnstile.render)"):
            return True
        await page.wait_for_timeout(200)
    return False


async def force_render(
    page,
    sitekey: str,
    action: str = "",
    cdata: str = "",
    ns: str = "default",
) -> Dict[str, Any]:
    js = """
    ({ sitekey, action, cdata, ns }) => {
      try {
        if (!window.turnstile || !window.turnstile.render) return {ok:false, err:'turnstile api missing'};
        const tokenKey = '__ts_token_' + ns;
        const errKey = '__ts_error_' + ns;
        const logKey = '__ts_logs_' + ns;
        window[tokenKey] = null;
        window[errKey] = null;
        window[logKey] = [];
        const log = (m) => { try { window[logKey].push(String(m)); } catch (e) {} };

        const boxId = '__ts_force_box_' + ns;
        const widgetId = '__ts_force_widget_' + ns;
        const inputId = '__ts_force_input_' + ns;
        document.querySelectorAll('#' + boxId).forEach(e => e.remove());
        let input = document.getElementById(inputId);
        if (!input) {
          input = document.createElement('input');
          input.type = 'hidden';
          input.name = 'cf-turnstile-response';
          input.id = inputId;
          document.body.appendChild(input);
        }
        const box = document.createElement('div');
        box.id = boxId;
        box.style.cssText = 'position:fixed;top:24px;left:24px;z-index:2147483647;background:#fff;padding:14px;border:1px solid #999;border-radius:8px;';
        const widget = document.createElement('div');
        widget.id = widgetId;
        box.appendChild(widget);
        document.body.appendChild(box);

        const opts = {
          sitekey,
          theme: 'light',
          size: 'normal',
          callback: (token) => {
            window[tokenKey] = token;
            input.value = token;
            log('token:' + token.length);
          },
          'error-callback': (e) => { window[errKey] = String(e); log('err:' + e); },
          'expired-callback': () => { window[tokenKey] = null; log('expired'); },
          'before-interactive-callback': () => log('bi'),
          'after-interactive-callback': () => log('ai')
        };
        if (action) opts.action = action;
        if (cdata) opts.cData = cdata;
        const id = window.turnstile.render(widget, opts);
        return {ok:true, id, ns, boxId, widgetId, inputId};
      } catch (e) {
        return {ok:false, err:String(e)};
      }
    }
    """
    return await peval(
        page,
        js,
        {
            "sitekey": sitekey,
            "action": action or "",
            "cdata": cdata or "",
            "ns": ns or "default",
        },
    )



async def extract_token(page, ns: str = "default") -> Optional[str]:
    token = await peval(
        page,
        """({ ns }) => {
          const tokenKey = '__ts_token_' + ns;
          const inputId = '__ts_force_input_' + ns;
          if (window[tokenKey] && window[tokenKey].length > 20) return window[tokenKey];
          const el = document.getElementById(inputId) || document.querySelector('input[name="cf-turnstile-response"]');
          if (el && el.value && el.value.length > 20) return el.value;
          try {
            if (window.turnstile && window.turnstile.getResponse) {
              const t = window.turnstile.getResponse();
              if (t && t.length > 20) return t;
            }
          } catch (e) {}
          return null;
        }""",
        {"ns": ns or "default"},
    )
    if token and isinstance(token, str) and len(token) > 20:
        return token
    return None


async def click_checkbox_once(page, humanize: bool = True, ns: str = "default") -> bool:
    try:
        for fr in page.frames:
            try:
                cb = fr.locator('input[type="checkbox"]').first
                if await cb.count() > 0 and await cb.is_visible():
                    box = await cb.bounding_box()
                    if box:
                        if humanize:
                            ok = await human_click_box(page, box, bias_left=False)
                        else:
                            await page.mouse.click(
                                box["x"] + box["width"] / 2,
                                box["y"] + box["height"] / 2,
                            )
                            ok = True
                        if ok:
                            logger.info("clicked checkbox")
                            return True
                    await cb.click(timeout=1000)
                    return True
            except Exception:
                continue

        # iframe body / challenge containers
        for fr in page.frames:
            try:
                for sel in ("body", "#challenge-stage", ".cb-i", ".ctp-checkbox-label"):
                    loc = fr.locator(sel).first
                    if await loc.count() == 0:
                        continue
                    box = await loc.bounding_box()
                    if not box or box["width"] < 8 or box["height"] < 8:
                        continue
                    # prefer left side for checkbox
                    if humanize:
                        if await human_click_box(page, box, bias_left=True):
                            logger.info("clicked frame widget %s", sel)
                            return True
                    else:
                        await page.mouse.click(
                            box["x"] + min(28, box["width"] * 0.15),
                            box["y"] + box["height"] * 0.5,
                        )
                        return True
            except Exception:
                continue

        # geometric fallback on widget
        sel = f"#__ts_force_widget_{ns}, #__ts_force_box_{ns}, .cf-turnstile"
        loc = page.locator(sel).first
        if await loc.count() > 0:
            box = await loc.bounding_box()
            if box:
                if humanize:
                    return await human_click_box(page, box, bias_left=True)
                await page.mouse.click(
                    box["x"] + min(28, box["width"] * 0.15),
                    box["y"] + box["height"] * 0.5,
                )
                return True
    except Exception as e:
        logger.debug("click checkbox err: %s", e)
    return False


async def solve_turnstile_token(
    *,
    url: str,
    sitekey: str,
    action: Optional[str] = None,
    cdata: Optional[str] = None,
    headless: bool = False,
    timeout_seconds: int = 90,
    proxy: Optional[str] = None,
    locale: Optional[str] = None,
    timezone: Optional[str] = None,
    accept_language: Optional[str] = None,
    mode: Optional[str] = None,
    worker_size: Optional[int] = None,
) -> Optional[str]:
    """
    Solve via isolated Chrome workers over CDP.

    Isolation model:
      - N Chrome processes (ports base..base+N-1, separate profiles)
      - each task acquires one worker
      - each task uses a brand-new page (never shared page[0])
      - token/error DOM keys are namespaced per task
    """
    from patchright.async_api import async_playwright

    mode = _normalize_mode(mode, headless)
    humanize = _env_bool("SOLVER_HUMANIZE", True)
    proxy = pick_live_proxy(proxy)
    if not proxy:
        if _env_bool("SOLVER_ALLOW_DIRECT", False):
            logger.warning("No live proxy; continuing with direct server egress")
        else:
            logger.error("No live proxy. Start Clash/V2Ray first.")
            return None

    size = int(worker_size or os.getenv("SOLVER_WORKERS", "1") or "1")
    await init_worker_pool(size=size, mode=mode, proxy=proxy)
    worker = await _WORKER_POOL.acquire(timeout=max(60.0, float(timeout_seconds or 90)))
    ns = uuid.uuid4().hex[:10]
    logger.info(
        "selected proxy %s (worker=%s port=%s mode=%s humanize=%s ns=%s)",
        (parse_proxy(proxy) or {}).get("server"),
        worker.worker_id,
        worker.port,
        mode,
        humanize,
        ns,
    )

    timeout_seconds = max(45, int(timeout_seconds or 90))
    action = action or ""
    cdata = cdata or ""

    # ensure this worker chrome is alive
    ok, pid = ensure_chrome_cdp(
        proxy=proxy,
        headless=(mode == "headless"),
        mode=mode,
        port=worker.port,
        profile_dir=worker.profile,
        worker_id=worker.worker_id,
    )
    if not ok:
        await _WORKER_POOL.release(worker)
        return None
    if pid:
        worker.pid = pid
    released = False

    try:
        async with async_playwright() as p:
            ws_url = None
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{worker.port}/json/version", timeout=2
                ) as r:
                    meta = json.loads(r.read().decode("utf-8", errors="replace"))
                    ws_url = meta.get("webSocketDebuggerUrl")
                    logger.info(
                        "CDP browser=%s worker=%s port=%s",
                        meta.get("Browser"),
                        worker.worker_id,
                        worker.port,
                    )
            except Exception as e:
                logger.warning("fetch CDP version failed worker=%s: %s", worker.worker_id, e)
            endpoint = ws_url or f"http://127.0.0.1:{worker.port}"
            browser = await p.chromium.connect_over_cdp(endpoint)
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            # CRITICAL: always create a dedicated page for this task
            page = await context.new_page()
            proxy_auth_session = None

            try:
                fp = await apply_cdp_fingerprint(
                    context,
                    page,
                    locale=locale,
                    timezone=timezone,
                    accept_language=accept_language,
                )
                try:
                    await page.set_viewport_size(
                        {"width": int(fp["width"]), "height": int(fp["height"])}
                    )
                except Exception:
                    pass
                logger.info(
                    "fingerprint ua=Chrome/%s platform=%s locale=%s tz=%s viewport=%sx%s worker=%s",
                    fp.get("major"),
                    fp.get("platform"),
                    fp.get("language"),
                    fp.get("timezone") or "default",
                    fp.get("width"),
                    fp.get("height"),
                    worker.worker_id,
                )

                await apply_stealth(page, fp)
                proxy_auth_session = await install_proxy_auth(
                    context, page, proxy
                )

                target = url or "https://accounts.x.ai/sign-up"
                if "sign-up" not in target and "accounts.x.ai" in target:
                    target = "https://accounts.x.ai/sign-up"

                resp = await page.goto(target, wait_until="domcontentloaded", timeout=60000)
                logger.info(
                    "loaded %s status=%s mode=%s worker=%s",
                    target,
                    resp.status if resp else None,
                    mode,
                    worker.worker_id,
                )
                await page.wait_for_timeout(random.randint(700, 1400))
                if humanize:
                    await human_warmup(page)

                for sel in [
                    'text=Sign up with email',
                    'text=使用邮箱注册',
                    'button:has-text("使用邮箱注册")',
                    'button:has-text("Sign up with email")',
                ]:
                    try:
                        loc = page.locator(sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            box = await loc.bounding_box()
                            if humanize and box:
                                await human_click_box(page, box, bias_left=False)
                            else:
                                await loc.click(timeout=1500)
                            await page.wait_for_timeout(random.randint(500, 1000))
                            break
                    except Exception:
                        pass

                if not await ensure_turnstile_api(page):
                    logger.error("turnstile api not ready worker=%s", worker.worker_id)
                    return None
                logger.info("turnstile api ready worker=%s ns=%s", worker.worker_id, ns)

                deadline = time.time() + timeout_seconds
                attempt = 0
                hard_fail_600010 = 0
                while time.time() < deadline:
                    attempt += 1
                    logger.info(
                        "CDP render attempt=%s left=%.0fs mode=%s worker=%s ns=%s",
                        attempt,
                        deadline - time.time(),
                        mode,
                        worker.worker_id,
                        ns,
                    )
                    result = await force_render(page, sitekey, action, cdata, ns=ns)
                    logger.info("render result=%s", result)
                    if not result or not result.get("ok"):
                        await page.wait_for_timeout(800)
                        continue

                    await page.wait_for_timeout(random.randint(700, 1400) if humanize else 500)
                    if humanize:
                        await human_warmup(page)

                    token = await extract_token(page, ns=ns)
                    if token:
                        logger.info(
                            "SUCCESS auto token len=%s worker=%s ns=%s",
                            len(token),
                            worker.worker_id,
                            ns,
                        )
                        return token

                    clicked = await click_checkbox_once(page, humanize=humanize, ns=ns)
                    logger.info("checkbox clicked=%s worker=%s", clicked, worker.worker_id)

                    for tick in range(30):
                        token = await extract_token(page, ns=ns)
                        if token:
                            logger.info(
                                "SUCCESS token len=%s tick=%s worker=%s ns=%s",
                                len(token),
                                tick,
                                worker.worker_id,
                                ns,
                            )
                            return token
                        st = await peval(
                            page,
                            """({ ns }) => ({
                              e: window['__ts_error_' + ns],
                              logs: (window['__ts_logs_' + ns] || []).slice(-6),
                              len: window['__ts_token_' + ns] ? window['__ts_token_' + ns].length : 0
                            })""",
                            {"ns": ns},
                        )
                        if tick in (3, 8, 15, 24) and st:
                            logger.info("wait state=%s worker=%s", st, worker.worker_id)
                        if st and str(st.get("e")) == "600010" and tick >= 3:
                            hard_fail_600010 += 1
                            logger.warning(
                                "600010, retry render (count=%s worker=%s)",
                                hard_fail_600010,
                                worker.worker_id,
                            )
                            break
                        if tick in (4, 11) and not token:
                            await click_checkbox_once(page, humanize=humanize, ns=ns)
                        await page.wait_for_timeout(900)

                    if (
                        mode == "headless"
                        and hard_fail_600010 >= 2
                        and _env_bool("SOLVER_HEADLESS_FALLBACK", True)
                    ):
                        logger.warning(
                            "headless unstable on worker=%s, fallback to offscreen pool",
                            worker.worker_id,
                        )
                        # release current worker then recurse once in offscreen
                        try:
                            await page.close()
                        except Exception:
                            pass
                        try:
                            await _cleanup_context_pages(context, keep_blank=True)
                        except Exception:
                            pass
                        try:
                            await browser.close()
                        except Exception:
                            pass
                        if not released:
                            await _WORKER_POOL.release(worker)
                            released = True
                        return await solve_turnstile_token(
                            url=url,
                            sitekey=sitekey,
                            action=action,
                            cdata=cdata,
                            headless=False,
                            timeout_seconds=max(45, int(deadline - time.time())),
                            proxy=proxy,
                            locale=locale,
                            timezone=timezone,
                            accept_language=accept_language,
                            mode="offscreen",
                            worker_size=size,
                        )

                    await page.wait_for_timeout(random.randint(900, 1800))
                    try:
                        await page.goto(
                            "https://accounts.x.ai/sign-up",
                            wait_until="domcontentloaded",
                            timeout=45000,
                        )
                        await page.wait_for_timeout(random.randint(500, 1000))
                        await apply_stealth(page, fp)
                        await ensure_turnstile_api(page)
                    except Exception as e:
                        logger.warning("reopen fail worker=%s: %s", worker.worker_id, e)

                return await extract_token(page, ns=ns)
            finally:
                if proxy_auth_session is not None:
                    try:
                        await proxy_auth_session.detach()
                    except Exception:
                        pass
                try:
                    await page.close()
                except Exception:
                    pass
                try:
                    await _cleanup_context_pages(context, keep_blank=True)
                except Exception:
                    pass
                try:
                    # disconnect only; keep worker chrome process for reuse
                    await browser.close()
                except Exception:
                    pass
                if mode == "offscreen":
                    _hide_chrome_windows_for_pid(worker.pid)
                    # Child GPU/renderer windows can reappear after navigation.
                    time.sleep(0.05)
                    _hide_chrome_windows_for_pid(worker.pid)
    finally:
        if 'released' in locals() and not released:
            await _WORKER_POOL.release(worker)
        elif 'released' not in locals():
            await _WORKER_POOL.release(worker)
