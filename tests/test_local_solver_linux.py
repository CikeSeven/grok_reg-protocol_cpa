import importlib.util
import os
import stat
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = ROOT / "local_solver" / "turnstile_engine.py"


def load_engine_module():
    spec = importlib.util.spec_from_file_location("local_solver_turnstile_engine_test", ENGINE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class LocalSolverLinuxChromeTest(unittest.TestCase):
    def test_find_chrome_locates_linux_google_chrome_on_path(self):
        with tempfile.TemporaryDirectory() as td:
            chrome = Path(td) / "google-chrome"
            chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            chrome.chmod(chrome.stat().st_mode | stat.S_IXUSR)
            env = {**os.environ, "PATH": f"{td}{os.pathsep}{os.environ.get('PATH', '')}"}
            env.pop("CHROME_BIN", None)
            env.pop("GOOGLE_CHROME_SHIM", None)
            with patch.dict(os.environ, env, clear=True):
                engine = load_engine_module()
                self.assertEqual(engine.find_chrome(), str(chrome))

    def test_find_listener_pid_parses_linux_ss_output(self):
        engine = load_engine_module()
        sample = (
            'LISTEN 0 10 127.0.0.1:9222 0.0.0.0:* '
            'users:(("chrome",pid=1087013,fd=89))\n'
            'LISTEN 0 10 [::1]:9222 [::]:* '
            'users:(("chrome",pid=1091412,fd=56))\n'
        )

        with patch.object(engine.subprocess, "check_output", return_value=sample):
            self.assertEqual(engine._find_listener_pid(9222), 1087013)

    def test_collect_descendant_pids_uses_linux_ps_parent_map(self):
        engine = load_engine_module()
        sample = "100 1\n101 100\n102 101\n200 1\n"

        with patch.object(engine.subprocess, "check_output", return_value=sample):
            self.assertEqual(engine._collect_descendant_pids(100), {100, 101, 102})


if __name__ == "__main__":
    unittest.main()

class LocalSolverRootChromeArgsTest(unittest.TestCase):
    def test_ensure_chrome_cdp_adds_no_sandbox_when_running_as_root(self):
        engine = load_engine_module()
        captured = {}

        class FakeProc:
            pid = 4242

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def read(self):
                return b'{"Browser":"Chrome/Test"}'

        def fake_popen(args, **kwargs):
            captured["args"] = args
            return FakeProc()

        with tempfile.TemporaryDirectory() as td:
            chrome = Path(td) / "google-chrome"
            chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            chrome.chmod(chrome.stat().st_mode | stat.S_IXUSR)
            with patch.object(engine, "find_chrome", return_value=str(chrome)), \
                 patch.object(engine, "_probe_port", return_value=False), \
                 patch.object(engine, "_find_listener_pid", return_value=4242), \
                 patch.object(engine.time, "sleep", return_value=None), \
                 patch.object(engine.os, "geteuid", return_value=0, create=True), \
                 patch.object(engine.subprocess, "Popen", side_effect=fake_popen), \
                 patch.object(engine.urllib.request, "urlopen", return_value=FakeResp()):
                ok, _pid = engine.ensure_chrome_cdp(
                    mode="offscreen",
                    port=9555,
                    profile_dir=Path(td) / "profile",
                    worker_id=0,
                )

        self.assertTrue(ok)
        self.assertIn("--no-sandbox", captured["args"])

    def test_ensure_chrome_cdp_converts_socks5h_proxy_to_chrome_socks5(self):
        engine = load_engine_module()
        captured = {}

        class FakeProc:
            pid = 4242

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def read(self):
                return b'{"Browser":"Chrome/Test"}'

        def fake_popen(args, **kwargs):
            captured["args"] = args
            return FakeProc()

        with tempfile.TemporaryDirectory() as td:
            chrome = Path(td) / "google-chrome"
            chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            chrome.chmod(chrome.stat().st_mode | stat.S_IXUSR)
            with patch.object(engine, "find_chrome", return_value=str(chrome)), \
                 patch.object(engine, "_probe_port", return_value=False), \
                 patch.object(engine, "_find_listener_pid", return_value=4242), \
                 patch.object(engine.time, "sleep", return_value=None), \
                 patch.object(engine.os, "geteuid", return_value=1000, create=True), \
                 patch.object(engine.subprocess, "Popen", side_effect=fake_popen), \
                 patch.object(engine.urllib.request, "urlopen", return_value=FakeResp()):
                ok, _pid = engine.ensure_chrome_cdp(
                    proxy="socks5h://user:pass@us.arxlabs.io:3010",
                    mode="headed",
                    port=9777,
                    profile_dir=Path(td) / "profile",
                    worker_id=0,
                )

        self.assertTrue(ok)
        self.assertIn("--proxy-server=socks5://us.arxlabs.io:3010", captured["args"])
        self.assertNotIn("--proxy-server=socks5h://us.arxlabs.io:3010", captured["args"])

class DirectSolverModeTest(unittest.TestCase):
    def test_solve_turnstile_can_continue_without_proxy_when_allow_direct_enabled(self):
        import asyncio
        import types

        engine = load_engine_module()

        class ReachedWorkerInit(Exception):
            pass

        async def fake_init_worker_pool(**kwargs):
            raise ReachedWorkerInit()

        patchright_pkg = types.ModuleType("patchright")
        patchright_async = types.ModuleType("patchright.async_api")
        patchright_async.async_playwright = object

        with patch.dict(sys.modules, {"patchright": patchright_pkg, "patchright.async_api": patchright_async}), \
             patch.dict(os.environ, {"SOLVER_ALLOW_DIRECT": "true"}), \
             patch.object(engine, "pick_live_proxy", return_value=None), \
             patch.object(engine, "init_worker_pool", side_effect=fake_init_worker_pool):
            with self.assertRaises(ReachedWorkerInit):
                asyncio.run(engine.solve_turnstile_token(url="https://example.test", sitekey="sitekey"))

class SolverFingerprintTests(unittest.TestCase):
    def test_solver_fingerprint_uses_installed_chrome_version_for_ua_metadata(self):
        engine = load_engine_module()
        with patch.object(engine, "find_chrome", return_value="/usr/bin/google-chrome"), \
             patch.object(engine.subprocess, "check_output", return_value="Google Chrome 140.0.7339.207\n"):
            fp = engine.build_solver_fingerprint()

        self.assertIn("Chrome/140.0.7339.207", fp["user_agent"])
        self.assertEqual(fp["major"], "140")
        self.assertEqual(fp["metadata"]["platform"], "Linux")
        self.assertIn({"brand": "Google Chrome", "version": "140"}, fp["metadata"]["brands"])
        self.assertIn({"brand": "Google Chrome", "version": "140.0.7339.207"}, fp["metadata"]["fullVersionList"])

    def test_solver_stealth_script_matches_fingerprint_locale_and_platform(self):
        engine = load_engine_module()
        fp = {
            "languages": ["en-US", "en"],
            "language": "en-US",
            "navigator_platform": "Linux x86_64",
            "hardware_concurrency": 8,
            "device_memory": 8,
            "webgl_vendor": "Intel Open Source Technology Center",
            "webgl_renderer": "Mesa Intel(R) UHD Graphics 620 (KBL GT2)",
        }

        js = engine.build_stealth_init_js(fp)

        self.assertIn("en-US", js)
        self.assertIn("Linux x86_64", js)
        self.assertIn("hardwareConcurrency", js)
        self.assertNotIn("zh-CN", js)
        self.assertNotIn("Direct3D11", js)

    def test_offscreen_inside_xvfb_uses_normal_window_position(self):
        engine = load_engine_module()
        captured = {}

        class FakeProc:
            pid = 4242

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def read(self):
                return b'{"Browser":"Chrome/Test"}'

        def fake_popen(args, **kwargs):
            captured["args"] = args
            return FakeProc()

        with tempfile.TemporaryDirectory() as td:
            chrome = Path(td) / "google-chrome"
            chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            chrome.chmod(chrome.stat().st_mode | stat.S_IXUSR)
            with patch.dict(os.environ, {"DISPLAY": ":99", "SOLVER_OFFSCREEN_IN_XVFB_AS_HEADED": "true"}), \
                 patch.object(engine, "find_chrome", return_value=str(chrome)), \
                 patch.object(engine, "_probe_port", return_value=False), \
                 patch.object(engine, "_find_listener_pid", return_value=4242), \
                 patch.object(engine.time, "sleep", return_value=None), \
                 patch.object(engine.os, "geteuid", return_value=1000, create=True), \
                 patch.object(engine.subprocess, "Popen", side_effect=fake_popen), \
                 patch.object(engine.urllib.request, "urlopen", return_value=FakeResp()):
                ok, _pid = engine.ensure_chrome_cdp(
                    mode="offscreen",
                    port=9666,
                    profile_dir=Path(td) / "profile",
                    worker_id=0,
                )

        self.assertTrue(ok)
        self.assertIn("--window-position=40,40", captured["args"])
        self.assertNotIn("--window-position=-32000,-32000", captured["args"])
        self.assertNotIn("--no-startup-window", captured["args"])

class SolverCdpFingerprintTests(unittest.TestCase):
    def test_apply_cdp_fingerprint_sends_ua_metadata_locale_and_metrics(self):
        import asyncio
        engine = load_engine_module()
        sent = []
        headers = {}

        class FakeSession:
            async def send(self, method, params=None):
                sent.append((method, params or {}))

        class FakeContext:
            async def new_cdp_session(self, page):
                return FakeSession()

        class FakePage:
            async def set_extra_http_headers(self, value):
                headers.update(value)

        fp = {
            "user_agent": "Mozilla/5.0 Chrome/140.0.7339.207 Safari/537.36",
            "accept_language": "en-US,en;q=0.9",
            "language": "en-US",
            "timezone": "America/New_York",
            "width": 1366,
            "height": 768,
            "hardware_concurrency": 8,
            "metadata": {"platform": "Linux", "brands": [{"brand": "Google Chrome", "version": "140"}]},
        }

        with patch.object(engine, "build_solver_fingerprint", return_value=fp):
            result = asyncio.run(engine.apply_cdp_fingerprint(FakeContext(), FakePage()))

        self.assertEqual(result, fp)
        methods = [m for m, _ in sent]
        self.assertIn("Network.setUserAgentOverride", methods)
        self.assertIn("Emulation.setLocaleOverride", methods)
        self.assertIn("Emulation.setTimezoneOverride", methods)
        self.assertIn("Emulation.setDeviceMetricsOverride", methods)
        self.assertIn("Emulation.setHardwareConcurrencyOverride", methods)
        self.assertEqual(headers["Accept-Language"], "en-US,en;q=0.9")
