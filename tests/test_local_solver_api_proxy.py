import asyncio
import importlib.util
import sys
import types
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOLVER_DIR = ROOT / "local_solver"
API_PATH = SOLVER_DIR / "api_solver.py"


def load_api_module():
    if str(SOLVER_DIR) not in sys.path:
        sys.path.insert(0, str(SOLVER_DIR))

    quart = types.ModuleType("quart")

    class FakeQuart:
        def __init__(self, *args, **kwargs):
            pass
        def before_serving(self, fn):
            return fn
        def after_serving(self, fn):
            return fn
        def route(self, *args, **kwargs):
            def deco(fn):
                return fn
            return deco

    quart.Quart = FakeQuart
    quart.request = types.SimpleNamespace(args={})
    quart.jsonify = lambda data: data

    spec = importlib.util.spec_from_file_location("local_solver_api_test", API_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with patch.dict(sys.modules, {"quart": quart}):
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
    return module


class LocalSolverApiProxyTests(unittest.TestCase):
    def test_task_proxy_is_passed_to_turnstile_engine(self):
        api = load_api_module()
        captured = {}

        async def fake_solve_turnstile_token(**kwargs):
            captured.update(kwargs)
            return "t" * 64

        server = api.TurnstileAPIServer(
            headless=False,
            useragent=None,
            debug=False,
            browser_type="chromium",
            thread=1,
            proxy_support=False,
        )

        with patch.object(api, "solve_turnstile_token", side_effect=fake_solve_turnstile_token), \
             patch.object(api, "save_result", new=lambda *args, **kwargs: asyncio.sleep(0)):
            asyncio.run(server._solve_turnstile(
                task_id="task-1",
                url="https://accounts.x.ai/sign-up",
                sitekey="site-key",
                proxy="http://user:pass@203.0.113.10:8080",
                locale="en-US",
                timezone="America/New_York",
                accept_language="en-US,en;q=0.9",
            ))

        self.assertEqual(captured["proxy"], "http://user:pass@203.0.113.10:8080")
        self.assertEqual(captured["locale"], "en-US")
        self.assertEqual(captured["timezone"], "America/New_York")
        self.assertEqual(captured["accept_language"], "en-US,en;q=0.9")


if __name__ == "__main__":
    unittest.main()
