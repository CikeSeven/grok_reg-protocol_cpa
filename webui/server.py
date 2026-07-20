"""Uvicorn entrypoint for Grok Reg WebUI."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grok Reg WebUI server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "缺少 uvicorn/fastapi 依赖，请先执行: uv sync 或 uv add fastapi uvicorn"
        ) from exc

    uvicorn.run(
        "webui.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
