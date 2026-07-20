"""FastAPI application for Grok Reg WebUI."""

from __future__ import annotations

import asyncio
import json
import mimetypes
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from starlette.background import BackgroundTask

from . import store
from . import timeutil
from .cpa_pool import monitor as cpa_pool_monitor
from .jobs import runner

STATIC_DIR = Path(__file__).with_name("static")


def _utc_now() -> str:
    return timeutil.now_iso()


def create_app() -> FastAPI:
    app = FastAPI(title="Grok Reg WebUI", version="1.0.0")
    proxy_check_lock = threading.Lock()
    proxy_check_state: dict[str, Any] = {
        "id": "",
        "status": "idle",
        "started_at": "",
        "finished_at": "",
        "total": 0,
        "ok": 0,
        "fail": 0,
        "error": "",
    }

    def _proxy_check_public() -> dict[str, Any]:
        with proxy_check_lock:
            return dict(proxy_check_state)

    def _run_proxy_check(job_id: str, keys: list[str]) -> None:
        started = time.time()
        try:
            workers = 4 if not keys else min(8, max(1, len(keys)))
            timeout = 8.0 if not keys else 10.0
            results = store.check_proxies(
                list(keys) if keys else None,
                workers=workers,
                timeout=timeout,
            )
            ok_count = sum(1 for r in results if r.get("ok"))
            status = "completed"
            error = ""
        except Exception as exc:
            results = []
            ok_count = 0
            status = "failed"
            error = str(exc)
        with proxy_check_lock:
            # Do not let a stale worker overwrite a newer submitted job.
            if proxy_check_state.get("id") != job_id:
                return
            proxy_check_state.update(
                {
                    "status": status,
                    "finished_at": _utc_now(),
                    "elapsed_sec": round(time.time() - started, 3),
                    "total": len(results),
                    "ok": ok_count,
                    "fail": max(0, len(results) - ok_count),
                    "error": error,
                }
            )

    @app.exception_handler(ValueError)
    async def _value_error(_: Request, exc: ValueError):
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(KeyError)
    async def _key_error(_: Request, exc: KeyError):
        return JSONResponse({"error": "记录不存在"}, status_code=404)

    @app.exception_handler(FileNotFoundError)
    async def _file_error(_: Request, exc: FileNotFoundError):
        return JSONResponse({"error": str(exc)}, status_code=404)

    @app.exception_handler(RuntimeError)
    async def _runtime_error(_: Request, exc: RuntimeError):
        return JSONResponse({"error": str(exc)}, status_code=409)

    @app.on_event("startup")
    def _start_cpa_pool_scheduler() -> None:
        cpa_pool_monitor.ensure_scheduler()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        data = store.overview()
        active = runner.active_job()
        data["active_job"] = active.public_dict() if active else None
        data["jobs"] = runner.list_jobs()[:10]
        return data

    @app.get("/api/accounts")
    def accounts(
        query: str = "",
        status: str = "all",
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        return store.list_accounts(query=query, status=status, page=page, page_size=page_size)

    @app.get("/api/accounts/ids")
    def account_ids(query: str = "", status: str = "all") -> dict[str, Any]:
        return store.account_ids_by_filter(query=query, status=status)

    @app.delete("/api/accounts")
    async def delete_accounts(request: Request) -> dict[str, int]:
        body = await request.json()
        emails = body.get("emails") or body.get("account_emails") or []
        if not emails:
            raise ValueError("请选择账号")
        return {"deleted": store.delete_accounts(list(emails))}

    @app.post("/api/accounts/export")
    async def export_accounts(request: Request):
        body = await request.json()
        emails = body.get("emails") or []
        text = store.export_accounts(list(emails) if emails else None)
        ts = timeutil.now_compact()
        return PlainTextResponse(
            text,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="accounts-{ts}.txt"'},
        )

    @app.get("/api/cpa")
    def cpa_list(
        query: str = "",
        status: str = "all",
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        scan_results = {
            str(r.get("email") or "").lower(): r
            for r in cpa_pool_monitor.list_results(page_size=10000).get("items", [])
            if isinstance(r, dict) and str(r.get("email") or "").strip()
        }
        return store.list_cpa(
            query=query,
            scan_status=status,
            scan_results=scan_results,
            page=page,
            page_size=page_size,
        )

    @app.delete("/api/cpa")
    async def cpa_delete(request: Request) -> dict[str, int]:
        body = await request.json()
        emails = body.get("emails") or []
        if not emails:
            raise ValueError("请选择 CPA 文件")
        return {"deleted": store.delete_cpa(list(emails))}

    @app.get("/api/cpa/download")
    def cpa_download(email: str = Query(...)):
        path = store.cpa_download_path(email)
        return FileResponse(
            path,
            media_type="application/json",
            filename=path.name,
        )

    @app.get("/api/cpa/pool/status")
    def cpa_pool_status() -> dict[str, Any]:
        return cpa_pool_monitor.status()

    @app.get("/api/cpa/pool/results")
    def cpa_pool_results(
        query: str = "",
        status: str = "all",
        page: int = Query(1, ge=1),
        page_size: int = Query(100, ge=1, le=10000),
    ) -> dict[str, Any]:
        return cpa_pool_monitor.list_results(
            query=query,
            status=status,
            page=page,
            page_size=page_size,
        )

    @app.post("/api/cpa/pool/scan")
    async def cpa_pool_scan(request: Request) -> JSONResponse:
        raw = await request.body()
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(body, dict):
            raise ValueError("body 必须是对象")
        result = cpa_pool_monitor.start_scan(body)
        return JSONResponse(result, status_code=202 if result.get("started") else 200)

    @app.post("/api/cpa/pool/stop")
    def cpa_pool_stop() -> dict[str, Any]:
        return cpa_pool_monitor.stop_scan()

    @app.post("/api/cpa/pool/action")
    async def cpa_pool_action(request: Request) -> dict[str, Any]:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("body 必须是对象")
        emails = body.get("emails") or []
        action = str(body.get("action") or "").strip()
        reason = str(body.get("reason") or "manual").strip()
        return cpa_pool_monitor.manual_action(
            emails=list(emails),
            action=action,
            reason=reason,
        )

    @app.get("/api/cpa/pool/quarantine")
    def cpa_pool_quarantine(
        query: str = "",
        bucket: str = "all",
        page: int = Query(1, ge=1),
        page_size: int = Query(100, ge=1, le=10000),
    ) -> dict[str, Any]:
        return cpa_pool_monitor.list_quarantine(
            query=query,
            bucket=bucket,
            page=page,
            page_size=page_size,
        )

    @app.post("/api/cpa/pool/quarantine/restore")
    async def cpa_pool_quarantine_restore(request: Request) -> dict[str, Any]:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("body 必须是对象")
        emails = body.get("emails") or []
        target = str(body.get("target") or "hotload").strip()
        overwrite = bool(body.get("overwrite", False))
        return cpa_pool_monitor.restore_quarantine(
            emails=list(emails),
            target=target,
            overwrite=overwrite,
        )

    @app.get("/api/cpa/pool/export")
    def cpa_pool_export() -> JSONResponse:
        return JSONResponse(cpa_pool_monitor.export_report())

    @app.get("/api/mail-credentials")
    def mail_list(
        query: str = "",
        status: str = "all",
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        return store.list_mail_credentials(query=query, status=status, page=page, page_size=page_size)

    @app.get("/api/mail-credentials/ids")
    def mail_ids(query: str = "", status: str = "all") -> dict[str, Any]:
        return store.mail_ids_by_status(query=query, status=status)

    @app.post("/api/mail-credentials/import")
    async def mail_import(request: Request) -> dict[str, Any]:
        body = await request.json()
        text = str(body.get("text") or "")
        mode = str(body.get("mode") or "append")
        if not text.strip():
            raise ValueError("请提供凭证内容")
        return store.import_mail_credentials(text, mode=mode)

    @app.delete("/api/mail-credentials")
    async def mail_delete(request: Request) -> dict[str, int]:
        body = await request.json()
        emails = body.get("emails") or []
        if not emails:
            raise ValueError("请选择邮箱凭证")
        return {"deleted": store.delete_mail_credentials(list(emails))}

    @app.get("/api/config")
    def get_config() -> dict[str, Any]:
        return store.public_config()

    @app.put("/api/config")
    async def put_config(request: Request) -> dict[str, Any]:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("配置必须是对象")
        store.merge_config_update(body)
        return store.public_config()

    @app.get("/api/proxies")
    def proxy_list() -> dict[str, Any]:
        return store.list_proxies()

    @app.post("/api/proxies/import")
    async def proxy_import(request: Request) -> dict[str, Any]:
        body = await request.json()
        text = str(body.get("text") or "")
        mode = str(body.get("mode") or "append")
        if not text.strip():
            raise ValueError("请提供代理内容")
        return store.import_proxies(text, mode=mode)

    @app.delete("/api/proxies")
    async def proxy_delete(request: Request) -> dict[str, int]:
        body = await request.json()
        keys = body.get("keys") or body.get("proxies") or []
        if not keys:
            raise ValueError("请选择代理")
        return {"deleted": store.delete_proxies(list(keys))}

    @app.post("/api/proxies/check")
    async def proxy_check(request: Request) -> dict[str, Any]:
        body = await request.json() if (await request.body()) else {}
        keys = body.get("keys") or []
        if keys and not isinstance(keys, list):
            raise ValueError("keys 必须是列表")
        key_list = [str(k).strip() for k in keys if str(k).strip()]
        total = len(key_list) if key_list else int(store.list_proxies().get("total") or 0)
        with proxy_check_lock:
            if proxy_check_state.get("status") == "running":
                return {
                    "started": False,
                    "running": True,
                    "job": dict(proxy_check_state),
                }
            job_id = uuid.uuid4().hex[:12]
            proxy_check_state.update(
                {
                    "id": job_id,
                    "status": "running",
                    "started_at": _utc_now(),
                    "finished_at": "",
                    "elapsed_sec": 0,
                    "total": total,
                    "ok": 0,
                    "fail": 0,
                    "error": "",
                }
            )
        t = threading.Thread(
            target=_run_proxy_check,
            args=(job_id, key_list),
            daemon=True,
            name=f"proxy-check-{job_id}",
        )
        t.start()
        return {"started": True, "running": True, "job": _proxy_check_public()}

    @app.get("/api/proxies/check/status")
    def proxy_check_status() -> dict[str, Any]:
        return _proxy_check_public()

    @app.get("/api/jobs")
    def jobs() -> dict[str, Any]:
        return {"jobs": runner.list_jobs(), "active": (runner.active_job().public_dict() if runner.active_job() else None)}

    @app.get("/api/jobs/{job_id}")
    def job_detail(job_id: str, after: int = 0) -> dict[str, Any]:
        job = runner.get_job(job_id)
        return job.public_dict(include_logs=True, after=after)

    @app.post("/api/jobs/{job_id}/stop")
    def job_stop(job_id: str) -> dict[str, Any]:
        return runner.stop_job(job_id)

    @app.post("/api/jobs/register")
    async def job_register(request: Request) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("body 必须是对象")
        job = runner.start_register(body)
        return JSONResponse(job, status_code=202)

    @app.post("/api/jobs/backfill")
    async def job_backfill(request: Request) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("body 必须是对象")
        job = runner.start_backfill(body)
        return JSONResponse(job, status_code=202)

    @app.get("/api/jobs/{job_id}/events")
    async def job_events(job_id: str, after: int = 0):
        async def gen():
            cursor = after
            while True:
                try:
                    job = runner.get_job(job_id)
                except KeyError:
                    yield f"data: {json.dumps({'error': 'not found'}, ensure_ascii=False)}\n\n"
                    break
                payload = job.public_dict(include_logs=True, after=cursor)
                cursor = job.log_seq
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                if job.status in {"completed", "failed", "stopped"}:
                    break
                await asyncio.sleep(0.8)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/tools/convert")
    async def tools_convert(
        file: UploadFile = File(...),
        to: str = Form("auto"),
        note: str = Form(""),
    ):
        """账号格式转换：sub2api ↔ Grok CPA(xai-*.json) / OpenAI Codex(codex-*.json)。

        上传 .json / .zip，返回转换后的文件下载（多包时打包为一个 zip）。
        """
        import shutil
        import tempfile
        import zipfile

        import account_convert as ac

        filename = file.filename or "input.json"
        suffix = Path(filename).suffix.lower()
        if suffix not in (".json", ".zip"):
            return JSONResponse({"error": "仅支持 .json / .zip 文件"}, status_code=400)
        content = await file.read()
        if not content:
            return JSONResponse({"error": "文件为空"}, status_code=400)
        if len(content) > 200 * 1024 * 1024:
            return JSONResponse({"error": "文件过大（>200MB）"}, status_code=400)

        workdir = tempfile.mkdtemp(prefix="convert-")
        try:
            src = Path(workdir) / f"input{suffix}"
            src.write_bytes(content)
            out_dir = Path(workdir) / "out"
            out_dir.mkdir()
            note_clean = (note or "").strip() or Path(filename).stem

            target = str(to or "auto")
            if target == "auto":
                kind = ac.detect_input_kind(src)
                target = "native" if kind == "sub2" else "sub2"
            if target not in ("sub2", "cpa", "codex", "native"):
                return JSONResponse({"error": f"不支持的目标格式: {target}"}, status_code=400)

            try:
                if target == "sub2":
                    result = ac.native_to_sub2(src, out_dir, note=note_clean)
                    files = [Path(result["json"])]
                elif target == "cpa":
                    result = ac.sub2_to_cpa(src, out_dir, note=note_clean, keep_dir=False)
                    files = [Path(result["zip"])]
                elif target == "codex":
                    result = ac.sub2_to_codex(src, out_dir, note=note_clean, keep_dir=False)
                    files = [Path(result["zip"])]
                else:
                    result = ac.sub2_to_native(src, out_dir, note=note_clean, keep_dir=False)
                    files = [Path(p["zip"]) for p in result["packs"]]
            except ac.ConvertError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)

            if len(files) == 1:
                out = files[0]
                media = "application/zip" if out.suffix == ".zip" else "application/json"
                return FileResponse(
                    out,
                    media_type=media,
                    filename=out.name,
                    background=BackgroundTask(shutil.rmtree, workdir, True),
                )
            bundle = Path(workdir) / f"converted_{len(files)}packs.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for f in files:
                    zf.write(f, arcname=f.name)
            return FileResponse(
                bundle,
                media_type="application/zip",
                filename=bundle.name,
                background=BackgroundTask(shutil.rmtree, workdir, True),
            )
        except Exception as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            if isinstance(exc, (ac.ConvertError, ValueError)):
                return JSONResponse({"error": str(exc)}, status_code=400)
            raise

    @app.get("/")
    def index():
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/assets/{asset_path:path}")
    def assets(asset_path: str):
        path = (STATIC_DIR / asset_path).resolve()
        if not str(path).startswith(str(STATIC_DIR.resolve())) or not path.is_file():
            raise HTTPException(status_code=404, detail="not found")
        content_type, _ = mimetypes.guess_type(str(path))
        # no-cache：浏览器每次重新验证（配合 FileResponse 的 ETag/Last-Modified 走 304），
        # 避免 UI 更新后用户端长期拿到旧 CSS/JS
        return FileResponse(
            path,
            media_type=content_type or "application/octet-stream",
            headers={"Cache-Control": "no-cache"},
        )

    return app


app = create_app()
