"""Small, secret-safe client for the CLIProxyAPI management endpoints."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ManagementSettings:
    enabled: bool
    base_url: str
    key: str
    timeout_sec: float = 5.0
    cache_sec: float = 10.0


class CLIProxyManagementClient:
    def __init__(self, settings: ManagementSettings) -> None:
        self.settings = settings
        self._cache_lock = threading.Lock()
        self._cached_at = 0.0
        self._cached_files: list[dict[str, Any]] = []

    @property
    def available(self) -> bool:
        return bool(self.settings.enabled and self.settings.base_url and self.settings.key)

    def _url(self, path: str) -> str:
        base = self.settings.base_url.rstrip("/")
        return f"{base}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.available:
            raise RuntimeError("CLIProxy management API is not configured")
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=data,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.settings.key}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.timeout_sec) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"management API HTTP {exc.code}: {raw}") from None
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError(f"management API unavailable: {exc}") from None
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            raise RuntimeError("management API returned invalid JSON") from None
        if not isinstance(parsed, dict):
            raise RuntimeError("management API returned a non-object response")
        return parsed

    def list_auth_files(self, *, force: bool = False) -> list[dict[str, Any]]:
        if not self.available:
            return []
        now = time.monotonic()
        with self._cache_lock:
            if not force and self._cached_at and now - self._cached_at < self.settings.cache_sec:
                return [dict(item) for item in self._cached_files]
        payload = self._request("GET", "/auth-files")
        files = [dict(item) for item in (payload.get("files") or []) if isinstance(item, dict)]
        with self._cache_lock:
            self._cached_at = now
            self._cached_files = files
        return [dict(item) for item in files]

    def patch_fields(self, name: str, **fields: Any) -> None:
        body = {"name": name, **fields}
        self._request("PATCH", "/auth-files/fields", body)
        with self._cache_lock:
            self._cached_at = 0.0

    def patch_status(self, name: str, *, disabled: bool) -> None:
        self._request("PATCH", "/auth-files/status", {"name": name, "disabled": bool(disabled)})
        with self._cache_lock:
            self._cached_at = 0.0

    @staticmethod
    def by_email(files: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in files:
            email = str(item.get("email") or "").strip().lower()
            if email:
                result[email] = dict(item)
        return result

    @staticmethod
    def filename(item: dict[str, Any]) -> str:
        return str(item.get("name") or item.get("id") or "").strip()

