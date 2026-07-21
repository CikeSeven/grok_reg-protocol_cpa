"""SQLite-backed durable state for CPA pool health and governance."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


class PoolStateDB:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._init_lock = threading.Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            with self._connection() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS account_state (
                        email TEXT PRIMARY KEY,
                        tier TEXT NOT NULL,
                        health_status TEXT NOT NULL,
                        next_check_at REAL NOT NULL DEFAULT 0,
                        updated_at REAL NOT NULL,
                        state_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_account_state_due
                        ON account_state(next_check_at, tier);

                    CREATE TABLE IF NOT EXISTS observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        email TEXT NOT NULL,
                        observed_at REAL NOT NULL,
                        status TEXT NOT NULL,
                        stage TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        account_attributable INTEGER NOT NULL DEFAULT 0,
                        observation_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_observations_window
                        ON observations(observed_at, stage, status, fingerprint);
                    CREATE INDEX IF NOT EXISTS idx_observations_account
                        ON observations(email, observed_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_observations_breaker
                        ON observations(stage, observed_at, account_attributable, status, fingerprint);

                    CREATE TABLE IF NOT EXISTS breaker_state (
                        scope TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        updated_at REAL NOT NULL,
                        state_json TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS governance_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_at REAL NOT NULL,
                        email TEXT NOT NULL,
                        action TEXT NOT NULL,
                        old_state TEXT NOT NULL,
                        new_state TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        result TEXT NOT NULL,
                        action_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_governance_actions_time
                        ON governance_actions(action_at DESC);

                    CREATE TABLE IF NOT EXISTS pool_meta (
                        key TEXT PRIMARY KEY,
                        value_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )
                conn.execute(
                    "INSERT INTO pool_meta(key, value_json, updated_at) VALUES('schema_version', ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                    (json.dumps(SCHEMA_VERSION), time.time()),
                )
            self._initialized = True

    def upsert_account(self, state: dict[str, Any]) -> None:
        self.upsert_accounts([state])

    def upsert_accounts(self, states: list[dict[str, Any]]) -> None:
        self.initialize()
        rows: list[tuple[Any, ...]] = []
        for state in states:
            email = str(state.get("email") or "").strip().lower()
            if not email:
                continue
            updated_at = float(state.get("updated_at") or time.time())
            rows.append(
                (
                    email,
                    str(state.get("tier") or "candidate"),
                    str(state.get("health_status") or "unchecked"),
                    float(state.get("next_check_at") or 0),
                    updated_at,
                    json.dumps(state, ensure_ascii=False, separators=(",", ":")),
                )
            )
        if not rows:
            return
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO account_state(email, tier, health_status, next_check_at, updated_at, state_json)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    tier=excluded.tier,
                    health_status=excluded.health_status,
                    next_check_at=excluded.next_check_at,
                    updated_at=excluded.updated_at,
                    state_json=excluded.state_json
                """,
                rows,
            )

    def get_account(self, email: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT state_json FROM account_state WHERE email=?",
                (email.strip().lower(),),
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["state_json"])
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def list_accounts(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as conn:
            rows = conn.execute("SELECT state_json FROM account_state ORDER BY email").fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(row["state_json"])
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                values.append(value)
        return values

    def due_emails(self, *, now: float, limit: int) -> list[str]:
        self.initialize()
        query = "SELECT email FROM account_state WHERE next_check_at > 0 AND next_check_at <= ? ORDER BY next_check_at, email"
        params: list[Any] = [float(now)]
        if limit > 0:
            query += " LIMIT ?"
            params.append(int(limit))
        with self._connection() as conn:
            return [str(row["email"]) for row in conn.execute(query, params).fetchall()]

    def add_observation(self, *, scan_id: str, observation: dict[str, Any], observed_at: float | None = None) -> None:
        self.initialize()
        timestamp = time.time() if observed_at is None else float(observed_at)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO observations(
                    scan_id, email, observed_at, status, stage, fingerprint,
                    account_attributable, observation_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(scan_id or ""),
                    str(observation.get("email") or "").strip().lower(),
                    timestamp,
                    str(observation.get("status") or "probe_failed"),
                    str(observation.get("stage") or "probe"),
                    str(observation.get("fingerprint") or ""),
                    1 if observation.get("account_attributable") else 0,
                    json.dumps(observation, ensure_ascii=False, separators=(",", ":")),
                ),
            )

    def breaker_window(self, *, stage: str, since: float) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT observation_json FROM observations
                WHERE observed_at >= ? AND stage=?
                ORDER BY observed_at DESC
                """,
                (float(since), stage),
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(row["observation_json"])
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                values.append(value)
        return values

    def breaker_stats(
        self,
        *,
        stage: str,
        since: float,
        half_open_at: float | None = None,
        canary_limit: int = 5,
    ) -> dict[str, Any]:
        self.initialize()
        with self._connection() as conn:
            sample_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE observed_at >= ? AND stage = ?",
                    (float(since), stage),
                ).fetchone()[0]
                or 0
            )
            top = conn.execute(
                """
                SELECT fingerprint, COUNT(*) AS total
                FROM observations
                WHERE observed_at >= ? AND stage = ?
                  AND account_attributable = 0
                  AND status IN ('upstream_busy', 'transient_error', 'request_error')
                  AND fingerprint <> ''
                GROUP BY fingerprint
                ORDER BY total DESC, fingerprint
                LIMIT 1
                """,
                (float(since), stage),
            ).fetchone()
            canary_statuses: list[str] = []
            if half_open_at is not None:
                canary_statuses = [
                    str(row["status"])
                    for row in conn.execute(
                        """
                        SELECT status FROM observations
                        WHERE observed_at >= ? AND stage = ?
                        ORDER BY observed_at DESC, id DESC
                        LIMIT ?
                        """,
                        (float(half_open_at), stage, max(1, min(int(canary_limit), 100))),
                    ).fetchall()
                ]
        return {
            "sample_count": sample_count,
            "top_fingerprint": str(top["fingerprint"]) if top is not None else "",
            "top_errors": int(top["total"] or 0) if top is not None else 0,
            "canary_statuses": canary_statuses,
        }

    def put_breaker(self, scope: str, state: dict[str, Any]) -> None:
        self.initialize()
        timestamp = float(state.get("updated_at") or time.time())
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO breaker_state(scope, state, updated_at, state_json)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(scope) DO UPDATE SET
                    state=excluded.state,
                    updated_at=excluded.updated_at,
                    state_json=excluded.state_json
                """,
                (
                    scope,
                    str(state.get("state") or "closed"),
                    timestamp,
                    json.dumps(state, ensure_ascii=False, separators=(",", ":")),
                ),
            )

    def list_breakers(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as conn:
            rows = conn.execute("SELECT state_json FROM breaker_state ORDER BY scope").fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(row["state_json"])
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                result.append(value)
        return result

    def add_action(self, action: dict[str, Any]) -> None:
        self.initialize()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_actions(
                    action_at, email, action, old_state, new_state, reason, result, action_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(action.get("action_ts") or time.time()),
                    str(action.get("email") or "").strip().lower(),
                    str(action.get("action") or ""),
                    str(action.get("old_state") or ""),
                    str(action.get("new_state") or ""),
                    str(action.get("reason") or ""),
                    str(action.get("result") or ""),
                    json.dumps(action, ensure_ascii=False, separators=(",", ":")),
                ),
            )

    def count_actions(self) -> int:
        self.initialize()
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM governance_actions").fetchone()
        return int(row[0] or 0) if row is not None else 0

    def list_actions(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT action_json FROM governance_actions ORDER BY action_at DESC, id DESC LIMIT ? OFFSET ?",
                (max(1, min(int(limit), 1000)), max(0, int(offset))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(row["action_json"])
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                result.append(value)
        return result

    def get_meta(self, key: str, default: Any = None) -> Any:
        self.initialize()
        with self._connection() as conn:
            row = conn.execute("SELECT value_json FROM pool_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value_json"])
        except (TypeError, ValueError):
            return default

    def set_meta(self, key: str, value: Any) -> None:
        self.initialize()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO pool_meta(key, value_json, updated_at) VALUES(?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (key, json.dumps(value, ensure_ascii=False, separators=(",", ":")), time.time()),
            )

    def prune_history(
        self,
        *,
        observations_before: float | None = None,
        actions_before: float | None = None,
    ) -> dict[str, int]:
        """Delete expired append-only history without touching account state."""

        self.initialize()
        deleted = {"observations": 0, "actions": 0}
        with self._connection() as conn:
            if observations_before is not None:
                cursor = conn.execute(
                    "DELETE FROM observations WHERE observed_at < ?",
                    (float(observations_before),),
                )
                deleted["observations"] = max(0, int(cursor.rowcount or 0))
            if actions_before is not None:
                cursor = conn.execute(
                    "DELETE FROM governance_actions WHERE action_at < ?",
                    (float(actions_before),),
                )
                deleted["actions"] = max(0, int(cursor.rowcount or 0))
        return deleted
