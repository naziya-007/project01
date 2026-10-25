"""Thin wrapper over a psycopg 3 connection.

Every transaction begins by publishing who is asking (app.user_id, app.role,
app.share_token_hash, app.system) as transaction-local settings, which the
row-level-security policies in migrations/002_rls.sql read. Because they are
transaction-local, they are re-applied automatically after every commit or
rollback; there is no way to run a query on this wrapper without them.
"""
import uuid
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

DbError = psycopg.Error


def sqlstate(exc: BaseException) -> Optional[str]:
    return getattr(exc, "sqlstate", None)


def _normalise(row: dict) -> dict:
    out = {}
    for key, value in row.items():
        if isinstance(value, uuid.UUID):
            value = str(value)
        elif isinstance(value, memoryview):
            value = value.tobytes()
        out[key] = value
    return out


class Database:
    def __init__(self, url: str):
        self.url = url
        self.conn = None
        self._ctx = {"user_id": "", "role": "", "share": "", "system": ""}
        self._ctx_applied = False

    # ------------------------------------------------------------ context
    def set_context(self, user_id: Optional[str] = None, role: Optional[str] = None,
                    share_hash: Optional[str] = None, system: bool = False) -> None:
        self._ctx = {
            "user_id": user_id or "",
            "role": role or "",
            "share": share_hash or "",
            "system": "on" if system else "",
        }
        self._ctx_applied = False
        if self.conn is not None and not self.conn.closed:
            self._apply()

    def context(self) -> dict:
        return dict(self._ctx)

    def _connect(self) -> None:
        self.conn = psycopg.connect(self.url, row_factory=dict_row, autocommit=False)
        self.conn.execute("SET TIME ZONE 'UTC'")
        self.conn.commit()
        self._ctx_applied = False

    def _apply(self) -> None:
        self.conn.execute(
            "SELECT set_config('app.user_id', %s, true), set_config('app.role', %s, true), "
            "set_config('app.share_token_hash', %s, true), set_config('app.system', %s, true)",
            (self._ctx["user_id"], self._ctx["role"], self._ctx["share"], self._ctx["system"]),
        )
        self._ctx_applied = True

    # ------------------------------------------------------------ queries
    def _execute(self, sql: str, params: Any = None):
        if self.conn is None or self.conn.closed:
            self._connect()
        if not self._ctx_applied:
            self._apply()
        return self.conn.execute(sql, params)

    def all(self, sql: str, params: Any = None) -> list:
        cur = self._execute(sql, params)
        if cur.description is None:
            return []
        return [_normalise(r) for r in cur.fetchall()]

    def one(self, sql: str, params: Any = None) -> Optional[dict]:
        cur = self._execute(sql, params)
        if cur.description is None:
            return None
        row = cur.fetchone()
        return _normalise(row) if row is not None else None

    def scalar(self, sql: str, params: Any = None) -> Any:
        row = self.one(sql, params)
        if row is None:
            return None
        return next(iter(row.values()))

    def run(self, sql: str, params: Any = None) -> int:
        cur = self._execute(sql, params)
        return cur.rowcount

    # ------------------------------------------------------- transactions
    def commit(self) -> None:
        if self.conn is not None and not self.conn.closed:
            self.conn.commit()
        self._ctx_applied = False

    def rollback(self) -> None:
        if self.conn is not None and not self.conn.closed:
            self.conn.rollback()
        self._ctx_applied = False

    def close(self) -> None:
        if self.conn is not None and not self.conn.closed:
            try:
                self.conn.rollback()
            finally:
                self.conn.close()
        self.conn = None
