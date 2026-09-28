"""SQLite probe for atomic, single-use approvals and effect intents.

This records an intent in the same database transaction as consuming its
approval. It deliberately does not execute the external effect.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import sqlite3
from pathlib import Path
from collections.abc import Iterator


class ApprovalDenied(PermissionError):
    """The approval is absent, already used, or does not match the request."""


@dataclass(frozen=True)
class EffectIntent:
    token: str
    subject: str
    action: str
    payload: str


class ApprovalStore:
    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    token TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS effect_intents (
                    token TEXT PRIMARY KEY REFERENCES approvals(token),
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def grant(self, token: str, subject: str, action: str, payload: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO approvals(token, subject, action, payload) VALUES (?, ?, ?, ?)",
                (token, subject, action, payload),
            )

    def consume_and_record(self, token: str, subject: str,
                           action: str, payload: str) -> EffectIntent:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            approval = connection.execute(
                "SELECT subject, action, payload, consumed FROM approvals WHERE token = ?",
                (token,),
            ).fetchone()
            if approval != (subject, action, payload, 0):
                raise ApprovalDenied("approval missing, consumed, or mismatched")

            updated = connection.execute(
                "UPDATE approvals SET consumed = 1 WHERE token = ? AND consumed = 0",
                (token,),
            )
            if updated.rowcount != 1:
                raise ApprovalDenied("approval already consumed")

            connection.execute(
                "INSERT INTO effect_intents(token, subject, action, payload) VALUES (?, ?, ?, ?)",
                (token, subject, action, payload),
            )
            connection.execute("COMMIT")
            return EffectIntent(token, subject, action, payload)
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def intent_count(self, token: str) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM effect_intents WHERE token = ?", (token,)
            ).fetchone()
            assert row is not None
            return int(row[0])

    def is_consumed(self, token: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT consumed FROM approvals WHERE token = ?", (token,)
            ).fetchone()
            return row is not None and bool(row[0])
