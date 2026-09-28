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
from typing import Protocol


class ApprovalDenied(PermissionError):
    """The approval is absent, already used, or does not match the request."""


@dataclass(frozen=True)
class EffectIntent:
    token: str
    subject: str
    action: str
    payload: str


class EffectReceiver(Protocol):
    def deliver(self, idempotency_key: str, action: str, payload: str) -> None: ...


class IdempotencyConflict(ValueError):
    """A downstream key was reused for a different action or payload."""


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
                    payload TEXT NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)),
                    attempts INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            intent_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(effect_intents)")
            }
            if "delivered" not in intent_columns:
                connection.execute(
                    "ALTER TABLE effect_intents ADD COLUMN delivered INTEGER NOT NULL "
                    "DEFAULT 0 CHECK (delivered IN (0, 1))"
                )
            if "attempts" not in intent_columns:
                connection.execute(
                    "ALTER TABLE effect_intents ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
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

    def dispatch_pending(self, receiver: EffectReceiver) -> int:
        """Retry pending intents; receiver must atomically deduplicate the key."""
        with self._connection() as connection:
            pending = list(connection.execute(
                "SELECT token, action, payload FROM effect_intents "
                "WHERE delivered = 0 ORDER BY token"
            ))

        delivered_count = 0
        for token, action, payload in pending:
            try:
                receiver.deliver(token, action, payload)
            except Exception:
                with self._connection() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "UPDATE effect_intents SET attempts = attempts + 1 "
                        "WHERE token = ? AND delivered = 0", (token,)
                    )
                    connection.execute("COMMIT")
                raise

            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    "UPDATE effect_intents SET delivered = 1, attempts = attempts + 1 "
                    "WHERE token = ? AND delivered = 0", (token,)
                )
                connection.execute("COMMIT")
                delivered_count += updated.rowcount
        return delivered_count

    def intent_status(self, token: str) -> tuple[bool, int] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT delivered, attempts FROM effect_intents WHERE token = ?",
                (token,),
            ).fetchone()
            return None if row is None else (bool(row[0]), int(row[1]))


class SQLiteIdempotentReceiver:
    """A simulated downstream that commits an effect once per key."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS external_effects (
                       idempotency_key TEXT PRIMARY KEY,
                       action TEXT NOT NULL,
                       payload TEXT NOT NULL
                   )"""
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        try:
            yield connection
        finally:
            connection.close()

    def deliver(self, idempotency_key: str, action: str, payload: str) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT action, payload FROM external_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO external_effects(idempotency_key, action, payload) "
                    "VALUES (?, ?, ?)", (idempotency_key, action, payload)
                )
            elif existing != (action, payload):
                raise IdempotencyConflict("key already bound to a different effect")
            connection.execute("COMMIT")

    def effect_count(self, idempotency_key: str) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM external_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            assert row is not None
            return int(row[0])
