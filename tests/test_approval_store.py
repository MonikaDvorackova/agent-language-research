from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from comparison.approval_store import (
    ApprovalDenied,
    ApprovalStore,
    IdempotencyConflict,
    SQLiteIdempotentReceiver,
)


class ApprovalStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "approvals.sqlite3"
        self.receiver_database = Path(self.temporary.name) / "receiver.sqlite3"
        self.store = ApprovalStore(self.database)
        self.receiver = SQLiteIdempotentReceiver(self.receiver_database)
        self.store.grant("one-use-token", "agent-a", "payment", "invoice-17")

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_approval_creates_one_intent_and_replay_is_denied(self):
        intent = self.store.consume_and_record(
            "one-use-token", "agent-a", "payment", "invoice-17"
        )
        self.assertEqual(intent.action, "payment")
        self.assertTrue(self.store.is_consumed("one-use-token"))
        self.assertEqual(self.store.intent_count("one-use-token"), 1)
        with self.assertRaises(ApprovalDenied):
            self.store.consume_and_record(
                "one-use-token", "agent-a", "payment", "invoice-17"
            )
        self.assertEqual(self.store.intent_count("one-use-token"), 1)

    def test_mismatched_request_does_not_consume_the_approval(self):
        with self.assertRaises(ApprovalDenied):
            self.store.consume_and_record(
                "one-use-token", "agent-a", "payment", "different-invoice"
            )
        self.assertFalse(self.store.is_consumed("one-use-token"))
        self.assertEqual(self.store.intent_count("one-use-token"), 0)
        self.store.consume_and_record(
            "one-use-token", "agent-a", "payment", "invoice-17"
        )

    def test_concurrent_consumers_create_exactly_one_intent(self):
        start = threading.Barrier(2)

        def consume() -> str:
            start.wait(timeout=5)
            try:
                self.store.consume_and_record(
                    "one-use-token", "agent-a", "payment", "invoice-17"
                )
                return "accepted"
            except ApprovalDenied:
                return "denied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        self.assertCountEqual(results, ["accepted", "denied"])
        self.assertEqual(self.store.intent_count("one-use-token"), 1)

    def test_database_abort_rolls_back_consumption_and_intent_together(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """CREATE TRIGGER reject_intent BEFORE INSERT ON effect_intents
                   BEGIN SELECT RAISE(ABORT, 'simulated persistence failure'); END"""
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.consume_and_record(
                "one-use-token", "agent-a", "payment", "invoice-17"
            )
        self.assertFalse(self.store.is_consumed("one-use-token"))
        self.assertEqual(self.store.intent_count("one-use-token"), 0)

    def test_pending_intent_retries_after_receiver_is_temporarily_unavailable(self):
        self.store.consume_and_record(
            "one-use-token", "agent-a", "payment", "invoice-17"
        )

        class UnavailableReceiver:
            def deliver(self, idempotency_key, action, payload):
                raise ConnectionError("receiver unavailable before delivery")

        with self.assertRaises(ConnectionError):
            self.store.dispatch_pending(UnavailableReceiver())
        self.assertEqual(self.store.intent_status("one-use-token"), (False, 1))
        self.assertEqual(self.receiver.effect_count("one-use-token"), 0)
        self.assertEqual(self.store.dispatch_pending(self.receiver), 1)
        self.assertEqual(self.store.intent_status("one-use-token"), (True, 2))
        self.assertEqual(self.receiver.effect_count("one-use-token"), 1)

    def test_lost_ack_after_receiver_commit_retries_without_duplicate_effect(self):
        self.store.consume_and_record(
            "one-use-token", "agent-a", "payment", "invoice-17"
        )

        class LoseFirstAcknowledgment:
            def __init__(self, delegate):
                self.delegate = delegate
                self.first = True

            def deliver(self, idempotency_key, action, payload):
                self.delegate.deliver(idempotency_key, action, payload)
                if self.first:
                    self.first = False
                    raise TimeoutError("effect committed, acknowledgment lost")

        with self.assertRaises(TimeoutError):
            self.store.dispatch_pending(LoseFirstAcknowledgment(self.receiver))
        self.assertEqual(self.store.intent_status("one-use-token"), (False, 1))
        self.assertEqual(self.receiver.effect_count("one-use-token"), 1)

        self.assertEqual(self.store.dispatch_pending(self.receiver), 1)
        self.assertEqual(self.store.intent_status("one-use-token"), (True, 2))
        self.assertEqual(self.receiver.effect_count("one-use-token"), 1)

    def test_receiver_rejects_idempotency_key_reuse_with_different_effect(self):
        self.receiver.deliver("key", "payment", "invoice-17")
        with self.assertRaises(IdempotencyConflict):
            self.receiver.deliver("key", "payment", "invoice-18")
        self.assertEqual(self.receiver.effect_count("key"), 1)

    def test_existing_intent_database_is_migrated_with_pending_delivery_fields(self):
        legacy_database = Path(self.temporary.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_database) as connection:
            connection.executescript(
                """CREATE TABLE approvals (
                       token TEXT PRIMARY KEY, subject TEXT NOT NULL,
                       action TEXT NOT NULL, payload TEXT NOT NULL,
                       consumed INTEGER NOT NULL DEFAULT 0
                   );
                   CREATE TABLE effect_intents (
                       token TEXT PRIMARY KEY, subject TEXT NOT NULL,
                       action TEXT NOT NULL, payload TEXT NOT NULL
                   );
                   INSERT INTO approvals VALUES ('old-token', 'agent-a', 'payment', 'invoice-17', 1);
                   INSERT INTO effect_intents VALUES ('old-token', 'agent-a', 'payment', 'invoice-17');"""
            )
        migrated = ApprovalStore(legacy_database)
        self.assertEqual(migrated.intent_status("old-token"), (False, 0))


if __name__ == "__main__":
    unittest.main()
