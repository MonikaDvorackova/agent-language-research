"""Exercise outbox recovery after killing a process at the delivery boundary."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from comparison.approval_store import ApprovalStore, SQLiteIdempotentReceiver


WORKER = r'''
import os
import sys
from pathlib import Path
from comparison.approval_store import ApprovalStore, SQLiteIdempotentReceiver

intent_db, receiver_db, marker = sys.argv[1:]
receiver = SQLiteIdempotentReceiver(receiver_db)

class StopAfterReceiverCommit:
    def deliver(self, idempotency_key, action, payload):
        receiver.deliver(idempotency_key, action, payload)
        Path(marker).write_text("receiver transaction committed", encoding="utf-8")
        # The parent kills this process here, before dispatch_pending can mark
        # the intent delivered in the separate host database.
        os.read(0, 1)

ApprovalStore(intent_db).dispatch_pending(StopAfterReceiverCommit())
'''


class CrashRecoveryTests(unittest.TestCase):
    def test_killed_process_retries_after_receiver_commit_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent_db = root / "host.sqlite3"
            receiver_db = root / "receiver.sqlite3"
            marker = root / "receiver-committed"

            store = ApprovalStore(intent_db)
            store.grant("approval-1", "agent-a", "payment", "invoice-17")
            store.consume_and_record(
                "approval-1", "agent-a", "payment", "invoice-17"
            )

            env = os.environ.copy()
            repo_root = str(Path(__file__).resolve().parents[1])
            env["PYTHONPATH"] = os.pathsep.join(
                value for value in (repo_root, env.get("PYTHONPATH", "")) if value
            )
            process = subprocess.Popen(
                [sys.executable, "-c", WORKER, str(intent_db), str(receiver_db), str(marker)],
                cwd=repo_root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 10
                while not marker.exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("child did not reach the post-commit crash point")
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "receiver commit marker was not written")
                process.kill()
                _, stderr = process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(stderr, b"")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

            # Reopen both durable stores in the parent, simulating a fresh host
            # process after the child died between downstream commit and ACK.
            recovered_store = ApprovalStore(intent_db)
            recovered_receiver = SQLiteIdempotentReceiver(receiver_db)
            self.assertEqual(recovered_store.intent_status("approval-1"), (False, 0))
            self.assertEqual(recovered_receiver.effect_count("approval-1"), 1)

            self.assertEqual(recovered_store.dispatch_pending(recovered_receiver), 1)
            self.assertEqual(recovered_store.intent_status("approval-1"), (True, 1))
            self.assertEqual(recovered_receiver.effect_count("approval-1"), 1)
            self.assertTrue(recovered_store.is_consumed("approval-1"))


if __name__ == "__main__":
    unittest.main()
