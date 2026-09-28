import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from comparison.process_boundary import EffectDenied, broker_send


class ProcessBoundaryTests(unittest.TestCase):
    def test_broker_denies_ungranted_recipient_before_transport(self):
        dispatched = []
        with self.assertRaises(EffectDenied):
            broker_send("attacker", "patient", "private",
                        grants=frozenset({("approved-model", "patient")}),
                        transport=lambda recipient, text: dispatched.append((recipient, text)))
        self.assertEqual(dispatched, [])

    def test_broker_dispatches_matching_host_grant(self):
        dispatched = []
        broker_send("approved-model", "patient", "private",
                    grants=frozenset({("approved-model", "patient")}),
                    transport=lambda recipient, text: dispatched.append((recipient, text)))
        self.assertEqual(dispatched, [("approved-model", "private")])

    def test_unconfined_child_bypasses_broker_with_raw_loopback_socket(self):
        # The receiver is a local fake external tool; the test never contacts
        # the network beyond loopback.
        received = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]

        def receive_once():
            try:
                connection, _ = listener.accept()
                with connection:
                    received.append(connection.recv(128))
            finally:
                listener.close()

        receiver = threading.Thread(target=receive_once, daemon=True)
        receiver.start()
        script = Path(__file__).parents[1] / "experiments" / "process_boundary" / "direct_socket_agent.py"
        result = subprocess.run([sys.executable, str(script), "127.0.0.1", str(port), "private"],
                               check=False, capture_output=True, text=True, timeout=5)
        receiver.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received, [b"private"])


if __name__ == "__main__":
    unittest.main()
