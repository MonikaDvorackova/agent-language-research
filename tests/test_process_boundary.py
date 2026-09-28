import socket
import shutil
import subprocess
import sys
import tempfile
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

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc"),
                         "seccomp probe requires Linux and gcc")
    def test_seccomp_launcher_blocks_new_network_sockets_but_keeps_pipe(self):
        root = Path(__file__).parents[1]
        launcher_source = root / "experiments" / "process_boundary" / "seccomp_no_network.c"
        child = root / "experiments" / "process_boundary" / "seccomp_socket_probe.py"
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "seccomp-no-network"
            built = subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                                    "-o", str(launcher), str(launcher_source)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run(
                [str(launcher), "--", sys.executable, str(child)],
                input="approved broker channel\n", capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PIPE_OK:approved broker channel", result.stdout)
            self.assertIn("SOCKET_DENIED:1", result.stdout)
            self.assertNotIn("SOCKET_ALLOWED", result.stdout)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc"),
                         "combined probe requires Linux and gcc")
    def test_seccomp_and_landlock_limit_writes_when_landlock_is_available(self):
        root = Path(__file__).parents[1]
        launcher_source = root / "experiments" / "process_boundary" / "seccomp_no_network.c"
        child = root / "experiments" / "process_boundary" / "seccomp_landlock_probe.py"
        with tempfile.TemporaryDirectory() as temporary:
            root_dir = Path(temporary)
            writable_dir = root_dir / "work"
            outside_dir = root_dir / "outside"
            writable_dir.mkdir()
            outside_dir.mkdir()
            launcher = root_dir / "seccomp-landlock"
            built = subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                                    "-o", str(launcher), str(launcher_source)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run(
                [str(launcher), "--writable-dir", str(writable_dir), "--",
                 sys.executable, str(child), str(writable_dir),
                 str(outside_dir / "forbidden.txt")],
                input="approved broker channel\n", capture_output=True,
                text=True, timeout=10)
            if result.returncode == 125 and "errno=38" in result.stderr:
                self.skipTest("Landlock syscalls are unavailable in this execution environment (ENOSYS)")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("PIPE_OK:approved broker channel", result.stdout)
            self.assertIn("WRITE_ALLOWED", result.stdout)
            self.assertIn("OUTSIDE_WRITE_DENIED:13", result.stdout)
            self.assertIn("SOCKET_DENIED:1", result.stdout)
            self.assertTrue((writable_dir / "inside.txt").exists())
            self.assertFalse((outside_dir / "forbidden.txt").exists())

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc"),
                         "descriptor probes require Linux and gcc")
    def test_launcher_closes_inherited_socket_descriptors_above_stdio(self):
        root = Path(__file__).parents[1]
        launcher_source = root / "experiments" / "process_boundary" / "seccomp_no_network.c"
        child = root / "experiments" / "process_boundary" / "inherited_fd_probe.py"
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "seccomp-no-network"
            built = subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                                    "-o", str(launcher), str(launcher_source)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname())
            connection, _ = listener.accept()
            connection.settimeout(0.2)
            try:
                result = subprocess.run(
                    [str(launcher), "--", sys.executable, str(child), str(client.fileno())],
                    pass_fds=(client.fileno(),), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("INHERITED_FD_BLOCKED:9", result.stdout)
                with self.assertRaises(socket.timeout):
                    connection.recv(64)
            finally:
                connection.close()
                client.close()
                listener.close()

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc"),
                         "descriptor probes require Linux and gcc")
    def test_stdio_socket_remains_a_write_channel_by_design(self):
        root = Path(__file__).parents[1]
        launcher_source = root / "experiments" / "process_boundary" / "seccomp_no_network.c"
        child = root / "experiments" / "process_boundary" / "stdio_socket_probe.py"
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "seccomp-no-network"
            built = subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                                    "-o", str(launcher), str(launcher_source)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname())
            connection, _ = listener.accept()
            connection.settimeout(2)
            try:
                result = subprocess.run(
                    [str(launcher), "--", sys.executable, str(child)],
                    stdin=subprocess.DEVNULL, stdout=client, stderr=subprocess.PIPE,
                    text=False, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                client.shutdown(socket.SHUT_WR)
                received = connection.recv(128)
                self.assertEqual(received, b"STDIO_SOCKET_BYPASS\n")
            finally:
                connection.close()
                client.close()
                listener.close()


if __name__ == "__main__":
    unittest.main()
