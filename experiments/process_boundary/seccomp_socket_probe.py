"""Child probe: use the inherited pipe, then attempt a raw network socket."""
from __future__ import annotations

import socket
import subprocess
import sys


def main() -> int:
    broker_message = sys.stdin.readline().strip()
    print(f"PIPE_OK:{broker_message}", flush=True)
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as error:
        print(f"SOCKET_DENIED:{error.errno}", flush=True)
    else:
        print("SOCKET_ALLOWED", flush=True)
        return 1

    descendant_code = """import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except PermissionError as error:
    print(f'DESCENDANT_SOCKET_DENIED:{error.errno}')
else:
    print('DESCENDANT_SOCKET_ALLOWED')
    raise SystemExit(1)
"""
    descendant = subprocess.run([sys.executable, "-c", descendant_code],
                                capture_output=True, text=True, timeout=5)
    print(descendant.stdout.strip(), flush=True)
    return descendant.returncode


if __name__ == "__main__":
    raise SystemExit(main())
