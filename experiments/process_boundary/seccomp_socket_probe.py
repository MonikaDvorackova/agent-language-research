"""Child probe: use the inherited pipe, then attempt a raw network socket."""
from __future__ import annotations

import socket
import sys


def main() -> int:
    broker_message = sys.stdin.readline().strip()
    print(f"PIPE_OK:{broker_message}", flush=True)
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as error:
        print(f"SOCKET_DENIED:{error.errno}", flush=True)
        return 0
    print("SOCKET_ALLOWED", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
