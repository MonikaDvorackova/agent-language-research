"""Probe filesystem writes under the combined seccomp and Landlock launcher."""
from __future__ import annotations

import socket
import sys
from pathlib import Path


def main() -> int:
    allowed_dir = Path(sys.argv[1])
    denied_path = Path(sys.argv[2])
    broker_message = sys.stdin.readline().strip()
    print(f"PIPE_OK:{broker_message}", flush=True)

    try:
        (allowed_dir / "inside.txt").write_text("allowed", encoding="utf-8")
        print("WRITE_ALLOWED", flush=True)
    except OSError as error:
        print(f"WRITE_UNEXPECTEDLY_DENIED:{error.errno}", flush=True)
        return 2

    try:
        denied_path.write_text("outside", encoding="utf-8")
    except PermissionError as error:
        print(f"OUTSIDE_WRITE_DENIED:{error.errno}", flush=True)
    else:
        print("OUTSIDE_WRITE_ALLOWED", flush=True)
        return 3

    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as error:
        print(f"SOCKET_DENIED:{error.errno}", flush=True)
    else:
        print("SOCKET_ALLOWED", flush=True)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
