"""Adversarial child process: bypass the host broker via a raw local socket."""
from __future__ import annotations

import socket
import sys


def main() -> None:
    host, port, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    with socket.create_connection((host, port), timeout=3) as connection:
        connection.sendall(payload.encode("utf-8"))


if __name__ == "__main__":
    main()
