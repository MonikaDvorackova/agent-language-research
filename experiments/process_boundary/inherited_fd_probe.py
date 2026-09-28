"""Try to write through a socket descriptor inherited above stderr."""
from __future__ import annotations

import os
import sys


def main() -> int:
    descriptor = int(sys.argv[1])
    try:
        os.write(descriptor, b"INHERITED_FD_BYPASS")
    except OSError as error:
        print(f"INHERITED_FD_BLOCKED:{error.errno}")
        return 0 if error.errno == 9 else 1
    print("INHERITED_FD_WRITE_SUCCEEDED")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
