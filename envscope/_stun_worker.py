"""Subprocess isolation gives DNS resolution and UDP a shared hard deadline."""
import json
import sys
from pathlib import Path

from .stun import query


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        ip = query(args[0], int(args[1]), int(args[2]), float(args[3]))
        result = {"ip": ip}
    except (OSError, ValueError) as exc:
        result = {"error": type(exc).__name__}
    if len(args) > 4:
        Path(args[4]).write_text(json.dumps(result), encoding="utf-8")
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
