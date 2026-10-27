"""Reject private artifacts and recognizable credential formats before publishing."""
from pathlib import Path
import re
import subprocess

from envscope.legacy import LegacyBridge


def main():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(["git", "-c", "safe.directory=" + root.as_posix(), "ls-files", "-z"], cwd=root,
                            check=True, capture_output=True)
    names = [name for name in result.stdout.decode("utf-8").split("\0") if name]
    if not names:
        raise SystemExit("No tracked source files to review")
    pattern = re.compile(r"(?:\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-(?:ant-|proj-)[A-Za-z0-9_-]{32,}|-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----)")
    errors = []
    for name in names:
        path = Path(name)
        if (path.parts[0] in {"reports", "artifacts", "build", "dist", ".venv", ".env"}
                or "__pycache__" in path.parts or name.endswith((".private.json", ".log", ".pyc"))):
            errors.append("Private/build artifact tracked: " + name)
        file = root / path
        if file.suffix.lower() in {".py", ".mjs", ".js", ".json", ".md", ".yml", ".yaml", ".ps1", ".sh", ".command", ".txt"}:
            if pattern.search(file.read_text(encoding="utf-8-sig", errors="replace")):
                errors.append("Credential-like content requires review: " + name)
    vendor = LegacyBridge()._vendor_integrity()
    if not vendor["verified"]:
        errors.append("Pinned source verification failed: " + vendor["reason"])
    if errors:
        raise SystemExit("\n".join(errors))
    print("Tracked source excludes private/build artifacts; credential-pattern and pinned-source checks passed.")


if __name__ == "__main__":
    main()
