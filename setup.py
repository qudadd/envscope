"""Package the exact pinned vendor files, including hidden files and Python data."""
import json
from pathlib import Path
from setuptools import setup

root = Path(__file__).parent
prefix = "vendor/claude_switcher/"
manifest = json.loads((root / "envscope" / prefix / "VENDOR_MANIFEST.json").read_text(encoding="utf-8"))
setup(package_data={"envscope": ["web/*", prefix + "VENDOR_MANIFEST.json"] + [prefix + path for path in manifest["files"]]})
