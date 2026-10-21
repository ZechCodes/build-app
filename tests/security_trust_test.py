"""Regression checks for the October 2026 trust-store remediation."""
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pkg = json.loads((ROOT / "package-lock.json").read_text())
assert pkg["packages"]["node_modules/electron"]["version"] == "43.8.3", "Ship patched Electron"
assert "node-version: 20" not in (ROOT / ".github/workflows/release.yml").read_text(), "Retire old CI Node"
