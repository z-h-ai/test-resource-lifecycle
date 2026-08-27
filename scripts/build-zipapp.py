#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = "1.0.1"
DIST.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as raw:
    source = Path(raw)
    shutil.copytree(ROOT / "trl", source / "trl")
    target = DIST / "trl.pyz"
    zipapp.create_archive(source, target, interpreter="/usr/bin/env python3", main="trl.cli:main", compressed=True)
    target.chmod(0o755)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (DIST / "trl.pyz.sha256").write_text(f"{digest}  trl.pyz\n", encoding="utf-8")
    (DIST / "manifest.json").write_text(json.dumps({"version": VERSION, "sha256": digest, "asset": "trl.pyz"}, indent=2) + "\n", encoding="utf-8")
