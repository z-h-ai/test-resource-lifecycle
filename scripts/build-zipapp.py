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
VERSION = "1.0.5"
DIST.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as raw:
    source = Path(raw)
    shutil.copytree(ROOT / "trl", source / "trl")
    # zipapp's `main=` argument generates a stub that discards the callable's
    # return value (no SystemExit), so `python app.pyz` always exits 0 even
    # when the CLI returned failure. Provide an explicit entry point that
    # propagates the exit code instead.
    (source / "__main__.py").write_text(
        "# -*- coding: utf-8 -*-\nimport sys\nimport trl.cli\n\nraise SystemExit(trl.cli.main())\n",
        encoding="utf-8",
    )
    target = DIST / "trl.pyz"
    zipapp.create_archive(source, target, interpreter="/usr/bin/env python3", compressed=True)
    target.chmod(0o755)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (DIST / "trl.pyz.sha256").write_text(f"{digest}  trl.pyz\n", encoding="utf-8")
    (DIST / "manifest.json").write_text(json.dumps({"version": VERSION, "sha256": digest, "asset": "trl.pyz"}, indent=2) + "\n", encoding="utf-8")
