from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipapp
from pathlib import Path


class ZipappEntrypointTests(unittest.TestCase):
    """The zipapp entry point must propagate the CLI exit code.

    `zipapp.create_archive(main="trl.cli:main")` writes a stub that calls
    main() and discards its return value, so `python app.pyz` exited 0 even
    for failed runs. The distribution now ships an explicit __main__.py that
    raises SystemExit(main()).
    """

    def build_pyz(self, root: Path) -> Path:
        source = root / "source"
        shutil.copytree(Path(__file__).resolve().parents[1] / "trl", source / "trl")
        (source / "__main__.py").write_text(
            "# -*- coding: utf-8 -*-\nimport sys\nimport trl.cli\n\nraise SystemExit(trl.cli.main())\n",
            encoding="utf-8",
        )
        target = root / "trl.pyz"
        zipapp.create_archive(source, target, interpreter="/usr/bin/env python3", compressed=True)
        target.chmod(0o755)
        return target

    def run_pyz(self, root: Path, child_code: str) -> subprocess.CompletedProcess[str]:
        pyz = self.build_pyz(root)
        config = {
            "policy_version": 1,
            "repository_id": "zipapp-test",
            "profiles": {"unit": {"resources": {}}},
        }
        config_path = root / ".test-resource-lifecycle.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        env = os.environ.copy()
        env["XDG_STATE_HOME"] = str(root / "state")
        return subprocess.run(
            [sys.executable, str(pyz), "run", "--config", str(config_path), "--profile", "unit", "--", sys.executable, "-c", child_code],
            cwd=root, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_failure_exit_code_is_propagated(self):
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_pyz(Path(raw), "raise SystemExit(19)")
            self.assertEqual(result.returncode, 19, result.stderr)

    def test_success_exit_code_is_zero(self):
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_pyz(Path(raw), "print('ok')")
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()