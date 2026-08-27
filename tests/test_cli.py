from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliIntegrationTests(unittest.TestCase):
    def run_cli(self, root: Path, child_code: str):
        config = {
            "policy_version": 1,
            "repository_id": "cli-test",
            "profiles": {"unit": {"resources": {"filesystem": [{"name": "tmp", "path": ".tmp/${TRL_RUN_ID}"}]}}},
        }
        config_path = root / ".test-resource-lifecycle.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        env = os.environ.copy()
        env["XDG_STATE_HOME"] = str(root / "state")
        return subprocess.run(
            [sys.executable, "-m", "trl", "run", "--config", str(config_path), "--profile", "unit", "--run-id", "integration", "--", sys.executable, "-c", child_code],
            cwd=Path(__file__).resolve().parents[1], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_child_exit_and_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = self.run_cli(root, "raise SystemExit(19)")
            self.assertEqual(result.returncode, 19, result.stderr)
            report = next((root / ".pipeline/test-resource-runs").glob("*/*/cleanup-report.json"))
            self.assertEqual(json.loads(report.read_text())["checks"]["exit_code"], 19)
            self.assertFalse((root / ".tmp/integration").exists())

    def test_success(self):
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_cli(Path(raw), "print('ok')")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_workdir_places_audit_with_consumer(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            config_dir, consumer = base / "config", base / "consumer"
            config_dir.mkdir()
            consumer.mkdir()
            config = {"policy_version": 1, "repository_id": "consumer", "profiles": {"compat": {"resources": {}}}}
            config_path = config_dir / "trl.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            env = os.environ.copy()
            env["XDG_STATE_HOME"] = str(base / "state")
            result = subprocess.run(
                [sys.executable, "-m", "trl", "run", "--config", str(config_path), "--profile", "compat", "--workdir", str(consumer), "--run-id", "workdir", "--", sys.executable, "-c", "pass"],
                cwd=Path(__file__).resolve().parents[1], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(any((consumer / ".pipeline/test-resource-runs").glob("*/*/cleanup-report.json")))

    def test_command_cwd_is_independent_from_audit_workdir(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            child_dir = root / "packages/web"
            child_dir.mkdir(parents=True)
            config = {"policy_version": 1, "repository_id": "monorepo", "profiles": {"test": {"resources": {}}}}
            config_path = root / ".test-resource-lifecycle.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            env = os.environ.copy(); env["XDG_STATE_HOME"] = str(root / "state")
            result = subprocess.run(
                [sys.executable, "-m", "trl", "run", "--config", str(config_path), "--profile", "test", "--command-cwd", str(child_dir), "--", sys.executable, "-c", "import os; assert os.getcwd().endswith('packages/web')"],
                cwd=Path(__file__).resolve().parents[1], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(any((root / ".pipeline/test-resource-runs").glob("*/*/cleanup-report.json")))


if __name__ == "__main__":
    unittest.main()
