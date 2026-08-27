from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
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

    def test_immediate_child_exit_is_not_a_process_claim_failure(self):
        for _ in range(20):
            with tempfile.TemporaryDirectory() as raw:
                result = self.run_cli(Path(raw), "pass")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_child_starts_only_after_its_process_claim_is_durable(self):
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_cli(
                Path(raw),
                "import json,os; ledger=json.load(open(os.environ['TRL_RESOURCE_LEDGER'])); "
                "assert any(item.get('adapter') == 'test-command' and item.get('state') == 'created' for item in ledger['resources'])",
            )
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

    def test_next_run_recovers_the_orphaned_test_process_after_sigkill(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = {
                "policy_version": 1,
                "repository_id": "cli-crash-test",
                "profiles": {"unit": {"resources": {"filesystem": [{"name": "tmp", "path": ".tmp/${TRL_RUN_ID}"}]}}},
            }
            config_path = root / ".test-resource-lifecycle.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            pid_path = root / "child.pid"
            env = os.environ.copy()
            env["XDG_STATE_HOME"] = str(root / "state")
            command = [
                sys.executable, "-m", "trl", "run", "--config", str(config_path),
                "--profile", "unit", "--run-id", "crash", "--", sys.executable, "-c",
                f"import os,time; open({str(pid_path)!r}, 'w').write(str(os.getpid())); time.sleep(120)",
            ]
            owner = subprocess.Popen(
                command, cwd=Path(__file__).resolve().parents[1], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            ledger = root / "state/test-resource-lifecycle/runs/cli-crash-test/crash"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                ledgers = list(ledger.glob("*/resource-ledger.json"))
                if pid_path.exists() and ledgers:
                    resources = json.loads(ledgers[0].read_text())["resources"]
                    if any(item.get("adapter") == "test-command" for item in resources):
                        break
                time.sleep(.05)
            else:
                owner.kill()
                self.fail("test command was not durably recorded before the deadline")
            child_pid = int(pid_path.read_text())
            owner.kill()
            owner.wait(timeout=5)

            recovered = subprocess.run(
                [sys.executable, "-m", "trl", "run", "--config", str(config_path), "--profile", "unit", "--run-id", "recovery", "--", sys.executable, "-c", "pass"],
                cwd=Path(__file__).resolve().parents[1], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            for _ in range(100):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.05)
            else:
                os.killpg(child_pid, 9)
                self.fail("stale test process survived immediate same-repository recovery")


if __name__ == "__main__":
    unittest.main()
