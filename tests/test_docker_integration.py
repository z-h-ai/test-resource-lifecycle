from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get("TRL_DOCKER_INTEGRATION") == "1", "set TRL_DOCKER_INTEGRATION=1")
class DockerIntegrationTests(unittest.TestCase):
    def config(self):
        return {
            "policy_version": 1,
            "repository_id": "trl-integration",
            "profiles": {"postgres": {"resources": {"postgresql": [{
                "name": "db", "image": "postgres:16-alpine", "database": "trl_test",
                "username": "trl", "password_env": "TRL_TEST_POSTGRES_PASSWORD",
                "inject_url_env": "DATABASE_URL",
            }]}}},
        }

    def test_postgresql_dynamic_port_and_zero_residue(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_path = root / ".test-resource-lifecycle.json"
            config_path.write_text(json.dumps(self.config()), encoding="utf-8")
            env = os.environ.copy()
            env["XDG_STATE_HOME"] = str(root / "state")
            child = "import os,socket,urllib.parse; u=urllib.parse.urlparse(os.environ['DATABASE_URL']); s=socket.create_connection((u.hostname,u.port),5); s.close()"
            result = subprocess.run(
                [sys.executable, "-m", "trl", "run", "--config", str(config_path), "--profile", "postgres", "--run-id", "docker", "--", sys.executable, "-c", child],
                cwd=Path(__file__).resolve().parents[1], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            for args in (["docker", "ps", "-aq"], ["docker", "volume", "ls", "-q"]):
                check = subprocess.run(
                    [*args, "--filter", "label=com.z-h-ai.test.repository-id=trl-integration"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                self.assertEqual(check.stdout.strip(), "")

    def test_different_locales_keep_concurrent_runs_isolated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_path = root / ".test-resource-lifecycle.json"
            config_path.write_text(json.dumps(self.config()), encoding="utf-8")
            state = root / "state"
            child = (
                "import os,socket,sys,time,urllib.parse; from pathlib import Path; "
                "u=urllib.parse.urlparse(os.environ['DATABASE_URL']); "
                "connect=lambda: socket.create_connection((u.hostname,u.port),5).close(); "
                "connect(); Path(sys.argv[1]).write_text('ready'); "
                "deadline=time.monotonic()+60; "
                "exec(\"while not Path(sys.argv[2]).exists():\\n"
                "  assert time.monotonic() < deadline\\n  time.sleep(.05)\"); connect()"
            )

            def start(run_id: str, locale: str, ready: Path, release: Path):
                env = os.environ.copy()
                env.update({"XDG_STATE_HOME": str(state), "LC_ALL": locale})
                return subprocess.Popen(
                    [sys.executable, "-m", "trl", "run", "--config", str(config_path),
                     "--profile", "postgres", "--run-id", run_id, "--", sys.executable,
                     "-c", child, str(ready), str(release)],
                    cwd=Path(__file__).resolve().parents[1], env=env, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )

            ready_a, ready_b = root / "ready-a", root / "ready-b"
            release_a, release_b = root / "release-a", root / "release-b"
            run_a = start("locale-a", "zh_CN.UTF-8", ready_a, release_a)
            run_b = None
            try:
                deadline = time.monotonic() + 90
                while not ready_a.exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertTrue(ready_a.exists(), "first locale run did not become ready")

                run_b = start("locale-b", "C", ready_b, release_b)
                while not ready_b.exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertTrue(ready_b.exists(), "second locale run did not become ready")

                listed = subprocess.run(
                    ["docker", "ps", "--filter", "label=com.z-h-ai.test.repository-id=trl-integration",
                     "--format", "{{.Label \"com.z-h-ai.test.run-id\"}}"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                ).stdout.splitlines()
                self.assertEqual(set(listed), {"locale-a", "locale-b"})

                release_b.touch()
                stdout_b, stderr_b = run_b.communicate(timeout=90)
                self.assertEqual(run_b.returncode, 0, stderr_b + stdout_b)

                release_a.touch()
                stdout_a, stderr_a = run_a.communicate(timeout=90)
                self.assertEqual(run_a.returncode, 0, stderr_a + stdout_a)
            finally:
                for process in (run_b, run_a):
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
