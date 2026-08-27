from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get("TRL_DOCKER_INTEGRATION") == "1", "set TRL_DOCKER_INTEGRATION=1")
class DockerIntegrationTests(unittest.TestCase):
    def test_postgresql_dynamic_port_and_zero_residue(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = {
                "policy_version": 1,
                "repository_id": "trl-integration",
                "profiles": {"postgres": {"resources": {"postgresql": [{
                    "name": "db", "image": "postgres:16-alpine", "database": "trl_test",
                    "username": "trl", "password_env": "TRL_TEST_POSTGRES_PASSWORD",
                    "inject_url_env": "DATABASE_URL",
                }]}}},
            }
            config_path = root / ".test-resource-lifecycle.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
