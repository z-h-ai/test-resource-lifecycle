from __future__ import annotations

import json
import os
import subprocess
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trl.core import Lifecycle, cleanup_ledger_resource


class LifecycleTests(unittest.TestCase):
    def config(self, resources=None):
        return {"policy_version": 1, "repository_id": "example", "profiles": {"test": {"resources": resources or {}}}}

    def test_success_and_failure_exit_semantics(self):
        with tempfile.TemporaryDirectory() as raw, patch("trl.core.process_birth", return_value="birth"):
            root = Path(raw)
            lifecycle = Lifecycle(self.config(), "test", root, "run-1", root / "state")
            self.assertEqual(lifecycle.environment["TRL_RUN_ID"], "run-1")
            self.assertEqual(lifecycle.environment["TRL_RUN_CONTEXT"], str(lifecycle.paths.global_dir / "run-context.json"))
            lifecycle.prepare()
            code, report = lifecycle.cleanup(23, None)
            self.assertEqual(code, 23)
            self.assertEqual(report["checks"]["exit_code"], 23)
            self.assertTrue((root / ".pipeline/test-resource-runs/run-1" / lifecycle.nonce / "cleanup-report.json").is_file())

    def test_filesystem_requires_marker_and_cleans(self):
        resources = {"filesystem": [{"name": "tmp", "path": ".tmp/${TRL_RUN_ID}"}]}
        with tempfile.TemporaryDirectory() as raw, patch("trl.core.process_birth", return_value="birth"):
            root = Path(raw)
            lifecycle = Lifecycle(self.config(resources), "test", root, "run-2", root / "state")
            lifecycle.prepare()
            target = root / ".tmp/run-2"
            self.assertTrue(target.exists())
            code, report = lifecycle.cleanup(0, None)
            self.assertEqual(code, 0)
            self.assertFalse(target.exists())
            self.assertEqual(report["cleanup"]["status"], "passed")

    def test_label_mismatch_is_preserved(self):
        item = {"kind": "container", "id": "c1", "name": "db"}
        context = {"repository_id": "r", "run_id": "x", "execution_nonce": "n", "host_id": "h", "docker_context": "d"}
        def runner(argv, **kwargs):
            if "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps([{"Config": {"Labels": {"com.z-h-ai.test.managed": "true"}}}]), "")
            raise AssertionError("foreign resource must not be removed")
        result = cleanup_ledger_resource(item, context, 999999999.0, runner)
        self.assertEqual(result["result"], "preserved_label_mismatch")

    def test_signal_exit_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw, patch("trl.core.process_birth", return_value="birth"):
            root = Path(raw)
            lifecycle = Lifecycle(self.config(), "test", root, "run-signal", root / "state")
            lifecycle.prepare()
            code, report = lifecycle.cleanup(None, signal.SIGTERM)
            self.assertEqual(code, 143)
            self.assertEqual(report["checks"]["signal"], signal.SIGTERM)

    def test_cleanup_failure_overrides_check_but_retains_it(self):
        resources = {"filesystem": [{"name": "tmp", "path": ".tmp/${TRL_RUN_ID}"}]}
        with tempfile.TemporaryDirectory() as raw, patch("trl.core.process_birth", return_value="birth"):
            root = Path(raw)
            lifecycle = Lifecycle(self.config(resources), "test", root, "run-fail", root / "state")
            lifecycle.prepare()
            marker = root / ".tmp/run-fail/.trl-owner.json"
            marker.unlink()
            code, report = lifecycle.cleanup(17, None)
            self.assertEqual(code, 70)
            self.assertEqual(report["checks"]["exit_code"], 17)
            self.assertEqual(report["cleanup"]["classification"], "infrastructure")


if __name__ == "__main__":
    unittest.main()
