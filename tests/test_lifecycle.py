from __future__ import annotations

import json
import os
import subprocess
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from trl.core import Lifecycle, cleanup_ledger_resource, owner_alive, process_birth


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

    def test_process_birth_is_locale_and_timezone_stable(self):
        completed = subprocess.CompletedProcess(
            ["ps"], 0, "Fri Aug 28 06:00:11 2026\n", "",
        )
        with patch("trl.core.platform.system", return_value="Darwin"), patch(
            "trl.core.subprocess.run", return_value=completed,
        ) as run:
            birth = process_birth(123)
        self.assertTrue(birth.startswith("v2:"))
        identity_env = run.call_args.kwargs["env"]
        self.assertEqual(identity_env["LC_ALL"], "C")
        self.assertEqual(identity_env["LANG"], "C")
        self.assertEqual(identity_env["TZ"], "UTC")

    def test_process_birth_matches_across_caller_locales(self):
        with patch.dict(os.environ, {"LC_ALL": "zh_CN.UTF-8", "TZ": "America/Los_Angeles"}):
            localized = process_birth(os.getpid())
        with patch.dict(os.environ, {"LC_ALL": "C", "TZ": "UTC"}):
            canonical = process_birth(os.getpid())
        self.assertEqual(localized, canonical)

    def test_live_legacy_owner_is_preserved_fail_closed(self):
        owner = {"host_id": "host", "pid": 123, "process_birth": "legacy-hash"}
        with patch("trl.core.os.kill") as kill, patch(
            "trl.core.process_birth",
        ) as current_birth:
            self.assertTrue(owner_alive(owner, "host"))
        kill.assert_called_once_with(123, 0)
        current_birth.assert_not_called()

    def test_malformed_versioned_owner_is_preserved_fail_closed(self):
        owner = {"host_id": "host", "pid": 123, "process_birth": "v2:not-a-digest"}
        with patch("trl.core.os.kill"), patch("trl.core.process_birth") as current_birth:
            self.assertTrue(owner_alive(owner, "host"))
        current_birth.assert_not_called()

    def test_identity_read_failure_preserves_live_current_owner(self):
        owner = {"host_id": "host", "pid": 123, "process_birth": "v2:recorded"}
        with patch("trl.core.os.kill"), patch(
            "trl.core.process_birth", side_effect=RuntimeError("unavailable"),
        ):
            self.assertTrue(owner_alive(owner, "host"))

    def test_current_owner_requires_exact_birth_match(self):
        recorded = f"v2:{'a' * 64}"
        owner = {"host_id": "host", "pid": 123, "process_birth": recorded}
        with patch("trl.core.os.kill"), patch("trl.core.process_birth", return_value=recorded):
            self.assertTrue(owner_alive(owner, "host"))
        with patch("trl.core.os.kill"), patch(
            "trl.core.process_birth", return_value=f"v2:{'b' * 64}",
        ):
            self.assertFalse(owner_alive(owner, "host"))

    def test_legacy_process_resource_is_never_killed_without_stable_proof(self):
        item = {
            "kind": "process", "id": "123", "name": "child",
            "process_birth": "legacy-hash",
        }
        with patch("trl.core.os.kill") as kill:
            result = cleanup_ledger_resource(item, {}, 999999999.0, Mock())
        self.assertEqual(result["result"], "preserved_legacy_identity")
        kill.assert_called_once_with(123, 0)


if __name__ == "__main__":
    unittest.main()
