from __future__ import annotations

import unittest

from trl.core import labels, redact, validate_config


def valid() -> dict:
    return {"policy_version": 1, "repository_id": "repo-a", "profiles": {"unit": {"resources": {}}}}


class ContractTests(unittest.TestCase):
    def test_minimal_config(self):
        self.assertEqual(validate_config(valid(), "unit")["repository_id"], "repo-a")

    def test_unknown_and_inline_shell_fail_closed(self):
        value = valid()
        value["profiles"]["unit"]["resources"] = {"services": [{"name": "api", "argv": ["node", "x"], "cleanup_shell": "rm -rf /"}]}
        with self.assertRaisesRegex(ValueError, "inline cleanup shell"):
            validate_config(value, "unit")

    def test_filesystem_must_be_run_scoped(self):
        value = valid()
        value["profiles"]["unit"]["resources"] = {"filesystem": [{"name": "tmp", "path": "tmp/cache"}]}
        with self.assertRaisesRegex(ValueError, "TRL_RUN_ID"):
            validate_config(value, "unit")

    def test_invalid_database_name(self):
        value = valid()
        value["profiles"]["unit"]["resources"] = {"postgresql": [{"name": "db", "database": "postgres;drop", "username": "test", "password_env": "PW", "inject_url_env": "DATABASE_URL"}]}
        with self.assertRaisesRegex(ValueError, "database is invalid"):
            validate_config(value, "unit")

    def test_labels_are_complete(self):
        context = {"repository_id": "r", "run_id": "x", "execution_nonce": "n", "host_id": "h", "docker_context": "d"}
        actual = labels(context)
        self.assertEqual(len(actual), 7)
        self.assertEqual(actual["com.z-h-ai.test.managed"], "true")

    def test_redacts_connections(self):
        self.assertNotIn("hunter2", redact("DATABASE_URL=postgresql://u:hunter2@localhost/db"))


if __name__ == "__main__":
    unittest.main()
