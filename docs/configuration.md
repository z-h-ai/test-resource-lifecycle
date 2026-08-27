# Configuration and bootstrap contract

Each adopter tracks `.test-resource-lifecycle.json`, `.test-resource-lifecycle.lock.json`, and `scripts/trl`. The lock contains an immutable release URL plus SHA-256; the bootstrap caches the verified `trl.pyz` and refuses mismatches. It never follows `main`.

```json
{
  "policy_version": 1,
  "repository_id": "example",
  "profiles": {
    "e2e": {
      "timeout_seconds": 1800,
      "cleanup_timeout_seconds": 120,
      "environment": {"NODE_ENV": "test"},
      "resources": {
        "postgresql": [{
          "name": "primary",
          "image": "postgres:16-alpine",
          "database": "example_test",
          "username": "test",
          "password_env": "TRL_POSTGRES_PASSWORD",
          "inject_url_env": "DATABASE_URL"
        }],
        "filesystem": [{"name": "tmp", "path": ".tmp/trl/${TRL_RUN_ID}"}]
      }
    }
  }
}
```

Supported adapters are `postgresql`, `docker_compose`, `services`, `filesystem`, `http`, and `sql_file`. Commands are argv arrays; inline cleanup shell is rejected. Filesystem and SQL paths must stay inside the repository, filesystem paths must contain `${TRL_RUN_ID}`, and database identifiers use a strict identifier grammar.

Compose files must apply every `TRL_LABEL_*` environment value supplied by `trl` to their containers, networks, and volumes. This makes a missing label a fail-closed preservation event.
