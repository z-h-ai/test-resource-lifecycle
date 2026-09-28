"""Interactive resources owned by the existing long-lived executor supervisor.

No daemon or lease renewal: status is read-only, close uses Lifecycle.cleanup,
and dead owners use the existing ledger sweeper.
"""
from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .core import (Lifecycle, RunPaths, atomic_json, command, docker_context_hash,
                   is_current_process_birth, owner_alive, process_birth, read_json,
                   stable_host_id, state_home)


def deadline(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("session deadline requires a timezone")
    return parsed.astimezone(timezone.utc)


def verify_owner(owner, host):
    if (owner.get("host_id") != host or not is_current_process_birth(owner.get("process_birth"))
            or not owner_alive(owner, host)):
        raise ValueError("session requires a live owner with exact host/PID/birth identity")
    if process_birth(int(owner["pid"])) != owner["process_birth"]:
        raise ValueError("owner identity changed")


def open_session(config, profile, workdir, attempt, owner, deadline_at, state_root=None, response_path=None):
    if deadline(deadline_at) <= datetime.now(timezone.utc):
        raise ValueError("authorized session deadline has expired")
    lifecycle = Lifecycle(config, profile, Path(workdir), attempt, state_root)
    verify_owner(owner, lifecycle.host_id)
    lifecycle.owner = dict(owner)
    lifecycle.context.update(owner=lifecycle.owner, execution_protocol="agent-v1",
                             attempt_id=attempt, deadline_at=deadline_at)
    # The command timeout remains a trl run policy, never an environment lease.
    lifecycle.context["lifecycle_mode"] = "session"
    lifecycle.paths.global_dir.mkdir(parents=True, exist_ok=False)
    private = lifecycle.paths.global_dir / 'session-private.json'
    result = {"context": str(lifecycle.paths.global_dir / "run-context.json"),
              "environment_file": str(private), "attempt_id": attempt,
              "execution_nonce": lifecycle.nonce, "owner": lifecycle.owner, "deadline_at": deadline_at}
    with session_lock(lifecycle.paths.global_dir / 'run-context.json'):
        if response_path:
            atomic_json(Path(response_path), result)
        try:
            lifecycle.prepare()
            verify_owner(owner, lifecycle.host_id)
            lifecycle.context['session_status'] = 'open'
            lifecycle.persist()
        except BaseException:
            lifecycle.context['session_status'] = 'preparation_failed'
            lifecycle.cleanup(None, None, 'session preparation failed')
            raise
    return result



def persist_private(lifecycle):
    if lifecycle.context.get('session_status') == 'closed':
        return
    resources = lifecycle.profile.get('resources', {})
    names = set(lifecycle.profile.get('environment', {}))
    names.update(k for k in lifecycle.environment if k.startswith('TRL_'))
    for item in resources.get('postgresql', []):
        names.update([item['password_env'], item['inject_url_env']])
    names.update(x['database_url_env'] for x in resources.get('sql_file', []))
    if resources.get('sql_file'):
        names.update(k for k in lifecycle.environment if k.startswith('PG'))
    for item in resources.get('http', []):
        names.add(item.get('body_env'))
        names.update(v[1:] for v in item.get('headers', {}).values() if isinstance(v, str) and v.startswith('$'))
    injected = {k: lifecycle.environment[k] for k in names if k and k in lifecycle.environment}
    private = lifecycle.paths.global_dir / 'session-private.json'
    atomic_json(private, {'config': lifecycle.config, 'environment': injected,
                          'secrets': list(set(lifecycle.secrets + list(injected.values())))})
    private.chmod(0o600)


def load_session(context_path, state_root=None):
    path = Path(context_path).resolve()
    context = read_json(path)
    if context.get("lifecycle_mode") != "session":
        raise ValueError("not a TRL session context")
    expected = RunPaths.build(Path(context["workdir"]), context["repository_id"],
                              context["run_id"], context["execution_nonce"], state_root)
    if path != (expected.global_dir / "run-context.json").resolve():
        raise ValueError("session must use its canonical global ledger")
    if context.get("host_id") != stable_host_id(state_root):
        raise ValueError("session host mismatch; preserved")
    dc = context.get("docker_context")
    if dc not in {"none", "unavailable"} and dc != docker_context_hash():
        raise ValueError("session Docker context mismatch; preserved")
    ledger = read_json(path.parent / "resource-ledger.json")
    if ledger.get("context") != context:
        raise ValueError("session ledger/context mismatch; preserved")
    return context, ledger, expected


def status_session(context_path, state_root=None):
    context, ledger, paths = load_session(context_path, state_root)
    alive = owner_alive(context["owner"], context["host_id"])
    return {"attempt_id": context["attempt_id"], "execution_nonce": context["execution_nonce"],
            "owner": context["owner"], "owner_alive": alive,
            "status": "closed" if context.get("session_status") == "closed" else context.get("session_status", "preparing") if alive else "recovery_required",
            "deadline_at": context["deadline_at"],
            "deadline_expired": deadline(context["deadline_at"]) <= datetime.now(timezone.utc),
            "resources": ledger["resources"], "context": str(paths.global_dir / "run-context.json")}


@contextmanager
def session_lock(context_path):
    with (Path(context_path).parent / ".session.lock").open("a") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def close_session(context_path, owner, original_exit=0, received_signal=None, state_root=None, *, recovery=False):
    with session_lock(context_path):
        context, ledger, paths = load_session(context_path, state_root)
        if owner != context["owner"]:
            raise ValueError("only the bound supervisor can close a live session")
        if recovery:
            if (not is_current_process_birth(owner.get('process_birth')) or not isinstance(owner.get('pid'), int)
                    or owner_alive(owner, context['host_id'])):
                raise ValueError('owner alive or identity unknown; recovery preserved')
        else:
            verify_owner(owner, context["host_id"])
        if context.get("session_status") == "closed":
            report = read_json(paths.global_dir / "cleanup-report.json")
            return (0 if report["cleanup"]["status"] == "passed" else 70), report
        private_path = paths.global_dir / "session-private.json"
        if private_path.stat().st_mode & 0o077:
            raise ValueError("session credentials must be mode 0600")
        private = read_json(private_path)
        # Rehydrate the same lifecycle, without creating a second owner or ledger.
        life = Lifecycle.__new__(Lifecycle)
        life.config = private["config"]
        life.profile_name = context["profile"]
        life.profile = life.config["profiles"][life.profile_name]
        life.workdir = Path(context["workdir"])
        life.run_id, life.nonce = context["run_id"], context["execution_nonce"]
        ledger["context"] = context
        life.context, life.ledger, life.paths = context, ledger, paths
        life.owner, life.host_id = owner, context["host_id"]
        life.runner = command
        life.environment = {**os.environ, **private["environment"]}
        life.secrets = private["secrets"]
        code, report = life.cleanup(original_exit, received_signal)
        if report["cleanup"]["status"] == "passed":
            private_path.unlink()
            context["session_status"] = "closed"
        else:
            context["session_status"] = "cleanup_failed"
        life.persist()
        return code, report
