from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

POLICY_VERSION = 1
EXIT_INFRASTRUCTURE = 70
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
DB_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
LABEL_PREFIX = "com.z-h-ai.test"
LABEL_KEYS = (
    "managed", "policy-version", "repository-id", "run-id",
    "execution-nonce", "host-id", "docker-context",
)
SECRET_RE = re.compile(
    r"(?i)((?:authorization|password|token|secret|database_url)\s*[:=]\s*)([^\s,;]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def redact(value: Any, secrets_: Iterable[str] = ()) -> str:
    output = str(value)
    for secret in sorted((v for v in secrets_ if v), key=len, reverse=True):
        output = output.replace(secret, "<redacted>")
    output = re.sub(r"(?i)postgres(?:ql)?://[^\s]+", "postgresql://<redacted>", output)
    return SECRET_RE.sub(r"\1<redacted>", output)


def state_home() -> Path:
    raw = os.environ.get("XDG_STATE_HOME")
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "state"


def cache_home() -> Path:
    raw = os.environ.get("XDG_CACHE_HOME")
    return Path(raw).expanduser() if raw else Path.home() / ".cache"


def stable_host_id(root: Path | None = None) -> str:
    path = (root or state_home()) / "test-resource-lifecycle" / "host-id"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{32}", value):
            return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(16)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    return value


def process_birth(pid: int) -> str:
    if platform.system() == "Linux":
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            fields = stat.read_text(encoding="utf-8").split()
            if len(fields) > 21:
                return sha256_bytes(fields[21].encode())
    result = subprocess.run(
        ["ps", "-o", "lstart=", "-p", str(pid)], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    birth = result.stdout.strip()
    if result.returncode != 0 or not birth:
        raise RuntimeError("process identity is unavailable")
    return sha256_bytes(birth.encode())


def owner_alive(owner: dict[str, Any], current_host: str) -> bool:
    if owner.get("host_id") != current_host:
        return True
    try:
        pid = int(owner["pid"])
        os.kill(pid, 0)
    except (KeyError, TypeError, ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True
    try:
        return process_birth(pid) == owner.get("process_birth")
    except RuntimeError:
        return False


class CommandError(RuntimeError):
    def __init__(self, argv: list[str], code: int, stdout: str, stderr: str):
        super().__init__(f"command failed ({code}): {' '.join(argv)}: {stderr.strip()}")
        self.argv, self.code, self.stdout, self.stderr = argv, code, stdout, stderr


def command(
    argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
    timeout: float = 30, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    if check and result.returncode:
        raise CommandError(argv, result.returncode, result.stdout, result.stderr)
    return result


def docker_context_hash() -> str:
    shown = command(["docker", "context", "show"], timeout=10).stdout.strip()
    inspected = command(
        ["docker", "context", "inspect", shown, "--format", "{{json .Endpoints.docker.Host}}"],
        timeout=10,
    ).stdout.strip()
    return sha256_bytes(f"{shown}\n{inspected}".encode())[:24]


def labels(context: dict[str, Any]) -> dict[str, str]:
    values = {
        "managed": "true",
        "policy-version": str(POLICY_VERSION),
        "repository-id": context["repository_id"],
        "run-id": context["run_id"],
        "execution-nonce": context["execution_nonce"],
        "host-id": context["host_id"],
        "docker-context": context["docker_context"],
    }
    return {f"{LABEL_PREFIX}.{key}": value for key, value in values.items()}


def validate_config(config: dict[str, Any], profile_name: str | None = None) -> dict[str, Any]:
    allowed_root = {"policy_version", "repository_id", "profiles"}
    unknown = set(config) - allowed_root
    if unknown:
        raise ValueError(f"unknown config fields: {sorted(unknown)}")
    if config.get("policy_version") != POLICY_VERSION:
        raise ValueError("policy_version must be 1")
    repository_id = config.get("repository_id")
    if not isinstance(repository_id, str) or not ID_RE.fullmatch(repository_id):
        raise ValueError("repository_id must match the safe ID contract")
    profiles = config.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("profiles must be a non-empty object")
    selected = profiles.items() if profile_name is None else [(profile_name, profiles.get(profile_name))]
    for name, profile in selected:
        if not isinstance(name, str) or not ID_RE.fullmatch(name):
            raise ValueError("profile name must match the safe ID contract")
        if not isinstance(profile, dict):
            raise ValueError(f"unknown profile: {name}")
        _validate_profile(profile, f"profiles.{name}")
    return config


def _argv(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{label} must be a non-empty argv array")
    if any("\n" in v or "\x00" in v for v in value):
        raise ValueError(f"{label} contains unsafe characters")
    return value


def _validate_profile(profile: dict[str, Any], label: str) -> None:
    allowed = {"timeout_seconds", "cleanup_timeout_seconds", "environment", "resources"}
    unknown = set(profile) - allowed
    if unknown:
        raise ValueError(f"unknown {label} fields: {sorted(unknown)}")
    for field in ("timeout_seconds", "cleanup_timeout_seconds"):
        if field in profile and (not isinstance(profile[field], int) or profile[field] <= 0):
            raise ValueError(f"{label}.{field} must be a positive integer")
    environment = profile.get("environment", {})
    if not isinstance(environment, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in environment.items()):
        raise ValueError(f"{label}.environment must contain strings")
    resources = profile.get("resources", {})
    if not isinstance(resources, dict):
        raise ValueError(f"{label}.resources must be an object")
    kinds = {"postgresql", "docker_compose", "services", "filesystem", "http", "sql_file"}
    unknown = set(resources) - kinds
    if unknown:
        raise ValueError(f"unsupported adapters: {sorted(unknown)}")
    for kind, entries in resources.items():
        if not isinstance(entries, list):
            raise ValueError(f"{label}.resources.{kind} must be an array")
        for index, entry in enumerate(entries):
            _validate_resource(kind, entry, f"{label}.resources.{kind}[{index}]")


def _validate_resource(kind: str, entry: Any, label: str) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"{label} must be an object")
    if "shell" in entry or "cleanup_shell" in entry:
        raise ValueError("inline cleanup shell is forbidden")
    name = entry.get("name")
    if not isinstance(name, str) or not ID_RE.fullmatch(name):
        raise ValueError(f"{label}.name must match the safe ID contract")
    if kind == "postgresql":
        allowed = {"name", "image", "database", "username", "password_env", "inject_url_env"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        if not DB_RE.fullmatch(str(entry.get("database", ""))):
            raise ValueError(f"{label}.database is invalid")
        if not DB_RE.fullmatch(str(entry.get("username", ""))):
            raise ValueError(f"{label}.username is invalid")
        if not isinstance(entry.get("password_env"), str) or not isinstance(entry.get("inject_url_env"), str):
            raise ValueError(f"{label} requires password_env and inject_url_env")
    elif kind == "docker_compose":
        allowed = {"name", "file", "services", "environment", "remove_volumes"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        if Path(str(entry.get("file", ""))).is_absolute() or ".." in Path(str(entry.get("file", ""))).parts:
            raise ValueError(f"{label}.file must be repo-relative")
        if not isinstance(entry.get("services", []), list):
            raise ValueError(f"{label}.services must be an array")
    elif kind == "services":
        allowed = {"name", "argv", "environment", "ready_url", "ready_timeout_seconds"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        _argv(entry.get("argv"), f"{label}.argv")
    elif kind == "filesystem":
        allowed = {"name", "path"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        path = Path(str(entry.get("path", "")))
        if path.is_absolute() or ".." in path.parts or "${TRL_RUN_ID}" not in str(path):
            raise ValueError(f"{label}.path must be repo-relative and contain ${{TRL_RUN_ID}}")
    elif kind == "http":
        allowed = {"name", "url", "method", "headers", "body_env", "expected_status"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        if not str(entry.get("url", "")).startswith(("http://", "https://")):
            raise ValueError(f"{label}.url must be HTTP(S)")
    elif kind == "sql_file":
        allowed = {"name", "file", "database_url_env"}
        if set(entry) - allowed:
            raise ValueError(f"unknown {label} fields: {sorted(set(entry) - allowed)}")
        path = Path(str(entry.get("file", "")))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"{label}.file must be repo-relative")


@dataclass
class RunPaths:
    global_dir: Path
    repo_dir: Path

    @classmethod
    def build(cls, workdir: Path, repository_id: str, run_id: str, nonce: str, root: Path | None = None) -> "RunPaths":
        base = (root or state_home()) / "test-resource-lifecycle" / "runs" / repository_id / run_id / nonce
        audit = workdir / ".pipeline" / "test-resource-runs" / run_id / nonce
        return cls(base, audit)

    def write(self, name: str, payload: dict[str, Any]) -> None:
        atomic_json(self.global_dir / name, payload)
        atomic_json(self.repo_dir / name, payload)


class Lifecycle:
    def __init__(
        self, config: dict[str, Any], profile_name: str, workdir: Path,
        run_id: str | None = None, state_root: Path | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = command,
    ):
        validate_config(config, profile_name)
        self.config, self.profile = config, config["profiles"][profile_name]
        self.profile_name, self.workdir = profile_name, workdir.resolve()
        self.run_id = run_id or os.environ.get("TRL_RUN_ID") or f"run-{int(time.time())}-{os.getpid()}"
        if not ID_RE.fullmatch(self.run_id):
            raise ValueError("run ID must match the safe ID contract")
        self.nonce = secrets.token_hex(16)
        self.host_id = stable_host_id(state_root)
        self.runner = command_runner
        self.docker_error: str | None = None
        if self._needs_docker():
            try:
                self.docker_context = docker_context_hash()
            except Exception as exc:
                self.docker_context = "unavailable"
                self.docker_error = redact(exc)
        else:
            self.docker_context = "none"
        self.paths = RunPaths.build(self.workdir, config["repository_id"], self.run_id, self.nonce, state_root)
        self.owner = {
            "pid": os.getpid(), "process_birth": process_birth(os.getpid()),
            "host_id": self.host_id, "hostname": socket.gethostname(),
        }
        self.context = {
            "policy_version": POLICY_VERSION, "repository_id": config["repository_id"],
            "profile": profile_name, "run_id": self.run_id, "execution_nonce": self.nonce,
            "host_id": self.host_id, "docker_context": self.docker_context,
            "workdir": str(self.workdir), "owner": self.owner, "created_at": utc_now(),
        }
        self.ledger: dict[str, Any] = {"context": self.context, "resources": [], "updated_at": utc_now()}
        self.environment = os.environ.copy()
        self.environment.update(self.profile.get("environment", {}))
        self.environment.update({
            "TRL_RUN_ID": self.run_id,
            "TRL_EXECUTION_NONCE": self.nonce,
            "TRL_HOST_ID": self.host_id,
            "TRL_DOCKER_CONTEXT": self.docker_context,
            "TRL_RUN_CONTEXT": str(self.paths.global_dir / "run-context.json"),
            "TRL_RESOURCE_LEDGER": str(self.paths.global_dir / "resource-ledger.json"),
            "TRL_CLEANUP_REPORT": str(self.paths.global_dir / "cleanup-report.json"),
        })
        self.secrets: list[str] = []

    def _needs_docker(self) -> bool:
        resources = self.profile.get("resources", {})
        return bool(resources.get("postgresql") or resources.get("docker_compose"))

    def persist(self) -> None:
        self.ledger["updated_at"] = utc_now()
        self.paths.write("run-context.json", self.context)
        self.paths.write("resource-ledger.json", self.ledger)

    def add_resource(self, kind: str, resource_id: str, name: str, extra: dict[str, Any] | None = None) -> None:
        item = {"kind": kind, "id": resource_id, "name": name, "state": "created", "created_at": utc_now()}
        if extra:
            item.update(extra)
        self.ledger["resources"].append(item)
        self.persist()

    def recover_repo(self) -> list[dict[str, Any]]:
        return sweep_ledgers(
            repository_id=self.config["repository_id"], all_repos=False, immediate=True,
            state_root=self.paths.global_dir.parents[4], current_host=self.host_id,
        )

    def prepare(self) -> None:
        self.paths.global_dir.mkdir(parents=True, exist_ok=False)
        self.persist()
        if self.docker_error:
            raise RuntimeError(f"Docker is required by profile but unavailable: {self.docker_error}")
        resources = self.profile.get("resources", {})
        for entry in resources.get("filesystem", []):
            target = self._filesystem_path(entry["path"])
            target.mkdir(parents=True, exist_ok=False)
            marker = target / ".trl-owner.json"
            atomic_json(marker, self.context)
            self.add_resource("filesystem", str(target), entry["name"], {"marker": str(marker)})
        for entry in resources.get("postgresql", []):
            self._prepare_postgresql(entry)
        for entry in resources.get("docker_compose", []):
            self._prepare_compose(entry)
        for entry in resources.get("services", []):
            self._prepare_service(entry)

    def _filesystem_path(self, raw: str) -> Path:
        expanded = raw.replace("${TRL_RUN_ID}", self.run_id).replace("${TRL_EXECUTION_NONCE}", self.nonce)
        target = (self.workdir / expanded).resolve(strict=False)
        try:
            relative = target.relative_to(self.workdir)
        except ValueError as exc:
            raise ValueError("filesystem target escapes repository") from exc
        if relative.parts and relative.parts[0] == ".pipeline":
            raise ValueError("filesystem adapter cannot target .pipeline")
        current = self.workdir
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError("filesystem target contains a symlink")
        return target

    def _docker_label_args(self) -> list[str]:
        args: list[str] = []
        for key, value in labels(self.context).items():
            args.extend(["--label", f"{key}={value}"])
        return args

    def _prepare_postgresql(self, entry: dict[str, Any]) -> None:
        password = os.environ.get(entry["password_env"])
        if not password:
            password = secrets.token_urlsafe(24)
        self.secrets.append(password)
        self.environment[entry["password_env"]] = password
        safe_name = re.sub(r"[^a-z0-9_.-]", "-", f"trl-{self.config['repository_id']}-{self.run_id}-{entry['name']}").lower()[:63]
        volume_name = f"{safe_name}-data"[:63]
        volume_id = self.runner(
            ["docker", "volume", "create", *self._docker_label_args(), volume_name],
            cwd=self.workdir, timeout=30,
        ).stdout.strip()
        self.add_resource("volume", volume_id, f"{entry['name']}-data", {"adapter": "postgresql"})
        args = ["docker", "run", "-d", "--name", safe_name, "-p", "127.0.0.1::5432"]
        args += self._docker_label_args()
        args += [
            "-v", f"{volume_id}:/var/lib/postgresql/data",
            "-e", f"POSTGRES_USER={entry['username']}", "-e", f"POSTGRES_PASSWORD={password}",
            "-e", f"POSTGRES_DB={entry['database']}", entry.get("image", "postgres:16-alpine"),
        ]
        container_id = self.runner(args, cwd=self.workdir, timeout=60).stdout.strip()
        self.add_resource("container", container_id, entry["name"], {"adapter": "postgresql"})
        port = self.runner(
            ["docker", "port", container_id, "5432/tcp"], cwd=self.workdir, timeout=10,
        ).stdout.strip().rsplit(":", 1)[-1]
        deadline = time.monotonic() + 60
        while True:
            ready = self.runner(
                ["docker", "exec", container_id, "pg_isready", "-U", entry["username"], "-d", entry["database"]],
                cwd=self.workdir, timeout=10, check=False,
            )
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("managed PostgreSQL readiness timed out")
            time.sleep(.5)
        url = f"postgresql://{entry['username']}:{password}@127.0.0.1:{port}/{entry['database']}"
        self.environment[entry["inject_url_env"]] = url

    def _prepare_compose(self, entry: dict[str, Any]) -> None:
        compose_file = (self.workdir / entry["file"]).resolve()
        if not compose_file.is_file() or self.workdir not in compose_file.parents:
            raise ValueError("compose file is missing or outside repository")
        project = re.sub(r"[^a-z0-9_-]", "-", f"trl-{self.config['repository_id']}-{self.run_id}-{entry['name']}").lower()[:63]
        env = self.environment.copy()
        env.update(entry.get("environment", {}))
        env["TRL_LABEL_MANAGED"] = "true"
        env["TRL_LABEL_POLICY_VERSION"] = str(POLICY_VERSION)
        env["TRL_LABEL_REPOSITORY_ID"] = self.config["repository_id"]
        env["TRL_LABEL_RUN_ID"] = self.run_id
        env["TRL_LABEL_EXECUTION_NONCE"] = self.nonce
        env["TRL_LABEL_HOST_ID"] = self.host_id
        env["TRL_LABEL_DOCKER_CONTEXT"] = self.docker_context
        args = ["docker", "compose", "--project-name", project, "--file", str(compose_file), "up", "-d"]
        args += list(entry.get("services", []))
        self.runner(args, cwd=self.workdir, env=env, timeout=120)
        discovered = 0
        queries = {
            "container": ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
            "network": ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
            "volume": ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
        }
        for kind, query in queries.items():
            if kind == "volume" and not entry.get("remove_volumes"):
                continue
            output = self.runner(query, cwd=self.workdir, timeout=30).stdout
            for resource_id in output.split():
                self.add_resource(kind, resource_id, entry["name"], {
                    "adapter": "docker_compose", "compose_project": project,
                })
                discovered += 1
        if discovered == 0:
            raise RuntimeError("Compose started no discoverable project resources")

    def _prepare_service(self, entry: dict[str, Any]) -> None:
        env = self.environment.copy()
        env.update(entry.get("environment", {}))
        process = subprocess.Popen(entry["argv"], cwd=self.workdir, env=env, start_new_session=True)
        self.add_resource("process", str(process.pid), entry["name"], {"process_birth": process_birth(process.pid)})
        if entry.get("ready_url"):
            deadline = time.monotonic() + int(entry.get("ready_timeout_seconds", 30))
            while True:
                try:
                    with urlopen(entry["ready_url"], timeout=2) as response:
                        if response.status < 500:
                            break
                except (HTTPError, URLError, TimeoutError):
                    pass
                if process.poll() is not None:
                    raise RuntimeError(f"service exited during readiness: {entry['name']}")
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"service readiness timed out: {entry['name']}")
                time.sleep(.25)

    def cleanup(self, original_exit: int | None, received_signal: int | None, prepare_error: str | None = None) -> tuple[int, dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        errors: list[str] = []
        deadline = time.monotonic() + int(self.profile.get("cleanup_timeout_seconds", 120))
        resources = self.profile.get("resources", {})
        for entry in resources.get("http", []):
            self._cleanup_action("http", entry, actions, errors, deadline)
        for entry in resources.get("sql_file", []):
            self._cleanup_action("sql_file", entry, actions, errors, deadline)
        order = {"process": 0, "container": 1, "network": 2, "volume": 3, "filesystem": 4}
        for item in sorted(reversed(self.ledger.get("resources", [])), key=lambda x: order.get(x["kind"], 99)):
            self._cleanup_owned(item, actions, errors, deadline)
        residual = [item for item in self.ledger.get("resources", []) if item.get("state") not in {"removed", "already_absent"}]
        status = "failed" if prepare_error or errors or residual else "passed"
        classification = "infrastructure" if status == "failed" else "none"
        report = {
            "policy_version": POLICY_VERSION, "repository_id": self.config["repository_id"],
            "run_id": self.run_id, "execution_nonce": self.nonce,
            "checks": {"exit_code": original_exit, "signal": received_signal},
            "prepare_error": redact(prepare_error, self.secrets) if prepare_error else None,
            "cleanup": {"status": status, "classification": classification, "actions": actions,
                        "errors": [redact(e, self.secrets) for e in errors], "residual": residual},
            "finished_at": utc_now(),
        }
        self.paths.write("resource-ledger.json", self.ledger)
        self.paths.write("cleanup-report.json", report)
        if status == "failed":
            return EXIT_INFRASTRUCTURE, report
        if received_signal:
            return 128 + received_signal, report
        return original_exit or 0, report

    def _cleanup_action(self, kind: str, entry: dict[str, Any], actions: list[dict[str, Any]], errors: list[str], deadline: float) -> None:
        result = {"kind": kind, "name": entry["name"], "attempts": 0}
        for attempt in range(1, 4):
            result["attempts"] = attempt
            try:
                if time.monotonic() >= deadline:
                    raise TimeoutError("cleanup deadline exceeded")
                if kind == "http":
                    headers = {k: os.environ.get(v[1:], "") if isinstance(v, str) and v.startswith("$") else v for k, v in entry.get("headers", {}).items()}
                    body = os.environ.get(entry.get("body_env", ""), "").encode() or None
                    request = Request(entry["url"], data=body, headers=headers, method=entry.get("method", "DELETE"))
                    with urlopen(request, timeout=min(15, max(1, deadline - time.monotonic()))) as response:
                        expected = entry.get("expected_status", [200, 204])
                        if response.status not in expected:
                            raise RuntimeError(f"unexpected HTTP cleanup status: {response.status}")
                else:
                    sql_path = (self.workdir / entry["file"]).resolve()
                    if not sql_path.is_file() or self.workdir not in sql_path.parents:
                        raise ValueError("SQL cleanup file is missing or outside repository")
                    database_url = self.environment.get(entry["database_url_env"])
                    if not database_url:
                        raise ValueError("SQL cleanup database URL is unavailable")
                    self.secrets.append(database_url)
                    self.runner(["psql", database_url, "--set", "ON_ERROR_STOP=1", "--file", str(sql_path)], cwd=self.workdir, timeout=30)
                result["result"] = "passed"
                actions.append(result)
                return
            except Exception as exc:  # bounded retry is part of the cleanup contract
                result["error"] = redact(exc, self.secrets)
                if attempt < 3:
                    time.sleep(.25 * attempt)
        result["result"] = "failed"
        actions.append(result)
        errors.append(str(result.get("error")))

    def _cleanup_owned(self, item: dict[str, Any], actions: list[dict[str, Any]], errors: list[str], deadline: float) -> None:
        result = cleanup_ledger_resource(item, self.context, deadline, self.runner)
        item["state"] = result["result"]
        actions.append(result)
        if result["result"] not in {"removed", "already_absent"}:
            errors.append(f"{item['kind']} {item['id']}: {result['result']}")
        self.persist()


def _inspect_labels(kind: str, resource_id: str, runner: Callable[..., subprocess.CompletedProcess[str]]) -> dict[str, str] | None:
    docker_kind = "container" if kind == "container" else kind
    result = runner(["docker", docker_kind, "inspect", resource_id], timeout=10, check=False)
    if result.returncode:
        combined = f"{result.stdout}\n{result.stderr}"
        if re.search(r"no such|not found", combined, re.I):
            return None
        raise CommandError(["docker", docker_kind, "inspect", resource_id], result.returncode, result.stdout, result.stderr)
    parsed = json.loads(result.stdout)[0]
    return parsed.get("Config", {}).get("Labels") or parsed.get("Labels") or {}


def cleanup_ledger_resource(
    item: dict[str, Any], context: dict[str, Any], deadline: float,
    runner: Callable[..., subprocess.CompletedProcess[str]] = command,
) -> dict[str, Any]:
    kind, resource_id = item["kind"], item["id"]
    result = {"kind": kind, "id": resource_id, "attempts": 0}
    try:
        if kind == "process":
            pid = int(resource_id)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                result.update(result="already_absent", attempts=1)
                return result
            try:
                current_birth = process_birth(pid)
            except RuntimeError:
                result.update(result="already_absent", attempts=1)
                return result
            if current_birth != item.get("process_birth"):
                result.update(result="preserved_identity_mismatch", attempts=1)
                return result
            os.killpg(pid, signal.SIGTERM)
            until = min(deadline, time.monotonic() + 5)
            while time.monotonic() < until:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.05)
            else:
                os.killpg(pid, signal.SIGKILL)
            result.update(result="removed", attempts=1)
            return result
        if kind == "filesystem":
            path, marker = Path(resource_id), Path(item.get("marker", ""))
            if not path.exists():
                result.update(result="already_absent", attempts=1)
                return result
            try:
                proof = read_json(marker)
            except ValueError:
                result.update(result="preserved_missing_marker", attempts=1)
                return result
            fields = ("repository_id", "run_id", "execution_nonce", "host_id")
            if any(proof.get(field) != context.get(field) for field in fields):
                result.update(result="preserved_identity_mismatch", attempts=1)
                return result
            shutil.rmtree(path)
            result.update(result="removed", attempts=1)
            return result
        if kind in {"container", "network", "volume"}:
            expected = labels(context)
            for attempt in range(1, 4):
                result["attempts"] = attempt
                actual = _inspect_labels(kind, resource_id, runner)
                if actual is None:
                    result["result"] = "already_absent"
                    return result
                if any(actual.get(key) != value for key, value in expected.items()):
                    result["result"] = "preserved_label_mismatch"
                    return result
                args = ["docker", "rm", "-f", resource_id] if kind == "container" else ["docker", kind, "rm", resource_id]
                removed = runner(args, timeout=20, check=False)
                if removed.returncode == 0:
                    result["result"] = "removed"
                    return result
                if attempt < 3:
                    time.sleep(.25 * attempt)
            result["result"] = "remove_failed"
            return result
        result.update(result="preserved_unknown_kind", attempts=1)
        return result
    except Exception as exc:
        result.update(result="remove_failed", error=redact(exc), attempts=max(1, result["attempts"]))
        return result


def iter_ledgers(state_root: Path | None = None, repository_id: str | None = None) -> Iterable[Path]:
    base = (state_root or state_home()) / "test-resource-lifecycle" / "runs"
    roots = [base / repository_id] if repository_id else ([p for p in base.iterdir() if p.is_dir()] if base.exists() else [])
    for root in roots:
        if root.exists():
            yield from root.glob("*/*/resource-ledger.json")


def sweep_ledgers(
    *, repository_id: str | None, all_repos: bool, immediate: bool = False,
    state_root: Path | None = None, current_host: str | None = None,
) -> list[dict[str, Any]]:
    if not repository_id and not all_repos:
        raise ValueError("sweep requires --repo or --all")
    host_id = current_host or stable_host_id(state_root)
    outcomes: list[dict[str, Any]] = []
    for ledger_path in iter_ledgers(state_root, repository_id if not all_repos else None):
        try:
            ledger = read_json(ledger_path)
            context = ledger["context"]
        except (ValueError, KeyError, TypeError) as exc:
            outcomes.append({"ledger": str(ledger_path), "result": "preserved_invalid_ledger", "error": redact(exc)})
            continue
        ledger_context = context.get("docker_context")
        context_mismatch = ledger_context not in {"none", "unavailable"} and ledger_context != docker_context_hash()
        if context.get("host_id") != host_id or context_mismatch:
            outcomes.append({"ledger": str(ledger_path), "result": "preserved_host_or_context_mismatch"})
            continue
        if owner_alive(context.get("owner", {}), host_id):
            outcomes.append({"ledger": str(ledger_path), "result": "preserved_active_owner"})
            continue
        candidate = ledger_path.parent / "sweep-candidate.json"
        if not immediate:
            if not candidate.exists():
                atomic_json(candidate, {"first_seen": time.time(), "context": context})
                outcomes.append({"ledger": str(ledger_path), "result": "candidate_recorded"})
                continue
            first = read_json(candidate).get("first_seen", time.time())
            if time.time() - float(first) < 60:
                outcomes.append({"ledger": str(ledger_path), "result": "candidate_waiting"})
                continue
        deadline = time.monotonic() + 120
        actions = []
        for item in reversed(ledger.get("resources", [])):
            action = cleanup_ledger_resource(item, context, deadline)
            actions.append(action)
            item["state"] = action["result"]
        atomic_json(ledger_path, ledger)
        outcomes.append({"ledger": str(ledger_path), "result": "swept", "actions": actions})
    return outcomes
