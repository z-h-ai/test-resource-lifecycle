from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core import (
    EXIT_INFRASTRUCTURE, Lifecycle, cache_home, docker_context_hash, iter_ledgers,
    read_json, redact, stable_host_id, state_home, sweep_ledgers, validate_config,
)


def _print(value: Any, json_output: bool = True) -> None:
    if json_output:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(value)


def run_command(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    workdir = Path(args.workdir).resolve() if args.workdir else config_path.parent
    config = read_json(config_path)
    lifecycle: Lifecycle | None = None
    child: subprocess.Popen[Any] | None = None
    received_signal: int | None = None
    original_exit: int | None = None
    prepare_error: str | None = None

    def forward(signum: int, _frame: Any) -> None:
        nonlocal received_signal
        received_signal = signum
        if child and child.poll() is None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous:
        signal.signal(sig, forward)
    try:
        lifecycle = Lifecycle(config, args.profile, workdir, args.run_id)
        lifecycle.recover_repo()
        lifecycle.prepare()
        child = subprocess.Popen(args.command, cwd=workdir, env=lifecycle.environment, start_new_session=True)
        try:
            original_exit = child.wait(timeout=lifecycle.profile.get("timeout_seconds"))
        except subprocess.TimeoutExpired:
            received_signal = signal.SIGTERM
            os.killpg(child.pid, signal.SIGTERM)
            try:
                original_exit = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            original_exit = None
    except Exception as exc:
        prepare_error = redact(exc, lifecycle.secrets if lifecycle else ())
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if lifecycle is None:
        print(prepare_error, file=sys.stderr)
        return EXIT_INFRASTRUCTURE
    code, report = lifecycle.cleanup(original_exit, received_signal, prepare_error)
    _print(report)
    return code


def audit_command(args: argparse.Namespace) -> int:
    rows = []
    for path in iter_ledgers(repository_id=args.repo):
        try:
            ledger = read_json(path)
            rows.append({
                "ledger": str(path), "repository_id": ledger.get("context", {}).get("repository_id"),
                "run_id": ledger.get("context", {}).get("run_id"),
                "owner": ledger.get("context", {}).get("owner"),
                "resources": ledger.get("resources", []),
            })
        except ValueError as exc:
            rows.append({"ledger": str(path), "error": str(exc)})
    _print({"runs": rows, "count": len(rows)}, args.json)
    return 0


def doctor_command(_args: argparse.Namespace) -> int:
    checks: dict[str, Any] = {
        "version": __version__, "python": sys.version.split()[0],
        "platform": platform.system(), "state_home": str(state_home()),
        "cache_home": str(cache_home()),
    }
    failed = sys.version_info < (3, 10) or platform.system() not in {"Darwin", "Linux"}
    try:
        checks["host_id"] = stable_host_id()
        checks["docker_context"] = docker_context_hash()
        checks["docker"] = "passed"
    except Exception as exc:
        checks["docker"] = "failed"
        checks["docker_error"] = redact(exc)
        failed = True
    try:
        result = subprocess.run(["docker", "compose", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        checks["compose"] = "passed" if result.returncode == 0 else "failed"
        failed = failed or result.returncode != 0
    except OSError as exc:
        checks["compose"] = "failed"
        checks["compose_error"] = str(exc)
        failed = True
    _print(checks)
    return EXIT_INFRASTRUCTURE if failed else 0


def sweeper_paths() -> tuple[Path, list[str]]:
    executable = str(Path(sys.argv[0]).resolve())
    if platform.system() == "Darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "com.z-h-ai.test-resource-lifecycle.plist"
        content = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            '<plist version="1.0"><dict><key>Label</key><string>com.z-h-ai.test-resource-lifecycle</string>',
            f'<key>ProgramArguments</key><array><string>{executable}</string><string>sweep</string><string>--all</string></array>',
            '<key>RunAtLoad</key><true/><key>StartInterval</key><integer>900</integer></dict></plist>',
        ]
        return path, content
    path = Path.home() / ".config" / "systemd" / "user" / "test-resource-lifecycle.service"
    content = ["[Unit]", "Description=Test resource lifecycle sweeper", "[Service]", "Type=oneshot", f"ExecStart={executable} sweep --all"]
    return path, content


def sweeper_command(args: argparse.Namespace) -> int:
    path, lines = sweeper_paths()
    timer = path.with_suffix(".timer") if platform.system() == "Linux" else None
    if args.action == "status":
        _print({"installed": path.exists(), "path": str(path), "timer": str(timer) if timer else None})
        return 0
    if args.action == "install":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if timer:
            timer.write_text("[Unit]\nDescription=Run test resource lifecycle sweeper\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=15min\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "--user", "enable", "--now", timer.name], check=False)
        else:
            subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], check=False)
        _print({"installed": True, "path": str(path)})
        return 0
    if timer:
        subprocess.run(["systemctl", "--user", "disable", "--now", timer.name], check=False)
        timer.unlink(missing_ok=True)
    else:
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], check=False)
    path.unlink(missing_ok=True)
    _print({"installed": False, "path": str(path)})
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="trl")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="subcommand", required=True)
    run = sub.add_parser("run")
    run.add_argument("--config", default=".test-resource-lifecycle.json")
    run.add_argument("--profile", required=True)
    run.add_argument("--workdir", help="repository worktree; defaults to the config directory")
    run.add_argument("--run-id")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(handler=run_command)
    audit = sub.add_parser("audit")
    audit.add_argument("--repo")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(handler=audit_command)
    sweep = sub.add_parser("sweep")
    group = sweep.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo")
    group.add_argument("--all", action="store_true")
    sweep.set_defaults(handler=lambda args: (_print({"outcomes": sweep_ledgers(repository_id=args.repo, all_repos=args.all)}) or 0))
    doctor = sub.add_parser("doctor")
    doctor.set_defaults(handler=doctor_command)
    sweeper = sub.add_parser("sweeper")
    sweeper.add_argument("action", choices=("install", "status", "uninstall"))
    sweeper.set_defaults(handler=sweeper_command)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.subcommand == "run":
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        if not args.command:
            parser().error("trl run requires -- <command...>")
    try:
        return int(args.handler(args))
    except (ValueError, OSError) as exc:
        print(redact(exc), file=sys.stderr)
        return EXIT_INFRASTRUCTURE
