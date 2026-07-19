"""Bounded argv-only process execution and disposable container helpers."""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


class ProcessControlError(RuntimeError):
    """Process execution or cleanup violated a harness invariant."""


CONTAINER_PRELUDE = """{
const fs = require("fs");
process.umask(0o077);
for (const key of ["HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"]) {
  if (process.env[key]) fs.mkdirSync(process.env[key], {recursive: true, mode: 0o700});
}
}
"""


@dataclass(frozen=True)
class Completed:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    elapsed_seconds: float


def scrubbed_environment(run_root: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    root = run_root.resolve()
    home = root / "home"
    temporary = root / "tmp"
    cache = root / "cache"
    config = root / "config"
    state = root / "state"
    for path in (home, temporary, cache, config, state):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "XDG_STATE_HOME": str(state),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
    }
    if extra:
        forbidden = {
            key
            for key in extra
            if any(
                marker in key.upper()
                for marker in (
                    "TOKEN",
                    "SECRET",
                    "PASSWORD",
                    "COOKIE",
                    "AUTH",
                    "CREDENTIAL",
                    "PROXY",
                    "AWS",
                    "AZURE",
                    "GOOGLE",
                    "GITHUB",
                    "GITLAB",
                    "SSH",
                    "DOCKER",
                )
            )
        }
        if forbidden:
            raise ProcessControlError(f"refusing sensitive-shaped environment keys: {sorted(forbidden)}")
        environment.update(extra)
    return environment


def trusted_supervisor_environment(run_root: Path) -> dict[str, str]:
    environment = scrubbed_environment(run_root)
    environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    environment["DOCKER_HOST"] = docker_endpoint()
    environment["DOCKER_CLI_HINTS"] = "false"
    return environment


def _limit_child() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def run_argv(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 10,
    max_output_bytes: int = 2 * 1024 * 1024,
    apply_resource_limits: bool = True,
) -> Completed:
    if not argv or any(not isinstance(item, str) or "\0" in item for item in argv):
        raise ProcessControlError("argv must be nonempty NUL-free strings")
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        preexec_fn=_limit_child if apply_resource_limits else None,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=2)
    if len(stdout) > max_output_bytes or len(stderr) > max_output_bytes:
        raise ProcessControlError("process output exceeded its evidence ceiling")
    return Completed(
        tuple(argv),
        process.returncode,
        stdout,
        stderr,
        timed_out,
        time.monotonic() - started,
    )


def docker_binary() -> str:
    binary = shutil.which("docker")
    if binary is None:
        raise ProcessControlError("docker CLI unavailable")
    return binary


def docker_endpoint() -> str:
    inherited = os.environ.get("DOCKER_HOST", "")
    if inherited.startswith("unix://"):
        inherited_path = Path(inherited.removeprefix("unix://"))
        if inherited_path.exists() and stat_is_socket(inherited_path):
            return inherited
    candidates = [
        Path.home() / ".colima" / "default" / "docker.sock",
        Path.home() / ".docker" / "run" / "docker.sock",
        Path("/var/run/docker.sock"),
    ]
    for candidate in candidates:
        if candidate.exists() and stat_is_socket(candidate):
            return f"unix://{candidate}"
    raise ProcessControlError("no supported local Docker socket is available")


def stat_is_socket(path: Path) -> bool:
    return (path.stat().st_mode & 0o170000) == 0o140000


def docker(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float = 15,
) -> Completed:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(cwd.resolve()),
        "DOCKER_HOST": docker_endpoint(),
        "DOCKER_CLI_HINTS": "false",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    return run_argv(
        [docker_binary(), *arguments],
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_output_bytes=2 * 1024 * 1024,
        apply_resource_limits=False,
    )


def safe_container_arguments(
    *,
    name: str,
    run_id: str,
    image: str,
    command: Sequence[str],
    canary_mount: Path | None = None,
    detached: bool = False,
) -> list[str]:
    arguments = [
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        f"mhai.run_id={run_id}",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "16",
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--ulimit",
        "nofile=64:64",
        "--ulimit",
        "fsize=8388608:8388608",
        "--user",
        "65534:65534",
        "--workdir",
        "/tmp",
        "--env",
        "HOME=/tmp/home",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "XDG_CACHE_HOME=/tmp/cache",
        "--env",
        "XDG_CONFIG_HOME=/tmp/config",
        "--env",
        "XDG_STATE_HOME=/tmp/state",
        "--env",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]
    if detached:
        arguments.insert(1, "--detach")
    if canary_mount is not None:
        arguments.extend(
            ["--mount", f"type=bind,src={canary_mount.resolve()},dst=/canary"]
        )
    if len(command) < 3 or command[0:2] != ["node", "-e"]:
        raise ProcessControlError("safe container commands must be Node inline programs")
    prepared_command = ["node", "-e", CONTAINER_PRELUDE + command[2], *command[3:]]
    arguments.extend([image, *prepared_command])
    return arguments


def require_successful_empty_listing(completed: Completed, label: str) -> None:
    if completed.returncode != 0:
        raise ProcessControlError(
            f"{label} enumeration failed with {completed.returncode}: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    if completed.stdout.strip():
        raise ProcessControlError(
            f"{label} residue remained: {completed.stdout.decode(errors='replace').splitlines()}"
        )


def cleanup_labeled_containers(
    run_id: str,
    cwd: Path,
    *,
    docker_call: Callable[..., Completed] = docker,
) -> list[str]:
    listed = docker_call(
        ["ps", "-aq", "--filter", f"label=mhai.run_id={run_id}"],
        cwd=cwd,
    )
    if listed.returncode != 0:
        raise ProcessControlError(
            f"container enumeration failed with {listed.returncode}: "
            f"{listed.stderr.decode(errors='replace')}"
        )
    identities = [line for line in listed.stdout.decode().splitlines() if line]
    for identity in identities:
        removed = docker_call(["rm", "-f", identity], cwd=cwd)
        if removed.returncode != 0:
            raise ProcessControlError(
                f"container removal failed for {identity}: "
                f"{removed.stderr.decode(errors='replace')}"
            )
    final = docker_call(
        ["ps", "-aq", "--filter", f"label=mhai.run_id={run_id}"],
        cwd=cwd,
    )
    require_successful_empty_listing(final, f"containers for {run_id}")
    return identities
