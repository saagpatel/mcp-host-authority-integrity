"""Exact, disposable host-browser launcher for browser-required fixture cases."""

from __future__ import annotations

import contextlib
import hashlib
import html
import json
import os
import pwd
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from harness.process_control import scrubbed_environment

ROOT = Path(__file__).resolve().parents[1]
BROWSER_CONTRACT_VERSION = "MHAI-BROWSER-1"
BROWSER_REVISION = "1228"
BROWSER_VERSION = "149.0.7827.55"
BROWSER_CACHE_RELATIVE = Path(
    "Library/Caches/ms-playwright/"
    "chromium_headless_shell-1228/"
    "chrome-headless-shell-mac-arm64"
)
BROWSER_BINARY_NAME = "chrome-headless-shell"
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
MAX_STDIO_BYTES = 2 * 1024 * 1024

NORMAL_PROFILE_FRAGMENTS = (
    "/Library/Application Support/Google/Chrome",
    "/Library/Application Support/Chromium",
    "/Library/Application Support/Firefox",
    "/Library/Application Support/Microsoft Edge",
    "/Library/Application Support/BraveSoftware",
    "/Library/Safari",
)


class BrowserRuntimeError(RuntimeError):
    """A disposable browser invariant failed."""


@dataclass(frozen=True)
class BrowserIdentity:
    contract_version: str
    revision: str
    version: str
    bundle_sha256: str
    binary_sha256: str
    sandbox_exec_sha256: str
    playwright_core_version: str
    playwright_metadata_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "revision": self.revision,
            "version": self.version,
            "bundle_sha256": self.bundle_sha256,
            "binary_sha256": self.binary_sha256,
            "sandbox_exec_sha256": self.sandbox_exec_sha256,
            "playwright_core_version": self.playwright_core_version,
            "playwright_metadata_sha256": self.playwright_metadata_sha256,
        }


@dataclass(frozen=True)
class BrowserLaunch:
    payload: dict[str, Any]
    returncode: int
    elapsed_seconds: float
    stderr_sha256: str
    watchdog: dict[str, Any]
    command_profile_safe: bool
    environment_profile_safe: bool
    outer_sandbox_network_denied: bool
    outer_sandbox_home_reads_denied: bool
    chromium_inner_sandbox: str

    def evidence(self) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "stderr_sha256": self.stderr_sha256,
            "watchdog": self.watchdog,
            "command_profile_safe": self.command_profile_safe,
            "environment_profile_safe": self.environment_profile_safe,
            "outer_sandbox_network_denied": self.outer_sandbox_network_denied,
            "outer_sandbox_home_reads_denied": self.outer_sandbox_home_reads_denied,
            "chromium_inner_sandbox": self.chromium_inner_sandbox,
        }


class _ResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside = False
        self.parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "pre" and dict(attrs).get("id") == "mhai-result":
            self._inside = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "pre" and self._inside:
            self._inside = False

    def handle_data(self, data: str) -> None:
        if self._inside:
            self.parts.append(data)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def browser_bundle_root() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / BROWSER_CACHE_RELATIVE


def browser_binary() -> Path:
    return browser_bundle_root() / BROWSER_BINARY_NAME


def _validate_single_link_regular(path: Path, label: str) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or path.resolve(strict=True) != path
    ):
        raise BrowserRuntimeError(f"{label} is not an exact single-link regular file")
    return metadata


def _bundle_digest(root: Path) -> str:
    if root.resolve(strict=True) != root or not root.is_dir():
        raise BrowserRuntimeError("browser bundle root is not a real directory")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        metadata = path.lstat()
        relative = str(path.relative_to(root))
        if stat.S_ISLNK(metadata.st_mode):
            raise BrowserRuntimeError("browser bundle contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(f"d\0{relative}\0{stat.S_IMODE(metadata.st_mode):o}\0".encode())
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BrowserRuntimeError("browser bundle contains a non-regular or linked file")
        digest.update(
            f"f\0{relative}\0{stat.S_IMODE(metadata.st_mode):o}\0{metadata.st_size}\0".encode()
        )
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _playwright_provenance() -> tuple[str, str]:
    candidates = sorted(
        (Path(pwd.getpwuid(os.getuid()).pw_dir) / ".npm" / "_npx").glob(
            "*/node_modules/playwright-core/browsers.json"
        )
    )
    matches: list[tuple[str, str]] = []
    for metadata_path in candidates:
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            package_path = metadata_path.with_name("package.json")
            package = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        browsers = metadata.get("browsers")
        if not isinstance(browsers, list):
            continue
        match = next(
            (
                item
                for item in browsers
                if isinstance(item, dict)
                and item.get("name") == "chromium-headless-shell"
                and item.get("revision") == BROWSER_REVISION
                and item.get("browserVersion") == BROWSER_VERSION
            ),
            None,
        )
        version = package.get("version")
        if match is not None and isinstance(version, str):
            matches.append((version, _sha256(metadata_path)))
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise BrowserRuntimeError(
            "exact cached Playwright browser provenance is missing or ambiguous"
        )
    return unique[0]


def current_browser_identity() -> BrowserIdentity:
    bundle = browser_bundle_root()
    binary = browser_binary()
    binary_metadata = _validate_single_link_regular(binary, "browser binary")
    sandbox_metadata = _validate_single_link_regular(SANDBOX_EXEC, "sandbox-exec")
    if binary_metadata.st_uid != os.getuid():
        raise BrowserRuntimeError("browser binary is not owned by the current synthetic controller")
    if sandbox_metadata.st_uid != 0:
        raise BrowserRuntimeError("sandbox-exec is not root-owned")
    playwright_version, playwright_digest = _playwright_provenance()
    return BrowserIdentity(
        contract_version=BROWSER_CONTRACT_VERSION,
        revision=BROWSER_REVISION,
        version=BROWSER_VERSION,
        bundle_sha256=_bundle_digest(bundle),
        binary_sha256=_sha256(binary),
        sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        playwright_core_version=playwright_version,
        playwright_metadata_sha256=playwright_digest,
    )


def browser_identity_matches(expected: dict[str, Any]) -> bool:
    return current_browser_identity().as_dict() == expected


def _path_ancestors(path: Path) -> list[Path]:
    resolved = path.resolve(strict=True)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    if resolved != home and home not in resolved.parents:
        raise BrowserRuntimeError("browser path is outside the expected user root")
    chain: list[Path] = []
    current = resolved
    while True:
        chain.append(current)
        if current == home.parent:
            break
        current = current.parent
    return list(reversed(chain))


def _seatbelt_string(value: Path) -> str:
    return json.dumps(str(value.resolve(strict=True)))


def _sandbox_policy(
    *,
    browser_state_root: Path,
    fixture_path: Path,
) -> str:
    metadata_paths = {
        *_path_ancestors(browser_bundle_root()),
        *_path_ancestors(browser_state_root),
        *_path_ancestors(fixture_path),
    }
    metadata_rules = " ".join(
        f"(literal {_seatbelt_string(path)})"
        for path in sorted(metadata_paths, key=str)
    )
    return "\n".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny file-write*)",
            f"(allow file-write* (subpath {_seatbelt_string(browser_state_root)}))",
            '(deny file-read* (subpath "/Users"))',
            '(deny file-read* (subpath "/Volumes"))',
            f"(allow file-read-metadata {metadata_rules})",
            f"(allow file-read* (subpath {_seatbelt_string(browser_bundle_root())}))",
            f"(allow file-read* (subpath {_seatbelt_string(browser_state_root)}))",
            f"(allow file-read* (literal {_seatbelt_string(fixture_path)}))",
        )
    )


def _browser_flags(profile: Path) -> list[str]:
    return [
        "--headless",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--single-process",
        "--no-zygote",
        "--renderer-process-limit=1",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-crashpad",
        "--disable-notifications",
        "--deny-permission-prompts",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-default-browser-check",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disk-cache-size=1048576",
        "--media-cache-size=1048576",
        (
            "--disable-features="
            "AutofillServerCommunication,CertificateTransparencyComponentUpdater,"
            "IdentityInAuthError,MediaRouter,OptimizationHints,Signin,Translate"
        ),
        f"--user-data-dir={profile}",
        "--virtual-time-budget=1500",
        "--dump-dom",
    ]


def _profile_safe_strings(values: list[str]) -> bool:
    return all(fragment not in value for value in values for fragment in NORMAL_PROFILE_FRAGMENTS)


def _browser_child_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    with temporary.open("wb") as handle:
        os.chmod(temporary, 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _parse_payload(stdout: bytes) -> dict[str, Any]:
    try:
        rendered = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BrowserRuntimeError("browser output was not UTF-8") from exc
    parser = _ResultParser()
    parser.feed(rendered)
    raw = html.unescape("".join(parser.parts))
    if not raw or raw == "pending":
        raise BrowserRuntimeError("browser fixture did not emit a terminal result")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserRuntimeError("browser fixture result was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise BrowserRuntimeError("browser fixture result must be an object")
    if payload.get("harness_error"):
        raise BrowserRuntimeError("browser fixture reported a harness error")
    return payload


def _read_watchdog_receipt(
    watchdog: subprocess.Popen[bytes],
    receipt_path: Path,
) -> dict[str, Any]:
    try:
        returncode = watchdog.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(watchdog.pid, signal.SIGKILL)
        watchdog.wait(timeout=2)
        raise BrowserRuntimeError("browser watchdog did not terminate") from None
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrowserRuntimeError("browser watchdog receipt is unavailable") from exc
    if not isinstance(receipt, dict) or receipt.get("result") != "PASS" or returncode != 0:
        reason = receipt.get("reason") if isinstance(receipt, dict) else "invalid-receipt"
        max_pids = receipt.get("max_observed_pids") if isinstance(receipt, dict) else None
        max_rss = receipt.get("max_observed_rss_kib") if isinstance(receipt, dict) else None
        raise BrowserRuntimeError(
            "browser watchdog did not prove cleanup: "
            f"reason={reason}, max_pids={max_pids}, max_rss_kib={max_rss}, "
            f"returncode={returncode}"
        )
    return receipt


def _launch(
    *,
    session_root: Path,
    browser_state_root: Path,
    fixture_path: Path,
    profile: Path,
    launch_id: str,
    timeout_seconds: float,
) -> BrowserLaunch:
    before_binary = browser_binary().stat()
    policy = _sandbox_policy(
        browser_state_root=browser_state_root,
        fixture_path=fixture_path,
    )
    environment = scrubbed_environment(browser_state_root / "environment")
    environment["PATH"] = "/usr/bin:/bin"
    flags = _browser_flags(profile)
    argv = [
        str(SANDBOX_EXEC),
        "-p",
        policy,
        str(browser_binary()),
        *flags,
        fixture_path.resolve(strict=True).as_uri(),
    ]
    command_safe = _profile_safe_strings(argv)
    environment_safe = _profile_safe_strings([*environment, *environment.values()])
    if not command_safe or not environment_safe:
        raise BrowserRuntimeError("normal browser profile path entered child command or environment")

    control_root = session_root / "control" / launch_id
    control_root.mkdir(parents=True, mode=0o700)
    identity_path = control_root / "identity.json"
    lease_path = control_root / "lease.json"
    receipt_path = control_root / "watchdog-receipt.json"
    run_id = f"{session_root.name}-{launch_id}"
    deadline = time.monotonic() + timeout_seconds + 1.0
    _atomic_json(
        lease_path,
        {
            "run_id": run_id,
            "active": True,
            "deadline_monotonic": deadline,
        },
    )
    watchdog_environment = scrubbed_environment(control_root / "watchdog-environment")
    watchdog = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "harness.browser_watchdog",
            "--run-id",
            run_id,
            "--controller-pid",
            str(os.getpid()),
            "--identity",
            str(identity_path),
            "--lease",
            str(lease_path),
            "--receipt",
            str(receipt_path),
        ],
        cwd=ROOT,
        env=watchdog_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    process: subprocess.Popen[bytes] | None = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            cwd=browser_state_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=_browser_child_limits,
        )
        _atomic_json(
            identity_path,
            {
                "run_id": run_id,
                "pid": process.pid,
                "pgid": os.getpgid(process.pid),
                "profile_marker": str(profile),
            },
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=2)
            raise BrowserRuntimeError("browser fixture exceeded its wall-time ceiling") from None
        if len(stdout) > MAX_STDIO_BYTES or len(stderr) > MAX_STDIO_BYTES:
            raise BrowserRuntimeError("browser fixture exceeded its output ceiling")
    finally:
        _atomic_json(
            lease_path,
            {
                "run_id": run_id,
                "active": False,
                "deadline_monotonic": deadline,
            },
        )
    watchdog_receipt = _read_watchdog_receipt(watchdog, receipt_path)
    if process is None:
        raise BrowserRuntimeError("browser subject did not start")
    if process.returncode != 0:
        raise BrowserRuntimeError(
            f"browser fixture exited {process.returncode}; stderr_sha256={hashlib.sha256(stderr).hexdigest()}"
        )
    after_binary = browser_binary().stat()
    if (
        before_binary.st_dev,
        before_binary.st_ino,
        before_binary.st_size,
        before_binary.st_mtime_ns,
    ) != (
        after_binary.st_dev,
        after_binary.st_ino,
        after_binary.st_size,
        after_binary.st_mtime_ns,
    ):
        raise BrowserRuntimeError("browser binary identity changed during launch")
    payload = _parse_payload(stdout)
    return BrowserLaunch(
        payload=payload,
        returncode=process.returncode,
        elapsed_seconds=time.monotonic() - started,
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        watchdog=watchdog_receipt,
        command_profile_safe=command_safe,
        environment_profile_safe=environment_safe,
        outer_sandbox_network_denied=True,
        outer_sandbox_home_reads_denied=True,
        chromium_inner_sandbox=(
            "disabled; nested Chromium sandbox is incompatible with sandbox-exec, "
            "so the qualified outer sandbox is the enforced boundary"
        ),
    )


def _validate_session_root(root: Path) -> None:
    resolved_parent = root.parent.resolve(strict=True)
    program_root = ROOT.resolve(strict=True)
    if program_root != resolved_parent and program_root not in resolved_parent.parents:
        raise BrowserRuntimeError("browser session parent is outside the program repository")
    if root.exists() or root.is_symlink():
        raise BrowserRuntimeError("browser session root must be fresh")


def _validate_profile_seed(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise BrowserRuntimeError("browser profile seed contains a symbolic link")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise BrowserRuntimeError("browser profile seed contains a multiply linked file")


class BrowserSession:
    """One fresh profile and supervisor domain; reusable only within one control."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state_root = root / "browser-state"
        self.profile = self.state_root / "profile"
        self.fixture_path = root / "fixture.html"
        self._closed = False
        self._launch_count = 0

    def __enter__(self) -> BrowserSession:
        _validate_session_root(self.root)
        self.root.mkdir(mode=0o700)
        self.state_root.mkdir(mode=0o700)
        self.profile.mkdir(mode=0o700)
        return self

    def run_html(self, content: str, *, timeout_seconds: float = 8.0) -> BrowserLaunch:
        if self._closed or not self.root.exists():
            raise BrowserRuntimeError("browser session is closed")
        _validate_profile_seed(self.profile)
        temporary = self.fixture_path.with_suffix(".html.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise BrowserRuntimeError("browser fixture temporary path is not fresh")
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.fixture_path)
        _validate_single_link_regular(self.fixture_path, "browser fixture")
        self._launch_count += 1
        return _launch(
            session_root=self.root,
            browser_state_root=self.state_root,
            fixture_path=self.fixture_path,
            profile=self.profile,
            launch_id=f"launch-{self._launch_count:03d}",
            timeout_seconds=timeout_seconds,
        )

    def close(self) -> None:
        if self._closed:
            return
        shutil.rmtree(self.root)
        if self.root.exists():
            raise BrowserRuntimeError("browser session root remained after cleanup")
        self._closed = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def browser_html(script: str, *, csp: str | None = None) -> str:
    policy = (
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">'
        if csp is not None
        else ""
    )
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
{policy}
<title>MHAI disposable browser fixture</title>
</head>
<body>
<pre id="mhai-result">pending</pre>
<script>
"use strict";
const mhaiFinish = (value) => {{
  document.getElementById("mhai-result").textContent = JSON.stringify(value);
}};
try {{
{script}
}} catch (error) {{
  mhaiFinish({{harness_error: String(error && error.message || error)}});
}}
</script>
</body>
</html>
"""


def sandbox_filesystem_probe(root: Path) -> dict[str, bool]:
    probe_root = root / "sandbox-filesystem-probe"
    state = probe_root / "browser-state"
    state.mkdir(parents=True, mode=0o700)
    allowed = probe_root / "allowed.txt"
    denied = root / "denied.txt"
    allowed.write_text("allowed-marker", encoding="utf-8")
    denied.write_text("denied-marker", encoding="utf-8")
    policy = _sandbox_policy(browser_state_root=state, fixture_path=allowed)
    environment = scrubbed_environment(state / "environment")
    allowed_probe = subprocess.run(
        [str(SANDBOX_EXEC), "-p", policy, "/bin/cat", str(allowed)],
        check=False,
        capture_output=True,
        env=environment,
        timeout=2,
    )
    denied_probe = subprocess.run(
        [str(SANDBOX_EXEC), "-p", policy, "/bin/cat", str(denied)],
        check=False,
        capture_output=True,
        env=environment,
        timeout=2,
    )
    result = {
        "allowed_read_detected": (
            allowed_probe.returncode == 0 and allowed_probe.stdout == b"allowed-marker"
        ),
        "outside_read_denied": (
            denied_probe.returncode != 0 and b"denied-marker" not in denied_probe.stdout
        ),
    }
    shutil.rmtree(probe_root)
    denied.unlink()
    return result


def profile_boundary_probe(root: Path) -> dict[str, bool]:
    probe_root = root / "profile-boundary-probe"
    probe_root.mkdir(mode=0o700)
    target = probe_root / "target"
    target.mkdir(mode=0o700)
    symlink = probe_root / "profile-symlink"
    symlink.symlink_to(target, target_is_directory=True)
    symlink_rejected = False
    try:
        _validate_profile_seed(symlink)
    except BrowserRuntimeError:
        symlink_rejected = True

    linked_profile = probe_root / "linked-profile"
    linked_profile.mkdir(mode=0o700)
    first = linked_profile / "first"
    second = linked_profile / "second"
    first.write_text("synthetic", encoding="utf-8")
    os.link(first, second)
    hardlink_rejected = False
    try:
        _validate_profile_seed(linked_profile)
    except BrowserRuntimeError:
        hardlink_rejected = True

    shutil.rmtree(probe_root)
    return {
        "profile_symlink_rejected": symlink_rejected,
        "profile_hardlink_rejected": hardlink_rejected,
    }


def browser_version_probe(root: Path) -> str:
    probe_root = root / "browser-version-probe"
    state = probe_root / "browser-state"
    state.mkdir(parents=True, mode=0o700)
    fixture = probe_root / "fixture.html"
    fixture.write_text("<!doctype html><title>version probe</title>", encoding="utf-8")
    policy = _sandbox_policy(browser_state_root=state, fixture_path=fixture)
    environment = scrubbed_environment(state / "environment")
    environment["PATH"] = "/usr/bin:/bin"
    completed = subprocess.run(
        [str(SANDBOX_EXEC), "-p", policy, str(browser_binary()), "--version"],
        check=False,
        capture_output=True,
        env=environment,
        timeout=3,
        preexec_fn=_browser_child_limits,
    )
    try:
        output = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise BrowserRuntimeError("browser version output was not UTF-8") from exc
    shutil.rmtree(probe_root)
    if completed.returncode != 0:
        raise BrowserRuntimeError("browser version probe failed")
    expected = f"Google Chrome for Testing {BROWSER_VERSION}"
    if output != expected:
        raise BrowserRuntimeError("browser version differs from cached provenance")
    return output


def browser_watchdog_controller_death_probe(root: Path) -> dict[str, bool]:
    trial_root = root / "browser-watchdog-controller-death"
    trial_root.mkdir(mode=0o700)
    session_root = trial_root / "session"
    identity_path = session_root / "control/launch-001/identity.json"
    receipt_path = session_root / "control/launch-001/watchdog-receipt.json"
    environment = scrubbed_environment(trial_root / "controller-environment")
    controller = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "harness.browser_controller_probe",
            "--session-root",
            str(session_root),
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    browser_pgid: int | None = None
    try:
        identity_deadline = time.monotonic() + 5.0
        while not identity_path.exists() and time.monotonic() < identity_deadline:
            if controller.poll() is not None:
                raise BrowserRuntimeError(
                    "sacrificial browser controller exited before publishing identity"
                )
            time.sleep(0.05)
        if not identity_path.exists():
            raise BrowserRuntimeError("sacrificial browser identity was not published")
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        browser_pgid = int(identity["pgid"])
        os.killpg(controller.pid, signal.SIGKILL)
        controller.wait(timeout=2)

        receipt_deadline = time.monotonic() + 5.0
        while not receipt_path.exists() and time.monotonic() < receipt_deadline:
            time.sleep(0.05)
        if not receipt_path.exists():
            raise BrowserRuntimeError("browser watchdog controller-death receipt is absent")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        cleanup_verified = (
            receipt.get("result") == "PASS"
            and receipt.get("reason") == "controller-death-revocation"
            and receipt.get("cleanup_verified") is True
        )
        try:
            os.killpg(browser_pgid, 0)
        except ProcessLookupError:
            group_absent = True
        else:
            group_absent = False
        result = {
            "watchdog_started_before_subject": True,
            "controller_death_detected": cleanup_verified,
            "browser_process_group_absent": group_absent,
            "controller_death_cleanup_verified": cleanup_verified and group_absent,
        }
        if not all(result.values()):
            raise BrowserRuntimeError("browser watchdog controller-death control failed")
        return result
    finally:
        if controller.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(controller.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                controller.wait(timeout=2)
        if browser_pgid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(browser_pgid, signal.SIGKILL)
        shutil.rmtree(trial_root, ignore_errors=True)
