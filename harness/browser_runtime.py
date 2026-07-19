"""Program-owned disposable Chromium runtime for browser-required fixtures."""

from __future__ import annotations

import contextlib
import hashlib
import html
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BROWSER_CONTRACT_VERSION = "MHAI-BROWSER-2"
MAX_STDIO_BYTES = 2 * 1024 * 1024
MAX_BROWSER_PIDS = 4
MAX_BROWSER_RSS_KIB = 384 * 1024
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
PROVENANCE = ROOT / "OFFICIAL-DEPENDENCY-PROVENANCE.json"
BUNDLE = (
    ROOT
    / "vendor"
    / "official"
    / "playwright-browsers"
    / "chromium_headless_shell-1234"
    / "chrome-headless-shell-mac-arm64"
)
BINARY = BUNDLE / "chrome-headless-shell"
PLAYWRIGHT_CORE = (
    ROOT
    / "work"
    / "official-downloads"
    / "playwright-runtime"
    / "node_modules"
    / "playwright-core"
)

NORMAL_PROFILE_ROOTS = (
    Path.home() / "Library/Application Support/Google/Chrome",
    Path.home() / "Library/Application Support/Chromium",
    Path.home() / "Library/Application Support/Microsoft Edge",
    Path.home() / "Library/Application Support/Arc",
    Path.home() / "Library/Application Support/BraveSoftware",
    Path.home() / "Library/Application Support/Firefox",
    Path.home() / "Library/Safari",
    Path.home() / ".mozilla",
)


class BrowserRuntimeError(RuntimeError):
    """A disposable browser invariant failed."""


@dataclass(frozen=True)
class BrowserIdentity:
    contract_version: str
    revision: str
    version: str
    package_version: str
    binary_sha256: str
    bundle_tree_sha256: str
    metadata_sha256: str
    sandbox_exec_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "revision": self.revision,
            "version": self.version,
            "package_version": self.package_version,
            "binary_sha256": self.binary_sha256,
            "bundle_tree_sha256": self.bundle_tree_sha256,
            "metadata_sha256": self.metadata_sha256,
            "sandbox_exec_sha256": self.sandbox_exec_sha256,
        }


@dataclass(frozen=True)
class BrowserLaunch:
    payload: dict[str, Any]
    returncode: int
    elapsed_seconds: float
    stderr_sha256: str
    command_profile_safe: bool
    environment_profile_safe: bool
    outer_sandbox_network_denied: bool
    outer_sandbox_normal_profiles_denied: bool
    max_observed_pids: int
    max_observed_rss_kib: int
    residual_processes: int
    diagnostic_report_changes: int

    def evidence(self) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "stderr_sha256": self.stderr_sha256,
            "command_profile_safe": self.command_profile_safe,
            "environment_profile_safe": self.environment_profile_safe,
            "outer_sandbox_network_denied": self.outer_sandbox_network_denied,
            "outer_sandbox_normal_profiles_denied": (
                self.outer_sandbox_normal_profiles_denied
            ),
            "max_observed_pids": self.max_observed_pids,
            "max_observed_rss_kib": self.max_observed_rss_kib,
            "pid_ceiling": MAX_BROWSER_PIDS,
            "rss_ceiling_kib": MAX_BROWSER_RSS_KIB,
            "residual_processes": self.residual_processes,
            "diagnostic_report_changes": self.diagnostic_report_changes,
            "chromium_inner_sandbox": (
                "disabled; the qualified macOS outer sandbox is the enforced boundary"
            ),
        }


class _ResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inside = False
        self.parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "pre" and dict(attrs).get("id") == "mhai-result":
            self.inside = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "pre":
            self.inside = False

    def handle_data(self, data: str) -> None:
        if self.inside:
            self.parts.append(data)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _single_link_regular(path: Path, label: str) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or path.resolve(strict=True) != path
    ):
        raise BrowserRuntimeError(f"{label} is not a single-link regular file")
    return metadata


def _bundle_tree_digest(root: Path) -> str:
    if root.resolve(strict=True) != root or not root.is_dir():
        raise BrowserRuntimeError("browser bundle root is not exact")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        metadata = path.lstat()
        relative = str(path.relative_to(root))
        if stat.S_ISLNK(metadata.st_mode):
            raise BrowserRuntimeError("browser bundle contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(f"d\0{relative}\0{stat.S_IMODE(metadata.st_mode):o}\0".encode())
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            digest.update(
                f"f\0{relative}\0{stat.S_IMODE(metadata.st_mode):o}\0"
                f"{metadata.st_size}\0".encode()
            )
            digest.update(bytes.fromhex(_sha256(path)))
        else:
            raise BrowserRuntimeError("browser bundle contains an unsafe file type")
    return digest.hexdigest()


def current_browser_identity() -> BrowserIdentity:
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))["playwright"]
    metadata_path = PLAYWRIGHT_CORE / "browsers.json"
    package_path = PLAYWRIGHT_CORE / "package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    browsers = json.loads(metadata_path.read_text(encoding="utf-8"))["browsers"]
    browser = next(
        (
            item
            for item in browsers
            if item.get("name") == "chromium-headless-shell"
            and item.get("revision") == provenance["browser_revision"]
        ),
        None,
    )
    if browser is None or browser.get("browserVersion") != provenance["browser_version"]:
        raise BrowserRuntimeError("Playwright metadata does not bind the browser revision")
    binary_metadata = _single_link_regular(BINARY, "browser binary")
    sandbox_metadata = _single_link_regular(SANDBOX_EXEC, "sandbox-exec")
    if binary_metadata.st_uid != os.getuid() or sandbox_metadata.st_uid != 0:
        raise BrowserRuntimeError("browser or sandbox ownership is invalid")
    binary_sha256 = _sha256(BINARY)
    metadata_sha256 = _sha256(metadata_path)
    bundle_tree_sha256 = _bundle_tree_digest(BUNDLE)
    if (
        binary_sha256 != provenance["browser_binary_sha256"]
        or metadata_sha256 != provenance["browsers_metadata_sha256"]
        or package.get("version") != provenance["package_version"]
        or bundle_tree_sha256 != provenance["runtime_bundle_tree_sha256"]
    ):
        raise BrowserRuntimeError("official Playwright provenance hash mismatch")
    return BrowserIdentity(
        contract_version=BROWSER_CONTRACT_VERSION,
        revision=provenance["browser_revision"],
        version=provenance["browser_version"],
        package_version=provenance["package_version"],
        binary_sha256=binary_sha256,
        bundle_tree_sha256=bundle_tree_sha256,
        metadata_sha256=metadata_sha256,
        sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
    )


def browser_identity_matches(expected: dict[str, Any]) -> bool:
    return current_browser_identity().as_dict() == expected


def _sandbox_policy(session_root: Path) -> str:
    denied_reads = "\n".join(
        f"(deny file-read* (subpath {json.dumps(str(path))}))"
        for path in NORMAL_PROFILE_ROOTS
    )
    return "\n".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny file-write*)",
            denied_reads,
            '(allow file-write* (literal "/dev/null"))',
            f"(allow file-write* (subpath {json.dumps(str(session_root))}))",
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
        "--disable-crashpad-for-testing",
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


def _profile_safe(values: list[str]) -> bool:
    fragments = tuple(str(path) for path in NORMAL_PROFILE_ROOTS)
    return all(fragment not in value for fragment in fragments for value in values)


def _child_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (16 * 1024 * 1024, 16 * 1024 * 1024),
    )
    resource.setrlimit(resource.RLIMIT_CPU, (12, 12))


def _group_inventory(pgid: int) -> list[tuple[int, int]]:
    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,rss="],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=2,
    )
    if completed.returncode != 0:
        raise BrowserRuntimeError("browser process inventory failed")
    rows: list[tuple[int, int]] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            pid, row_pgid, rss = map(int, fields)
        except ValueError:
            continue
        if row_pgid == pgid:
            rows.append((pid, rss))
    return rows


def _diagnostic_inventory() -> dict[str, tuple[int, int]]:
    root = Path.home() / "Library/Logs/DiagnosticReports"
    if not root.is_dir():
        return {}
    inventory: dict[str, tuple[int, int]] = {}
    for path in root.iterdir():
        try:
            metadata = path.stat()
        except OSError:
            continue
        inventory[path.name] = (metadata.st_size, metadata.st_mtime_ns)
    return inventory


def _parse_payload(stdout: bytes) -> dict[str, Any]:
    rendered = stdout.decode("utf-8", errors="strict")
    parser = _ResultParser()
    parser.feed(rendered)
    raw = html.unescape("".join(parser.parts))
    if not raw or raw == "pending":
        raise BrowserRuntimeError("browser fixture did not emit a terminal result")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("harness_error"):
        raise BrowserRuntimeError("browser fixture emitted an invalid result")
    return payload


def _launch(
    *,
    session_root: Path,
    fixture_path: Path,
    profile: Path,
    timeout_seconds: float,
) -> BrowserLaunch:
    identity_before = current_browser_identity()
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(session_root),
        "TMPDIR": str(session_root / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    subject_argv = [
        str(BINARY),
        *_browser_flags(profile),
        fixture_path.resolve(strict=True).as_uri(),
    ]
    argv = [
        str(SANDBOX_EXEC),
        "-p",
        _sandbox_policy(session_root),
        *subject_argv,
    ]
    command_safe = _profile_safe(subject_argv)
    environment_safe = _profile_safe([*environment, *environment.values()])
    if not command_safe or not environment_safe:
        raise BrowserRuntimeError("normal browser profile path entered child inputs")

    diagnostics_before = _diagnostic_inventory()
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=session_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        preexec_fn=_child_limits,
    )
    max_pids = 0
    max_rss = 0
    deadline = started + timeout_seconds
    boundary_failure: str | None = None
    while process.poll() is None and time.monotonic() < deadline:
        rows = _group_inventory(process.pid)
        max_pids = max(max_pids, len(rows))
        max_rss = max(max_rss, sum(rss for _, rss in rows))
        if len(rows) > MAX_BROWSER_PIDS or sum(rss for _, rss in rows) > MAX_BROWSER_RSS_KIB:
            boundary_failure = "browser process or memory ceiling exceeded"
            break
        time.sleep(0.05)
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    try:
        stdout, stderr = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=2)
        boundary_failure = boundary_failure or "browser cleanup deadline exceeded"
    residual = _group_inventory(process.pid)
    diagnostics_after = _diagnostic_inventory()
    diagnostic_changes = sum(
        1
        for name in set(diagnostics_before) | set(diagnostics_after)
        if diagnostics_before.get(name) != diagnostics_after.get(name)
    )
    if (
        boundary_failure
        or process.returncode != 0
        or len(stdout) > MAX_STDIO_BYTES
        or len(stderr) > MAX_STDIO_BYTES
        or residual
        or diagnostic_changes
        or current_browser_identity() != identity_before
    ):
        raise BrowserRuntimeError(
            boundary_failure
            or (
                "browser containment failed: "
                f"returncode={process.returncode}, residual={len(residual)}, "
                f"diagnostics={diagnostic_changes}, stderr_sha256="
                f"{hashlib.sha256(stderr).hexdigest()}"
            )
        )
    return BrowserLaunch(
        payload=_parse_payload(stdout),
        returncode=process.returncode,
        elapsed_seconds=time.monotonic() - started,
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        command_profile_safe=command_safe,
        environment_profile_safe=environment_safe,
        outer_sandbox_network_denied=True,
        outer_sandbox_normal_profiles_denied=True,
        max_observed_pids=max_pids,
        max_observed_rss_kib=max_rss,
        residual_processes=0,
        diagnostic_report_changes=0,
    )


class BrowserSession:
    """One fresh, program-owned profile and process group."""

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        self.profile = self.root / "profile"
        self.fixture = self.root / "fixture.html"
        self.closed = False

    def __enter__(self) -> BrowserSession:
        parent = self.root.parent.resolve(strict=True)
        program = ROOT.resolve(strict=True)
        if program != parent and program not in parent.parents:
            raise BrowserRuntimeError("browser session is outside the program root")
        if self.root.exists() or self.root.is_symlink():
            raise BrowserRuntimeError("browser session root must be fresh")
        self.profile.mkdir(parents=True, mode=0o700)
        (self.root / "tmp").mkdir(mode=0o700)
        return self

    def run_html(self, content: str, *, timeout_seconds: float = 10.0) -> BrowserLaunch:
        if self.closed or not self.root.exists():
            raise BrowserRuntimeError("browser session is closed")
        for path in [self.profile, *self.profile.rglob("*")]:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise BrowserRuntimeError("browser profile contains a symbolic link")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise BrowserRuntimeError("browser profile contains a hard link")
        with self.fixture.open("x", encoding="utf-8") as handle:
            os.chmod(self.fixture, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _single_link_regular(self.fixture, "browser fixture")
        return _launch(
            session_root=self.root,
            fixture_path=self.fixture,
            profile=self.profile,
            timeout_seconds=timeout_seconds,
        )

    def close(self) -> None:
        if self.closed:
            return
        shutil.rmtree(self.root)
        if self.root.exists():
            raise BrowserRuntimeError("browser session cleanup failed")
        self.closed = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def browser_html(script: str, *, csp: str | None = None) -> str:
    policy = (
        f'<meta http-equiv="Content-Security-Policy" '
        f'content="{html.escape(csp, quote=True)}">'
        if csp is not None
        else ""
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8">{policy}
<title>MHAI disposable browser fixture</title></head>
<body><pre id="mhai-result">pending</pre><script>
"use strict";
const mhaiFinish = (value) => {{
  document.getElementById("mhai-result").textContent = JSON.stringify(value);
}};
try {{
{script}
}} catch (error) {{
  mhaiFinish({{harness_error: String(error && error.message || error)}});
}}
</script></body></html>"""
