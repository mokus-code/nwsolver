"""Core data model and runtime context for the nwsolver diagnostic engine.

This module is the single API contract used by every diagnostic suite
(``nwsolver/diag/*.py``). It must stay pure Python / stdlib-only so the
engine can run headless (``python3 run.py --selftest``) without PySide6.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------
# Status / verdicts
# --------------------------------------------------------------------------

class Status(str, Enum):
    """Verdict of a single diagnostic check."""

    PASS = "pass"    # check ran, everything healthy
    WARN = "warn"    # degraded or suspicious, not necessarily fatal
    FAIL = "fail"    # a real problem was found
    SKIP = "skip"    # not applicable (no device / tool missing / needs root)
    ERROR = "error"  # the check itself could not be executed

    @property
    def weight(self) -> int:
        """Higher = worse. Used for sorting issues and scoring."""
        return {"fail": 4, "error": 3, "warn": 2, "skip": 1, "pass": 0}[self.value]

    @property
    def label(self) -> str:
        return self.value.upper()


# --------------------------------------------------------------------------
# Command results
# --------------------------------------------------------------------------

class CmdResult:
    """Result of running one external command via :meth:`Ctx.run`."""

    __slots__ = ("argv", "elapsed_s", "rc", "stderr", "stdout", "timed_out")

    def __init__(self, argv: list[str], rc: int, stdout: str, stderr: str,
                 timed_out: bool = False, elapsed_s: float = 0.0):
        self.argv: list[str] = list(argv)
        self.rc: int = rc
        self.stdout: str = stdout
        self.stderr: str = stderr
        self.timed_out: bool = timed_out
        self.elapsed_s: float = elapsed_s

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def text(self) -> str:
        """Trimmed stdout (the main output consumers parse)."""
        return self.stdout.strip()

    @property
    def permission_denied(self) -> bool:
        """True when the failure smells like a privileges problem."""
        if self.rc == 0:
            return False
        blob = (self.stderr + " " + self.stdout).lower()
        needles = (
            "permission denied",
            "operation not permitted",
            "not permitted",
            "permission problem",
            "you must be root",
            "requires root",
            "root privileges",
            "insufficient permissions",
        )
        return any(n in blob for n in needles)

    @property
    def command_not_found(self) -> bool:
        return self.rc == -1 and "command not found" in self.stderr


# --------------------------------------------------------------------------
# Check result
# --------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Outcome of one check, ready to display / export."""

    check_id: str
    title: str
    status: Status
    summary: str
    raw: str = ""          # command/sysfs output shown in the detail viewer
    suggestion: str = ""   # human-readable remediation hint
    duration_ms: int = 0
    # Machine-readable measurements (latency, throughput, …) used by the
    # verdict logic and the UI tiles. Never shown verbatim.
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class Check:
    """A diagnostic check: metadata + the function that performs it.

    ``fn`` receives the shared :class:`Ctx` and returns a :class:`CheckResult`.
    It must never raise (the engine wraps execution in try/except anyway),
    never touch Qt, and only use stdlib plus the ``Ctx`` API.
    """

    check_id: str
    title: str
    fn: Callable[["Ctx"], CheckResult]
    deep: bool = False  # slow/optional checks, skipped unless requested


# --------------------------------------------------------------------------
# Runtime context handed to every check
# --------------------------------------------------------------------------

class Ctx:
    """Shared runtime context: safe command execution + sysfs/plain-file reads.

    Created once per scan and reused by every check. Never touches Qt.
    """

    def __init__(self, **options: Any) -> None:
        self._which_cache: dict[str, str | None] = {}
        # Per-run options (e.g. the target of a resource check) and shared
        # state that sequential checks hand to each other.
        self.options: dict[str, Any] = dict(options)
        self.state: dict[str, Any] = {}

    # -- identity ----------------------------------------------------------

    @property
    def is_root(self) -> bool:
        try:
            return os.geteuid() == 0
        except AttributeError:  # non-POSIX
            return False

    # -- external commands -------------------------------------------------

    def run(self, argv: list[str], timeout: float = 6.0) -> CmdResult:
        """Run ``argv`` with a stable C locale, never through a shell."""
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        start = time.monotonic()
        try:
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=env,
            )
            return CmdResult(
                argv, proc.returncode, proc.stdout, proc.stderr,
                elapsed_s=time.monotonic() - start,
            )
        except FileNotFoundError:
            return CmdResult(
                argv, -1, "",
                f"command not found: {argv[0]}",
                elapsed_s=time.monotonic() - start,
            )
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CmdResult(argv, -1, out, err, timed_out=True,
                             elapsed_s=time.monotonic() - start)

    # -- file / sysfs reads (never raise) ----------------------------------

    def read(self, path: str, max_bytes: int = 65536) -> str | None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(max_bytes)
        except (OSError, ValueError):
            return None

    def readlines(self, path: str) -> list[str]:
        text = self.read(path)
        if text is None:
            return []
        return [ln.rstrip("\n") for ln in text.splitlines()]

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    # -- system introspection ----------------------------------------------

    def interfaces(self) -> list[str]:
        """All network interfaces (including loopback), sorted by name."""
        return self.listdir("/sys/class/net")

    def which(self, name: str) -> str | None:
        cached = self._which_cache.get(name)
        if cached is not None:
            return cached or None
        found = shutil.which(name)
        self._which_cache[name] = found or ""
        return found

    def sysctl(self, name: str) -> str | None:
        """Read a sysctl value, e.g. ``ctx.sysctl("net.ipv4.ip_forward")``."""
        if name.startswith("/"):
            path = name
        else:
            path = "/proc/sys/" + name.replace(".", "/")
        val = self.read(path)
        if val is None:
            return None
        val = val.strip()
        return val or None


# --------------------------------------------------------------------------
# Small helpers shared by layers
# --------------------------------------------------------------------------

def skip_result(check_id: str, title: str, reason: str, suggestion: str = "") -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=title,
        status=Status.SKIP,
        summary=reason,
        suggestion=suggestion,
    )


def pass_result(check_id: str, title: str, summary: str, raw: str = "") -> CheckResult:
    return CheckResult(check_id=check_id, title=title, status=Status.PASS,
                       summary=summary, raw=raw)


def worst_status(*statuses: Status) -> Status:
    """Aggregate several statuses: the most severe one wins."""
    best = Status.PASS
    for s in statuses:
        if s.weight > best.weight:
            best = s
    return best
