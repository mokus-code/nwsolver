"""Suite runner + environment info. Pure Python — no Qt."""
from __future__ import annotations

import os
import platform
import socket
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from nwsolver.engine.checks import Check, CheckResult, Ctx, Status


def _safe_run(ctx: Ctx, check: Check) -> CheckResult:
    """Run one check, guaranteeing a valid CheckResult is returned."""
    start = time.monotonic()
    try:
        result = check.fn(ctx)
    except Exception as exc:  # noqa: BLE001 — keep the run alive
        result = CheckResult(
            check.check_id, check.title, Status.ERROR,
            f"The check crashed: {exc.__class__.__name__}: {exc}",
            raw=traceback.format_exc()[-4000:],
            suggestion="This is a bug in nwsolver — please report it with "
                       "the raw output.")
    if not isinstance(result, CheckResult):
        result = CheckResult(check.check_id, check.title, Status.ERROR,
                             f"Check returned {type(result).__name__}")
    result.check_id = result.check_id or check.check_id
    result.title = result.title or check.title
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def run_suite(ctx: Ctx, suite, on_result=None, on_progress=None,
              cancel_check=None, include_deep: bool = False,
              max_workers: int = 4) -> list[CheckResult]:
    """Run every check of ``suite`` and return results in display order.

    ``on_progress(done, total, title)`` fires before each sequential check /
    after each parallel one; ``on_result(index, result)`` as soon as a
    result is ready. Sequential suites stop early when a check sets
    ``ctx.state["abort"]``.
    """
    checks = [c for c in suite.make_checks(ctx) if include_deep or not c.deep]
    results: list[CheckResult | None] = [None] * len(checks)
    total = len(checks)
    if getattr(suite, "PARALLEL", False):
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers,
                                                       total))) as pool:
            futs = {pool.submit(_safe_run, ctx, c): i
                    for i, c in enumerate(checks)}
            for fut in as_completed(futs):
                if cancel_check is not None and cancel_check():
                    for f in futs:
                        f.cancel()
                    break
                i = futs[fut]
                results[i] = fut.result()
                done += 1
                if on_progress:
                    on_progress(done, total, results[i].title)
                if on_result:
                    on_result(i, results[i])
    else:
        for i, c in enumerate(checks):
            if cancel_check is not None and cancel_check():
                break
            if on_progress:
                on_progress(i, total, c.title)
            results[i] = _safe_run(ctx, c)
            if on_result:
                on_result(i, results[i])
            if ctx.state.get("abort"):
                break
        if on_progress:
            on_progress(total, total, "done")
    return [r for r in results if r is not None]


def _os_release(ctx: Ctx) -> str:
    for line in (ctx.read("/etc/os-release") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Linux"


def collect_env(ctx: Ctx) -> dict[str, Any]:
    """Minimal host facts for reports and the AI prompt."""
    return {
        "hostname": socket.gethostname() or "?",
        "distro": _os_release(ctx),
        "kernel": platform.release(),
        "user": os.environ.get("USER", "?"),
        "is_root": ctx.is_root,
        "lang": os.environ.get("LANG", ""),
    }


def count_statuses(results: list[CheckResult]) -> dict[Status, int]:
    counts = {s: 0 for s in Status}
    for r in results:
        counts[r.status] += 1
    return counts


def issues(results: list[CheckResult]) -> list[CheckResult]:
    """Non-passing results, worst first."""
    out = [r for r in results if r.status.weight >= Status.WARN.weight]
    out.sort(key=lambda r: r.status.weight, reverse=True)
    return out
