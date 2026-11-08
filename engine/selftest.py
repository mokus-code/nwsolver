"""Headless mode — run a suite in the terminal (no PySide6 needed).

    python3 run.py --selftest               # connection diagnosis
    python3 run.py --selftest --speed       # speed test
    python3 run.py --selftest --check URL   # why doesn't URL open
"""
from __future__ import annotations

import sys
import time

from nwsolver.diag import SUITE_BY_ID
from nwsolver.engine.checks import Ctx, Status
from nwsolver.engine.collector import collect_env, run_suite

_COL = {Status.PASS: "32", Status.WARN: "33", Status.FAIL: "31",
        Status.SKIP: "90", Status.ERROR: "35"}
_STATE = {"ok": ("32", "OK"), "warn": ("33", "PROBLEM"),
          "fail": ("31", "FAILED"), "unknown": ("90", "UNKNOWN")}


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def run_selftest(suite_id: str = "connection", target: str = "",
                 max_workers: int = 4) -> int:
    suite = SUITE_BY_ID[suite_id]
    ctx = Ctx(target=target)
    env = collect_env(ctx)
    print(f"nwsolver — {suite.SUITE_NAME}: {suite.SUITE_DESC}")
    print(f"{env['hostname']} · {env['distro']} · kernel {env['kernel']}"
          f" · root: {'yes' if env['is_root'] else 'no'}")
    if target:
        print(f"target: {target}")
    print()
    start = time.monotonic()

    def progress(done, total, label):
        if suite.PARALLEL or label == "done":
            return
        print(f"  … {label}", flush=True)

    results = run_suite(ctx, suite, on_progress=progress,
                        max_workers=max_workers)
    print()
    for r in results:
        print(f"{_c(_COL[r.status], f'{r.status.label:<5}')} {r.title}")
        print(f"      {r.summary}")
        if r.suggestion and r.status is not Status.PASS:
            print(f"      → {r.suggestion}")
    v = suite.analyze(results, ctx)
    color, word = _STATE.get(v.state, _STATE["unknown"])
    print()
    print("=" * 72)
    print(_c(color, f"{word}: {v.headline}"))
    if v.detail:
        print(v.detail)
    for a in v.actions:
        print(f"→ {a}")
    if v.steps:
        marks = {Status.PASS: "✓", Status.WARN: "!", Status.FAIL: "✗",
                 Status.ERROR: "✗", Status.SKIP: "–"}
        print("Chain: " + "  ".join(
            ("·" if s.blocked else marks[s.status]) + " " + s.label
            for s in v.steps))
    print(f"({time.monotonic() - start:.1f} s)")
    print("=" * 72)
    return 0 if v.state == "ok" else 1
