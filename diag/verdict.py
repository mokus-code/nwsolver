"""Verdict model shared by all suites: one plain-language answer per run."""
from __future__ import annotations

from dataclasses import dataclass, field

from nwsolver.engine.checks import CheckResult, Status

STATE_COLORS = {
    "ok": "#1e8e3e",
    "warn": "#d99a06",
    "fail": "#d93025",
    "unknown": "#80868b",
}


@dataclass
class Step:
    """One link in a dependency chain (shown as a pill in the UI)."""

    step_id: str
    label: str
    status: Status
    check: CheckResult | None = None
    blocked: bool = False   # not reached because an earlier step failed


@dataclass
class Verdict:
    state: str                      # ok | warn | fail | unknown
    headline: str                   # one short sentence
    detail: str = ""                # explanation (why)
    actions: list[str] = field(default_factory=list)   # what to do
    steps: list[Step] = field(default_factory=list)
    culprit: str | None = None      # check_id of the root cause, if any

    @property
    def color(self) -> str:
        return STATE_COLORS.get(self.state, STATE_COLORS["unknown"])


def chain_verdict(results: list[CheckResult],
                  chain: list[tuple[str, str]]) -> tuple[list[Step], Step | None,
                                                         Step | None]:
    """Walk a chain of (check_id, label).

    Returns (steps, first_broken, first_degraded). Steps after the first
    broken one are marked *blocked* unless they failed themselves (then they
    are symptoms and keep their status).
    """
    by_id = {r.check_id: r for r in results}
    steps = []
    for cid, label in chain:
        r = by_id.get(cid)
        steps.append(Step(cid, label, r.status if r else Status.SKIP, r))
    broken = next((s for s in steps
                   if s.status in (Status.FAIL, Status.ERROR)), None)
    if broken is not None:
        idx = steps.index(broken)
        for s in steps[idx + 1:]:
            s.blocked = True
    degraded = next((s for s in steps if s.status is Status.WARN), None)
    return steps, broken, degraded


def first_sentence(text: str) -> str:
    text = (text or "").strip()
    for sep in (". ", " — "):
        if sep in text:
            return text.split(sep, 1)[0].rstrip(".") + "."
    return text
