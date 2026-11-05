"""Builds the prompt sent to the AI assistant from one tab's results.

Contains the verdict, every step (status + summary + suggested fix) and,
for a focused question, that step's raw output. No API keys or other
secrets are ever included.
"""
from __future__ import annotations

from nwsolver.engine.checks import CheckResult, Status

SYSTEM_PROMPT = (
    "You are a senior network engineer helping a home or office user on "
    "Ubuntu Linux whose internet does not work, is slow, or who cannot open "
    "a specific site. You get the results of an automated step-by-step "
    "check. Explain in plain words where the problem is (this computer, "
    "Wi-Fi/cable, router, ISP, DNS, a block on the way, or the remote "
    "server), then give concrete steps to fix or confirm it, with exact "
    "Ubuntu commands where useful. Most likely cause first. Be concise "
    "(max ~400 words). Do not invent facts that are not in the data. "
    "Answer in the language the user asks for."
)

def _line(r: CheckResult) -> str:
    fix = f" | suggested fix: {r.suggestion}" if r.suggestion and \
        r.status is not Status.PASS else ""
    return f"[{r.status.label}] {r.title}: {r.summary}{fix}"


def build_prompt(env: dict, run: dict | None,
                 focus: CheckResult | None = None) -> tuple[str, str]:
    """Return ``(system_prompt, user_prompt)`` — the same context the
    "Copy for AI" export produces, plus an optional focused step."""
    from nwsolver.engine.report import build_ai_context
    parts = []
    if run is not None:
        parts.append(build_ai_context(env, {run["suite"]: run}))
    else:
        parts.append(f"Computer: {env.get('distro')}, kernel "
                     f"{env.get('kernel')}")
    if focus is not None:
        parts.append("## Explain this one step in detail")
        parts.append(_line(focus))
        if focus.raw:
            parts.append("```text\n" + focus.raw[:2500] + "\n```")
    return SYSTEM_PROMPT, "\n\n".join(parts)
