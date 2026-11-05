"""Export: a compact, self-contained context to paste into an AI chat.

The text says what the user wants, describes the environment in a few
lines, and lists the problems the checks found (with short evidence) so an
AI assistant can recommend a fix. Passing steps are summarised in one line
each; full raw dumps, host name, user name, MAC and public IP addresses are
left out on purpose.
"""
from __future__ import annotations

import datetime
import re
from typing import Any

from nwsolver.engine.checks import CheckResult, Status

_SYMPTOM = {
    "connection": "There is no internet connection (or it is unreliable).",
    "speed": "The internet is slow.",
    "resource": "A specific website/service does not open: {target}.",
}
_SECTION = {
    "connection": "Check: no internet connection",
    "speed": "Check: slow internet",
    "resource": "Check: site/service does not open — {target}",
}
_STATE = {"ok": "OK", "warn": "PROBLEM", "fail": "BROKEN", "unknown": "UNKNOWN"}
_MARK = {Status.PASS: "✓", Status.WARN: "!", Status.FAIL: "✗",
         Status.ERROR: "✗", Status.SKIP: "–"}
_LANGS = {"ru": "Russian", "uk": "Ukrainian", "uz": "Uzbek", "kk": "Kazakh",
          "be": "Belarusian", "en": "English", "de": "German",
          "fr": "French", "es": "Spanish", "it": "Italian", "pl": "Polish",
          "tr": "Turkish", "pt": "Portuguese", "zh": "Chinese",
          "ja": "Japanese"}
_EVIDENCE_MAX = 1200


def answer_language(env: dict[str, Any]) -> str:
    code = (env.get("lang") or "").split("_", 1)[0].split(".", 1)[0].lower()
    return _LANGS.get(code, "the language of my question")


def _short(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    text = re.sub(r"\s*Public IP \S+(?: \([^)]*\))?\.?", "", text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


_MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)
_PUBLIC_IP = re.compile(r"\bip=\S+")


def _evidence(raw: str) -> str:
    raw = (raw or "").strip()
    raw = _MAC.sub("xx:xx:xx:xx:xx:xx", raw)
    raw = _PUBLIC_IP.sub("ip=<hidden>", raw)
    if len(raw) > _EVIDENCE_MAX:
        raw = raw[:_EVIDENCE_MAX].rstrip() + "\n… (shortened)"
    return raw


def _connection_line(runs: dict[str, dict]) -> list[str]:
    """Environment bullets from the connection overview + measurements."""
    ov: dict = {}
    for sid in ("connection", "speed", "resource"):
        run = runs.get(sid)
        if run and run.get("overview"):
            ov = run["overview"]
            break
    if not ov:
        # Speed / website runs have no overview of their own: read the
        # current connection facts now (a few quick local commands).
        try:
            from nwsolver.diag import connection
            from nwsolver.engine.checks import Ctx
            ov = connection.overview(Ctx())
        except Exception:  # noqa: BLE001 — the context is still useful
            ov = {}
    metrics: dict = {}
    for run in runs.values():
        for r in run["results"]:
            for k, v in r.metrics.items():
                metrics.setdefault(k, v)
    out = []
    via = ov.get("type") or "unknown"
    bits = []
    if ov.get("network"):
        bits.append(f"“{ov['network']}”" if ov.get("type") == "Wi-Fi"
                    else str(ov["network"]))
    if ov.get("interface"):
        bits.append(ov["interface"])
    if metrics.get("band"):
        bits.append(str(metrics["band"]))
    if metrics.get("signal") is not None:
        bits.append(f"signal {metrics['signal']} dBm")
    out.append(f"- Connection: {via}" + (f" ({', '.join(bits)})" if bits
                                          else ""))
    net_bits = []
    if ov.get("ip"):
        net_bits.append(f"local IP {ov['ip']}")
    if ov.get("gateway"):
        net_bits.append(f"router {ov['gateway']}")
    if ov.get("dns"):
        net_bits.append(f"DNS {ov['dns']}")
    if net_bits:
        out.append("- Network: " + ", ".join(net_bits))
    out.append(f"- VPN: {ov.get('vpn') or 'none'}; proxy: "
               f"{'configured' if ov.get('proxy') else 'none'}")
    if metrics.get("location"):
        out.append(f"- Location by IP: {metrics['location']}")
    return out


def _measurements(run: dict) -> str:
    from nwsolver.diag import net, speed
    m = speed.metrics(run["results"])
    parts = []
    if m.get("down_mbps") is not None:
        parts.append(f"download {net.fmt_mbps(m['down_mbps'])}")
    if m.get("up_mbps") is not None:
        parts.append(f"upload {net.fmt_mbps(m['up_mbps'])}")
    if m.get("idle_ms") is not None:
        lat = f"latency {net.fmt_ms(m['idle_ms'])} idle"
        if m.get("loaded_ms") is not None:
            lat += f" / {net.fmt_ms(m['loaded_ms'])} under load"
        parts.append(lat)
    if m.get("lan_rtt_ms") is not None:
        parts.append(f"to router {net.fmt_ms(m['lan_rtt_ms'])}, "
                     f"{m.get('lan_loss_pct', 0):.0f}% loss")
    if m.get("wan_rtt_ms") is not None:
        parts.append(f"to internet {net.fmt_ms(m['wan_rtt_ms'])}, jitter "
                     f"{net.fmt_ms(m.get('wan_jitter_ms'))}, "
                     f"{m.get('wan_loss_pct', 0):.0f}% loss")
    if m.get("link_mbps"):
        parts.append(f"link rate {m['link_mbps']:.0f} Mbit/s")
    if m.get("dns_ms") is not None:
        parts.append(f"DNS lookup {net.fmt_ms(m['dns_ms'])}")
    return "; ".join(parts)


def _problem(r: CheckResult) -> list[str]:
    out = [f"- **[{r.status.label}] {r.title}:** {r.summary}"]
    if r.suggestion:
        out.append(f"  - Tool's suggestion: {r.suggestion}")
    ev = _evidence(r.raw)
    if ev:
        out.append("  - Evidence:")
        out.append("    ```text")
        out.extend("    " + line for line in ev.splitlines())
        out.append("    ```")
    return out


def _section(suite_id: str, run: dict) -> list[str]:
    v = run["verdict"]
    target = (run.get("options") or {}).get("target") or ""
    when = datetime.datetime.fromtimestamp(run.get("when", 0))
    out = [f"## {_SECTION[suite_id].format(target=target)}", ""]
    out.append(f"Automatic verdict ({when:%H:%M}): **{_STATE.get(v.state, v.state)}** "
               f"— {v.headline}" + (f" {v.detail}" if v.detail else ""))
    if v.steps:
        out.append("")
        out.append("Chain: " + " → ".join(
            ("· " if s.blocked and s.status is not Status.PASS
             else _MARK[s.status] + " ") + s.label
            for s in v.steps)
            + "  (✓ ok, ! problem, ✗ broken, · not reached)")
    if suite_id == "speed":
        meas = _measurements(run)
        if meas:
            out.append("")
            out.append(f"Measurements: {meas}.")
    problems = [r for r in run["results"]
                if r.status in (Status.FAIL, Status.ERROR, Status.WARN)]
    problems.sort(key=lambda r: r.status.weight, reverse=True)
    out.append("")
    if problems:
        out.append("Problems found:")
        out.append("")
        for r in problems:
            out.extend(_problem(r))
    else:
        out.append("Problems found: none.")
    ok = [r for r in run["results"] if r.status is Status.PASS]
    if ok:
        out.append("")
        out.append("Checked and OK:")
        out.extend(f"- {r.title}: {_short(r.summary)}" for r in ok)
    skipped = [r for r in run["results"] if r.status is Status.SKIP]
    if skipped:
        out.append("")
        out.append("Not checked: " + "; ".join(
            f"{r.title} ({_short(r.summary, 80)})" for r in skipped))
    out.append("")
    return out


def build_ai_context(env: dict[str, Any], runs: dict[str, dict]) -> str:
    """Markdown text to paste into an AI chat (also used for the built-in
    assistant)."""
    order = [s for s in ("connection", "speed", "resource") if runs.get(s)]
    any_problem = any(runs[s]["verdict"].state in ("warn", "fail")
                      for s in order)
    symptoms = []
    for s in order:
        target = (runs[s].get("options") or {}).get("target") or ""
        if runs[s]["verdict"].state in ("warn", "fail") or s == "resource":
            symptoms.append(_SYMPTOM[s].format(target=target))
    if not symptoms:
        symptoms = ["I have network problems, but the automatic checks "
                    "found nothing wrong."]

    out = ["# Internet problem on Ubuntu — please help me fix it", ""]
    out.append("## What I need")
    out.append("")
    out.extend(f"- {s}" for s in symptoms)
    out.append("")
    out.append(
        "Below are the results of an automated diagnosis (nwsolver) run on "
        "my computer. Please:")
    out.append("1. Name the most likely cause and where it is (this "
               "computer, Wi-Fi/cable, router, ISP, DNS, a block on the way, "
               "or the remote server) — based only on these data.")
    out.append("2. Give step-by-step instructions to fix it, with exact "
               "Ubuntu commands or settings paths.")
    out.append("3. Say how to confirm it is fixed, and what to check next "
               "if it does not help.")
    if not any_problem:
        out.append("If the data show no fault, say what else could explain "
                   "the symptom and what to test next.")
    out.append(f"Answer in {answer_language(env)}.")
    out.append("")
    out.append("## Environment")
    out.append("")
    out.append(f"- OS: {env.get('distro')}, kernel {env.get('kernel')}"
               + (f", locale {env['lang']}" if env.get("lang") else ""))
    out.extend(_connection_line(runs))
    out.append(f"- Diagnosis run {'as root' if env.get('is_root') else 'as a normal user'}"
               f" on {datetime.datetime.now():%Y-%m-%d %H:%M}")
    out.append("")
    for s in order:
        out.extend(_section(s, runs[s]))
    return "\n".join(out).rstrip() + "\n"


# Backwards-compatible name used by the UI.
build_report = build_ai_context
