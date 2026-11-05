"""Diagnostic Context — one structured object built from the runs, used for
the JSON export, the Markdown technical report, the history and the
comparison with earlier checks. (The AI prompt in ``report.py`` is the
third view of the same data.)

Unified result format per check: Status, Symptom, Evidence, Diagnosis
(the verdict), Recommendation. Statuses: OK, WARNING, ERROR, UNKNOWN,
NOT TESTED.

Also contains :class:`Masker`, which hides IP/MAC addresses, Wi-Fi names
and host/user names on request, and always removes secrets.

Pure Python — no Qt.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from nwsolver import __version__
from nwsolver.engine.checks import CheckResult, Status

SCHEMA = "nwsolver.diagnostic-context/1"

STATUS_NAMES = {Status.PASS: "OK", Status.WARN: "WARNING",
                Status.FAIL: "ERROR", Status.ERROR: "UNKNOWN",
                Status.SKIP: "NOT TESTED"}
_STATUS_BACK = {v: k for k, v in STATUS_NAMES.items()}
SUITE_TITLES = {"connection": "No connection", "speed": "Slow internet",
                "resource": "Site doesn't open"}


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(
        timespec="seconds")


def _clean(value: Any) -> Any:
    """Make metrics JSON-safe."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return str(value)


def check_to_dict(r: CheckResult) -> dict:
    return {
        "id": r.check_id,
        "title": r.title,
        "status": STATUS_NAMES[r.status],
        "symptom": r.summary,
        "evidence": r.raw,
        "recommendation": r.suggestion if r.status is not Status.PASS
        else "",
        "duration_ms": r.duration_ms,
        "metrics": _clean(r.metrics),
    }


def run_to_dict(run: dict) -> dict:
    """Serialisable form of one finished run (as emitted by the worker)."""
    v = run["verdict"]
    return {
        "suite": run["suite"],
        "title": SUITE_TITLES.get(run["suite"], run["suite"]),
        "started_at": _iso(run.get("when", 0) - run.get("elapsed", 0)),
        "finished_at": _iso(run.get("when", 0)),
        "timestamp": run.get("when", 0),
        "elapsed_s": round(run.get("elapsed", 0), 1),
        "target": (run.get("options") or {}).get("target") or None,
        "network": _clean(run.get("overview") or {}),
        "diagnosis": {
            "state": v.state,
            "confidence": getattr(v, "confidence", ""),
            "headline": v.headline,
            "explanation": v.detail,
            "root_cause_check": v.culprit,
            "recommendations": list(v.actions),
            "notes": list(getattr(v, "notes", [])),
            "link": list(v.link) if getattr(v, "link", None) else None,
            "chain": [{"id": s.step_id, "label": s.label,
                       "status": STATUS_NAMES[s.status],
                       "reached": not s.blocked} for s in v.steps],
        },
        "checks": [check_to_dict(r) for r in run["results"]],
    }


def check_from_dict(d: dict) -> CheckResult:
    return CheckResult(d["id"], d["title"],
                       _STATUS_BACK.get(d["status"], Status.SKIP),
                       d.get("symptom", ""), raw=d.get("evidence", ""),
                       suggestion=d.get("recommendation", ""),
                       duration_ms=d.get("duration_ms", 0),
                       metrics=d.get("metrics") or {})


# --------------------------------------------------------------------------
# Comparison with an earlier run
# --------------------------------------------------------------------------

def diff_runs(prev: dict, cur: dict) -> list[str]:
    """Human-readable changes between two serialised runs of one suite."""
    out = []
    pv, cv = prev["diagnosis"], cur["diagnosis"]
    if pv["state"] != cv["state"]:
        out.append(f"overall: {pv['state'].upper()} → {cv['state'].upper()}")
    before = {c["id"]: c for c in prev["checks"]}
    for c in cur["checks"]:
        p = before.get(c["id"])
        if p is None or p["status"] == c["status"]:
            continue
        out.append(f"{c['title']}: {p['status']} → {c['status']}")
    return out


def changes_text(prev: dict, cur: dict) -> str:
    changes = diff_runs(prev, cur)
    when = datetime.datetime.fromtimestamp(prev["timestamp"])
    day = "" if when.date() == datetime.date.today() else f"{when:%d %b} "
    if not changes:
        return f"No change since the last check ({day}{when:%H:%M})."
    better = sum(1 for c in changes if c.endswith("→ OK"))
    trend = ("better" if better and better >= len(changes) / 2 else
             "different")
    return (f"Since the last check ({day}{when:%H:%M}) things are {trend}: "
            + "; ".join(changes) + ".")


# --------------------------------------------------------------------------
# The context object
# --------------------------------------------------------------------------

def build_context(env: dict, runs: dict[str, dict],
                  history: list[dict] | None = None) -> dict:
    """``runs``: suite id → worker run dict; ``history``: serialised runs
    (newest first) to include as the timeline."""
    current = [run_to_dict(runs[s]) for s in ("connection", "speed",
                                              "resource") if runs.get(s)]
    network: dict = {}
    for r in current:
        for k, v in (r.get("network") or {}).items():
            if v not in (None, "") and k != "root":
                network.setdefault(k, v)
    current_ts = {r["timestamp"] for r in current}
    timeline = []
    for h in (history or []):
        if h.get("timestamp") in current_ts:
            continue
        timeline.append({
            "time": h.get("finished_at"), "suite": h.get("suite"),
            "target": h.get("target"),
            "state": h["diagnosis"]["state"],
            "headline": h["diagnosis"]["headline"],
            "recommendations": h["diagnosis"].get("recommendations", []),
        })
    comparisons = []
    for r in current:
        prev = next((h for h in (history or [])
                     if h.get("suite") == r["suite"]
                     and h.get("target") == r.get("target")
                     and h.get("timestamp", 0) < r["timestamp"]), None)
        if prev is not None:
            comparisons.append({"suite": r["suite"],
                                "previous_check": prev.get("finished_at"),
                                "changes": diff_runs(prev, r)})
    return {
        "schema": SCHEMA,
        "generated_at": _iso(datetime.datetime.now().timestamp()),
        "app": {"name": "nwsolver", "version": __version__},
        "environment": {
            "os": env.get("distro"), "kernel": env.get("kernel"),
            "locale": env.get("lang"), "hostname": env.get("hostname"),
            "user": env.get("user"), "privileged": bool(env.get("is_root")),
        },
        "network": network,
        "runs": current,
        "repeated_checks": comparisons,
        "timeline": timeline[:20],
    }


def render_json(context: dict) -> str:
    return json.dumps(context, indent=2, ensure_ascii=False) + "\n"


def _cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(context: dict) -> str:
    """Full technical report (every step, evidence, timeline)."""
    env = context["environment"]
    out = ["# nwsolver diagnostic report", "",
           f"_Generated {context['generated_at']} · nwsolver "
           f"{context['app']['version']}_", "",
           "## Environment", "",
           f"- OS: {env.get('os')}, kernel {env.get('kernel')}, locale "
           f"{env.get('locale') or '—'}",
           f"- Host: {env.get('hostname')}, user {env.get('user')}, "
           f"{'root' if env.get('privileged') else 'unprivileged'}"]
    net_items = context.get("network") or {}
    if net_items:
        out.append("- Network: " + ", ".join(f"{k} = {v}" for k, v in
                                             net_items.items()))
    out.append("")
    for r in context["runs"]:
        d = r["diagnosis"]
        title = r["title"] + (f" — {r['target']}" if r.get("target") else "")
        out += [f"## {title}", "",
                f"_{r['started_at']} → {r['finished_at']} "
                f"({r['elapsed_s']} s)_", "",
                f"**Diagnosis: {d['state'].upper()}"
                + (f" ({d['confidence']})" if d.get("confidence") else "")
                + f" — {d['headline']}**", ""]
        if d.get("explanation"):
            out += [d["explanation"], ""]
        for a in d.get("recommendations", []):
            out.append(f"- Recommendation: {a}")
        for n in d.get("notes", []):
            out.append(f"- Note: {n}")
        if d.get("chain"):
            out += ["", "Chain: " + " → ".join(
                f"{c['label']} [{c['status'] if c['reached'] else 'not reached'}]"
                for c in d["chain"])]
        out += ["", "| Status | Check | Symptom | Recommendation |",
                "|---|---|---|---|"]
        for c in r["checks"]:
            out.append(f"| {c['status']} | {_cell(c['title'])} | "
                       f"{_cell(c['symptom'])} | "
                       f"{_cell(c['recommendation']) or '—'} |")
        out.append("")
        for c in r["checks"]:
            if c.get("evidence"):
                out += [f"<details><summary>Evidence: {c['title']} "
                        f"({c['status']}, {c['duration_ms']} ms)</summary>",
                        "", "```text", c["evidence"][:6000], "```",
                        "</details>", ""]
    if context.get("repeated_checks"):
        out += ["## Repeated checks", ""]
        for cmp in context["repeated_checks"]:
            ch = "; ".join(cmp["changes"]) or "no change"
            out.append(f"- {SUITE_TITLES.get(cmp['suite'], cmp['suite'])}: "
                       f"vs {cmp['previous_check']}: {ch}")
        out.append("")
    if context.get("timeline"):
        out += ["## Earlier checks", ""]
        for t in context["timeline"]:
            out.append(f"- {t['time']} · {SUITE_TITLES.get(t['suite'], t['suite'])}"
                       + (f" ({t['target']})" if t.get("target") else "")
                       + f": {t['state'].upper()} — {t['headline']}")
        out.append("")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

@dataclass
class MaskOptions:
    local_ip: bool = False
    public_ip: bool = True
    mac: bool = True
    ssid: bool = True
    host: bool = True


# Well-known public services: not identifying, keep them readable.
_KEEP_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
             "149.112.112.112", "127.0.0.53", "127.0.0.54", "127.0.0.1",
             "0.0.0.0", "2606:4700:4700::1111", "2001:4860:4860::8888"}
_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{0,4}:){2,7}"
                      r"[0-9a-fA-F]{0,4}(?![0-9A-Za-z:])")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pass|psk|secret|token|api[_-]?key|"
    r"private[_-]?key|preshared[_-]?key|cookie)\b(\s*[=:]\s*)(\S+)")
_BEARER_RE = re.compile(r"(?i)(authorization:\s*\w+\s+)\S+")
_URL_CRED_RE = re.compile(r"://([^:@/\s]+):([^@/\s]+)@")


class Masker:
    """Replaces identifiers with stable placeholders (<LAN-IP-1> …)."""

    def __init__(self, options: MaskOptions, ssids: list[str] = (),
                 host: str = "", user: str = ""):
        self.o = options
        self.ssids = sorted({s for s in ssids if s and len(s) > 1},
                            key=len, reverse=True)
        self.host, self.user = host, user
        self._maps: dict[str, dict[str, str]] = {}

    def _token(self, kind: str, value: str) -> str:
        m = self._maps.setdefault(kind, {})
        if value not in m:
            m[value] = f"<{kind}-{len(m) + 1}>"
        return m[value]

    @staticmethod
    def scrub_secrets(text: str) -> str:
        text = _SECRET_RE.sub(lambda m: m.group(1) + m.group(2) +
                              "<removed>", text)
        text = _BEARER_RE.sub(lambda m: m.group(1) + "<removed>", text)
        return _URL_CRED_RE.sub(r"://\1:<removed>@", text)

    def _ip(self, raw: str, version: int) -> str:
        if raw in _KEEP_IPS:
            return raw
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        if ip.version != version:
            return raw
        local = ip.is_private or ip.is_link_local or ip.is_loopback
        if local and self.o.local_ip:
            return self._token("LAN-IP", raw)
        if not local and self.o.public_ip and not ip.is_reserved \
                and not ip.is_multicast:
            return self._token("PUBLIC-IP", raw)
        return raw

    def text(self, text: str) -> str:
        if not text:
            return text
        text = self.scrub_secrets(text)
        if self.o.mac:
            text = _MAC_RE.sub(lambda m: self._token("MAC", m.group(0)
                                                     .lower()), text)
        if self.o.ssid:
            for s in self.ssids:
                text = re.sub(rf"(?<!\w){re.escape(s)}(?!\w)",
                              self._token("WIFI-NAME", s), text)
        if self.o.host:
            for value, kind in ((self.host, "HOST"), (self.user, "USER")):
                if value and len(value) > 2:
                    text = re.sub(rf"(?<![\w-]){re.escape(value)}(?![\w-])",
                                  f"<{kind}>", text)
        if self.o.local_ip or self.o.public_ip:
            text = _IPV4_RE.sub(lambda m: self._ip(m.group(0), 4), text)
            text = _IPV6_RE.sub(lambda m: self._ip(m.group(0), 6), text)
        return text

    def data(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.data(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.data(v) for v in value]
        return value


def ssids_of(context: dict) -> list[str]:
    """Wi-Fi names that appear in the context (own network, hotspot)."""
    out = []
    for r in context.get("runs", []) + [{"network": context.get("network")}]:
        n = r.get("network") or {}
        if "Wi-Fi" in str(n.get("type") or "") and n.get("network"):
            out.append(str(n["network"]))
    return out
