"""System clock check that works even when HTTPS is broken.

HTTPS certificate errors after travelling are almost always a wrong clock
(the time was changed by hand instead of the time zone, automatic time is
off, or the hardware clock keeps local time). The real time is taken from
the ``Date`` header of the plain-HTTP connectivity probes (no TLS needed),
compared with the system clock, and combined with ``timedatectl``.

Stdlib only, no Qt, never raises.
"""
from __future__ import annotations

import datetime
import email.utils
import statistics
import threading
import urllib.request
from dataclasses import dataclass, field

from nwsolver.engine.checks import Ctx

_ZONE_TABS = ("/usr/share/zoneinfo/zone1970.tab", "/usr/share/zoneinfo/zone.tab")
_FALLBACK_URLS = ("http://www.google.com/generate_204",
                  "http://captive.apple.com/hotspot-detect.html")


@dataclass
class ClockInfo:
    skew_s: float | None = None        # system − real time (seconds)
    sources: list[str] = field(default_factory=list)
    ntp: bool | None = None            # automatic time enabled
    synced: bool | None = None         # NTP synchronised now
    local_rtc: bool | None = None      # hardware clock in local time
    timezone: str = ""
    raw: str = ""

    @property
    def wrong(self) -> bool:
        return self.skew_s is not None and abs(self.skew_s) > 300


def _timedatectl(ctx: Ctx, info: ClockInfo) -> str:
    if not ctx.which("timedatectl"):
        return "timedatectl not available"
    res = ctx.run(["timedatectl", "show"], timeout=5.0)
    vals = {}
    for line in res.text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k] = v
    yes = {"yes": True, "no": False}
    info.ntp = yes.get(vals.get("NTP", ""))
    info.synced = yes.get(vals.get("NTPSynchronized", ""))
    info.local_rtc = yes.get(vals.get("LocalRTC", ""))
    info.timezone = vals.get("Timezone", "")
    return "$ timedatectl show\n" + res.text


def _date_of(url: str, timeout: float = 3.0) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, method="HEAD"),
                         timeout=timeout) as resp:
            return resp.headers.get("Date", "")
    except Exception as exc:  # noqa: BLE001 — HTTPError still has headers
        hdrs = getattr(exc, "headers", None)
        return hdrs.get("Date", "") if hdrs else ""


def measure(ctx: Ctx) -> ClockInfo:
    lock = ctx.state.setdefault("_clock_lock", threading.Lock())
    with lock:
        cached = ctx.state.get("_clock")
        if cached is None:
            cached = _measure(ctx)
            ctx.state["_clock"] = cached
        return cached


def _measure(ctx: Ctx) -> ClockInfo:
    from nwsolver.diag import portal
    info = ClockInfo()
    lines = [_timedatectl(ctx, info)]
    dates = [(p.name, p.date) for p in portal.detect(ctx).probes if p.date]
    if not dates:
        dates = [(u, _date_of(u)) for u in _FALLBACK_URLS]
        dates = [(n, d) for n, d in dates if d]
    now = datetime.datetime.now(datetime.timezone.utc)
    skews = []
    for name, d in dates:
        try:
            server = email.utils.parsedate_to_datetime(d)
        except (TypeError, ValueError):
            continue
        if server.tzinfo is None:
            server = server.replace(tzinfo=datetime.timezone.utc)
        skew = (now - server).total_seconds()
        skews.append(skew)
        info.sources.append(name)
        lines.append(f"{name}: server time {d} → skew {skew:+.0f} s")
    if skews:
        info.skew_s = statistics.median(skews)
    lines.append(f"system time (UTC): {now:%Y-%m-%d %H:%M:%S}")
    info.raw = "\n".join(lines)
    return info


def fmt_skew(seconds: float) -> str:
    s = abs(int(round(seconds)))
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days} d")
    if hours:
        parts.append(f"{hours} h")
    if mins or not parts:
        parts.append(f"{mins} min")
    return " ".join(parts) + (" ahead" if seconds > 0 else " behind")


def fix_steps(info: ClockInfo) -> str:
    steps = []
    if info.local_rtc:
        steps.append("store the hardware clock in UTC: `sudo timedatectl "
                     "set-local-rtc 0`")
    if info.ntp is False:
        steps.append("turn on automatic time: `sudo timedatectl set-ntp "
                     "true` (or Settings → Date & Time → Automatic Date & "
                     "Time)")
    else:
        steps.append("make sure Settings → Date & Time → Automatic Date & "
                     "Time is on; if NTP can't sync on this network, set "
                     "the correct time once by hand")
    steps.append("set the time zone of where you are instead of moving "
                 "the clock: Settings → Date & Time → Time Zone, or `sudo "
                 "timedatectl set-timezone <Region/City>`")
    return "Fix: " + "; ".join(steps) + "."


def tz_country(tz: str) -> str:
    """ISO country code of a tz database zone ('' if unknown)."""
    if not tz:
        return ""
    for path in _ZONE_TABS:
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 3 and parts[2].strip() == tz:
                        return parts[0].split(",")[0].strip().upper()
        except OSError:
            continue
    return ""
