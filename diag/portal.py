"""Captive-portal detection (hotel / café / office / airport Wi-Fi).

Portals often intercept only *some* well-known connectivity-check URLs —
the ones phones and Windows use — and let others time out. So several
probes run in parallel (Ubuntu, GNOME, Android/Chrome, Apple, Microsoft,
Firefox); a probe whose answer differs from the expected one proves that
the network intercepts traffic, and tells us *which* URL triggers the
redirect. That URL (or the login address taken from the redirect / the
intercepted page) is what the UI opens with "Open login page".

NetworkManager's own verdict (``nmcli networking connectivity``) is used as
an extra hint when every probe fails.

Stdlib only, no Qt, never raises.
"""
from __future__ import annotations

import html
import re
import urllib.error
import urllib.parse
import urllib.request
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from nwsolver import __version__
from nwsolver.diag import net
from nwsolver.engine.checks import Ctx

_UA = f"Mozilla/5.0 (X11; Linux x86_64) nwsolver/{__version__} captive-check"

# (name, url, expected status, expected body substring or None)
PROBES = [
    ("Apple", "http://captive.apple.com/hotspot-detect.html", 200,
     "<TITLE>Success</TITLE>"),
    ("Microsoft", "http://www.msftconnecttest.com/connecttest.txt", 200,
     "Microsoft Connect Test"),
    ("Google", "http://connectivitycheck.gstatic.com/generate_204", 204, None),
    ("Ubuntu", "http://connectivity-check.ubuntu.com/", 204, None),
    ("GNOME", "http://nmcheck.gnome.org/check_network_status.txt", 200,
     "NetworkManager is online"),
    ("Firefox", "http://detectportal.firefox.com/success.txt", 200,
     "success"),
]

# Order in which intercepted probes are offered to the browser: Apple and
# Microsoft trigger the redirect on the largest number of portals.
_TRIGGER_ORDER = ("Apple", "Microsoft", "Google", "Firefox", "Ubuntu",
                  "GNOME")


@dataclass
class Probe:
    name: str
    url: str
    outcome: str = "error"     # ok | intercepted | error
    status: int | None = None
    location: str = ""         # login URL found in the answer, if any
    detail: str = ""
    date: str = ""             # server's Date header (for the clock check)
    via_router_dns: bool = False


@dataclass
class PortalResult:
    state: str = "unknown"     # portal | none | unknown
    login_url: str = ""        # best URL to open in the browser
    nm_state: str = ""         # full | limited | portal | none | unknown
    probes: list[Probe] = field(default_factory=list)
    raw: str = ""
    router_dns_needed: bool = False   # probes only worked via router DNS
    under_vpn: str = ""               # VPN interface the probes went through
    gateway_page: str = ""            # router web page (portal candidate)

    @property
    def intercepted(self) -> list[Probe]:
        return [p for p in self.probes if p.outcome == "intercepted"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*?url=([^"'>\s]+)""",
    re.I)
_JS_LOCATION = re.compile(
    r"""(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']""",
    re.I)
_FORM_ACTION = re.compile(r"""<form[^>]+action=["']([^"']+)["']""", re.I)
_ANY_URL = re.compile(r"""https?://[^\s"'<>]+""", re.I)


def _login_from_body(body: str, base: str) -> str:
    for rx in (_META_REFRESH, _JS_LOCATION, _FORM_ACTION):
        m = rx.search(body)
        if m:
            return urllib.parse.urljoin(base, html.unescape(m.group(1)))
    m = _ANY_URL.search(body)
    if m:
        url = html.unescape(m.group(0))
        if urllib.parse.urlsplit(url).hostname != \
                urllib.parse.urlsplit(base).hostname:
            return url
    return ""


def _run_probe(name: str, url: str, want_status: int,
               want_body: str | None, timeout: float,
               connect_ip: str = "") -> Probe:
    p = Probe(name, url)
    headers = {"User-Agent": _UA, "Cache-Control": "no-cache",
               "Pragma": "no-cache"}
    target = url
    if connect_ip:
        u = urllib.parse.urlsplit(url)
        headers["Host"] = u.hostname or ""
        target = urllib.parse.urlunsplit(
            (u.scheme, connect_ip, u.path, u.query, ""))
        p.via_router_dns = True
    req = urllib.request.Request(target, headers=headers)
    # Portals only intercept plain connections: never go through a proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         _NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
        status, headers = resp.status, resp.headers
        body = resp.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, exc.headers
        try:
            body = exc.read(16384).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
    except urllib.error.URLError as exc:
        reason = exc.reason
        p.detail = net.os_reason(reason) if isinstance(
            reason, BaseException) else str(reason)
        return p
    except (OSError, ValueError) as exc:
        p.detail = net.os_reason(exc)
        return p
    p.status = status
    p.date = (headers.get("Date") if headers else "") or ""
    if status == want_status and (want_body is None or
                                  want_body.lower() in body.lower()):
        p.outcome = "ok"
        return p
    p.outcome = "intercepted"
    loc = headers.get("Location") if headers else None
    if loc:
        p.location = urllib.parse.urljoin(url, loc)
        if connect_ip and p.location.startswith(target):
            p.location = url + p.location[len(target):]
        p.detail = f"HTTP {status} → {p.location}"
    else:
        p.location = _login_from_body(body, url)
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        p.detail = f"HTTP {status}, unexpected page" + (
            f" “{_short(title.group(1))}”" if title else "") + (
            f" → {p.location}" if p.location else "")
    return p


def _short(text: str, n: int = 60) -> str:
    text = " ".join(html.unescape(text).split())
    return text if len(text) <= n else text[:n - 1] + "…"


def _nm_connectivity(ctx: Ctx) -> str:
    if not ctx.which("nmcli"):
        return ""
    res = ctx.run(["nmcli", "-t", "networking", "connectivity", "check"],
                  timeout=8.0)
    if not res.ok:
        res = ctx.run(["nmcli", "-t", "networking", "connectivity"],
                      timeout=4.0)
    return res.text.strip().lower() if res.ok else ""


def _gateway_page(ctx: Ctx, timeout: float) -> str:
    """Many portals serve the login page on the router itself."""
    gw = net.local_gateway(ctx)
    if not gw or ":" in gw:
        return ""
    p = _run_probe("Router", f"http://{gw}/", -1, None, timeout)
    if p.status is not None:
        return p.location or f"http://{gw}/"
    return ""


def detect(ctx: Ctx, timeout: float = 4.0) -> PortalResult:
    """Run all probes in parallel. Cached in ``ctx.state`` for the run
    (thread-safe: parallel checks share one detection)."""
    lock = ctx.state.setdefault("_portal_lock", threading.Lock())
    with lock:
        cached = ctx.state.get("_portal")
        if cached is not None:
            return cached
        res = _detect(ctx, timeout)
        ctx.state["_portal"] = res
        return res


def _detect(ctx: Ctx, timeout: float) -> PortalResult:
    res = PortalResult()
    with ThreadPoolExecutor(max_workers=len(PROBES) + 1) as pool:
        nm_future = pool.submit(_nm_connectivity, ctx)
        futures = [pool.submit(_run_probe, n, u, s, b, timeout)
                   for n, u, s, b in PROBES]
        res.probes = [f.result() for f in futures]
        res.nm_state = nm_future.result()

    vpn = net.vpn_uplink(ctx)
    res.under_vpn = vpn.name if vpn is not None else ""
    # Portals often block every DNS server except their own. With DNS set
    # by hand (1.1.1.1, DNS-over-TLS…) all probes then fail on the name
    # lookup: retry them with addresses from the router's DNS.
    gw = net.local_gateway(ctx)
    dns_failed = [i for i, p in enumerate(res.probes)
                  if p.outcome == "error" and p.detail.startswith("DNS")]
    if gw and ":" not in gw and dns_failed:
        def retry(i):
            n, u, st, b = PROBES[i]
            ans = net.dns_query(gw, urllib.parse.urlsplit(u).hostname or "",
                                timeout=2.0)
            ips = [a for a in ans.addresses if ":" not in a]
            if not ips:
                return None
            return _run_probe(n, u, st, b, timeout, connect_ip=ips[0])
        with ThreadPoolExecutor(max_workers=len(dns_failed)) as pool:
            for i, p in zip(dns_failed, pool.map(retry, dns_failed)):
                if p is not None and p.outcome != "error":
                    res.probes[i] = p
                    res.router_dns_needed = True

    ok = [p for p in res.probes if p.outcome == "ok"]
    hit = res.intercepted
    if hit and (len(hit) >= 2 or not ok or res.nm_state == "portal"):
        res.state = "portal"
    elif ok:
        # A single intercepted URL while the others pass is a DNS/ad
        # filter (Pi-hole, AdGuard) blocking that one host — not a portal.
        res.state = "none"
    elif res.nm_state == "portal":
        res.state = "portal"
    else:
        res.state = "unknown"

    if res.state == "portal":
        ranked = sorted(hit, key=lambda p: _TRIGGER_ORDER.index(p.name)
                        if p.name in _TRIGGER_ORDER else 99)
        with_login = [p for p in ranked if p.location]
        if with_login:
            res.login_url = with_login[0].location
        elif ranked:
            res.login_url = ranked[0].url      # opening it shows the portal
        else:
            res.login_url = _gateway_page(ctx, timeout) or \
                "http://captive.apple.com/hotspot-detect.html"
    elif res.state == "unknown" and (res.under_vpn or not ok):
        # Nothing answered: under a VPN the probes went into a dead tunnel.
        # The router's own page may still be the hotel's login page.
        res.gateway_page = _gateway_page(ctx, timeout)

    lines = [f"NetworkManager connectivity: {res.nm_state or 'n/a'}"]
    for p in res.probes:
        lines.append(f"{p.name:<10} {p.outcome:<12} {p.url}"
                     + (" [via router DNS]" if p.via_router_dns else "")
                     + (f"  — {p.detail}" if p.detail else ""))
    if res.under_vpn:
        lines.append(f"probes went through VPN interface {res.under_vpn}")
    if res.gateway_page:
        lines.append(f"router web page: {res.gateway_page}")
    if res.login_url:
        lines.append(f"login page: {res.login_url}")
    res.raw = "\n".join(lines)
    return res


def login_hint(res: PortalResult) -> str:
    extra = ""
    if res.router_dns_needed:
        extra = ("The network only allows its own DNS, and your DNS is set "
                 "by hand (or DNS-over-TLS is on): switch DNS to Automatic "
                 "for this Wi-Fi first, otherwise the login page won't "
                 "open. ")
    if res.under_vpn:
        extra += (f"Turn the VPN ({res.under_vpn}) off while signing in, "
                  "then turn it back on. ")
    return (extra + f"Open {res.login_url} in the browser (button “Open "
            "login page”) and sign in / accept the terms. If no page "
            "appears, "
            "try http://neverssl.com or reconnect to the Wi-Fi. After "
            "signing in, run the check again.")
