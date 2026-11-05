"""Suite 3 — "Why doesn't this website / service open?"

Takes one target (URL, host name, host:port or IP) and follows it step by
step: is the internet up at all → /etc/hosts override → DNS through the
system and through public resolvers (spots DNS blocking) → TCP connect to
every address (IPv4 and IPv6) → TLS handshake and certificate → HTTP
answer → where the route stops. The verdict says whether the problem is
on this computer, in DNS, a block on the way, or the server itself.

Checks run sequentially and pass their findings on via ``ctx.state``.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from nwsolver.diag import net
from nwsolver.diag.verdict import Verdict
from nwsolver.engine.checks import Check, CheckResult, Ctx, Status

SUITE_ID = "resource"
SUITE_NAME = "Website"
SUITE_DESC = "Checks why a specific website or service does not open."
PARALLEL = False

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
       "Gecko) Chrome/126.0 Safari/537.36 nwsolver/0.2")


def _r(cid, title, status, summary, fix="", raw="", **metrics):
    return CheckResult(cid, title, status, summary, raw=net.trunc(raw),
                       suggestion=fix, metrics=metrics)


# --------------------------------------------------------------------------
# Target parsing
# --------------------------------------------------------------------------

class Target:
    def __init__(self, text: str):
        self.text = text.strip()
        self.error = ""
        self.scheme = "https"
        self.host = ""
        self.port = 443
        self.path = "/"
        self.is_ip = False
        self.web = True
        t = self.text
        if not t:
            self.error = "Enter a website address, e.g. example.com"
            return
        if "://" not in t:
            # host:port (but not a bare IPv6 address)
            if t.count(":") == 1 and not t.startswith("["):
                host, _, port = t.partition(":")
                if port.isdigit():
                    p = int(port)
                    scheme = {80: "http", 443: "https"}.get(p, "tcp")
                    t = f"{scheme}://{host}:{p}"
                else:
                    t = "https://" + t
            else:
                t = "https://" + t
        try:
            u = urllib.parse.urlsplit(t)
            self.scheme = (u.scheme or "https").lower()
            self.host = (u.hostname or "").rstrip(".")
            self.port = u.port or {"http": 80, "https": 443}.get(
                self.scheme, 443)
        except ValueError as exc:
            self.error = f"Not a valid address: {exc}"
            return
        self.path = (u.path or "/") + (("?" + u.query) if u.query else "")
        if not self.host:
            self.error = "Not a valid address"
            return
        try:
            ipaddress.ip_address(self.host)
            self.is_ip = True
        except ValueError:
            try:
                self.host.encode("idna")
            except UnicodeError:
                self.error = "Not a valid host name"
                return
        self.web = self.scheme in ("http", "https")

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = {"http": 80, "https": 443}.get(self.scheme)
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{host}{port}{self.path}"

    @property
    def display(self) -> str:
        return self.url if self.web else f"{self.host}:{self.port}"


def _target(ctx: Ctx) -> Target:
    t = ctx.state.get("target")
    if t is None:
        t = Target(str(ctx.options.get("target", "")))
        ctx.state["target"] = t
    return t


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------

def check_baseline(ctx: Ctx) -> CheckResult:
    cid, title = "res.baseline", "Your internet connection"
    t = _target(ctx)
    if t.error:
        ctx.state["abort"] = True
        return _r(cid, title, Status.ERROR, t.error,
                  "Type an address like example.com, https://site.org/page "
                  "or host:port.")
    lines, ok = [], 0
    for ip, name in net.INTERNET_ANCHORS[:2]:
        rtt, why = net.tcp_connect(ip, 443, timeout=3.0)
        lines.append(f"{name} {ip}:443 — " + (net.fmt_ms(rtt) if rtt
                                                is not None else why))
        ok += rtt is not None
    _addrs, _ms, err = net.system_resolve("example.com")
    lines.append("DNS example.com — " + ("OK" if not err else err))
    ctx.state["internet_ok"] = ok > 0
    ctx.state["dns_ok"] = not err
    if ok == 0:
        return _r(cid, title, Status.FAIL,
                  "The internet does not work at all on this computer, so "
                  "no site can open.",
                  "Run the Connection tab to find the cause.",
                  "\n".join(lines))
    if err:
        return _r(cid, title, Status.WARN,
                  "The internet is up but DNS is broken for every site.",
                  "See the DNS step on the Connection tab.", "\n".join(lines))
    return _r(cid, title, Status.PASS,
              "The internet works in general — other sites are reachable.",
              raw="\n".join(lines))


def check_hosts(ctx: Ctx) -> CheckResult:
    cid, title = "res.hosts", "Local override (/etc/hosts)"
    t = _target(ctx)
    if t.is_ip:
        return _r(cid, title, Status.SKIP, "Target is an IP address.")
    entries = []
    for line in ctx.readlines("/etc/hosts"):
        content = line.split("#", 1)[0].split()
        if len(content) >= 2 and t.host.lower() in (
                n.lower() for n in content[1:]):
            entries.append(" ".join(content))
    if entries:
        ip = entries[0].split()[0]
        ctx.state["hosts_ip"] = ip
        blocked = net.is_bogus_answer(ip)
        return _r(cid, title, Status.FAIL if blocked else Status.WARN,
                  f"/etc/hosts forces {t.host} to {ip}"
                  + (" — this blocks the site." if blocked else
                     " — DNS is bypassed for this name."),
                  f"Remove the line for {t.host} from /etc/hosts "
                  "(`sudo nano /etc/hosts`) unless you added it on purpose.",
                  "\n".join(entries))
    return _r(cid, title, Status.PASS, "No local override for this name.")


def check_dns(ctx: Ctx) -> CheckResult:
    cid, title = "res.dns", "Address lookup (DNS)"
    t = _target(ctx)
    if t.is_ip:
        ctx.state["addrs"] = [t.host]
        return _r(cid, title, Status.SKIP, "Target is an IP address — no DNS "
                  "needed.")
    sys_addrs, ms, err = net.system_resolve(t.host, t.port)
    pub_answers = []
    for srv in net.PUBLIC_DNS:
        a4 = net.dns_query(srv, t.host, 1, timeout=2.5)
        pub_answers.append(a4)
        if a4.ok:
            break
    pub = next((a for a in pub_answers if a.ok), None)
    pub_addrs = list(pub.addresses) if pub else []
    if pub and pub.rcode == 0:
        a6 = net.dns_query(pub.server, t.host, 28, timeout=2.5)
        pub_addrs += a6.addresses
    lines = [f"System resolver: {', '.join(sys_addrs) or err} "
             f"({net.fmt_ms(ms)})"]
    for a in pub_answers:
        lines.append(f"Public DNS {a.server}: " + (
            f"{a.rcode_name} {', '.join(a.addresses) or '(no A record)'}"
            if a.ok else a.error))
    raw = "\n".join(lines)
    ctx.state["pub_addrs"] = pub_addrs
    bogus = [a for a in sys_addrs if net.is_bogus_answer(a)]
    pub_real = [a for a in pub_addrs if not net.is_bogus_answer(a)]
    m = {"dns_ms": ms}
    if sys_addrs and not bogus:
        ctx.state["addrs"] = sys_addrs
        note = ""
        if pub_real and not set(sys_addrs) & set(pub_addrs) and \
                all(net.is_private(a) for a in sys_addrs) and \
                not all(net.is_private(a) for a in pub_real):
            ctx.state["dns_hijack"] = True
            return _r(cid, title, Status.WARN,
                      f"{t.host} → {', '.join(sys_addrs[:3])}, but public "
                      f"DNS says {', '.join(pub_real[:3])}. Your DNS sends "
                      "you to a local address — possibly a block page.",
                      "If the site shows a block/warning page, your "
                      "router, ISP or a filter (Pi-hole, AdGuard, parental "
                      "control) redirects it. Try DNS 1.1.1.1.", raw, **m)
        return _r(cid, title, Status.PASS,
                  f"{t.host} → {', '.join(sys_addrs[:4])}"
                  f"{' …' if len(sys_addrs) > 4 else ''} "
                  f"({net.fmt_ms(ms)}).{note}", raw=raw, **m)
    if bogus:
        ctx.state["addrs"] = pub_real
        ctx.state["dns_block"] = True
        return _r(cid, title, Status.FAIL,
                  f"Your DNS answers {bogus[0]} for {t.host} — the name is "
                  "blocked by a DNS filter"
                  + (f" (the real address is {pub_real[0]})." if pub_real
                     else "."),
                  "The block is in your DNS (router parental control, ISP "
                  "filter, Pi-hole/AdGuard). Use a different DNS server "
                  "such as 1.1.1.1, or whitelist the site in the filter.",
                  raw, **m)
    # System resolver failed.
    if pub and pub.rcode == 3:
        ctx.state["nxdomain"] = True
        return _r(cid, title, Status.FAIL,
                  f"The name {t.host} does not exist (NXDOMAIN) — public "
                  "DNS agrees.",
                  "Check the spelling. If it worked before, the domain "
                  "may have expired or been removed.", raw, **m)
    if pub_real:
        ctx.state["addrs"] = pub_real
        ctx.state["dns_block"] = True
        return _r(cid, title, Status.FAIL,
                  f"Your DNS cannot resolve {t.host} ({err}), but public DNS "
                  f"returns {', '.join(pub_real[:3])}.",
                  "Your DNS server fails or filters this name. Switch DNS "
                  "to 1.1.1.1 / 8.8.8.8 (Settings → Network → IPv4 → DNS).",
                  raw, **m)
    if pub and pub.rcode == 0 and not pub_addrs:
        return _r(cid, title, Status.FAIL,
                  f"{t.host} exists but has no IP address records.",
                  "The site's DNS is misconfigured — nothing to do on your "
                  "side; contact the site owner.", raw, **m)
    return _r(cid, title, Status.FAIL,
              f"Could not look up {t.host}: {err}.",
              "No DNS server answered. Check the DNS step on the Connection "
              "tab.", raw, **m)


def check_tcp(ctx: Ctx) -> CheckResult:
    cid, title = "res.tcp", "Connection to the server"
    t = _target(ctx)
    addrs = ctx.state.get("addrs") or []
    if not addrs:
        return _r(cid, title, Status.SKIP,
                  "No address to connect to (DNS step failed).")
    v4 = [a for a in addrs if ":" not in a][:2]
    v6 = [a for a in addrs if ":" in a][:2]
    lines, ok4, ok6, reasons = [], [], [], []
    for a in v4 + v6:
        rtt, why = net.tcp_connect(a, t.port, timeout=4.0)
        label = f"[{a}]:{t.port}" if ":" in a else f"{a}:{t.port}"
        if rtt is not None and not why:
            (ok6 if ":" in a else ok4).append(a)
            lines.append(f"{label} — connected in {net.fmt_ms(rtt)}")
        else:
            reasons.append(why or "refused")
            lines.append(f"{label} — {why or 'refused'}")
    raw = "\n".join(lines)
    ctx.state["tcp_ok"] = ok4 + ok6
    ctx.state["tcp_reasons"] = reasons
    if ok4 or ok6:
        if v6 and not ok6 and ok4:
            return _r(cid, title, Status.WARN,
                      f"Port {t.port} is open over IPv4, but IPv6 fails. "
                      "Apps that try IPv6 first may hang.",
                      "If the site loads slowly, IPv6 on your network is "
                      "broken — disable IPv6 in the connection settings or "
                      "ask the ISP.", raw)
        return _r(cid, title, Status.PASS,
                  f"Connected to port {t.port}.", raw=raw)
    if all(r in ("refused", "connection refused") for r in reasons):
        return _r(cid, title, Status.FAIL,
                  f"The server is reachable but refuses connections on port "
                  f"{t.port} — the service is not running there.",
                  "Check the port number; otherwise the service is down — "
                  "contact the site owner.", raw)
    if any("unreachable" in r.lower() for r in reasons):
        return _r(cid, title, Status.FAIL,
                  "There is no route to this server's address.",
                  "If only IPv6 addresses exist and your network has no "
                  "IPv6, the site can't be reached from here.", raw)
    return _r(cid, title, Status.FAIL,
              f"Connections to port {t.port} time out — packets are "
              "dropped on the way.",
              "Either the server is down, or a firewall (yours, the "
              "network's, or the ISP's) blocks it. Try from another "
              "network (e.g. phone hotspot) or via VPN to tell which.", raw)


def check_tls(ctx: Ctx) -> CheckResult:
    cid, title = "res.tls", "Secure connection (TLS)"
    t = _target(ctx)
    if t.scheme != "https":
        return _r(cid, title, Status.SKIP, "Not an HTTPS address.")
    ok_addrs = ctx.state.get("tcp_ok") or []
    if not ok_addrs:
        return _r(cid, title, Status.SKIP, "No TCP connection — skipped.")
    addr = ok_addrs[0]
    sni = None if t.is_ip else t.host
    ctxs = ssl.create_default_context()
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    start = time.monotonic()
    raw = f"TLS handshake with {addr}:{t.port} (SNI {sni})"
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(6.0)
            s.connect((addr, t.port))
            with ctxs.wrap_socket(s, server_hostname=sni or addr) as tls:
                ms = (time.monotonic() - start) * 1000
                cert = tls.getpeercert() or {}
                version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        msg = exc.verify_message or str(exc)
        low = msg.lower()
        if "expired" in low or "not yet valid" in low:
            fix = ("If other HTTPS sites work, the site's certificate has "
                   "expired (owner's problem). If many sites show this, "
                   "fix your system clock: `sudo timedatectl set-ntp true`.")
        elif "self-signed" in low or "unable to get local issuer" in low:
            fix = ("Something between you and the site replaces "
                   "certificates — antivirus, corporate proxy or a block "
                   "page. Check those; on a work network ask IT.")
        elif "hostname" in low or "ip address mismatch" in low:
            fix = ("The certificate is for a different name — usually a "
                   "block page or a misconfigured server.")
        else:
            fix = "The certificate is not trusted."
        ctx.state["tls_error"] = msg
        return _r(cid, title, Status.FAIL, f"Certificate problem: {msg}.",
                  fix, raw + "\n" + str(exc))
    except (ConnectionResetError, ssl.SSLError, socket.timeout,
            TimeoutError, OSError) as exc:
        why = net.os_reason(exc) if not isinstance(exc, ssl.SSLError) \
            else (exc.reason or str(exc))
        ctx.state["tls_error"] = why
        return _r(cid, title, Status.FAIL,
                  f"The connection is cut during the TLS handshake ({why}).",
                  "TCP works but the secure handshake is reset — the typical "
                  "sign of the site being blocked by the network or ISP "
                  "(SNI filtering). Check from another network or via VPN.",
                  raw + "\n" + repr(exc))
    not_after = cert.get("notAfter")
    days = None
    if not_after:
        try:
            days = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
        except ValueError:
            pass
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    org = issuer.get("organizationName") or issuer.get("commonName") or "?"
    raw += (f"\nversion {version}, {ms:.0f} ms\nissuer: {issuer}\n"
            f"valid until: {not_after}")
    summary = f"{version}, certificate by {org}"
    if days is not None:
        summary += f", valid for {days:.0f} more days"
    summary += "."
    if days is not None and days < 7:
        return _r(cid, title, Status.WARN, summary + " It expires soon.",
                  "Nothing to do on your side.", raw)
    return _r(cid, title, Status.PASS, summary, raw=raw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_http(ctx: Ctx) -> CheckResult:
    cid, title = "res.http", "Server response (HTTP)"
    t = _target(ctx)
    if not t.web:
        return _r(cid, title, Status.SKIP,
                  f"Port {t.port} is not a web port — HTTP not tested.")
    if ctx.state.get("nxdomain") or (not ctx.state.get("tcp_ok")
                                     and not net.proxy_env()):
        return _r(cid, title, Status.SKIP, "No connection — skipped.")
    if t.scheme == "https" and ctx.state.get("tls_error"):
        return _r(cid, title, Status.SKIP, "TLS failed — skipped.")
    url = t.url
    hops = []
    code, ms, err, server = None, None, "", ""
    ctx_ssl = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ctx_ssl))
    for _ in range(6):
        req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                                   "Accept": "*/*"})
        start = time.monotonic()
        try:
            resp = opener.open(req, timeout=10.0)
            code = resp.status
            server = resp.headers.get("Server", "")
            resp.read(1024)
            ms = (time.monotonic() - start) * 1000
            hops.append(f"{code} {url} ({ms:.0f} ms)")
            break
        except urllib.error.HTTPError as exc:
            code = exc.code
            ms = (time.monotonic() - start) * 1000
            server = exc.headers.get("Server", "") if exc.headers else ""
            loc = exc.headers.get("Location") if exc.headers else None
            hops.append(f"{code} {url} ({ms:.0f} ms)"
                        + (f" → {loc}" if loc else ""))
            if code in (301, 302, 303, 307, 308) and loc:
                url = urllib.parse.urljoin(url, loc)
                continue
            break
        except urllib.error.URLError as exc:
            err = net.os_reason(exc.reason) if isinstance(
                exc.reason, BaseException) else str(exc.reason)
            hops.append(f"{url}: {err}")
            break
        except (OSError, ValueError) as exc:
            err = net.os_reason(exc)
            hops.append(f"{url}: {err}")
            break
    raw = "\n".join(hops) + (f"\nServer: {server}" if server else "")
    m = {"http_code": code, "ttfb_ms": ms}
    if code is None:
        return _r(cid, title, Status.FAIL,
                  f"No HTTP answer ({err}).",
                  "The server accepted the connection but did not answer "
                  "— it is overloaded or broken. Try again later.", raw, **m)
    srv = f" (server: {server})" if server else ""
    if 200 <= code < 400:
        slow = ms is not None and ms > 3000
        s = Status.WARN if slow else Status.PASS
        return _r(cid, title, s,
                  f"The site answers: HTTP {code} in {net.fmt_ms(ms)}"
                  + (" — very slowly." if slow else ".")
                  + (f" Redirect chain: {len(hops) - 1}." if len(hops) > 1
                     else ""),
                  "The server itself is slow — not your connection."
                  if slow else "", raw, **m)
    if code in (401, 403):
        cf = "cloudflare" in server.lower()
        return _r(cid, title, Status.WARN,
                  f"The server refuses access: HTTP {code}{srv}.",
                  ("The site's protection (e.g. Cloudflare) blocks automated "
                   "requests or your IP/country — open it in a browser; if "
                   "it is blocked there too, your IP is banned or the site "
                   "is region-restricted (try VPN).") if cf else
                  "Access is denied by the site (login, IP or region "
                  "restriction).", raw, **m)
    if code == 451:
        return _r(cid, title, Status.FAIL,
                  "HTTP 451 — unavailable for legal reasons in your "
                  "region.", "The site is blocked by law/region.", raw, **m)
    if code == 429:
        return _r(cid, title, Status.WARN, "HTTP 429 — too many requests "
                  "from your IP.", "Wait a while and retry.", raw, **m)
    if code >= 500:
        return _r(cid, title, Status.FAIL,
                  f"The server has an internal error: HTTP {code}{srv}.",
                  "The problem is on the site's side — nothing to fix on "
                  "your computer. Try later.", raw, **m)
    if code == 404:
        return _r(cid, title, Status.WARN,
                  "HTTP 404 — the server works but this page does not "
                  "exist.", "Check the link / path.", raw, **m)
    return _r(cid, title, Status.WARN, f"HTTP {code}{srv}.", raw=raw, **m)


def check_trace(ctx: Ctx) -> CheckResult:
    cid, title = "res.trace", "Where the route stops"
    addrs = ctx.state.get("addrs") or []
    if ctx.state.get("tcp_ok") or not addrs:
        return _r(cid, title, Status.SKIP,
                  "Not needed — the server is reachable."
                  if ctx.state.get("tcp_ok") else "No address to trace.")
    target = next((a for a in addrs if ":" not in a), addrs[0])
    tool = "tracepath" if ctx.which("tracepath") else (
        "traceroute" if ctx.which("traceroute") else None)
    if tool is None:
        return _r(cid, title, Status.SKIP,
                  "Install traceroute to see where packets stop "
                  "(`sudo apt install traceroute`).")
    argv = ([tool, "-n", "-m", "20", target] if tool == "tracepath" else
            [tool, "-n", "-m", "20", "-q", "1", "-w", "1", target])
    res = ctx.run(argv, timeout=40.0)
    hops: list[tuple[int, str]] = []
    for line in res.text.splitlines():
        parts = line.replace(":", " ").split()
        if len(parts) >= 2 and parts[0].rstrip("?").isdigit():
            ip = parts[1]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            hops.append((int(parts[0].rstrip("?")), ip))
    raw = "$ " + " ".join(argv) + "\n" + res.text
    if not hops:
        return _r(cid, title, Status.WARN,
                  "No router along the way answered — packets stop right "
                  "after your computer or traces are filtered.", raw=raw)
    last_n, last_ip = hops[-1]
    reached = last_ip == target
    if reached:
        return _r(cid, title, Status.PASS,
                  f"Packets reach the server ({last_n} hops) — it just does "
                  "not accept connections on this port.", raw=raw)
    private = net.is_private(last_ip)
    where = ("inside your local network / at your router" if private
             else "in the ISP or backbone network")
    return _r(cid, title, Status.WARN,
              f"The route stops after hop {last_n} ({last_ip}), {where}.",
              ("The block is local: router firewall or parental control."
               if private else
               "The traffic is dropped by the ISP or on the way to the "
               "site — likely a block or an outage beyond your control."),
              raw, last_hop=last_ip)


# --------------------------------------------------------------------------
# Suite API
# --------------------------------------------------------------------------

def make_checks(ctx: Ctx | None = None) -> list[Check]:
    return [
        Check("res.baseline", "Your internet connection", check_baseline),
        Check("res.hosts", "Local override (/etc/hosts)", check_hosts),
        Check("res.dns", "Address lookup (DNS)", check_dns),
        Check("res.tcp", "Connection to the server", check_tcp),
        Check("res.tls", "Secure connection (TLS)", check_tls),
        Check("res.http", "Server response (HTTP)", check_http),
        Check("res.trace", "Where the route stops", check_trace),
    ]


_CHAIN = [("res.baseline", "Internet"), ("res.hosts", "Hosts"),
          ("res.dns", "DNS"), ("res.tcp", "Connect"), ("res.tls", "TLS"),
          ("res.http", "HTTP")]


def analyze(results: list[CheckResult], ctx: Ctx | None = None) -> Verdict:
    from nwsolver.diag.verdict import chain_verdict
    by_id = {r.check_id: r for r in results}
    steps, broken, degraded = chain_verdict(results, _CHAIN)
    st = ctx.state if ctx is not None else {}
    t = st.get("target")
    name = t.display if t is not None else "the site"
    if "res.baseline" in by_id and by_id["res.baseline"].status is \
            Status.ERROR:
        b = by_id["res.baseline"]
        return Verdict("unknown", b.summary, "", [b.suggestion], steps)
    trace = by_id.get("res.trace")
    if broken is not None and broken.check is not None:
        c = broken.check
        where = {
            "res.baseline": "Your internet is down — not a problem with "
                            "this site.",
            "res.hosts": "Blocked on this computer (/etc/hosts).",
            "res.dns": ("Blocked by your DNS." if st.get("dns_block") else
                        "The name does not exist." if st.get("nxdomain")
                        else "The address can't be looked up."),
            "res.tcp": ("The service is down on the server."
                        if "refuses" in c.summary else
                        "The server can't be reached from your network."),
            "res.tls": ("Blocked or intercepted on the way."
                        if "cut during" in c.summary else
                        "Certificate problem."),
            "res.http": "The server itself has a problem.",
        }.get(c.check_id, f"Problem at “{broken.label}”.")
        detail = c.summary
        actions = [c.suggestion] if c.suggestion else []
        if trace is not None and trace.status is Status.WARN:
            detail += " " + trace.summary
            if trace.suggestion:
                actions.append(trace.suggestion)
        return Verdict("fail", f"{name}: {where}", detail, actions, steps,
                       c.check_id)
    if degraded is not None and degraded.check is not None:
        c = degraded.check
        return Verdict("warn", f"{name} is reachable, with a problem at "
                       f"“{degraded.label}”.", c.summary,
                       [c.suggestion] if c.suggestion else [], steps,
                       c.check_id)
    if by_id:
        return Verdict("ok", f"{name} works from this computer.",
                       "DNS, connection, encryption and the server answer "
                       "are all fine. If it does not open in your browser, "
                       "clear the browser cache/cookies, disable extensions "
                       "(ad-blockers), or check the browser's proxy/VPN "
                       "settings.", [], steps)
    return Verdict("unknown", "Enter an address and press Check.", "", [],
                   steps)
