"""Detection of content filtering / censorship (DPI) on the network path.

A plain firewall refuses a connection or lets it time out. Deep packet
inspection (DPI) lets the connection open, *reads* it, and kills it when it
sees a blocked name — in a DNS query, in the TLS SNI, or in the HTTP Host
header — typically by injecting a TCP reset or silently dropping packets.

Every probe here is therefore *differential*: the same request is sent
twice to the same server, once naming the target and once naming a neutral
control domain. "Control works, target fails" proves the name is being
filtered; "both fail" proves nothing. Probes:

* DNS over UDP to public resolvers (dropped?);
* DNS over TCP (reset right after the handshake?);
* DNS query to an address that runs no DNS server (an answer = injected);
* TLS ClientHello with SNI=target vs SNI=control to a neutral server;
* HTTP request with Host=target vs Host=control to a neutral server;
* TCP to the target's own addresses vs a neutral address (IP blocking);
* DNS over HTTPS (encrypted) to learn the real addresses.

Stdlib only, no Qt, never raises.
"""
from __future__ import annotations

import json
import socket
import ssl
import struct
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from nwsolver.diag import net

CONTROL = "example.com"          # never filtered anywhere
NEUTRAL_IP = "1.1.1.1"           # answers TLS and HTTP for any name
RESOLVERS = ("1.1.1.1", "8.8.8.8")
TIMEOUT = 3.5


# --------------------------------------------------------------------------
# Low-level probes. Outcomes: ok | reset | timeout | closed | refused | error
# --------------------------------------------------------------------------

def _classify(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (ssl.SSLEOFError, ConnectionAbortedError,
                        BrokenPipeError)):
        return "closed"
    if isinstance(exc, ssl.SSLError):
        text = (exc.reason or str(exc)).upper()
        if "EOF" in text or "UNEXPECTED" in text:
            return "closed"
        # A TLS alert means the *server* answered — not interference.
        return "ok"
    if isinstance(exc, OSError) and exc.errno in (104,):
        return "reset"
    return "error"


def dns_udp(server: str, name: str) -> str:
    a = net.dns_query(server, name, 1, timeout=TIMEOUT)
    return "ok" if a.ok else ("timeout" if a.error == "timeout" else "error")


def dns_tcp(server: str, name: str) -> str:
    """DNS over TCP (RFC 7766). 'reset' after a completed handshake is the
    signature of an injecting middlebox."""
    try:
        query = struct.pack(">HHHHHH", 0x4E57, 0x0100, 1, 0, 0, 0) + \
            net._encode_name(name) + struct.pack(">HH", 1, 1)
    except UnicodeError:
        return "error"
    try:
        sock = socket.create_connection((server, 53), timeout=TIMEOUT)
    except OSError as exc:
        return "no-connect:" + _classify(exc)
    try:
        sock.settimeout(TIMEOUT)
        sock.sendall(struct.pack(">H", len(query)) + query)
        data = sock.recv(2)
        if not data:
            return "closed"
        return "ok"
    except OSError as exc:
        return _classify(exc)
    finally:
        sock.close()


def dns_injected(non_resolver: str, name: str) -> bool | None:
    """Ask an address that runs no DNS server. Any answer was forged by a
    device on the path. None = could not test."""
    a = net.dns_query(non_resolver, name, 1, timeout=2.5)
    if a.error and a.error != "timeout":
        return None
    return a.ok


def tls_sni(ip: str, sni: str, port: int = 443) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    except OSError as exc:
        return "no-connect:" + _classify(exc)
    try:
        sock.settimeout(TIMEOUT)
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            tls.do_handshake()
        return "ok"
    except (OSError, ssl.SSLError) as exc:
        return _classify(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_host(ip: str, host: str, port: int = 80) -> tuple[str, str]:
    """(outcome, first status line + Location/Server) for Host=host."""
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    except OSError as exc:
        return "no-connect:" + _classify(exc), ""
    try:
        sock.settimeout(TIMEOUT)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: "
                     "Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            return "closed", ""
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        lines = head.split("\r\n")
        keep = [lines[0]] + [ln for ln in lines[1:] if ln.lower().startswith(
            ("location:", "server:"))]
        return "ok", " | ".join(keep)
    except OSError as exc:
        return _classify(exc), ""
    finally:
        sock.close()


def doh_resolve(name: str) -> tuple[list[str], str]:
    """Encrypted DNS (DNS over HTTPS) — invisible to DPI. Returns (A
    addresses, source) or ([], error)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    errors = []
    for url in (f"https://1.1.1.1/dns-query?name={name}&type=A",
                f"https://8.8.8.8/resolve?name={name}&type=A"):
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json", "User-Agent": "nwsolver"})
        try:
            with opener.open(req, timeout=5.0) as resp:
                data = json.loads(resp.read(65536).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url.split('/')[2]}: {net.os_reason(exc)}")
            continue
        addrs = [a.get("data", "") for a in data.get("Answer", [])
                 if a.get("type") == 1]
        if data.get("Status") == 3:
            return [], "NXDOMAIN via encrypted DNS"
        if addrs:
            return addrs, url.split("/")[2]
    return [], "; ".join(errors) or "no answer"


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

@dataclass
class Finding:
    layer: str          # dns | sni | http | ip
    blocked: bool
    proof: str          # one human sentence


@dataclass
class FilterReport:
    findings: list[Finding] = field(default_factory=list)
    inconclusive: list[str] = field(default_factory=list)
    real_addrs: list[str] = field(default_factory=list)
    raw: str = ""

    @property
    def layers(self) -> list[str]:
        return [f.layer for f in self.findings if f.blocked]


_FAILED = ("reset", "timeout", "closed")


def _bad(outcome: str) -> bool:
    return outcome.split(":")[-1] in _FAILED


def analyse(name: str, target_ips: list[str], web: bool = True,
            control_ip: str = "") -> FilterReport:
    """Run all differential probes in parallel for host ``name``."""
    rep = FilterReport()
    jobs = {
        "udp_t": lambda: [dns_udp(s, name) for s in RESOLVERS],
        "udp_c": lambda: [dns_udp(s, CONTROL) for s in RESOLVERS],
        "tcp_t": lambda: dns_tcp(RESOLVERS[0], name),
        "tcp_c": lambda: dns_tcp(RESOLVERS[0], CONTROL),
        "sni_t": lambda: tls_sni(NEUTRAL_IP, name),
        "sni_c": lambda: tls_sni(NEUTRAL_IP, CONTROL),
        "doh": lambda: doh_resolve(name),
    }
    if control_ip:
        jobs["inj_t"] = lambda: dns_injected(control_ip, name)
        jobs["inj_c"] = lambda: dns_injected(control_ip, CONTROL)
    if web:
        jobs["http_t"] = lambda: http_host(NEUTRAL_IP, name)
        jobs["http_c"] = lambda: http_host(NEUTRAL_IP, CONTROL)
    v4 = [a for a in target_ips if ":" not in a][:2]
    if v4:
        jobs["own_sni_t"] = lambda: tls_sni(v4[0], name)
        jobs["own_sni_c"] = lambda: tls_sni(v4[0], CONTROL)
        jobs["ip_t"] = lambda: [net.tcp_connect(a, 443, TIMEOUT) for a in v4]
        jobs["ip_c"] = lambda: net.tcp_connect(NEUTRAL_IP, 443, TIMEOUT)
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futs = {k: pool.submit(f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}

    lines = [f"target: {name}   control: {CONTROL}   neutral server: "
             f"{NEUTRAL_IP}"]
    lines.append(f"DNS/UDP {', '.join(RESOLVERS)}: target {r['udp_t']} | "
                 f"control {r['udp_c']}")
    lines.append(f"DNS/TCP {RESOLVERS[0]}: target {r['tcp_t']} | control "
                 f"{r['tcp_c']}")
    if "inj_t" in r:
        lines.append(f"DNS to non-resolver {control_ip}: target "
                     f"{'ANSWERED' if r['inj_t'] else 'silent'} | control "
                     f"{'ANSWERED' if r['inj_c'] else 'silent'}")
    lines.append(f"TLS SNI to {NEUTRAL_IP}: target {r['sni_t']} | control "
                 f"{r['sni_c']}")
    if web:
        lines.append(f"HTTP Host to {NEUTRAL_IP}: target {r['http_t'][0]} "
                     f"[{r['http_t'][1]}] | control {r['http_c'][0]} "
                     f"[{r['http_c'][1]}]")
    if v4:
        lines.append(f"TLS to the site's own IP {v4[0]}: SNI=target "
                     f"{r['own_sni_t']} | SNI=control {r['own_sni_c']}")
        lines.append("TCP 443 to site IPs: " + ", ".join(
            f"{a} {'ok' if rtt is not None else why}"
            for a, (rtt, why) in zip(v4, r["ip_t"]))
            + f" | neutral {NEUTRAL_IP}: "
            + ("ok" if r["ip_c"][0] is not None else r["ip_c"][1]))
    addrs, src = r["doh"]
    rep.real_addrs = addrs
    lines.append(f"Encrypted DNS (DoH): {', '.join(addrs) or src}")

    # ---- DNS layer
    udp_t_bad = all(o == "timeout" for o in r["udp_t"])
    udp_c_ok = any(o == "ok" for o in r["udp_c"])
    if udp_t_bad and udp_c_ok:
        rep.findings.append(Finding(
            "dns", True, f"DNS queries for {name} are silently dropped while "
            f"the same query for {CONTROL} is answered"))
    if _bad(r["tcp_t"]) and r["tcp_c"] == "ok" and \
            not r["tcp_t"].startswith("no-connect"):
        rep.findings.append(Finding(
            "dns", True, f"a DNS-over-TCP query for {name} is cut "
            f"({r['tcp_t']}) right after the connection opens, while "
            f"{CONTROL} works — something on the path reads DNS queries"))
    if r.get("inj_t") and not r.get("inj_c"):
        rep.findings.append(Finding(
            "dns", True, f"a DNS answer for {name} came back from "
            f"{control_ip}, which runs no DNS server — the answer was "
            "forged on the way"))
    # ---- TLS SNI layer
    if _bad(r["sni_t"]) and r["sni_c"] == "ok":
        rep.findings.append(Finding(
            "sni", True, f"a secure connection that names {name} is cut "
            f"({r['sni_t']}), while the same connection naming {CONTROL} "
            "works — the site name is read from the TLS handshake (SNI)"))
    elif "own_sni_t" in r and _bad(r["own_sni_t"]) and \
            r["own_sni_c"] == "ok":
        rep.findings.append(Finding(
            "sni", True, f"the site's server accepts a secure connection "
            f"for {CONTROL} but the one naming {name} is cut "
            f"({r['own_sni_t']})"))
    elif r["sni_c"] != "ok":
        rep.inconclusive.append(f"TLS test inconclusive ({NEUTRAL_IP} "
                                f"control: {r['sni_c']})")
    # ---- HTTP Host layer
    if web:
        (ot, st), (oc, sc) = r["http_t"], r["http_c"]
        status = lambda s: s.split("|")[0].split(" ")[1] if s.count(" ") \
            else ""  # noqa: E731
        # A server may echo the requested name in its redirect — normal.
        own = {"", _loc_host(sc), name.lower(), "www." + name.lower()}
        if oc == "ok" and (_bad(ot) or (ot == "ok" and (
                status(st) != status(sc) or _loc_host(st) not in own))):
            rep.findings.append(Finding(
                "http", True, f"a plain web request for {name} is "
                + (f"cut ({ot})" if ot != "ok" else
                   f"answered by someone else ({st[:120]})")
                + f", while the one for {CONTROL} is not — a block page or "
                "reset is injected"))
    # ---- IP layer
    if "ip_t" in r:
        own_ok = any(rtt is not None for rtt, _w in r["ip_t"])
        if not own_ok and r["ip_c"][0] is not None:
            rep.findings.append(Finding(
                "ip", True, f"the site's addresses ({', '.join(v4)}) can't "
                "be reached at all while other servers can — the "
                "addresses are blocked, or the site is down"))
    rep.raw = "\n".join(lines)
    return rep


def _loc_host(status_line: str) -> str:
    for part in status_line.split(" | "):
        if part.lower().startswith("location:"):
            url = part.split(":", 1)[1].strip()
            host = url.split("//", 1)[-1].split("/", 1)[0]
            return host.split(":")[0].lower()
    return ""


LAYER_NAMES = {"dns": "DNS (address lookup)",
               "sni": "secure connection (TLS/SNI)",
               "http": "web requests (HTTP)",
               "ip": "IP address"}


def advice(layers: list[str]) -> str:
    if layers == ["dns"]:
        return ("Only the address lookup is filtered. Turning on encrypted "
                "DNS is enough: in Firefox or Chrome open Settings → "
                "Privacy and security → Use secure DNS (DNS over HTTPS), "
                "or system-wide set DNS-over-TLS with 1.1.1.1 in "
                "/etc/systemd/resolved.conf (`DNSOverTLS=yes`).")
    if "ip" in layers and len(layers) == 1:
        return ("The site's addresses are blocked (or the site is down). "
                "Encrypted DNS won't help; check from another network "
                "(e.g. a phone on mobile data) or via a VPN.")
    return ("The filter recognises the site name inside the connection "
            "itself, so changing DNS is not enough. It opens from another "
            "network (e.g. mobile data or abroad) or through a VPN/proxy "
            "that is not blocked — on such networks plain VPN protocols "
            "are often blocked too, so obfuscated ones (e.g. “stealth” "
            "modes) may be needed. Whether such tools may be used depends "
            "on local law.")
