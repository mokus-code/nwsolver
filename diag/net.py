"""Shared network helpers for the diagnostic suites.

Everything here answers one question: *what does this machine use to reach
the internet, and does it work?* Interfaces that never carry internet
traffic (docker0, veth*, br-*, virbr*, vboxnet*, …) are classified as
``virtual`` and ignored by every suite, unless the kernel actually routes
internet traffic through them.

Stdlib only, no Qt, never raises.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field

from nwsolver.engine.checks import Ctx

RAW_MAX = 8000

# Public anchors used for "is the internet reachable" probes. Plain IPs, so
# the probes work even when DNS is broken.
INTERNET_ANCHORS = (("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"),
                    ("9.9.9.9", "Quad9"))
PUBLIC_DNS = ("1.1.1.1", "8.8.8.8")

# Container / VM / bridge interfaces: never the path to the internet by
# themselves. Tunnels (VPN) are handled separately — they *can* be.
_VIRTUAL_PREFIXES = ("docker", "veth", "br-", "virbr", "vboxnet", "vmnet",
                     "lxcbr", "lxdbr", "cni", "flannel", "cali", "kube",
                     "podman", "dummy", "ifb", "hwsim", "sit", "ip6tnl",
                     "gre", "erspan", "nlmon")
_VPN_PREFIXES = ("tun", "tap", "wg", "ppp", "tailscale", "zt", "nordlynx",
                 "proton", "outline", "vpn", "ipsec", "utun", "cscotun")

_PROXY_NAMES = ("https_proxy", "http_proxy", "all_proxy")


def trunc(text: str | None, limit: int = RAW_MAX) -> str:
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "\n… (truncated)"


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------

@dataclass
class Iface:
    name: str
    kind: str            # ethernet | wifi | mobile | vpn | virtual | loopback
    operstate: str = "unknown"
    carrier: bool | None = None
    admin_up: bool = False
    mac: str = ""
    speed_mbps: int | None = None
    duplex: str = ""
    driver: str = ""
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)   # global scope only

    @property
    def physical(self) -> bool:
        return self.kind in ("ethernet", "wifi", "mobile")

    @property
    def label(self) -> str:
        return {"ethernet": "Ethernet", "wifi": "Wi-Fi", "mobile": "Mobile",
                "vpn": "VPN", "virtual": "virtual",
                "loopback": "loopback"}.get(self.kind, self.kind)


def _sys(ctx: Ctx, iface: str, attr: str) -> str:
    return (ctx.read(f"/sys/class/net/{iface}/{attr}") or "").strip()


def iface_kind(ctx: Ctx, name: str) -> str:
    if name == "lo":
        return "loopback"
    if ctx.listdir(f"/sys/class/net/{name}/phy80211") or \
            os.path.isdir(f"/sys/class/net/{name}/wireless"):
        return "wifi"
    if name.startswith(_VPN_PREFIXES):
        return "vpn"
    dev_type = _sys(ctx, name, "type")
    if dev_type in ("65534", "512", "776", "778"):  # tun(none) / ppp / ipip
        return "vpn"
    if name.startswith(_VIRTUAL_PREFIXES):
        return "virtual"
    has_device = os.path.exists(f"/sys/class/net/{name}/device")
    if not has_device:
        return "virtual"  # bridges, bonds, macvlans without hardware
    if name.startswith(("wwan", "wwp", "rmnet")):
        return "mobile"
    return "ethernet"


def _driver(name: str) -> str:
    try:
        return os.path.basename(os.readlink(
            f"/sys/class/net/{name}/device/driver"))
    except OSError:
        return ""


def _addresses(ctx: Ctx) -> dict[str, tuple[list[str], list[str]]]:
    """iface -> ([ipv4 cidr…], [global ipv6 cidr…]) via ``ip -j addr``."""
    out: dict[str, tuple[list[str], list[str]]] = {}
    res = ctx.run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return out
    try:
        data = json.loads(res.stdout or "[]")
    except ValueError:
        return out
    for entry in data:
        name = entry.get("ifname", "")
        v4: list[str] = []
        v6: list[str] = []
        for a in entry.get("addr_info", []):
            local = a.get("local")
            plen = a.get("prefixlen")
            if not local:
                continue
            cidr = f"{local}/{plen}" if plen is not None else local
            if a.get("family") == "inet":
                v4.append(cidr)
            elif a.get("family") == "inet6" and a.get("scope") == "global":
                v6.append(cidr)
        out[name] = (v4, v6)
    return out


def interfaces(ctx: Ctx) -> list[Iface]:
    """All interfaces except loopback, classified. Cached per run."""
    cached = ctx.state.get("_ifaces")
    if cached is not None:
        return cached
    addrs = _addresses(ctx)
    result: list[Iface] = []
    for name in ctx.interfaces():
        kind = iface_kind(ctx, name)
        if kind == "loopback":
            continue
        carrier_raw = _sys(ctx, name, "carrier")
        try:
            admin_up = bool(int(_sys(ctx, name, "flags") or "0", 16) & 0x1)
        except ValueError:
            admin_up = False
        speed = None
        try:
            val = int(_sys(ctx, name, "speed"))
            speed = val if val > 0 else None
        except ValueError:
            pass
        v4, v6 = addrs.get(name, ([], []))
        result.append(Iface(
            name=name, kind=kind,
            operstate=_sys(ctx, name, "operstate") or "unknown",
            carrier=(carrier_raw == "1") if carrier_raw in ("0", "1") else None,
            admin_up=admin_up, mac=_sys(ctx, name, "address"),
            speed_mbps=speed, duplex=_sys(ctx, name, "duplex"),
            driver=_driver(name), ipv4=v4, ipv6=v6))
    ctx.state["_ifaces"] = result
    return result


def relevant_interfaces(ctx: Ctx) -> list[Iface]:
    """Interfaces that can carry internet traffic: physical ones, plus the
    VPN/virtual interface the kernel currently routes the internet through."""
    up = uplink(ctx)
    out = []
    for i in interfaces(ctx):
        if i.physical or (up.dev and i.name == up.dev):
            out.append(i)
    return out


def find_iface(ctx: Ctx, name: str | None) -> Iface | None:
    return next((i for i in interfaces(ctx) if i.name == name), None)


# --------------------------------------------------------------------------
# Uplink: which interface / gateway the kernel uses for the internet
# --------------------------------------------------------------------------

@dataclass
class Uplink:
    dev: str | None = None
    gateway: str | None = None
    src: str | None = None
    error: str = ""          # e.g. "Network is unreachable"
    raw: str = ""
    v6_dev: str | None = None
    v6_gateway: str | None = None


def uplink(ctx: Ctx) -> Uplink:
    """Ask the kernel how it would reach 1.1.1.1 (honours policy routing,
    VPNs and metrics — more reliable than parsing the default route)."""
    cached = ctx.state.get("_uplink")
    if cached is not None:
        return cached
    up = Uplink()
    res = ctx.run(["ip", "-j", "route", "get", "1.1.1.1"])
    up.raw = "$ ip route get 1.1.1.1\n" + (res.stdout or res.stderr).strip()
    if res.ok:
        try:
            data = json.loads(res.stdout or "[]")
            if data:
                up.dev = data[0].get("dev")
                up.gateway = data[0].get("gateway")
                up.src = data[0].get("prefsrc")
        except ValueError:
            pass
    elif res.command_not_found:
        up.dev, up.gateway = _proc_default_route(ctx)
        if up.dev is None:
            up.error = "no default gateway"
        up.raw = "iproute2 not installed — read /proc/net/route\n" + \
            "\n".join(ctx.readlines("/proc/net/route"))
    else:
        up.error = (res.stderr or res.stdout).strip() or f"rc {res.rc}"
    res6 = ctx.run(["ip", "-j", "-6", "route", "get", "2606:4700:4700::1111"])
    if res6.ok:
        try:
            data = json.loads(res6.stdout or "[]")
            if data:
                up.v6_dev = data[0].get("dev")
                up.v6_gateway = data[0].get("gateway")
        except ValueError:
            pass
    up.raw += "\n$ ip -6 route get 2606:4700:4700::1111\n" + \
        (res6.stdout or res6.stderr).strip()
    ctx.state["_uplink"] = up
    return up


def _proc_default_route(ctx: Ctx) -> tuple[str | None, str | None]:
    """Fallback without iproute2: default route from /proc/net/route."""
    best = None
    for line in ctx.readlines("/proc/net/route")[1:]:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000" or f[7] != "00000000":
            continue
        try:
            metric = int(f[6])
            gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        except (ValueError, OSError):
            continue
        if best is None or metric < best[0]:
            best = (metric, f[0], None if gw == "0.0.0.0" else gw)
    return (best[1], best[2]) if best else (None, None)


def ip_tool_missing(ctx: Ctx) -> bool:
    return ctx.which("ip") is None


def physical_uplink(ctx: Ctx) -> Iface | None:
    """The physical interface carrying traffic (under a VPN, if any)."""
    up = uplink(ctx)
    cur = find_iface(ctx, up.dev)
    if cur is not None and cur.physical:
        return cur
    # Under a VPN: pick the physical interface with a default route / IPv4.
    res = ctx.run(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(res.stdout or "[]") if res.ok else []
    except ValueError:
        routes = []
    for r in routes:
        cand = find_iface(ctx, r.get("dev"))
        if cand is not None and cand.physical:
            return cand
    connected = [i for i in interfaces(ctx) if i.physical and i.ipv4
                 and i.operstate in ("up", "unknown")]
    return connected[0] if connected else None


# --------------------------------------------------------------------------
# Wi-Fi
# --------------------------------------------------------------------------

def wifi_link(ctx: Ctx, iface: str) -> dict:
    """Parse ``iw dev <iface> link`` (+ power save). Keys may be None."""
    info: dict = {"connected": False, "ssid": None, "signal": None,
                  "tx_mbps": None, "rx_mbps": None, "freq": None,
                  "power_save": None, "raw": ""}
    if not ctx.which("iw"):
        info["raw"] = "iw not installed"
        return info
    res = ctx.run(["iw", "dev", iface, "link"])
    ps = ctx.run(["iw", "dev", iface, "get", "power_save"])
    info["raw"] = trunc(f"$ iw dev {iface} link\n{res.text}\n"
                        f"$ iw dev {iface} get power_save\n{ps.text}")
    text = res.text
    if text.lower().startswith("connected to"):
        info["connected"] = True
    for line in text.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("ssid:"):
            info["ssid"] = s.split(":", 1)[1].strip()
        elif low.startswith("signal:"):
            m = re.search(r"(-?\d+)\s*dbm", low)
            if m:
                info["signal"] = int(m.group(1))
        elif low.startswith("tx bitrate:"):
            m = re.search(r"([\d.]+)\s*mbit", low)
            if m:
                info["tx_mbps"] = float(m.group(1))
        elif low.startswith("rx bitrate:"):
            m = re.search(r"([\d.]+)\s*mbit", low)
            if m:
                info["rx_mbps"] = float(m.group(1))
        elif low.startswith("freq:"):
            m = re.search(r"(\d+)", low)
            if m:
                info["freq"] = int(m.group(1))
    m = re.search(r"power save:\s*(\w+)", ps.text.lower())
    if m:
        info["power_save"] = m.group(1) == "on"
    return info


def wifi_band(freq: int | None) -> str:
    if not freq:
        return ""
    if freq < 3000:
        return "2.4 GHz"
    if freq < 5950:
        return "5 GHz"
    return "6 GHz"


def nm_state(ctx: Ctx) -> dict:
    """NetworkManager global state + per-device states (if nmcli exists)."""
    out: dict = {"available": False, "state": None, "networking": None,
                 "wifi": None, "devices": {}, "raw": ""}
    if not ctx.which("nmcli"):
        return out
    gen = ctx.run(["nmcli", "-t", "-f", "STATE,NETWORKING,WIFI-HW,WIFI",
                   "general"], timeout=5.0)
    dev = ctx.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION",
                   "device"], timeout=5.0)
    out["raw"] = f"$ nmcli general\n{gen.text}\n$ nmcli device\n{dev.text}"
    if not gen.ok:
        return out
    out["available"] = True
    parts = gen.text.splitlines()[0].split(":") if gen.text else []
    if len(parts) >= 4:
        out["state"], out["networking"] = parts[0], parts[1]
        out["wifi"] = parts[3]
    for line in dev.text.splitlines():
        p = line.split(":")
        if len(p) >= 4:
            out["devices"][p[0]] = {"type": p[1], "state": p[2],
                                    "connection": p[3]}
    return out


# --------------------------------------------------------------------------
# Probes: ping, TCP, ARP
# --------------------------------------------------------------------------

@dataclass
class PingStats:
    target: str
    sent: int = 0
    received: int = 0
    loss_pct: float = 100.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None   # mdev
    method: str = "icmp"            # icmp | tcp
    error: str = ""
    raw: str = ""

    @property
    def ok(self) -> bool:
        return self.received > 0


def ping(ctx: Ctx, target: str, count: int = 5, interval: float = 0.2,
         timeout_s: float = 1.0) -> PingStats:
    """ICMP ping; returns parsed statistics (error set when ping is unusable)."""
    st = PingStats(target)
    if not ctx.which("ping"):
        st.error = "ping not installed"
        return st
    argv = ["ping", "-n", "-c", str(count), "-i", str(interval),
            "-W", str(max(1, int(timeout_s))), target]
    res = ctx.run(argv, timeout=count * max(interval, 0.2) + timeout_s + 5)
    st.raw = trunc("$ " + " ".join(argv) + "\n" + res.stdout + res.stderr)
    if res.permission_denied:
        st.error = "ping not permitted (needs CAP_NET_RAW)"
        return st
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received",
                  res.stdout)
    if not m:
        st.error = (res.stderr.strip() or "no ping statistics")[:160]
        return st
    st.sent, st.received = int(m.group(1)), int(m.group(2))
    st.loss_pct = 100.0 * (st.sent - st.received) / st.sent if st.sent else 100
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", res.stdout)
    if m:
        st.min_ms, st.avg_ms, st.max_ms, st.jitter_ms = (
            float(m.group(i)) for i in range(1, 5))
    return st


def tcp_connect(host: str, port: int, timeout: float = 3.0,
                family: int = 0) -> tuple[float | None, str]:
    """Return (rtt_ms, '') on success or (None, reason).

    A refused connection still proves the host is reachable; the reason is
    then ``'refused'`` and the RTT is returned as well.
    """
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return None, f"DNS: {exc.strerror or exc}"
    af, st, proto, _cn, addr = infos[0]
    sock = socket.socket(af, st, proto)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect(addr)
        return (time.monotonic() - start) * 1000.0, ""
    except ConnectionRefusedError:
        return (time.monotonic() - start) * 1000.0, "refused"
    except (socket.timeout, TimeoutError):
        return None, "timeout"
    except OSError as exc:
        return None, os_reason(exc)
    finally:
        sock.close()


def os_reason(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    if isinstance(exc, socket.gaierror):
        return f"DNS: {exc.strerror or exc}"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return str(exc)[:120] or exc.__class__.__name__


def tcp_ping(host: str, port: int = 443, count: int = 5,
             timeout: float = 2.0) -> PingStats:
    """Latency via TCP handshakes — fallback when ICMP is unavailable."""
    st = PingStats(host, method="tcp")
    samples = []
    lines = []
    for _ in range(count):
        rtt, why = tcp_connect(host, port, timeout)
        st.sent += 1
        if rtt is not None:
            st.received += 1
            samples.append(rtt)
            lines.append(f"tcp {host}:{port} {rtt:.1f} ms"
                         + (" (refused)" if why else ""))
        else:
            lines.append(f"tcp {host}:{port} {why}")
        time.sleep(0.05)
    st.loss_pct = 100.0 * (st.sent - st.received) / st.sent
    if samples:
        st.min_ms, st.max_ms = min(samples), max(samples)
        st.avg_ms = sum(samples) / len(samples)
        if len(samples) > 1:
            diffs = [abs(a - b) for a, b in zip(samples, samples[1:])]
            st.jitter_ms = sum(diffs) / len(diffs)
        else:
            st.jitter_ms = 0.0
    st.raw = "\n".join(lines)
    return st


def latency(ctx: Ctx, host: str, count: int = 5, tcp_port: int = 443,
            interval: float = 0.2) -> PingStats:
    """ICMP ping, falling back to TCP handshakes when ICMP can't be used or
    is filtered (100 % loss)."""
    st = ping(ctx, host, count=count, interval=interval)
    if st.error or not st.ok:
        tcp = tcp_ping(host, tcp_port, count=min(count, 5))
        if tcp.ok:
            tcp.raw = (st.raw + "\n\n" if st.raw else "") + \
                "ICMP unavailable/filtered — measured with TCP handshakes:\n" \
                + tcp.raw
            return tcp
        if st.error:
            tcp.raw = st.raw + "\n" + tcp.raw
            return tcp
    return st


def neighbor_state(ctx: Ctx, ip: str, dev: str | None) -> str:
    argv = ["ip", "neigh", "show", ip]
    if dev:
        argv += ["dev", dev]
    res = ctx.run(argv)
    for tok in reversed(res.text.split()):
        if tok.isupper() and tok.isalpha():
            return tok
    return ""


def iface_counters(ctx: Ctx, iface: str) -> dict[str, int]:
    out = {}
    for name in ("rx_bytes", "tx_bytes", "rx_errors", "tx_errors",
                 "rx_dropped", "tx_dropped", "rx_crc_errors"):
        try:
            out[name] = int(_sys(ctx, iface, f"statistics/{name}") or "0")
        except ValueError:
            out[name] = 0
    return out


def tcp_counters(ctx: Ctx) -> tuple[int, int]:
    """(OutSegs, RetransSegs) from /proc/net/snmp."""
    lines = ctx.readlines("/proc/net/snmp")
    for i in range(len(lines) - 1):
        if lines[i].startswith("Tcp:") and lines[i + 1].startswith("Tcp:"):
            keys = lines[i].split()[1:]
            vals = lines[i + 1].split()[1:]
            d = dict(zip(keys, vals))
            try:
                return int(d.get("OutSegs", 0)), int(d.get("RetransSegs", 0))
            except ValueError:
                return 0, 0
    return 0, 0


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

RESOLVED_STUB = ("127.0.0.53", "127.0.0.54")


def resolv_conf_servers(ctx: Ctx) -> list[str]:
    servers = []
    for line in ctx.readlines("/etc/resolv.conf"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def upstream_dns_servers(ctx: Ctx) -> tuple[list[str], str]:
    """Real upstream DNS servers (resolving the systemd-resolved stub)."""
    servers = resolv_conf_servers(ctx)
    raw = "/etc/resolv.conf nameservers: " + (", ".join(servers) or "none")
    if any(s in RESOLVED_STUB for s in servers) and ctx.which("resolvectl"):
        res = ctx.run(["resolvectl", "dns"], timeout=5.0)
        raw += "\n$ resolvectl dns\n" + res.text
        upstream: list[str] = []
        for line in res.text.splitlines():
            if ":" not in line:
                continue
            for tok in line.split(":", 1)[1].split():
                tok = tok.split("#", 1)[0]
                tok = tok.split("%", 1)[0]
                try:
                    ipaddress.ip_address(tok)
                except ValueError:
                    continue
                if tok not in upstream:
                    upstream.append(tok)
        return upstream, raw
    return [s for s in servers if _valid_ip(s)], raw


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _skip_name(data: bytes, off: int) -> int:
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length
    return off


@dataclass
class DnsAnswer:
    server: str
    ok: bool = False             # got any reply
    rcode: int | None = None     # 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED
    addresses: list[str] = field(default_factory=list)
    ms: float | None = None
    error: str = ""

    @property
    def rcode_name(self) -> str:
        return {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                4: "NOTIMP", 5: "REFUSED"}.get(self.rcode or 0, str(self.rcode))


def dns_query(server: str, name: str, qtype: int = 1,
              timeout: float = 2.0) -> DnsAnswer:
    """Hand-built UDP DNS query (A=1, AAAA=28) straight to ``server``."""
    ans = DnsAnswer(server)
    qid = random.randint(0, 0xFFFF)
    try:
        packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + \
            _encode_name(name) + struct.pack(">HH", qtype, 1)
    except UnicodeError:
        ans.error = "invalid name"
        return ans
    try:
        ip = ipaddress.ip_address(server.split("%", 1)[0])
    except ValueError:
        ans.error = "invalid server address"
        return ans
    fam = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
        ans.ms = (time.monotonic() - start) * 1000.0
    except (socket.timeout, TimeoutError):
        ans.error = "timeout"
        return ans
    except OSError as exc:
        ans.error = os_reason(exc)
        return ans
    finally:
        sock.close()
    ans.ok = True
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    ans.rcode = flags & 0x000F
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            ans.addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == 28 and rdlen == 16:
            ans.addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return ans


def system_resolve(host: str, port: int = 443) -> tuple[list[str], float, str]:
    """Resolve through the system resolver (nsswitch: /etc/hosts, resolved…).

    Returns (addresses, elapsed_ms, error). IPv4 first.
    """
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        ms = (time.monotonic() - start) * 1000.0
        if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return [], ms, "name does not exist (NXDOMAIN)"
        if exc.errno == socket.EAI_AGAIN:
            return [], ms, "temporary failure — DNS server not answering"
        return [], ms, exc.strerror or str(exc)
    ms = (time.monotonic() - start) * 1000.0
    addrs: list[str] = []
    for fam, _st, _p, _cn, sa in sorted(infos, key=lambda i: i[0] != socket.AF_INET):
        if sa[0] not in addrs:
            addrs.append(sa[0])
    return addrs, ms, ""


def is_bogus_answer(addr: str) -> bool:
    """Addresses DNS filters return instead of the real one."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_unspecified or ip.is_loopback


def is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local


# --------------------------------------------------------------------------
# Proxy
# --------------------------------------------------------------------------

def redact(value: str) -> str:
    return re.sub(r"://([^:@/]+):([^@/]+)@", r"://\1:***@", value)


def proxy_env() -> dict[str, str]:
    out = {}
    for name in _PROXY_NAMES:
        val = os.environ.get(name) or os.environ.get(name.upper())
        if val:
            out[name] = redact(val)
    return out


def fmt_ms(ms: float | None) -> str:
    return "—" if ms is None else (f"{ms:.0f} ms" if ms >= 10 else f"{ms:.1f} ms")


def fmt_mbps(mbps: float | None) -> str:
    if mbps is None:
        return "—"
    return f"{mbps:.0f} Mbit/s" if mbps >= 10 else f"{mbps:.1f} Mbit/s"


# --------------------------------------------------------------------------
# VPN
# --------------------------------------------------------------------------

def vpn_uplink(ctx: Ctx) -> Iface | None:
    """The VPN interface internet traffic goes through, or None."""
    itf = find_iface(ctx, uplink(ctx).dev)
    return itf if itf is not None and itf.kind == "vpn" else None


def physical_gateway(ctx: Ctx) -> tuple[str | None, str | None]:
    """(device, gateway) of the real network under a VPN.

    VPN clients (wg-quick, OpenVPN redirect-gateway, NetworkManager) keep
    the original default route in the main table, so it is read from there.
    """
    cached = ctx.state.get("_phys_gw")
    if cached is not None:
        return cached
    out: tuple[str | None, str | None] = (None, None)
    res = ctx.run(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(res.stdout or "[]") if res.ok else []
    except ValueError:
        routes = []
    for r in sorted(routes, key=lambda r: r.get("metric", 0)):
        cand = find_iface(ctx, r.get("dev"))
        if cand is not None and cand.physical:
            out = (cand.name, r.get("gateway"))
            break
    if out == (None, None) and res.command_not_found:
        dev, gw = _proc_default_route(ctx)
        cand = find_iface(ctx, dev)
        if cand is not None and cand.physical:
            out = (dev, gw)
    ctx.state["_phys_gw"] = out
    return out


def local_gateway(ctx: Ctx) -> str | None:
    """The router on the local network (under a VPN: the real one)."""
    if vpn_uplink(ctx) is not None:
        return physical_gateway(ctx)[1]
    return uplink(ctx).gateway


# --------------------------------------------------------------------------
# Wi-Fi details: BSSID, channel, width, security (nmcli + iw, no root)
# --------------------------------------------------------------------------

def _nmcli_split(line: str) -> list[str]:
    """Split one `nmcli -t` line, honouring escaped colons."""
    return [p.replace("\x00", ":") for p in
            line.replace("\\:", "\x00").split(":")]


def wifi_details(ctx: Ctx, iface: str) -> dict:
    """Facts about the access point in use. Keys may be None."""
    cached = ctx.state.setdefault("_wifi_details", {}).get(iface)
    if cached is not None:
        return cached
    d: dict = {"ssid": None, "bssid": None, "channel": None, "freq": None,
               "width": None, "security": None, "signal_pct": None,
               "raw": ""}
    if ctx.which("nmcli"):
        res = ctx.run(["nmcli", "-t", "-f",
                       "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                       "device", "wifi", "list", "ifname", iface,
                       "--rescan", "no"], timeout=8.0)
        d["raw"] = "$ nmcli device wifi list\n" + res.text
        for line in res.text.splitlines():
            p = _nmcli_split(line)
            if len(p) >= 7 and p[0] == "*":
                d["ssid"], d["bssid"] = p[1] or None, p[2] or None
                try:
                    d["channel"] = int(p[3])
                except ValueError:
                    pass
                m = re.search(r"(\d+)", p[4])
                d["freq"] = int(m.group(1)) if m else None
                try:
                    d["signal_pct"] = int(p[5])
                except ValueError:
                    pass
                sec = p[6].strip()
                d["security"] = "open" if sec in ("", "--") else sec
                break
    if ctx.which("iw"):
        res = ctx.run(["iw", "dev", iface, "info"], timeout=4.0)
        m = re.search(r"width:\s*(\d+)\s*MHz", res.text)
        if m:
            d["width"] = int(m.group(1))
        m = re.search(r"channel\s+(\d+)", res.text)
        if m and d["channel"] is None:
            d["channel"] = int(m.group(1))
        d["raw"] += "\n$ iw dev info\n" + res.text
    ctx.state["_wifi_details"][iface] = d
    return d


def wifi_is_open(details: dict) -> bool:
    return details.get("security") == "open"


# --------------------------------------------------------------------------
# Phone hotspot / USB tethering
# --------------------------------------------------------------------------

_TETHER_DRIVERS = {"rndis_host": "USB tethering", "cdc_ether": "USB tethering",
                   "cdc_ncm": "USB tethering", "ipheth": "iPhone USB tethering"}
_HOTSPOT_SSID = re.compile(
    r"iphone|android|galaxy|redmi|xiaomi|pixel|huawei|honor|oneplus|"
    r"oppo|vivo|realme|nokia|motorola|moto |poco", re.I)
_HOTSPOT_GW = {"172.20.10.1": "iPhone hotspot", "192.168.43.1":
               "Android hotspot"}


def hotspot_info(ctx: Ctx) -> str:
    """'' or a label such as 'iPhone hotspot' / 'USB tethering'."""
    cached = ctx.state.get("_hotspot")
    if cached is not None:
        return cached
    label = ""
    itf = physical_uplink(ctx)
    gw = local_gateway(ctx) or ""
    if itf is not None:
        label = _TETHER_DRIVERS.get(itf.driver, "")
        if not label and itf.kind == "wifi":
            ssid = wifi_link(ctx, itf.name).get("ssid") or ""
            if _HOTSPOT_SSID.search(ssid):
                label = ("iPhone hotspot" if "iphone" in ssid.lower()
                         else "Phone hotspot")
        if not label and gw in _HOTSPOT_GW:
            label = _HOTSPOT_GW[gw]
        if not label and ctx.which("nmcli"):
            res = ctx.run(["nmcli", "-g", "GENERAL.METERED", "device", "show",
                           itf.name], timeout=4.0)
            # NetworkManager marks Android hotspots as metered (guessed).
            if res.text.strip().lower().startswith("yes (guessed)"):
                label = "Phone hotspot"
    ctx.state["_hotspot"] = label
    return label


def hotspot_tips(label: str, problem: str) -> str:
    """Extra advice when the connection is a phone hotspot."""
    if not label:
        return ""
    if problem == "slow":
        return (f"You are connected through a phone ({label}): the speed "
                "is the phone's mobile "
                "signal. Put the phone near a window, check it shows "
                "4G/5G, turn off its Low Data / Battery Saver mode, and "
                "check the data plan is not throttled.")
    return (f"You are connected through a phone ({label}), so the "
            "internet comes from its mobile data: check that mobile data "
            "is on and has credit, enable Data Roaming if you are abroad, "
            "keep the "
            "hotspot screen open on iPhone, and turn the hotspot off and "
            "on. Some plans block tethering.")


# --------------------------------------------------------------------------
# MAC address policy (portals remember devices by MAC)
# --------------------------------------------------------------------------

def mac_policy(ctx: Ctx, iface: str) -> tuple[str, str]:
    """(connection name, cloned-mac setting) for the active Wi-Fi."""
    nm = nm_state(ctx)
    conn = (nm.get("devices", {}).get(iface) or {}).get("connection", "")
    if not conn or not ctx.which("nmcli"):
        return conn, ""
    res = ctx.run(["nmcli", "-g", "802-11-wireless.cloned-mac-address",
                   "connection", "show", conn], timeout=4.0)
    return conn, res.text.strip().lower()


# --------------------------------------------------------------------------
# Path MTU (ping -M do, binary search) — no root needed
# --------------------------------------------------------------------------

def path_mtu(ctx: Ctx, host: str) -> tuple[int | None, str]:
    """Largest packet (bytes, incl. 28-byte IP/ICMP header) that reaches
    ``host`` without fragmentation, or (None, reason)."""
    if not ctx.which("ping"):
        return None, "ping not installed"

    def fits(payload: int) -> bool | None:
        res = ctx.run(["ping", "-n", "-c", "1", "-W", "1", "-M", "do",
                       "-s", str(payload), host], timeout=4.0)
        if res.permission_denied:
            return None
        return res.ok and " 0% packet loss" in res.stdout

    small = fits(500)
    if small is None:
        return None, "ping not permitted"
    if not small:
        return None, f"{host} does not answer ping"
    if fits(1472):
        return 1500, ""
    lo, hi = 500, 1472
    steps = 0
    while hi - lo > 1 and steps < 10:
        mid = (lo + hi) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid
        steps += 1
    return lo + 28, ""


# --------------------------------------------------------------------------
# UDP reachability via STUN (what video calls and WireGuard need)
# --------------------------------------------------------------------------

STUN_SERVERS = (("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478),
                ("global.stun.twilio.com", 3478))


@dataclass
class StunResult:
    ok: bool = False
    server: str = ""
    rtt_ms: float | None = None
    mapped: str = ""          # public address:port as seen by the server
    error: str = ""
    raw: str = ""


def stun_probe(timeout: float = 2.0) -> StunResult:
    """Send a STUN Binding Request (RFC 5389) to public servers over UDP."""
    res = StunResult()
    lines = []
    for host, port in STUN_SERVERS:
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET,
                                      socket.SOCK_DGRAM)[0][4]
        except socket.gaierror as exc:
            lines.append(f"{host}:{port} — DNS: {exc.strerror or exc}")
            res.error = "DNS failed"
            continue
        tid = os.urandom(12)
        packet = struct.pack(">HHI", 0x0001, 0, 0x2112A442) + tid
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        try:
            sock.sendto(packet, addr)
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, TimeoutError):
            lines.append(f"{host}:{port} ({addr[0]}) — no UDP reply")
            res.error = "no UDP reply"
            continue
        except OSError as exc:
            lines.append(f"{host}:{port} — {os_reason(exc)}")
            res.error = os_reason(exc)
            continue
        finally:
            sock.close()
        rtt = (time.monotonic() - start) * 1000.0
        if len(data) < 20 or data[8:20] != tid:
            lines.append(f"{host}:{port} — unexpected reply")
            continue
        res.ok, res.server, res.rtt_ms = True, f"{host}:{port}", rtt
        res.mapped = _stun_mapped(data)
        lines.append(f"{host}:{port} — reply in {fmt_ms(rtt)}"
                     + (f", public address {res.mapped}" if res.mapped
                        else ""))
        break
    res.raw = "UDP STUN Binding Request:\n" + "\n".join(lines)
    return res


def _stun_mapped(data: bytes) -> str:
    off = 20
    while off + 4 <= len(data):
        atype, alen = struct.unpack(">HH", data[off:off + 4])
        val = data[off + 4:off + 4 + alen]
        if atype in (0x0020, 0x0001) and len(val) >= 8 and val[1] == 1:
            port = struct.unpack(">H", val[2:4])[0]
            ip = bytes(val[4:8])
            if atype == 0x0020:
                port ^= 0x2112
                ip = bytes(b ^ m for b, m in zip(ip, b"\x21\x12\xa4\x42"))
            return f"{socket.inet_ntoa(ip)}:{port}"
        off += 4 + alen + ((4 - alen % 4) % 4)
    return ""
