"""Suite 1 — "Why is there no internet connection?"

Walks the path a packet takes from this machine to a website, one link at a
time. The first broken link is the root cause; everything after it is a
symptom. Only interfaces that can carry internet traffic are inspected —
Docker bridges, veths, libvirt/VirtualBox networks etc. are ignored.
"""
from __future__ import annotations

import datetime
import email.utils
import socket
import ssl
import urllib.error
import urllib.request

from nwsolver.diag import net
from nwsolver.diag.verdict import Verdict, chain_verdict
from nwsolver.engine.checks import Check, CheckResult, Ctx, Status

SUITE_ID = "connection"
SUITE_NAME = "Connection"
SUITE_DESC = "Finds where the path from this computer to the internet breaks."
PARALLEL = True

CHAIN = [
    ("conn.adapter", "Adapter"),
    ("conn.link", "Link"),
    ("conn.ip", "IP address"),
    ("conn.route", "Route"),
    ("conn.gateway", "Router"),
    ("conn.internet", "Internet"),
    ("conn.dns", "DNS"),
    ("conn.web", "Web"),
]

_UA = "nwsolver/0.2 (network diagnostics)"


def _r(cid: str, title: str, status: Status, summary: str, fix: str = "",
       raw: str = "", **metrics) -> CheckResult:
    return CheckResult(cid, title, status, summary, raw=net.trunc(raw),
                       suggestion=fix, metrics=metrics)


# --------------------------------------------------------------------------
# 1. Adapter
# --------------------------------------------------------------------------

def _rfkill(ctx: Ctx) -> list[dict]:
    """Wireless kill switches from sysfs (no root needed)."""
    out = []
    for dev in ctx.listdir("/sys/class/rfkill"):
        base = f"/sys/class/rfkill/{dev}"
        kind = (ctx.read(base + "/type") or "").strip()
        if kind not in ("wlan", "wwan"):
            continue
        out.append({
            "name": (ctx.read(base + "/name") or dev).strip(),
            "type": kind,
            "soft": (ctx.read(base + "/soft") or "0").strip() == "1",
            "hard": (ctx.read(base + "/hard") or "0").strip() == "1",
        })
    return out


def _driverless_pci(ctx: Ctx) -> list[str]:
    if not ctx.which("lspci"):
        return []
    res = ctx.run(["lspci", "-nnk"])
    found, cur, has_driver = [], None, False
    for line in res.text.splitlines() + ["END"]:
        if line and not line[0].isspace():
            if cur and not has_driver:
                found.append(cur)
            cur, has_driver = None, False
            if "[0200]" in line or "[0280]" in line:
                cur = line.split("]:", 1)[-1].strip()
        elif cur and "kernel driver in use" in line.lower():
            has_driver = True
    return found


def check_adapter(ctx: Ctx) -> CheckResult:
    cid, title = "conn.adapter", "Network adapter"
    phys = [i for i in net.interfaces(ctx) if i.physical]
    nm = net.nm_state(ctx)
    kills = _rfkill(ctx)
    raw = nm["raw"] + "\n\nrfkill (sysfs):\n" + "\n".join(
        f"{k['name']} {k['type']} soft={k['soft']} hard={k['hard']}"
        for k in kills)

    if nm["available"] and nm["networking"] == "disabled":
        return _r(cid, title, Status.FAIL,
                  "Networking is switched off in NetworkManager.",
                  "Turn networking on: click the network icon → enable it, "
                  "or run `nmcli networking on`.", raw)
    if not phys:
        missing = _driverless_pci(ctx)
        if missing:
            return _r(cid, title, Status.FAIL,
                      "A network adapter is installed but has no driver: "
                      + "; ".join(missing),
                      "Install the driver: open “Software & Updates → "
                      "Additional Drivers”, or look up the device with "
                      "`lspci -nnk` and install its firmware package.", raw)
        return _r(cid, title, Status.FAIL,
                  "No network adapter found (no Ethernet, Wi-Fi or modem).",
                  "Plug in a cable/USB adapter or check that the Wi-Fi card "
                  "is enabled in BIOS.", raw)

    wifi = [i for i in phys if i.kind == "wifi"]
    blocked_wifi = [k for k in kills if k["type"] == "wlan"
                    and (k["soft"] or k["hard"])]
    names = ", ".join(f"{i.label} {i.name}" + (f" ({i.driver})" if i.driver
                                                 else "") for i in phys)
    if wifi and blocked_wifi and len(wifi) == len(phys):
        hard = any(k["hard"] for k in blocked_wifi)
        return _r(cid, title, Status.FAIL,
                  "Wi-Fi is turned off" + (" by a hardware switch / Fn key."
                                           if hard else " (airplane mode or "
                                           "software switch)."),
                  "Use the laptop's Wi-Fi switch / Fn key." if hard else
                  "Turn off airplane mode or run `rfkill unblock wifi`.", raw)
    if nm["available"] and nm["wifi"] == "disabled" and \
            len(wifi) == len(phys):
        return _r(cid, title, Status.FAIL,
                  "Wi-Fi is disabled in NetworkManager.",
                  "Enable Wi-Fi in the network menu or run `nmcli radio "
                  "wifi on`.", raw)
    note = ""
    if blocked_wifi:
        note = " Wi-Fi radio is switched off."
    return _r(cid, title, Status.PASS, f"Found: {names}.{note}", raw=raw)


# --------------------------------------------------------------------------
# 2. Link
# --------------------------------------------------------------------------

def _link_up(ctx: Ctx, i: net.Iface) -> tuple[bool, str]:
    """(has_link, description) for one physical interface."""
    if not i.admin_up:
        return False, f"{i.name}: disabled (interface is down)"
    if i.kind == "wifi":
        w = net.wifi_link(ctx, i.name)
        ctx.state.setdefault("_wifi", {})[i.name] = w
        if w["connected"] or (w["ssid"] is None and i.operstate == "up"):
            bits = [f"connected to “{w['ssid']}”" if w["ssid"]
                    else "connected"]
            if w["signal"] is not None:
                bits.append(f"signal {w['signal']} dBm")
            band = net.wifi_band(w["freq"])
            if band:
                bits.append(band)
            return True, f"Wi-Fi {i.name}: " + ", ".join(bits)
        return False, f"Wi-Fi {i.name}: not connected to any network"
    if i.carrier:
        speed = f", {i.speed_mbps} Mbit/s" if i.speed_mbps else ""
        duplex = f" {i.duplex} duplex" if i.duplex and i.duplex != \
            "unknown" else ""
        return True, f"{i.label} {i.name}: cable connected{speed}{duplex}"
    if i.kind == "mobile" and i.operstate == "up":
        return True, f"Mobile {i.name}: connected"
    return False, f"{i.label} {i.name}: no cable / no carrier"


def check_link(ctx: Ctx) -> CheckResult:
    cid, title = "conn.link", "Physical link"
    phys = [i for i in net.interfaces(ctx) if i.physical]
    if not phys:
        return _r(cid, title, Status.FAIL, "No network adapter to connect.")
    up = net.uplink(ctx)
    lines, linked = [], []
    for i in phys:
        ok, text = _link_up(ctx, i)
        lines.append(text)
        if ok:
            linked.append(i)
    ctx.state["linked"] = [i.name for i in linked]
    nm = net.nm_state(ctx)
    raw = "\n".join(lines) + "\n\n" + nm.get("raw", "")
    for w in ctx.state.get("_wifi", {}).values():
        raw += "\n\n" + w["raw"]
    if not linked:
        has_wifi = any(i.kind == "wifi" for i in phys)
        has_eth = any(i.kind == "ethernet" for i in phys)
        fixes = []
        if has_eth:
            fixes.append("check the cable at both ends and the router's "
                         "port lights")
        if has_wifi:
            fixes.append("connect to your Wi-Fi network from the network "
                         "menu (or `nmcli device wifi connect <SSID> "
                         "password <pw>`)")
        down = [i.name for i in phys if not i.admin_up]
        if down:
            fixes.append("enable the interface: `sudo ip link set "
                         f"{down[0]} up`")
        return _r(cid, title, Status.FAIL,
                  "No active connection: " + "; ".join(lines) + ".",
                  "To fix: " + "; ".join(fixes) + ".", raw)
    main = next((i for i in linked if i.name == up.dev), linked[0])
    summary = next(t for t in lines if f" {main.name}:" in t)
    w = ctx.state.get("_wifi", {}).get(main.name)
    if w and w.get("signal") is not None and w["signal"] < -80:
        tip = ("Move closer to the router, or use a cable."
               if net.wifi_band(w.get("freq")) != "2.4 GHz" else
               "Move closer to the router; the 5 GHz network is faster "
               "but has a shorter range, so a cable may be best.")
        return _r(cid, title, Status.WARN,
                  summary + " — the signal is too weak for a stable "
                  "connection.", tip, raw, signal=w["signal"])
    if main.kind == "ethernet" and main.duplex == "half":
        return _r(cid, title, Status.WARN,
                  summary + " — half duplex causes errors and slowness.",
                  "Replace the cable or try another router port.", raw)
    return _r(cid, title, Status.PASS, summary, raw=raw)


# --------------------------------------------------------------------------
# 3. IP address
# --------------------------------------------------------------------------

def check_ip(ctx: Ctx) -> CheckResult:
    cid, title = "conn.ip", "IP address"
    if net.ip_tool_missing(ctx):
        return _r(cid, title, Status.SKIP,
                  "Cannot read IP addresses: the `ip` tool (iproute2) is "
                  "not installed.", "Install it: `sudo apt install "
                  "iproute2`.")
    up = net.uplink(ctx)
    cand = [i for i in net.relevant_interfaces(ctx)
            if i.operstate in ("up", "unknown", "dormant") or i.carrier]
    if not cand:
        return _r(cid, title, Status.FAIL,
                  "No connected interface, so no IP address.",
                  "Fix the physical link first.")
    lines, good, apipa = [], [], []
    for i in cand:
        v4 = [a for a in i.ipv4 if not a.startswith("169.254.")]
        ll = [a for a in i.ipv4 if a.startswith("169.254.")]
        if v4 or i.ipv6:
            good.append(i)
            lines.append(f"{i.name}: " + ", ".join(v4 + i.ipv6[:1]))
        elif ll:
            apipa.append(i)
            lines.append(f"{i.name}: only {ll[0]} (self-assigned)")
        else:
            lines.append(f"{i.name}: no address")
    raw = "\n".join(lines)
    if good:
        main = next((i for i in good if i.name == up.dev), good[0])
        v4 = [a for a in main.ipv4 if not a.startswith("169.254.")]
        if not v4 and main.kind != "vpn":
            return _r(cid, title, Status.WARN,
                      f"{main.name} has only an IPv6 address — sites without "
                      "IPv6 won't open.",
                      "The router's DHCP did not give an IPv4 address: "
                      "reconnect, or restart the router.", raw)
        return _r(cid, title, Status.PASS,
                  f"{main.name}: {', '.join(v4 + main.ipv6[:1])}", raw=raw)
    if apipa:
        return _r(cid, title, Status.FAIL,
                  f"{apipa[0].name} did not get an address from the router "
                  "(DHCP failed) and assigned itself 169.254.x.x.",
                  "Reconnect to the network; if it repeats, restart the "
                  "router. On a static setup, check the IP settings in "
                  "the connection profile.", raw)
    return _r(cid, title, Status.FAIL,
              "Connected, but no IP address was assigned (DHCP is not "
              "answering).",
              "Reconnect (`nmcli device reapply <iface>` or toggle the "
              "connection); restart the router if it persists.", raw)


# --------------------------------------------------------------------------
# 4. Route
# --------------------------------------------------------------------------

def check_route(ctx: Ctx) -> CheckResult:
    cid, title = "conn.route", "Route to the internet"
    up = net.uplink(ctx)
    raw = up.raw
    if up.dev is None:
        if up.v6_dev:
            return _r(cid, title, Status.WARN,
                      f"No IPv4 route; only IPv6 via {up.v6_dev}.",
                      "Most sites still need IPv4 — reconnect so DHCP sets "
                      "a default gateway.", raw)
        return _r(cid, title, Status.FAIL,
                  "The system has no route to the internet ("
                  + (up.error or "no default gateway") + ").",
                  "The connection did not set a default gateway. Reconnect; "
                  "on a static setup, add the router's address as gateway.",
                  raw)
    itf = net.find_iface(ctx, up.dev)
    kind = itf.label if itf else "?"
    via = f" via router {up.gateway}" if up.gateway else ""
    summary = f"Internet traffic goes through {kind} {up.dev}{via}."
    if itf is not None and itf.kind == "vpn":
        phys = net.physical_uplink(ctx)
        return _r(cid, title, Status.PASS,
                  summary + " A VPN is active — all traffic is tunnelled"
                  + (f" over {phys.name}." if phys else "."), raw=raw,
                  vpn=up.dev)
    if itf is not None and itf.kind == "virtual":
        return _r(cid, title, Status.WARN,
                  summary + " This is a virtual interface — unusual "
                  "for a desktop.",
                  "Check for a leftover VM/container route: `ip route`.",
                  raw)
    return _r(cid, title, Status.PASS, summary, raw=raw)


# --------------------------------------------------------------------------
# 5. Router (gateway)
# --------------------------------------------------------------------------

def check_gateway(ctx: Ctx) -> CheckResult:
    cid, title = "conn.gateway", "Router (gateway)"
    up = net.uplink(ctx)
    if up.dev is None:
        return _r(cid, title, Status.FAIL, "No gateway is configured.",
                  "Fix the route first.")
    if not up.gateway:
        return _r(cid, title, Status.PASS,
                  f"{up.dev} is a point-to-point link (no router to check).")
    st = net.latency(ctx, up.gateway, count=4, tcp_port=80)
    neigh = net.neighbor_state(ctx, up.gateway, up.dev)
    raw = st.raw + f"\n\nARP/neighbour state of {up.gateway}: " + \
        (neigh or "none")
    metrics = {"rtt_ms": st.avg_ms, "loss_pct": st.loss_pct}
    if st.ok:
        summary = (f"Router {up.gateway} answers: {net.fmt_ms(st.avg_ms)}, "
                   f"{st.loss_pct:.0f}% loss.")
        if st.loss_pct >= 25:
            return _r(cid, title, Status.WARN, summary,
                      "Packets are lost between you and the router — weak "
                      "Wi-Fi or a bad cable.", raw, **metrics)
        return _r(cid, title, Status.PASS, summary, raw=raw, **metrics)
    if neigh in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"):
        return _r(cid, title, Status.PASS,
                  f"Router {up.gateway} is present on the network (ARP "
                  "OK) but ignores ping.", raw=raw, **metrics)
    return _r(cid, title, Status.FAIL,
              f"Router {up.gateway} does not respond"
              + (" (ARP failed — it is not on this network)."
                 if neigh in ("FAILED", "INCOMPLETE") else "."),
              "Check that the router is powered on; reboot it. If you use a "
              "static IP, check the gateway address.", raw, **metrics)


# --------------------------------------------------------------------------
# 6. Internet (IP level, no DNS)
# --------------------------------------------------------------------------

def check_internet(ctx: Ctx) -> CheckResult:
    cid, title = "conn.internet", "Internet reachability"
    lines, ok_rtts, reasons = [], [], []
    for ip, name in net.INTERNET_ANCHORS:
        rtt, why = net.tcp_connect(ip, 443, timeout=3.0)
        if rtt is not None:
            ok_rtts.append(rtt)
            lines.append(f"{name} {ip}:443 — {net.fmt_ms(rtt)}")
        else:
            reasons.append(why)
            lines.append(f"{name} {ip}:443 — {why}")
    up = net.uplink(ctx)
    v6_note = ""
    if up.v6_dev:
        rtt6, why6 = net.tcp_connect("2606:4700:4700::1111", 443, 3.0,
                                     socket.AF_INET6)
        lines.append("Cloudflare IPv6 :443 — "
                     + (net.fmt_ms(rtt6) if rtt6 is not None else why6))
        if rtt6 is None and ok_rtts:
            v6_note = "IPv6 is configured but does not work"
    raw = "\n".join(lines)
    if ok_rtts:
        best = min(ok_rtts)
        summary = (f"Internet servers are reachable ({len(ok_rtts)}/"
                   f"{len(net.INTERNET_ANCHORS)}, {net.fmt_ms(best)}).")
        if v6_note:
            return _r(cid, title, Status.WARN, summary + f" {v6_note}.",
                      "Broken IPv6 makes some sites load slowly or not at "
                      "all. Ask the ISP, or disable IPv6 in the connection "
                      "settings (IPv6 → Disabled).", raw, rtt_ms=best)
        return _r(cid, title, Status.PASS, summary, raw=raw, rtt_ms=best)
    proxy = net.proxy_env()
    if proxy:
        return _r(cid, title, Status.WARN,
                  "Direct internet access is blocked; a proxy is "
                  "configured (" + ", ".join(f"{k}={v}" for k, v in
                                              proxy.items()) + ").",
                  "Normal for corporate networks. Apps that ignore the "
                  "proxy will not work.", raw)
    if any("unreachable" in r.lower() for r in reasons):
        why = "the system has no usable route"
    else:
        why = "the router does not pass traffic onward"
    return _r(cid, title, Status.FAIL,
              f"The local network works, but the internet does not: {why}.",
              "The problem is between your router and the ISP: check the "
              "router's internet/WAN light, reboot the router and modem, "
              "check that the ISP account is paid; then call the ISP.",
              raw)


# --------------------------------------------------------------------------
# 7. DNS
# --------------------------------------------------------------------------

def check_dns(ctx: Ctx) -> CheckResult:
    cid, title = "conn.dns", "Name resolution (DNS)"
    servers, raw_cfg = net.upstream_dns_servers(ctx)
    names = ("example.com", "www.wikipedia.org")
    resolved, times, errors = {}, [], []
    for name in names:
        addrs, ms, err = net.system_resolve(name)
        times.append(ms)
        if addrs:
            resolved[name] = addrs[0]
        else:
            errors.append(f"{name}: {err}")
    direct = [net.dns_query(s, "example.com") for s in servers[:4]]
    public = net.dns_query(net.PUBLIC_DNS[0], "example.com")
    lines = [raw_cfg, "", "System resolver:"]
    lines += [f"  {n} → {resolved.get(n, '—')}" for n in names]
    lines += [f"  {e}" for e in errors]
    lines.append("Direct queries (example.com A):")
    for a in direct + [public]:
        lines.append(f"  {a.server}: " + (f"{a.rcode_name} {net.fmt_ms(a.ms)}"
                                          if a.ok else a.error))
    raw = "\n".join(lines)
    dead = [a.server for a in direct if not a.ok]
    avg = sum(times) / len(times)
    srv = ", ".join(servers) or "none"
    if len(resolved) == len(names):
        summary = f"Names resolve ({net.fmt_ms(avg)}) using DNS {srv}."
        if dead and len(dead) < len(direct):
            return _r(cid, title, Status.WARN,
                      summary + f" Not answering: {', '.join(dead)}.",
                      "One of your DNS servers is dead, which causes "
                      "random delays. Remove it or use 1.1.1.1 / 8.8.8.8.",
                      raw, dns_ms=avg)
        if avg > 500:
            return _r(cid, title, Status.WARN,
                      summary + " Lookups are slow.",
                      "Slow DNS makes every new site open with a delay. "
                      "Try DNS 1.1.1.1 or 8.8.8.8 in the connection "
                      "settings.", raw, dns_ms=avg)
        return _r(cid, title, Status.PASS, summary, raw=raw, dns_ms=avg)
    change_dns = ("Set DNS to 1.1.1.1 and 8.8.8.8: Settings → Network → "
                  "your connection → IPv4 → DNS (turn off Automatic), "
                  "or `nmcli connection modify <name> ipv4.dns "
                  "\"1.1.1.1 8.8.8.8\" ipv4.ignore-auto-dns yes`, then "
                  "reconnect.")
    if not servers:
        return _r(cid, title, Status.FAIL,
                  "No DNS server is configured, so names can't be "
                  "resolved.", change_dns, raw)
    if public.ok and (not direct or all(not a.ok for a in direct)):
        return _r(cid, title, Status.FAIL,
                  f"Your DNS server ({srv}) does not answer, but public DNS "
                  "works.", change_dns, raw)
    if any(a.ok for a in direct):
        stub = any(s in net.RESOLVED_STUB
                   for s in net.resolv_conf_servers(ctx))
        if stub:
            return _r(cid, title, Status.FAIL,
                      "The DNS server answers, but the local resolver "
                      "(systemd-resolved) does not.",
                      "Restart it: `sudo systemctl restart "
                      "systemd-resolved`.", raw)
        return _r(cid, title, Status.FAIL,
                  "The DNS server answers direct queries, but the system "
                  "cannot resolve names.",
                  "Check the `hosts:` line in /etc/nsswitch.conf and any "
                  "firewall/VPN that filters DNS for applications.", raw)
    return _r(cid, title, Status.FAIL,
              "No DNS server answers, not even public ones — DNS traffic "
              "(port 53) is blocked.",
              "A firewall/router blocks DNS. Check firewall rules (`sudo "
              "ufw status`), or the router's parental-control settings.",
              raw)


# --------------------------------------------------------------------------
# 8. Web (HTTP/HTTPS, captive portal, clock)
# --------------------------------------------------------------------------

def _fetch(url: str, timeout: float = 6.0):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(4096)
        return resp.status, dict(resp.headers), body, ""
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), b"", ""
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return None, {}, b"", "certificate: " + (
                reason.verify_message or str(reason))
        if isinstance(reason, BaseException):
            return None, {}, b"", net.os_reason(reason)
        return None, {}, b"", str(reason)
    except (OSError, ValueError) as exc:
        return None, {}, b"", net.os_reason(exc)


def check_web(ctx: Ctx) -> CheckResult:
    cid, title = "conn.web", "Websites (HTTP/HTTPS)"
    lines = []
    code, headers, body, err = _fetch("http://connectivity-check.ubuntu.com/")
    lines.append(f"GET http://connectivity-check.ubuntu.com/ → {code or err}")
    captive = False
    if code is not None and code != 204:
        captive = True
        loc = headers.get("Location") or headers.get("location") or ""
        lines.append(f"  unexpected answer (expected 204) {loc}")
    code2, headers2, body2, err2 = _fetch(
        "https://www.cloudflare.com/cdn-cgi/trace")
    lines.append(f"GET https://www.cloudflare.com/cdn-cgi/trace → "
                 f"{code2 or err2}")
    info = {}
    if body2:
        for line in body2.decode("utf-8", "replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v
        lines.append("  " + ", ".join(f"{k}={info[k]}" for k in
                                       ("ip", "loc", "colo") if k in info))
    clock_note = ""
    date_hdr = headers2.get("Date") or headers2.get("date")
    if date_hdr:
        try:
            server_time = email.utils.parsedate_to_datetime(date_hdr)
            skew = (datetime.datetime.now(datetime.timezone.utc)
                    - server_time).total_seconds()
            lines.append(f"  clock skew vs server: {skew:+.0f} s")
            if abs(skew) > 300:
                clock_note = (f"Your system clock is off by "
                              f"{abs(skew) / 60:.0f} minutes. ")
        except (TypeError, ValueError):
            pass
    raw = "\n".join(lines)
    ip_note = ""
    if info.get("ip"):
        ip_note = f" Public IP {info['ip']}" + (
            f" ({info['loc']})" if info.get("loc") else "") + "."
    if captive and code2 != 200:
        return _r(cid, title, Status.FAIL,
                  "This network requires a login page (captive portal: "
                  "hotel/café/office Wi-Fi).",
                  "Open any http:// site in the browser (e.g. "
                  "http://neverssl.com) and sign in on the page that "
                  "appears.", raw)
    if code2 == 200:
        if clock_note:
            return _r(cid, title, Status.WARN,
                      "Websites open." + ip_note + " " + clock_note.strip(),
                      "A wrong clock breaks HTTPS on many sites: enable "
                      "automatic time (Settings → Date & Time) or `sudo "
                      "timedatectl set-ntp true`.", raw,
                      public_ip=info.get("ip"))
        return _r(cid, title, Status.PASS,
                  "Websites open over HTTP and HTTPS." + ip_note, raw=raw,
                  public_ip=info.get("ip"), location=info.get("loc"))
    if err2.startswith("certificate"):
        return _r(cid, title, Status.FAIL,
                  "HTTPS connections fail certificate checks (" + err2 +
                  "). " + clock_note,
                  "Either the system clock is wrong (enable automatic time) "
                  "or something intercepts HTTPS — antivirus, corporate "
                  "proxy or a captive portal.", raw)
    if code == 204:
        return _r(cid, title, Status.WARN,
                  f"Plain HTTP works but HTTPS does not ({err2}).",
                  "Something blocks or intercepts HTTPS (port 443): check "
                  "firewall, antivirus or proxy settings.", raw)
    return _r(cid, title, Status.FAIL,
              f"Websites do not open ({err2 or err}).",
              "If the steps above are OK, a firewall or proxy blocks web "
              "traffic — check `sudo ufw status` and the proxy settings.",
              raw)


# --------------------------------------------------------------------------
# Suite API
# --------------------------------------------------------------------------

def make_checks(ctx: Ctx | None = None) -> list[Check]:
    return [
        Check("conn.adapter", "Network adapter", check_adapter),
        Check("conn.link", "Physical link", check_link),
        Check("conn.ip", "IP address", check_ip),
        Check("conn.route", "Route to the internet", check_route),
        Check("conn.gateway", "Router (gateway)", check_gateway),
        Check("conn.internet", "Internet reachability", check_internet),
        Check("conn.dns", "Name resolution (DNS)", check_dns),
        Check("conn.web", "Websites (HTTP/HTTPS)", check_web),
    ]


def overview(ctx: Ctx) -> dict:
    """Compact facts for the header card: what the machine is connected to."""
    up = net.uplink(ctx)
    itf = net.find_iface(ctx, up.dev)
    phys = net.physical_uplink(ctx)
    via = phys or itf
    out = {"interface": None, "type": None, "network": None, "ip": None,
           "gateway": up.gateway, "dns": None, "vpn": None, "proxy": None,
           "root": ctx.is_root}
    if via is not None:
        out["interface"] = via.name
        out["type"] = via.label
        v4 = [a for a in via.ipv4 if not a.startswith("169.254.")]
        first = (v4 or via.ipv6 or [None])[0]
        out["ip"] = first.split("/", 1)[0] if first else None
        if via.kind == "wifi":
            w = net.wifi_link(ctx, via.name)
            if w["ssid"]:
                out["network"] = w["ssid"]
        elif via.kind == "ethernet" and via.speed_mbps:
            out["network"] = f"{via.speed_mbps} Mbit/s"
    if itf is not None and itf.kind == "vpn":
        out["vpn"] = itf.name
    servers, _ = net.upstream_dns_servers(ctx)
    out["dns"] = ", ".join(servers[:3]) or None
    proxy = net.proxy_env()
    if proxy:
        out["proxy"] = next(iter(proxy.values()))
    return out


def analyze(results: list[CheckResult], ctx: Ctx | None = None) -> Verdict:
    steps, broken, degraded = chain_verdict(results, CHAIN)
    if broken is not None and broken.check is not None:
        c = broken.check
        later = [s.label for s in steps[steps.index(broken) + 1:]
                 if s.check and s.check.status is Status.FAIL]
        detail = c.summary
        if later:
            detail += (" Because of this, the later steps fail too ("
                       + ", ".join(later) + ") — they are not separate "
                       "problems.")
        return Verdict("fail", f"No internet: problem at “{broken.label}”.",
                       detail, [c.suggestion] if c.suggestion else [],
                       steps, c.check_id)
    if degraded is not None and degraded.check is not None:
        c = degraded.check
        return Verdict("warn", "Internet works, but there is a problem at "
                       f"“{degraded.label}”.", c.summary,
                       [c.suggestion] if c.suggestion else [], steps,
                       c.check_id)
    if all(s.status is Status.PASS for s in steps):
        web = next((s.check for s in steps if s.step_id == "conn.web"), None)
        return Verdict("ok", "Internet connection works.",
                       "Every step from the adapter to websites is fine. If "
                       "it is slow, use the Speed tab; if one site does not "
                       "open, check it on the Website tab."
                       + (" " + web.summary.split(". ", 1)[-1]
                          if web and "Public IP" in web.summary else ""),
                       [], steps)
    return Verdict("unknown", "Could not finish the check.", "", [], steps)
