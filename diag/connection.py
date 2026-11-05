"""Suite 1 — "Why is there no internet connection?"

Walks the path a packet takes from this machine to a website, one link at a
time. The first broken link is the root cause; everything after it is a
symptom. Only interfaces that can carry internet traffic are inspected —
Docker bridges, veths, libvirt/VirtualBox networks etc. are ignored.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request

from nwsolver import __version__
from nwsolver.diag import clock, net, portal
from nwsolver.diag.verdict import (Verdict, chain_confidence, chain_verdict,
                                   collect_notes)
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
    ("conn.portal", "Login page"),
    ("conn.internet", "Internet"),
    ("conn.dns", "DNS"),
    ("conn.clock", "Clock"),
    ("conn.web", "Web"),
]

_UA = f"nwsolver/{__version__} (network diagnostics)"


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
            d = net.wifi_details(ctx, i.name)
            if d.get("channel"):
                bits.append(f"channel {d['channel']}"
                            + (f" ({d['width']} MHz)" if d.get("width")
                               else ""))
            if d.get("security"):
                bits.append("no password (open network)"
                            if net.wifi_is_open(d) else d["security"])
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
    for d in ctx.state.get("_wifi_details", {}).values():
        raw += "\n\n" + d.get("raw", "")
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
    vpn = net.vpn_uplink(ctx)
    gw_ip, gw_dev, note = up.gateway, up.dev, ""
    if vpn is not None:
        # Under a VPN check the real (hotel/home) router, not the tunnel.
        gw_dev, gw_ip = net.physical_gateway(ctx)
        note = f" (the network under the VPN {vpn.name})"
        if not gw_ip:
            return _r(cid, title, Status.PASS,
                      f"Traffic goes through the VPN {vpn.name}; the router "
                      "under it could not be identified.")
    elif not gw_ip:
        return _r(cid, title, Status.PASS,
                  f"{up.dev} is a point-to-point link (no router to check).")
    up = net.Uplink(dev=gw_dev, gateway=gw_ip)
    st = net.latency(ctx, up.gateway, count=4, tcp_port=80)
    neigh = net.neighbor_state(ctx, up.gateway, up.dev)
    raw = st.raw + f"\n\nARP/neighbour state of {up.gateway}: " + \
        (neigh or "none")
    metrics = {"rtt_ms": st.avg_ms, "loss_pct": st.loss_pct}
    if st.ok:
        summary = (f"Router {up.gateway}{note} answers: "
                   f"{net.fmt_ms(st.avg_ms)}, {st.loss_pct:.0f}% loss.")
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
# 5b. Captive portal (hotel / café / office Wi-Fi login page)
# --------------------------------------------------------------------------

def _mac_note(ctx: Ctx) -> str:
    itf = net.physical_uplink(ctx)
    if itf is None or itf.kind != "wifi":
        return ""
    conn, policy = net.mac_policy(ctx, itf.name)
    if policy == "random":
        return (f"The Wi-Fi profile “{conn}” uses a new random MAC address "
                "on every connection, so the hotel will ask you to sign in "
                "again after each reconnect. To keep the login: `nmcli "
                f"connection modify \"{conn}\" "
                "802-11-wireless.cloned-mac-address stable`.")
    return ""


def check_portal(ctx: Ctx) -> CheckResult:
    cid, title = "conn.portal", "Login page (captive portal)"
    res = portal.detect(ctx)
    if res.state == "portal":
        names = ", ".join(p.name for p in res.intercepted) or \
            "NetworkManager"
        note = _mac_note(ctx)
        return _r(cid, title, Status.FAIL,
                  "This network requires signing in on a login page "
                  "(captive portal) before it lets you onto the internet. "
                  f"Intercepted checks: {names}.",
                  portal.login_hint(res), res.raw, login_url=res.login_url,
                  note=note)
    if res.state == "none":
        filtered = [p.name for p in res.intercepted]
        note = (f" (the {filtered[0]} check address is filtered — normal "
                "with ad/DNS filters)" if filtered else "")
        return _r(cid, title, Status.PASS,
                  "No login page — the network lets traffic through."
                  + note, raw=res.raw)
    if res.under_vpn:
        page = (f" The router's page {res.gateway_page} answers — it may "
                "be the hotel's login page." if res.gateway_page else "")
        return _r(cid, title, Status.SKIP,
                  f"Could not check for a login page: the checks went into "
                  f"the VPN {res.under_vpn} and got no answer." + page,
                  raw=res.raw, login_url=res.gateway_page)
    return _r(cid, title, Status.SKIP,
              "Could not check for a login page: no web check address "
              "answered.", raw=res.raw)


# --------------------------------------------------------------------------
# 5c. Network security (not part of the chain — shown as a note)
# --------------------------------------------------------------------------

def check_security(ctx: Ctx) -> CheckResult:
    cid, title = "conn.security", "Network security"
    itf = net.physical_uplink(ctx)
    bits, notes = [], []
    if itf is not None and itf.kind == "wifi":
        d = net.wifi_details(ctx, itf.name)
        if net.wifi_is_open(d):
            notes.append("This Wi-Fi has no password: people nearby can "
                         "see unencrypted traffic. Use only https:// sites "
                         "and, ideally, a VPN.")
        elif d.get("security"):
            bits.append(f"Wi-Fi encryption: {d['security']}")
        if d.get("bssid"):
            bits.append(f"access point {d['bssid']}")
    proxy = net.proxy_env()
    if proxy:
        notes.append("A proxy is configured, so web traffic passes through "
                     f"{next(iter(proxy.values()))}. Make sure you set it "
                     "up yourself.")
    if not bits and not notes:
        return _r(cid, title, Status.SKIP,
                  "Wired connection — nothing to check.")
    summary = "; ".join(bits) + ("." if bits else "")
    if notes:
        return _r(cid, title, Status.WARN, (summary + " " if summary else "")
                  + " ".join(notes), raw=summary, note=" ".join(notes))
    return _r(cid, title, Status.PASS, summary)


# --------------------------------------------------------------------------
# 5d. UDP (video calls, WireGuard / OpenVPN-UDP) — a note, not a chain step
# --------------------------------------------------------------------------

def check_udp(ctx: Ctx) -> CheckResult:
    cid, title = "conn.udp", "UDP traffic (calls, VPN)"
    if portal.detect(ctx).state == "portal":
        return _r(cid, title, Status.SKIP, "Not tested before signing in "
                  "on the network's login page.")
    tcp_ok = any(net.tcp_connect(ip, 443, 3.0)[0] is not None
                 for ip, _n in net.INTERNET_ANCHORS[:2])
    stun = net.stun_probe()
    vpn = net.vpn_uplink(ctx)
    via = f" (tested through the VPN {vpn.name})" if vpn is not None else ""
    if stun.ok:
        return _r(cid, title, Status.PASS,
                  f"UDP works{via}: video calls and UDP-based VPNs can "
                  "connect.", raw=stun.raw, udp_ok=True)
    if not tcp_ok:
        return _r(cid, title, Status.SKIP,
                  "Not tested — there is no internet connection at all.",
                  raw=stun.raw)
    note = ("This network blocks UDP traffic" + via + ": video calls fall "
            "back to slower relays (more lag), and VPNs using UDP "
            "(WireGuard, OpenVPN-UDP, most VPN apps by default) won't "
            "connect. Switch the VPN to TCP / port 443 mode (often called "
            "“TCP”, “Stealth” or “OpenVPN TCP”).")
    return _r(cid, title, Status.WARN, note, raw=stun.raw, udp_ok=False,
              note=note)


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
    v4 = f"IPv4 {len(ok_rtts)}/{len(net.INTERNET_ANCHORS)}"
    v6_state = "not available on this network"
    rtt6 = None
    if up.v6_dev:
        rtt6, why6 = net.tcp_connect("2606:4700:4700::1111", 443, 3.0,
                                     socket.AF_INET6)
        rtt6b, _ = (None, "") if rtt6 is not None else net.tcp_connect(
            "2001:4860:4860::8888", 443, 3.0, socket.AF_INET6)
        rtt6 = rtt6 if rtt6 is not None else rtt6b
        lines.append("IPv6 Cloudflare/Google :443 — "
                     + (net.fmt_ms(rtt6) if rtt6 is not None else why6))
        v6_state = "works" if rtt6 is not None else "configured but broken"
    raw = "\n".join(lines)
    m = {"ipv4_ok": bool(ok_rtts), "ipv6": v6_state}
    if ok_rtts:
        best = min(ok_rtts)
        summary = (f"Internet servers are reachable — IPv4: works "
                   f"({len(ok_rtts)}/{len(net.INTERNET_ANCHORS)}, "
                   f"{net.fmt_ms(best)}); IPv6: {v6_state}.")
        if v6_state == "configured but broken":
            m["headline"] = ("Internet works, but IPv6 is broken — some "
                             "sites may load slowly.")
            return _r(cid, title, Status.WARN, summary,
                      "Broken IPv6 makes some sites load slowly or not at "
                      "all, because apps try IPv6 first and wait. Ask the "
                      "network/ISP, or disable IPv6 for this connection "
                      "(Settings → Network → IPv6 → Disable).", raw,
                      rtt_ms=best, **m)
        return _r(cid, title, Status.PASS, summary, raw=raw, rtt_ms=best,
                  **m)
    if rtt6 is not None:
        return _r(cid, title, Status.WARN,
                  f"Only IPv6 works ({v4} failed). Sites without IPv6 will "
                  "not open.",
                  "The network gives no working IPv4 internet: reconnect; "
                  "if it persists, ask the network operator.", raw, **m)
    proxy = net.proxy_env()
    if proxy:
        return _r(cid, title, Status.WARN,
                  "Direct internet access is blocked; a proxy is "
                  "configured (" + ", ".join(f"{k}={v}" for k, v in
                                              proxy.items()) + ").",
                  "Normal for corporate networks. Apps that ignore the "
                  "proxy will not work.", raw)
    vpn = net.vpn_uplink(ctx)
    if vpn is not None:
        pres = portal.detect(ctx)
        m["confidence"] = "confirmed"
        page = (f" The local router's page {pres.gateway_page} answers — "
                "if this is a hotel/café network, its login page may be "
                "what blocks the VPN." if pres.gateway_page else "")
        return _r(cid, title, Status.FAIL,
                  f"The VPN ({vpn.name}) is on, but nothing passes through "
                  "the tunnel — the VPN server is unreachable from this "
                  "network." + page,
                  "Turn the VPN off (VPN app, network menu, or `nmcli "
                  "connection down <vpn>` / `sudo wg-quick down "
                  f"{vpn.name}`) and run the check again. If the internet "
                  "works without it: sign in on the network's login page "
                  "first, then connect the VPN; if it still fails, the "
                  "network blocks VPNs — run this check with the VPN off: "
                  "the “UDP traffic” step shows whether UDP is blocked, in "
                  "which case switch the VPN to TCP / port 443 (“Stealth”) "
                  "mode or another server/protocol.",
                  raw, vpn=vpn.name, login_url=pres.gateway_page, **m)
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
    gw = net.local_gateway(ctx)
    router = net.dns_query(gw, "example.com") if gw and ":" not in gw \
        and gw not in servers else None
    if router is not None and router.ok:
        dot = ""
        if ctx.which("resolvectl"):
            st = ctx.run(["resolvectl", "status"], timeout=5.0)
            if "+DNSOverTLS" in st.text:
                dot = " DNS-over-TLS is enabled in systemd-resolved."
        return _r(cid, title, Status.FAIL,
                  f"Your DNS ({srv}) is blocked by this network, but the "
                  f"router's own DNS ({gw}) answers.{dot} Hotel/café "
                  "networks often allow only their DNS.",
                  "Switch DNS to Automatic for this Wi-Fi: Settings → "
                  "Wi-Fi → (gear) → IPv4/IPv6 → DNS Automatic on (or "
                  "`nmcli connection modify <wifi> ipv4.ignore-auto-dns no "
                  "ipv4.dns \"\"`)"
                  + (", and disable DNS-over-TLS (`DNSOverTLS=no` in "
                     "/etc/systemd/resolved.conf, then `sudo systemctl "
                     "restart systemd-resolved`)" if dot else "")
                  + ". Reconnect afterwards.", raw)
    return _r(cid, title, Status.FAIL,
              "No DNS server answers, not even public ones — DNS traffic "
              "(port 53) is blocked.",
              "A firewall/router blocks DNS. Check firewall rules (`sudo "
              "ufw status`), or the router's parental-control settings.",
              raw)


# --------------------------------------------------------------------------
# 7b. System clock (wrong time breaks HTTPS certificates)
# --------------------------------------------------------------------------

def check_clock(ctx: Ctx) -> CheckResult:
    cid, title = "conn.clock", "System clock"
    info = clock.measure(ctx)
    tz = info.timezone or "unknown zone"
    auto = {True: "automatic time on", False: "automatic time OFF",
            None: "automatic time: unknown"}[info.ntp]
    m = {"clock_skew_s": info.skew_s, "timezone": info.timezone}
    if info.wrong:
        hint = ""
        if abs(abs(info.skew_s) % 3600) < 300 or \
                abs(abs(info.skew_s) % 3600 - 3600) < 300:
            hint = (" A whole-hour error usually means the clock was moved "
                    "by hand to the new local time instead of changing the "
                    "time zone.")
        return _r(cid, title, Status.FAIL,
                  f"The system clock is {clock.fmt_skew(info.skew_s)} "
                  f"(time zone {tz}, {auto}). HTTPS certificates are "
                  "rejected when the clock is wrong, so secure sites fail."
                  + hint, clock.fix_steps(info), info.raw, **m)
    if info.skew_s is None:
        if info.ntp is False:
            return _r(cid, title, Status.WARN,
                      f"Could not compare with real time; automatic time "
                      f"is OFF (time zone {tz}).",
                      clock.fix_steps(info), info.raw, **m)
        return _r(cid, title, Status.SKIP,
                  "Could not compare the clock with real time (no web "
                  "server answered).", raw=info.raw, **m)
    if info.local_rtc:
        return _r(cid, title, Status.WARN,
                  f"Clock is correct now, but the hardware clock keeps local "
                  f"time — it will jump after reboots or zone changes "
                  f"(zone {tz}).", clock.fix_steps(info), info.raw, **m)
    return _r(cid, title, Status.PASS,
              f"Clock is correct (±{abs(info.skew_s):.0f} s), zone {tz}, "
              f"{auto}.", raw=info.raw, **m)


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
    pres = portal.detect(ctx)
    if pres.state == "portal":
        return _r(cid, title, Status.FAIL,
                  "Websites are held back by the network's login page.",
                  portal.login_hint(pres), pres.raw,
                  login_url=pres.login_url)
    http_ok = [p for p in pres.probes if p.outcome == "ok"]
    code = 204 if http_ok else None
    err = "" if http_ok else (pres.probes[0].detail if pres.probes
                              else "no answer")
    lines.append("plain HTTP: " + (f"OK via {http_ok[0].name}" if http_ok
                                   else err))
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
    cinfo = clock.measure(ctx)
    clock_note = (f"Your system clock is {clock.fmt_skew(cinfo.skew_s)}. "
                  if cinfo.wrong else "")
    region = _region_note(ctx, info.get("loc", ""), cinfo.timezone)
    if region:
        lines.append("  " + region)
    raw = "\n".join(lines)
    ip_note = ""
    if info.get("ip"):
        ip_note = f" Public IP {info['ip']}" + (
            f" ({info['loc']})" if info.get("loc") else "") + "."
    dest = _destinations() if code2 == 200 else []
    blocked = [n for n, ok, _ in dest if not ok]
    for n, ok, why in dest:
        lines.append(f"  {n}: {'OK' if ok else why}")
    raw = "\n".join(lines)
    if code2 == 200 and blocked and len(blocked) < len(dest):
        return _r(cid, title, Status.WARN,
                  f"The internet is only partly available: "
                  f"{', '.join(blocked)} do not open, the other "
                  f"{len(dest) - len(blocked)} test sites do." + ip_note,
                  "These services are blocked by the network or in this "
                  "country, or are down right now. Check one on the “Site "
                  "doesn't open” tab; a VPN may help if it is a regional "
                  "block.", raw, public_ip=info.get("ip"),
                  location=info.get("loc"), region_note=region,
                  confidence="likely",
                  headline="Internet works, but some services are "
                  "blocked.")
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
                  public_ip=info.get("ip"), location=info.get("loc"),
                  region_note=region)
    if err2.startswith("certificate"):
        if cinfo.wrong:
            return _r(cid, title, Status.FAIL,
                      "HTTPS fails certificate checks because the system "
                      f"clock is {clock.fmt_skew(cinfo.skew_s)} (" + err2 +
                      ").", clock.fix_steps(cinfo), raw)
        return _r(cid, title, Status.FAIL,
                  "HTTPS connections fail certificate checks (" + err2 +
                  "), although the clock is "
                  + ("correct" if cinfo.skew_s is not None else
                     "not verifiable") + ".",
                  "Something intercepts HTTPS — antivirus web protection, "
                  "a corporate proxy or the network itself. Check those; "
                  "on a work network ask IT.", raw)
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
        Check("conn.portal", "Login page (captive portal)", check_portal),
        Check("conn.security", "Network security", check_security),
        Check("conn.udp", "UDP traffic (calls, VPN)", check_udp),
        Check("conn.internet", "Internet reachability", check_internet),
        Check("conn.dns", "Name resolution (DNS)", check_dns),
        Check("conn.clock", "System clock", check_clock),
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
            d = net.wifi_details(ctx, via.name)
            if d.get("security"):
                out["security"] = ("open (no password)"
                                   if net.wifi_is_open(d) else d["security"])
        hs = net.hotspot_info(ctx)
        if hs:
            out["type"] = f"{out['type']} · {hs}"
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


_DESTINATIONS = (("Google", "https://www.google.com/generate_204"),
                 ("Microsoft", "https://www.microsoft.com/"),
                 ("Apple", "https://www.apple.com/"),
                 ("Wikipedia", "https://www.wikipedia.org/"),
                 ("GitHub", "https://github.com/"),
                 ("YouTube", "https://www.youtube.com/"))


def _destinations() -> list[tuple[str, bool, str]]:
    """Independent HTTPS sites in parallel: (name, reachable, reason)."""
    def one(item):
        name, url = item
        code, _h, _b, err = _fetch(url, timeout=6.0)
        return name, code is not None, err or ""
    with ThreadPoolExecutor(max_workers=len(_DESTINATIONS)) as pool:
        return list(pool.map(one, _DESTINATIONS))


def _region_note(ctx: Ctx, loc: str, tz: str) -> str:
    """Compare where traffic exits (IP country) with the time zone."""
    tzc = clock.tz_country(tz)
    loc = (loc or "").upper()
    if not loc or not tzc or loc == tzc or loc in ("XX", "T1"):
        return ""
    vpn = net.vpn_uplink(ctx)
    if vpn is not None:
        return (f"Your traffic exits in {loc} through the VPN {vpn.name}, "
                f"while the time zone is {tz} ({tzc}). If you did not mean "
                "to use the VPN here, turn it off.")
    return (f"Your public IP is in {loc}, but the time zone is still {tz} "
            f"({tzc}). If you have travelled, set the new time zone "
            "(Settings → Date & Time). A proxy or a VPN app in the browser "
            "can also cause this.")


def _login_link(results: list[CheckResult]) -> tuple[str, str] | None:
    for r in results:
        url = r.metrics.get("login_url")
        if url and r.status is Status.FAIL:
            return ("Open login page", url)
    return None


# Failures whose *cause* is an inference rather than a direct measurement.
_INFERRED = {"conn.internet", "conn.web"}


def analyze(results: list[CheckResult], ctx: Ctx | None = None) -> Verdict:
    steps, broken, degraded = chain_verdict(results, CHAIN)
    notes = collect_notes(results)
    region = next((r.metrics.get("region_note") for r in results
                   if r.metrics.get("region_note")), "")
    if region and region not in notes:
        notes.append(region)
    hotspot = net.hotspot_info(ctx) if ctx is not None else ""

    def done(v: Verdict, cause=None) -> Verdict:
        v.confidence = chain_confidence(steps, cause, _INFERRED)
        v.notes = notes
        return v

    if broken is not None and broken.check is not None:
        c = broken.check
        later = [s.label for s in steps[steps.index(broken) + 1:]
                 if s.check and s.check.status is Status.FAIL]
        detail = c.summary
        if later:
            detail += (" Because of this, the later steps fail too ("
                       + ", ".join(later) + ") — they are not separate "
                       "problems.")
        actions = [c.suggestion] if c.suggestion else []
        if hotspot and c.check_id in ("conn.ip", "conn.route",
                                      "conn.internet", "conn.dns") and \
                not c.metrics.get("vpn"):
            tips = net.hotspot_tips(hotspot, "offline")
            if c.check_id == "conn.internet":
                # "Reboot the router / call the ISP" does not apply to a phone.
                return done(Verdict(
                    "fail", "No internet: the phone's mobile connection is "
                    "not passing traffic.", detail, [tips], steps,
                    c.check_id), broken)
            actions.append(tips)
        if c.check_id == "conn.internet" and c.metrics.get("vpn"):
            url = c.metrics.get("login_url")
            return done(Verdict(
                "fail", "The VPN is on but is not working on this network.",
                detail, actions, steps, c.check_id,
                ("Open router page", url) if url else None), broken)
        if c.check_id == "conn.clock":
            return done(Verdict(
                "fail", "The system clock is wrong — secure sites fail.",
                detail, actions, steps, c.check_id), broken)
        login = _login_link(results)
        if login:
            return done(Verdict("fail", "You need to sign in to this "
                                "network.", detail, actions, steps,
                                c.check_id, login), broken)
        return done(Verdict("fail", f"No internet: problem at "
                            f"“{broken.label}”.", detail, actions, steps,
                            c.check_id), broken)
    if degraded is not None and degraded.check is not None:
        c = degraded.check
        return done(Verdict("warn", c.metrics.get("headline") or
                            "Internet works, but there is a problem at "
                            f"“{degraded.label}”.", c.summary,
                            [c.suggestion] if c.suggestion else [], steps,
                            c.check_id), degraded)
    if all(s.status in (Status.PASS, Status.SKIP) for s in steps) and \
            any(s.status is Status.PASS for s in steps):
        detail = ("Every step from the adapter to websites works. If it "
                  "is slow, use the “Slow internet” tab; if one site does "
                  "not open, check it on the “Site doesn't open” tab.")
        if hotspot:
            detail += f" Connected through a {hotspot}."
        return done(Verdict("ok", "Internet connection works.", detail, [],
                            steps))
    return done(Verdict("unknown", "Could not finish the check.", "", [],
                        steps))
