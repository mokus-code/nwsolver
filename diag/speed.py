"""Suite 2 — "Why is the internet slow?"

Measures every segment that can limit speed and names the bottleneck:

    your link (Wi-Fi signal / cable speed)  →  local network (to the router)
    →  ISP / internet path  →  real throughput and latency under load

plus things that eat bandwidth or add delay: other traffic on the same
connection, slow DNS, packet loss and retransmissions during the test.
Checks run sequentially so they don't disturb each other's measurements.
"""
from __future__ import annotations

import http.client
import os
import ssl
import statistics
import threading
import time
import urllib.parse

from nwsolver.diag import net
from nwsolver.diag.verdict import Verdict
from nwsolver.engine.checks import Check, CheckResult, Ctx, Status

SUITE_ID = "speed"
SUITE_NAME = "Speed"
SUITE_DESC = "Measures speed and latency and shows what slows the connection."
PARALLEL = False

DOWNLOAD_URLS = (
    "https://speed.cloudflare.com/__down?bytes=200000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "http://speedtest.tele2.net/100MB.zip",
)
UPLOAD_URL = "https://speed.cloudflare.com/__up"
STREAMS = 4
DOWNLOAD_SECONDS = 8.0
UPLOAD_SECONDS = 6.0
WARMUP_SECONDS = 1.0
LATENCY_HOST = "1.1.1.1"


def _r(cid, title, status, summary, fix="", raw="", **metrics):
    return CheckResult(cid, title, status, summary, raw=net.trunc(raw),
                       suggestion=fix, metrics=metrics)


def _uplink_iface(ctx: Ctx) -> net.Iface | None:
    return net.physical_uplink(ctx) or net.find_iface(ctx, net.uplink(ctx).dev)


# --------------------------------------------------------------------------
# 1. Local link capacity
# --------------------------------------------------------------------------

def check_link(ctx: Ctx) -> CheckResult:
    cid, title = "speed.link", "Your connection to the router"
    itf = _uplink_iface(ctx)
    if itf is None:
        return _r(cid, title, Status.FAIL,
                  "Not connected — see the Connection tab.")
    if itf.kind == "wifi":
        w = net.wifi_link(ctx, itf.name)
        sig, tx, rx = w["signal"], w["tx_mbps"], w["rx_mbps"]
        band = net.wifi_band(w["freq"])
        bits = [f"Wi-Fi “{w['ssid'] or '?'}”"]
        if band:
            bits.append(band)
        if sig is not None:
            bits.append(f"signal {sig} dBm")
        rate = max(x for x in (tx, rx, 0) if x is not None) or None
        if rate:
            bits.append(f"link rate {net.fmt_mbps(rate)}")
        if w["power_save"]:
            bits.append("power saving on")
        summary = ", ".join(bits) + "."
        m = {"kind": "wifi", "signal": sig, "link_mbps": rate,
             "band": band, "power_save": w["power_save"]}
        problems, fixes = [], []
        status = Status.PASS
        if sig is not None and sig < -75:
            status = Status.FAIL if sig < -82 else Status.WARN
            problems.append("weak signal")
            fixes.append("move closer to the router or remove obstacles "
                         "(walls, metal, microwave oven)")
        if rate is not None and rate < 30:
            status = Status.WARN if status is Status.PASS else status
            problems.append(f"low link rate ({net.fmt_mbps(rate)})")
        if band == "2.4 GHz" and (sig is None or sig > -65):
            if status is Status.PASS:
                status = Status.WARN
            problems.append("2.4 GHz band is usually crowded and slow")
            fixes.append("connect to the router's 5 GHz network if it has "
                         "one")
        if w["power_save"]:
            if status is Status.PASS:
                status = Status.WARN
            problems.append("Wi-Fi power saving adds latency")
            fixes.append(f"disable it: `sudo iw dev {itf.name} set "
                         "power_save off`")
        if problems:
            summary += " Problem: " + "; ".join(problems) + "."
        return _r(cid, title, status, summary,
                  ("To improve: " + "; ".join(fixes) + ".") if fixes else "",
                  w["raw"], **m)
    speed = itf.speed_mbps
    summary = f"{itf.label} {itf.name}"
    if speed:
        summary += f", {speed} Mbit/s"
    if itf.duplex and itf.duplex != "unknown":
        summary += f", {itf.duplex} duplex"
    summary += "."
    m = {"kind": itf.kind, "link_mbps": speed}
    if itf.duplex == "half":
        return _r(cid, title, Status.FAIL,
                  summary + " Half duplex — the cable or port is faulty.",
                  "Replace the cable and try another router port.", **m)
    if speed is not None and speed <= 100:
        return _r(cid, title, Status.WARN,
                  summary + f" The cable link is limited to {speed} Mbit/s.",
                  "This usually means an old/damaged cable (only 4 of 8 "
                  "wires work) or a 100 Mbit port. Use a Cat5e/Cat6 cable "
                  "and a gigabit port.", **m)
    return _r(cid, title, Status.PASS, summary, **m)


# --------------------------------------------------------------------------
# 2. Other traffic on the connection
# --------------------------------------------------------------------------

def check_background(ctx: Ctx) -> CheckResult:
    cid, title = "speed.background", "Other traffic right now"
    itf = _uplink_iface(ctx)
    if itf is None:
        return _r(cid, title, Status.SKIP, "No active connection.")
    a = net.iface_counters(ctx, itf.name)
    t0 = time.monotonic()
    time.sleep(2.0)
    b = net.iface_counters(ctx, itf.name)
    dt = time.monotonic() - t0
    rx = (b["rx_bytes"] - a["rx_bytes"]) * 8 / dt / 1e6
    tx = (b["tx_bytes"] - a["tx_bytes"]) * 8 / dt / 1e6
    ctx.state["bg_rx_mbps"], ctx.state["bg_tx_mbps"] = rx, tx
    summary = (f"This computer is already using ↓ {net.fmt_mbps(rx)} / "
               f"↑ {net.fmt_mbps(tx)} on {itf.name}.")
    raw = summary
    if ctx.which("ss"):
        res = ctx.run(["ss", "-tnpH", "state", "established"], timeout=4.0)
        procs: dict[str, int] = {}
        for line in res.text.splitlines():
            if 'users:(("' in line:
                name = line.split('users:(("', 1)[1].split('"', 1)[0]
                procs[name] = procs.get(name, 0) + 1
        if procs:
            top = sorted(procs.items(), key=lambda kv: -kv[1])[:6]
            raw += "\nPrograms with open connections: " + ", ".join(
                f"{n} ({c})" for n, c in top)
    m = {"bg_rx_mbps": rx, "bg_tx_mbps": tx}
    if rx > 2 or tx > 1:
        return _r(cid, title, Status.WARN,
                  summary + " Downloads, updates, cloud sync or streaming "
                  "share the bandwidth and slow everything else.",
                  "Pause downloads/torrents/cloud sync/updates and repeat "
                  "the test. Other devices on the same network can also "
                  "use the bandwidth.", raw, **m)
    return _r(cid, title, Status.PASS,
              summary + " Nothing else is using the connection.", raw=raw,
              **m)


# --------------------------------------------------------------------------
# 3. Local network quality (to the router)
# --------------------------------------------------------------------------

def check_lan(ctx: Ctx) -> CheckResult:
    cid, title = "speed.lan", "Local network quality (to the router)"
    up = net.uplink(ctx)
    if not up.gateway:
        return _r(cid, title, Status.SKIP,
                  "No router on this link (VPN/point-to-point) — skipped.")
    st = net.latency(ctx, up.gateway, count=20, interval=0.2, tcp_port=80)
    ctx.state["lan"] = st
    m = {"rtt_ms": st.avg_ms, "loss_pct": st.loss_pct,
         "jitter_ms": st.jitter_ms}
    if not st.ok:
        return _r(cid, title, Status.SKIP,
                  f"Router {up.gateway} does not answer ping — local "
                  "quality could not be measured.", raw=st.raw, **m)
    itf = _uplink_iface(ctx)
    wifi = itf is not None and itf.kind == "wifi"
    summary = (f"Router {up.gateway}: {net.fmt_ms(st.avg_ms)} average, "
               f"jitter {net.fmt_ms(st.jitter_ms)}, "
               f"{st.loss_pct:.0f}% loss.")
    lim_rtt = 30 if wifi else 5
    where = "Wi-Fi" if wifi else "cable/switch"
    if st.loss_pct >= 10:
        return _r(cid, title, Status.FAIL,
                  summary + f" Heavy packet loss inside your home network "
                  f"({where}).",
                  ("Wi-Fi interference or distance: move closer, change the "
                   "router channel, use 5 GHz.") if wifi else
                  "Replace the cable / switch port.", st.raw, **m)
    if st.loss_pct >= 2 or (st.avg_ms or 0) > lim_rtt or \
            (st.jitter_ms or 0) > lim_rtt:
        return _r(cid, title, Status.WARN,
                  summary + f" The {where} part of the connection is "
                  "unstable.",
                  ("Wi-Fi is congested or the signal is weak — move "
                   "closer, use 5 GHz, change the router channel.") if wifi
                  else "Check the cable and the router load.", st.raw, **m)
    return _r(cid, title, Status.PASS, summary + " Your home network is fine.",
              raw=st.raw, **m)


# --------------------------------------------------------------------------
# 4. Internet path quality
# --------------------------------------------------------------------------

def check_wan(ctx: Ctx) -> CheckResult:
    cid, title = "speed.wan", "Internet path quality (ISP)"
    st = net.latency(ctx, LATENCY_HOST, count=20, interval=0.2)
    ctx.state["wan"] = st
    m = {"rtt_ms": st.avg_ms, "loss_pct": st.loss_pct,
         "jitter_ms": st.jitter_ms}
    if not st.ok:
        return _r(cid, title, Status.FAIL,
                  f"{LATENCY_HOST} is unreachable — there is no working "
                  "internet path (see the Connection tab).", raw=st.raw, **m)
    lan: net.PingStats | None = ctx.state.get("lan")
    lan_loss = lan.loss_pct if lan and lan.ok else 0.0
    lan_rtt = lan.avg_ms if lan and lan.ok and lan.avg_ms else 0.0
    summary = (f"Internet ({LATENCY_HOST}): {net.fmt_ms(st.avg_ms)} average, "
               f"jitter {net.fmt_ms(st.jitter_ms)}, {st.loss_pct:.0f}% loss.")
    isp_loss = st.loss_pct - lan_loss
    isp_rtt = (st.avg_ms or 0) - lan_rtt
    if isp_loss >= 5:
        return _r(cid, title, Status.FAIL,
                  summary + " Packets are lost beyond your router — on the "
                  "ISP side.",
                  "Reboot the router/modem. If it persists, report packet "
                  "loss to the ISP (attach this report).", st.raw, **m)
    if isp_loss >= 1 or isp_rtt > 80 or (st.jitter_ms or 0) > 30:
        return _r(cid, title, Status.WARN,
                  summary + " The ISP part of the path adds noticeable "
                  "delay or loss.",
                  "Usually ISP congestion (often in the evening). Reboot "
                  "the router; if it is regular, contact the ISP.",
                  st.raw, **m)
    return _r(cid, title, Status.PASS, summary + " The ISP path is healthy.",
              raw=st.raw, **m)


# --------------------------------------------------------------------------
# 5. DNS speed
# --------------------------------------------------------------------------

def check_dns(ctx: Ctx) -> CheckResult:
    cid, title = "speed.dns", "DNS lookup speed"
    rnd = os.urandom(3).hex()
    names = ("www.wikipedia.org", "github.com", f"nws-{rnd}.example.com")
    times, lines, failed = [], [], []
    for n in names:
        addrs, ms, err = net.system_resolve(n)
        lines.append(f"{n}: {net.fmt_ms(ms)} " + (addrs[0] if addrs else err))
        # The random name must not exist (it defeats caches): NXDOMAIN is
        # the expected, successful answer for it.
        if addrs or (n.startswith("nws-") and "NXDOMAIN" in err):
            times.append(ms)
        else:
            failed.append(n)
    if len(failed) >= 2 or not times:
        return _r(cid, title, Status.FAIL,
                  "Names do not resolve — DNS is broken, so nothing can be "
                  "measured here.", "See the DNS step on the “No "
                  "connection” tab.", "\n".join(lines))
    avg = statistics.mean(times)
    m = {"dns_ms": avg}
    summary = f"Average lookup time {net.fmt_ms(avg)}."
    if avg > 300:
        return _r(cid, title, Status.WARN,
                  summary + " Slow DNS adds this delay to every new site.",
                  "Use a faster DNS server, e.g. 1.1.1.1 or 8.8.8.8 "
                  "(Settings → Network → IPv4 → DNS).", "\n".join(lines),
                  **m)
    return _r(cid, title, Status.PASS, summary, raw="\n".join(lines), **m)


# --------------------------------------------------------------------------
# 6/7. Throughput (download / upload) + latency under load
# --------------------------------------------------------------------------

def _connection(url: str, timeout: float):
    u = urllib.parse.urlsplit(url)
    secure = u.scheme == "https"
    port = u.port or (443 if secure else 80)
    proxy = os.environ.get("https_proxy" if secure else "http_proxy") or \
        os.environ.get("HTTPS_PROXY" if secure else "HTTP_PROXY")
    if proxy:
        p = urllib.parse.urlsplit(proxy)
        conn = (http.client.HTTPSConnection if secure else
                http.client.HTTPConnection)(p.hostname, p.port or 3128,
                                            timeout=timeout,
                                            **({"context":
                                                ssl.create_default_context()}
                                               if secure else {}))
        if secure:
            conn.set_tunnel(u.hostname, port)
        path = url if not secure else (u.path or "/") + (
            "?" + u.query if u.query else "")
    else:
        if secure:
            conn = http.client.HTTPSConnection(
                u.hostname, port, timeout=timeout,
                context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(u.hostname, port,
                                              timeout=timeout)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
    return conn, path, u.hostname


class _Meter:
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = 0
        self.mark_bytes = 0
        self.errors: list[str] = []

    def add(self, n: int):
        with self.lock:
            self.bytes += n


def _probe_latency(stop: threading.Event, out: list[float]):
    while not stop.is_set():
        rtt, _ = net.tcp_connect(LATENCY_HOST, 443, timeout=2.0)
        if rtt is not None:
            out.append(rtt)
        stop.wait(0.3)


def _idle_latency() -> float | None:
    samples = []
    for _ in range(5):
        rtt, _ = net.tcp_connect(LATENCY_HOST, 443, timeout=2.0)
        if rtt is not None:
            samples.append(rtt)
    return statistics.median(samples) if samples else None


def _run_transfer(ctx: Ctx, upload: bool) -> dict:
    """Run STREAMS parallel transfers for a fixed time; return stats."""
    seconds = UPLOAD_SECONDS if upload else DOWNLOAD_SECONDS
    meter = _Meter()
    deadline = time.monotonic() + seconds + WARMUP_SECONDS
    urls = (UPLOAD_URL,) if upload else DOWNLOAD_URLS
    chosen = {"url": None}

    def pick_url() -> str | None:
        for url in urls:
            try:
                conn, path, host = _connection(url, 6.0)
                if upload:
                    conn.request("POST", path, body=b"x" * 1024,
                                 headers={"Host": host,
                                          "Content-Type":
                                          "application/octet-stream"})
                else:
                    conn.request("GET", path, headers={
                        "Host": host, "Range": "bytes=0-1023"})
                resp = conn.getresponse()
                resp.read(2048)
                conn.close()
                if resp.status < 400:
                    return url
                meter.errors.append(f"{url}: HTTP {resp.status}")
            except (OSError, http.client.HTTPException) as exc:
                meter.errors.append(f"{url}: {net.os_reason(exc)}")
        return None

    url = pick_url()
    chosen["url"] = url
    if url is None:
        return {"ok": False, "errors": meter.errors}
    deadline = time.monotonic() + seconds + WARMUP_SECONDS
    chunk = os.urandom(64 * 1024)

    def worker():
        while time.monotonic() < deadline:
            try:
                conn, path, host = _connection(url, 10.0)
                if upload:
                    total = 50 * 1024 * 1024
                    conn.putrequest("POST", path, skip_host=True)
                    conn.putheader("Host", host)
                    conn.putheader("Content-Type", "application/octet-stream")
                    conn.putheader("Content-Length", str(total))
                    conn.endheaders()
                    sent = 0
                    while sent < total and time.monotonic() < deadline:
                        conn.send(chunk)
                        sent += len(chunk)
                        meter.add(len(chunk))
                    conn.close()
                    if sent < total:
                        return
                else:
                    conn.request("GET", path, headers={"Host": host})
                    resp = conn.getresponse()
                    while time.monotonic() < deadline:
                        data = resp.read(64 * 1024)
                        if not data:
                            break
                        meter.add(len(data))
                    conn.close()
            except (OSError, http.client.HTTPException) as exc:
                meter.errors.append(net.os_reason(exc))
                time.sleep(0.2)
                if len(meter.errors) > 20:
                    return

    itf = _uplink_iface(ctx)
    c0 = net.iface_counters(ctx, itf.name) if itf else {}
    tcp0 = net.tcp_counters(ctx)
    lat: list[float] = []
    stop = threading.Event()
    prober = threading.Thread(target=_probe_latency, args=(stop, lat),
                              daemon=True)
    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(STREAMS)]
    start = time.monotonic()
    for t in threads:
        t.start()
    time.sleep(WARMUP_SECONDS)
    with meter.lock:
        meter.mark_bytes = meter.bytes
    mark_time = time.monotonic()
    prober.start()
    for t in threads:
        t.join(timeout=seconds + 15)
    end = time.monotonic()
    stop.set()
    prober.join(timeout=3)
    c1 = net.iface_counters(ctx, itf.name) if itf else {}
    tcp1 = net.tcp_counters(ctx)
    measured = meter.bytes - meter.mark_bytes
    dt = max(0.1, end - mark_time)
    out_segs = max(1, tcp1[0] - tcp0[0])
    retrans = max(0, tcp1[1] - tcp0[1])
    err_delta = sum(max(0, c1.get(k, 0) - c0.get(k, 0)) for k in
                    ("rx_errors", "tx_errors", "rx_crc_errors"))
    drop_delta = sum(max(0, c1.get(k, 0) - c0.get(k, 0)) for k in
                     ("rx_dropped", "tx_dropped"))
    return {
        "ok": measured > 0, "url": url, "mbps": measured * 8 / dt / 1e6,
        "bytes": meter.bytes, "seconds": end - start,
        "loaded_ms": statistics.median(lat) if lat else None,
        "retrans_pct": 100.0 * retrans / out_segs if upload or out_segs > 50
        else None,
        "nic_errors": err_delta, "nic_drops": drop_delta,
        "errors": meter.errors,
    }


def _transfer_raw(stats: dict) -> str:
    lines = [f"server: {stats.get('url')}",
             f"streams: {STREAMS}, transferred {stats.get('bytes', 0) / 1e6:.1f} MB "
             f"in {stats.get('seconds', 0):.1f} s",
             f"speed: {net.fmt_mbps(stats.get('mbps'))}",
             f"latency under load: {net.fmt_ms(stats.get('loaded_ms'))}",
             f"NIC errors during test: {stats.get('nic_errors')}, drops: "
             f"{stats.get('nic_drops')}"]
    if stats.get("retrans_pct") is not None:
        lines.append(f"TCP retransmissions during test: "
                     f"{stats['retrans_pct']:.2f}%")
    if stats.get("errors"):
        lines.append("errors: " + "; ".join(stats["errors"][:8]))
    return "\n".join(lines)


def check_download(ctx: Ctx) -> CheckResult:
    cid, title = "speed.download", "Download speed"
    idle = _idle_latency()
    ctx.state["idle_ms"] = idle
    stats = _run_transfer(ctx, upload=False)
    if not stats["ok"]:
        return _r(cid, title, Status.FAIL,
                  "Could not reach any speed-test server.",
                  "Check the Connection tab; a firewall or proxy may block "
                  "large downloads.", "\n".join(stats.get("errors", [])))
    mbps = stats["mbps"]
    loaded = stats["loaded_ms"]
    bloat = (loaded - idle) if (loaded is not None and idle is not None) \
        else None
    m = {"down_mbps": mbps, "idle_ms": idle, "loaded_ms": loaded,
         "bloat_ms": bloat, "retrans_pct": stats["retrans_pct"],
         "nic_errors": stats["nic_errors"]}
    summary = f"{net.fmt_mbps(mbps)} download."
    if bloat is not None:
        summary += (f" Latency {net.fmt_ms(idle)} idle → "
                    f"{net.fmt_ms(loaded)} while downloading.")
    raw = _transfer_raw(stats) + f"\nidle latency: {net.fmt_ms(idle)}"
    status, fixes = Status.PASS, []
    if bloat is not None and bloat > 100:
        status = Status.WARN
        summary += (" The connection gets laggy under load "
                    "(bufferbloat): calls and games stutter while "
                    "something downloads.")
        fixes.append("enable SQM / Smart Queue / QoS in the router "
                     "settings (set to ~90 % of your plan speed)")
    if stats["nic_errors"]:
        status = Status.WARN
        summary += f" The adapter recorded {stats['nic_errors']} errors " \
                   "during the test."
        fixes.append("errors on the adapter point to a bad cable or "
                     "radio interference")
    if mbps < 5:
        status = Status.WARN
    return _r(cid, title, status, summary,
              ("To improve: " + "; ".join(fixes) + ".") if fixes else "",
              raw, **m)


def check_upload(ctx: Ctx) -> CheckResult:
    cid, title = "speed.upload", "Upload speed"
    stats = _run_transfer(ctx, upload=True)
    if not stats["ok"]:
        return _r(cid, title, Status.SKIP,
                  "Upload test server not reachable — skipped.",
                  raw="\n".join(stats.get("errors", [])))
    mbps = stats["mbps"]
    m = {"up_mbps": mbps, "retrans_pct": stats["retrans_pct"]}
    summary = f"{net.fmt_mbps(mbps)} upload."
    rt = stats["retrans_pct"]
    if rt is not None and rt > 3:
        return _r(cid, title, Status.WARN,
                  summary + f" {rt:.1f}% of packets had to be re-sent — "
                  "the line is lossy.",
                  "Packet loss on the way out: check Wi-Fi signal/cable; "
                  "if the local network is fine, it is the ISP.",
                  _transfer_raw(stats), **m)
    return _r(cid, title, Status.PASS, summary, raw=_transfer_raw(stats), **m)


# --------------------------------------------------------------------------
# 8. Wi-Fi channel congestion
# --------------------------------------------------------------------------

def check_wifi_channels(ctx: Ctx) -> CheckResult:
    cid, title = "speed.wifi_channels", "Wi-Fi channel congestion"
    itf = _uplink_iface(ctx)
    if itf is None or itf.kind != "wifi":
        return _r(cid, title, Status.SKIP, "Not on Wi-Fi — not applicable.")
    if not ctx.which("nmcli"):
        return _r(cid, title, Status.SKIP,
                  "nmcli not available — cannot list nearby networks.")
    res = ctx.run(["nmcli", "-t", "-f", "IN-USE,SSID,CHAN,SIGNAL,FREQ",
                   "device", "wifi", "list", "ifname", itf.name,
                   "--rescan", "no"], timeout=10.0)
    if not res.ok:
        return _r(cid, title, Status.SKIP, "Could not list Wi-Fi networks.",
                  raw=res.stderr)
    nets = []
    for line in res.text.splitlines():
        parts = line.replace("\\:", "\x00").split(":")
        if len(parts) < 5:
            continue
        parts = [p.replace("\x00", ":") for p in parts]
        try:
            nets.append({"in_use": parts[0] == "*", "ssid": parts[1],
                         "chan": int(parts[2]), "signal": int(parts[3])})
        except ValueError:
            continue
    mine = next((n for n in nets if n["in_use"]), None)
    if mine is None:
        return _r(cid, title, Status.SKIP,
                  "Current network not found in the scan list.", raw=res.text)
    ch = mine["chan"]

    def overlaps(a: int, b: int) -> bool:
        if a <= 14 and b <= 14:
            return abs(a - b) < 5
        return a == b

    rivals = [n for n in nets if not n["in_use"] and overlaps(n["chan"], ch)
              and n["signal"] >= 30]
    strong = [n for n in rivals if n["signal"] >= 60]
    summary = (f"Channel {ch}: {len(rivals)} other networks share or overlap "
               f"it ({len(strong)} strong). {len(nets)} networks in range.")
    m = {"channel": ch, "rivals": len(rivals)}
    if ch <= 14:
        counts = {c: sum(1 for n in nets if overlaps(n["chan"], c)
                         and n["signal"] >= 30) for c in (1, 6, 11)}
    else:
        counts = {}
        for n in nets:
            if n["chan"] > 14:
                counts[n["chan"]] = counts.get(n["chan"], 0) + 1
    best = min(counts, key=counts.get) if counts else None
    if len(strong) >= 3 or len(rivals) >= 6:
        fix = "Change the Wi-Fi channel in the router settings"
        if best is not None and best != ch:
            fix += f" (channel {best} is the least busy)"
        fix += ", or switch to 5 GHz."
        return _r(cid, title, Status.WARN,
                  summary + " The channel is crowded — neighbours' Wi-Fi "
                  "slows yours down.", fix, res.text, **m)
    return _r(cid, title, Status.PASS, summary, raw=res.text, **m)


# --------------------------------------------------------------------------
# Suite API
# --------------------------------------------------------------------------

def make_checks(ctx: Ctx | None = None) -> list[Check]:
    return [
        Check("speed.link", "Your connection to the router", check_link),
        Check("speed.background", "Other traffic right now", check_background),
        Check("speed.lan", "Local network quality (to the router)", check_lan),
        Check("speed.wan", "Internet path quality (ISP)", check_wan),
        Check("speed.dns", "DNS lookup speed", check_dns),
        Check("speed.download", "Download speed", check_download),
        Check("speed.upload", "Upload speed", check_upload),
        Check("speed.wifi_channels", "Wi-Fi channel congestion",
              check_wifi_channels),
    ]


def metrics(results: list[CheckResult]) -> dict:
    out: dict = {}
    for r in results:
        for k, v in r.metrics.items():
            if r.check_id == "speed.lan" and k in ("rtt_ms", "loss_pct",
                                                   "jitter_ms"):
                out["lan_" + k] = v
            elif r.check_id == "speed.wan" and k in ("rtt_ms", "loss_pct",
                                                     "jitter_ms"):
                out["wan_" + k] = v
            else:
                out.setdefault(k, v)
    return out


_ORDER = ["speed.link", "speed.lan", "speed.wifi_channels", "speed.wan",
          "speed.background", "speed.download", "speed.upload", "speed.dns"]
_PLACES = {
    "speed.link": "your Wi-Fi / cable",
    "speed.lan": "your home network",
    "speed.wifi_channels": "Wi-Fi interference",
    "speed.wan": "the ISP",
    "speed.background": "other traffic on this computer",
    "speed.download": "latency under load",
    "speed.upload": "upload losses",
    "speed.dns": "slow DNS",
}


def analyze(results: list[CheckResult], ctx: Ctx | None = None) -> Verdict:
    by_id = {r.check_id: r for r in results}
    m = metrics(results)
    down, up = m.get("down_mbps"), m.get("up_mbps")
    bad = [by_id[c] for c in _ORDER if c in by_id
           and by_id[c].status in (Status.FAIL, Status.WARN)]
    bad.sort(key=lambda r: (r.status is not Status.FAIL,
                            _ORDER.index(r.check_id)))
    speed_txt = ""
    if down is not None:
        speed_txt = f"↓ {net.fmt_mbps(down)}"
        if up is not None:
            speed_txt += f"  ↑ {net.fmt_mbps(up)}"
    if not results:
        return Verdict("unknown", "No measurements yet.")
    if "speed.download" in by_id and \
            by_id["speed.download"].status is Status.FAIL:
        dl = by_id["speed.download"]
        return Verdict("fail", "Speed could not be measured.", dl.summary,
                       [dl.suggestion] if dl.suggestion else [],
                       culprit=dl.check_id)
    if bad:
        main = bad[0]
        place = _PLACES.get(main.check_id, main.title)
        headline = f"Slowed down by {place}."
        if speed_txt:
            headline = f"{speed_txt} — slowed down by {place}."
        detail = main.summary
        others = [_PLACES.get(r.check_id, r.title) for r in bad[1:3]]
        if others:
            detail += " Also: " + ", ".join(others) + "."
        actions = [r.suggestion for r in bad[:3] if r.suggestion]
        return Verdict("fail" if main.status is Status.FAIL else "warn",
                       headline, detail, actions, culprit=main.check_id)
    link = m.get("link_mbps")
    detail = ("Your link, home network and the ISP path are healthy. ")
    if down is not None and link and down < 0.3 * link and link >= 100:
        detail += (f"The measured speed is well below your link capacity "
                   f"({net.fmt_mbps(link)}), so the limit is your internet "
                   "plan or the ISP. Compare it with the speed in your "
                   "contract.")
    else:
        detail += "This is the real speed your plan delivers right now."
    return Verdict("ok", (speed_txt + " — no bottleneck found.")
                   if speed_txt else "No bottleneck found.", detail)
