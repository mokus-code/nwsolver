# nwsolver — design

**Goal:** a desktop app that tells the user, in plain words, *why* the
internet doesn't work, *why* it is slow, or *why* a particular site/service
does not open, and what to do about it.

Everything in the app serves one of these three questions. Anything that
does not help answer them (container/VM interfaces, VLANs, bonds, listening
ports, socket buffers, congestion-control sysctls, a generic "health score")
was removed.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ UI (PySide6)  ui/                                              │
│  main_window  — 3 tabs, short toolbar, View menu (text size)   │
│  pages        — ConnectionPage / SpeedPage / ResourcePage      │
│  widgets      — VerdictBanner, ResultCard, Tile, FlowLayout    │
│  worker       — SuiteWorker (QThread)                          │
└───────────────────────────────┬────────────────────────────────┘
                                │ Qt signals
┌───────────────────────────────▼────────────────────────────────┐
│ Engine (no Qt)  engine/                                        │
│  checks.py    — Ctx, Check, CheckResult(+metrics), Status       │
│  collector.py — run_suite(): parallel or sequential            │
│  report.py    — Markdown report of every tab that was run      │
│  selftest.py  — terminal mode                                  │
└───────────────────────────────┬────────────────────────────────┘
┌───────────────────────────────▼────────────────────────────────┐
│ Suites  diag/                                                  │
│  net.py        — uplink detection, iface classification, ping, │
│                  TCP probes, raw DNS queries, Wi-Fi, NM state  │
│  connection.py — "No connection"                               │
│  speed.py      — "Slow internet"                               │
│  resource.py   — "Site doesn't open"                           │
│  verdict.py    — Verdict / Step / chain logic                  │
└────────────────────────────────────────────────────────────────┘
```

Suite contract: `SUITE_ID`, `SUITE_NAME`, `SUITE_DESC`, `PARALLEL`,
`make_checks(ctx) -> list[Check]`, `analyze(results, ctx) -> Verdict`
(connection also has `overview(ctx)` and `CHAIN`). Checks are stdlib-only,
never raise, never use a shell. Sequential suites share findings via
`ctx.state`; `ctx.options` carries user input (the resource target).

## Which interfaces matter

`net.uplink()` asks the kernel `ip route get 1.1.1.1` — the interface and
gateway it would really use (honours VPNs, policy routing, metrics; falls
back to `/proc/net/route` without iproute2). Interfaces are classified as
ethernet / wifi / mobile / vpn / virtual. **virtual** (docker*, veth*, br-*,
virbr*, vboxnet*, cni*, …, or no hardware device) are ignored everywhere
unless the kernel actually routes the internet through them.

## 1. No connection — `diag/connection.py`

A dependency chain; the first FAIL is the root cause, later failures are
reported as its consequences, not as separate problems.

| step | check | typical causes it names |
|---|---|---|
| Adapter | NIC present, driver bound, rfkill/airplane mode, NM networking/Wi-Fi switch | no driver, Wi-Fi off, networking disabled |
| Link | cable carrier / Wi-Fi association (+ very weak signal, half duplex) | unplugged cable, not connected to an SSID |
| IP address | IPv4 / global IPv6 on the uplink, 169.254.x.x | DHCP failed |
| Route | `ip route get`; VPN detection | no default gateway |
| Router | ping (TCP fallback) + ARP state of the gateway | router off/unreachable, wrong gateway |
| Internet | TCP :443 to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (no DNS), IPv6 probe, proxy-only networks | ISP/WAN down, broken IPv6 |
| DNS | system resolver vs. direct UDP queries to the configured upstream servers vs. public DNS | dead DNS server, resolved broken, port 53 blocked |
| Web | HTTP connectivity check (captive portal), HTTPS, clock skew, public IP | hotel/café login page, HTTPS interception, wrong clock |

## 2. Slow internet — `diag/speed.py` (sequential)

| check | measures | flags |
|---|---|---|
| Your connection | Wi-Fi signal/band/link rate/power save; cable speed/duplex | weak signal, 2.4 GHz, 100 Mbit cable, half duplex |
| Other traffic | uplink throughput before the test; programs with connections | downloads/sync eating bandwidth |
| Local network | 20 pings to the router: latency, jitter, loss | Wi-Fi interference, bad cable |
| ISP path | 20 pings to 1.1.1.1, minus the local part | ISP loss/congestion |
| DNS speed | lookup time incl. an uncached name | slow DNS |
| Download | 4 streams × 8 s (Cloudflare, fallbacks), latency under load, NIC errors and TCP retransmits during the test | bufferbloat, errors under load |
| Upload | 4 streams × 6 s, retransmit ratio | lossy uplink |
| Wi-Fi channels | `nmcli device wifi list`: overlapping networks | crowded channel → best channel |

Verdict names the worst segment ("slowed down by your Wi-Fi / your home
network / the ISP / …"); if every segment is healthy and the measured speed
is far below the link capacity, the limit is the plan/ISP.

## 3. Site doesn't open — `diag/resource.py` (sequential)

Input: URL, host, host:port or IP.

| step | check | tells apart |
|---|---|---|
| Internet | quick anchor + DNS test | "your internet is down" vs. this site |
| /etc/hosts | local override | blocked on this computer |
| DNS | system resolver vs. 1.1.1.1/8.8.8.8 directly (A + AAAA) | NXDOMAIN, DNS filter (0.0.0.0 / local block page), broken DNS |
| Connect | TCP to up to 2 IPv4 + 2 IPv6 addresses | refused (service down), timeout (filtered), broken IPv6 |
| TLS | handshake with SNI, certificate | reset during handshake (SNI blocking), interception, expired cert |
| HTTP | status, redirects, timing, server | 403/451 blocks, 5xx server errors, slow server |
| Route | tracepath/traceroute when unreachable | stops at your router vs. in the ISP |

## UI rules (must fit any screen)

- Window size derives from the screen's available geometry (≤ 90 %), min
  420×420. No horizontal scrolling anywhere.
- No multi-column tables: results are cards with wrapping text; chain
  pills and fact tiles use a wrapping `FlowLayout`.
- Long unbreakable strings are clipped (WrapLabel) instead of widening
  the window.
- Toolbar has only three actions; text size is in View (Ctrl +/−/0).
- All styles in one app stylesheet keyed by `role`/`state` properties,
  re-generated when the text size changes; palette-aware for dark themes.

## Validation

- `python3 -m py_compile` on every file.
- `python3 run.py --selftest`, `--selftest --speed`,
  `--selftest --check example.com` on a real machine, plus failure drills:
  unplug cable / disable Wi-Fi, wrong DNS, captive portal, `/etc/hosts`
  block, unreachable port.
