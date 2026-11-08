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
│  report.py    — compact Markdown context for an AI chat        │
│  selftest.py  — terminal mode                                  │
└───────────────────────────────┬────────────────────────────────┘
┌───────────────────────────────▼────────────────────────────────┐
│ Suites  diag/                                                  │
│  net.py        — uplink detection, iface classification, ping, │
│                  TCP probes, raw DNS queries, Wi-Fi, NM state  │
│  connection.py — "No connection"                               │
│  speed.py      — "Slow internet"                               │
│  resource.py   — "Site doesn't open"                           │
│  portal.py     — captive-portal detection, login URL           │
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
| Login page | captive-portal probes (see below) | hotel/café/office Wi-Fi sign-in |
| Internet | TCP :443 to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (no DNS), IPv6 probe, proxy-only networks | ISP/WAN down, broken IPv6 |
| DNS | system resolver vs. direct UDP queries to the configured upstream servers vs. public DNS vs. router DNS | dead DNS server, resolved broken, port 53 blocked, network allows only its own DNS |
| Clock | HTTP `Date` headers + timedatectl | clock wrong → HTTPS fails |
| Web | plain HTTP (from portal probes), HTTPS, clock skew, public IP | HTTPS interception, wrong clock |

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

## Captive portals — `diag/portal.py`

Portals often redirect only some connectivity-check URLs (those phones and
Windows use) and let the others time out — e.g. connectivity-check.ubuntu.com
gets no redirect while captive.apple.com / msftconnecttest.com do.

- Six probes in parallel, plain HTTP, no proxy, no redirect following:
  Apple, Microsoft, Google (generate_204), Ubuntu, GNOME, Firefox — each with
  its expected status/body. Plus `nmcli networking connectivity check`.
- A probe answering differently = intercepted. Portal if ≥ 2 probes are
  intercepted, or 1 with no clean probe, or NM says `portal`. A single
  intercepted probe while others pass = DNS/ad filter, not a portal.
- Login URL: redirect `Location`, else meta-refresh / JS `location=` / form
  action / first foreign link in the page, else the intercepted probe URL
  itself (Apple/Microsoft first — they trigger most portals), else
  `http://<gateway>/`.
- Chain step "Login page" sits after "Router": a portal becomes the root
  cause and Internet/DNS/Web failures its consequences. Speed and Website
  tabs stop at a first "login page" gate. The verdict carries
  `link=("Open login page", url)`, shown as a button in the banner.

## Travel scenarios (hotel Wi-Fi, VPN, clock)

- **Portal behind manual DNS / DNS-over-TLS:** probes that fail on the name
  lookup are retried with addresses from the router's DNS (Host header kept).
  The DNS step recognises "your DNS is blocked, the router's DNS answers"
  and tells to switch DNS to Automatic / disable DoT.
- **VPN left on:** `net.vpn_uplink()` / `physical_gateway()` — the Router
  step checks the real router under the tunnel; if it answers but nothing
  passes the tunnel, the root cause is "VPN is on but not working on this
  network" (with the router's page as a possible login page). Speed blames
  "the VPN" instead of the ISP; Website ties 403/429/451 and timeouts to the
  VPN.
- **Clock (`diag/clock.py`):** real time from the plain-HTTP probes' `Date`
  headers (works when HTTPS is broken) + `timedatectl` (NTP, sync,
  LocalRTC, zone). Chain step "Clock" before "Web"; > 5 min skew is the
  root cause, whole-hour skew → "clock moved by hand instead of the zone".
  TLS errors on the Website tab use the same measurement.
- **IP country vs time zone:** Cloudflare `loc` vs the zone's country
  (zone1970.tab): notes "traffic exits in X through the VPN" or "time zone
  still Y after travelling".

## Spec stage A–C (traveller features)

- **Confidence** (`verdict.chain_confidence`): *confirmed* (fault measured
  directly), *likely* (inferred cause, or an earlier step could not be
  tested), *insufficient* (too few checks ran). Shown as a badge.
- **Notes** (`metrics["note"]` → `Verdict.notes`): non-causal findings
  shown as "Also noted": open Wi-Fi / proxy (`conn.security`), UDP blocked
  (`conn.udp`), random MAC behind a portal, IP country vs time zone,
  video-call quality.
- **Progressive disclosure:** pages show the verdict; steps and technical
  tiles sit under "Show details".
- **Wi-Fi details:** BSSID, channel, width, security via `nmcli device wifi
  list` + `iw dev info` (no root).
- **IPv4/IPv6** reported separately in "Internet"; broken IPv6 and
  IPv6-only are warnings with specific headlines.
- **Destinations:** "Web" probes Google, Microsoft, Apple, Wikipedia,
  GitHub, YouTube over HTTPS → "some services are blocked".
- **MTU:** `net.path_mtu` (ping -M do binary search, exact); Speed always,
  Website only when the connection stalls after TCP.
- **Phone hotspot:** USB tethering drivers, phone-like SSIDs, 172.20.10.1 /
  192.168.43.1 gateways, NM "metered (guessed)" → phone-specific advice
  instead of "call the ISP".
- **Video calls (`speed.calls`):** latency, jitter, loss, upload, bufferbloat
  + STUN Binding Request over UDP (Google/Cloudflare/Twilio) → Good / OK /
  Poor. The same STUN test in `conn.udp` tells "this network blocks UDP —
  switch the VPN to TCP/443".
- **History (`engine/history.py`):** every run → JSON in
  `~/.local/share/nwsolver/history` (newest 300); banner shows changes vs
  the previous run of the same tab/target; History dialog (Ctrl+H).
- **Diagnostic Context (`engine/context.py`, schema
  `nwsolver.diagnostic-context/1`):** environment, network, runs (verdict
  with confidence, chain, recommendations, notes; checks with Status /
  Symptom / Evidence / Recommendation; statuses OK, WARNING, ERROR,
  UNKNOWN, NOT TESTED), repeated-check comparisons, timeline. Views: JSON,
  Markdown technical report, AI prompt (`report.py`).
- **Masking (`Masker`):** stable placeholders (<PUBLIC-IP-1>, <LAN-IP-1>,
  <MAC-1>, <WIFI-NAME-1>, <HOST>, <USER>); well-known public DNS kept;
  secrets (password/psk/token/key/cookie, Authorization, URL credentials)
  always removed. Export dialog with live preview and switches; quick
  "Copy for AI" uses the defaults (public IP, MAC, Wi-Fi name, host hidden).

## Network filtering / DPI — `diag/censor.py`

Runs on the "Site doesn't open" tab when something failed. Every probe is
differential — the same request naming the target vs naming `example.com`,
to the same server — so "control works, target fails" proves name-based
filtering, and "both fail" proves nothing:

| layer | probe | sign of filtering |
|---|---|---|
| DNS/UDP | A query to 1.1.1.1 / 8.8.8.8 | target dropped (timeout), control answered |
| DNS/TCP | query over TCP to 1.1.1.1:53 | reset/close right after the handshake (middlebox read the query) |
| DNS forgery | query sent to a host with no DNS server (example.com's IP) | any answer for the target = injected |
| TLS SNI | ClientHello to 1.1.1.1 (and to the site's own IP) with SNI=target vs SNI=control | target reset/closed/timeout, control completes or gets a server alert |
| HTTP Host | GET to 1.1.1.1:80 with Host=target vs Host=control | reset, or a different status / redirect host (block page) |
| IP | TCP 443 to the site's addresses vs 1.1.1.1 | site unreachable while others are (blocked or down → "likely") |

DNS over HTTPS (1.1.1.1 / 8.8.8.8 JSON API, by IP) gives the real
addresses: the DNS step uses it when plain DNS times out or says NXDOMAIN
(forged NXDOMAIN detection) and the check continues with those addresses.
A FAIL here overrides the chain verdict: "<site> is blocked by filtering on
your network or internet provider", with the proof per layer and advice
(encrypted DNS is enough only for DNS-only filtering; otherwise another
network or an unblocked/obfuscated VPN — subject to local law).

## Export for AI — `engine/report.py`

"Copy for AI" / "Save for AI…" produce a compact Markdown context: request
(cause, fix steps with Ubuntu commands, verification; answer language from
locale), environment (OS, connection type/SSID/signal, local IP, router,
DNS, VPN/proxy), and per tab the verdict, chain, measurements, problems with
≤ 1200-char evidence, one-line OK steps. Host name, MAC and public IP are
removed. The built-in "Ask AI" uses the same text.

## Persistence

QSettings (`~/.config/nwsolver/nwsolver.conf`): text size, window geometry
(saved on move/resize with debounce and on close), site history. Settings
are synced immediately; an unwritable file (e.g. created by a root run)
triggers a status-bar hint.

## Packaging

`packaging/build_deb.sh` caches PySide6 wheels and the unpacked tree in
`dist/cache/` (first build downloads; `REFRESH_PYSIDE=1` refreshes),
normalises permissions (755 dirs / 644 files, bundled PySide keeps exec
bits), adds a prerm that removes `__pycache__`. Icon: `ui/icon.svg`
(magnifier + Wi-Fi + pulse) → hicolor PNGs via rsvg-convert or QtSvg.

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
