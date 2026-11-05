# nwsolver — why doesn't the internet work *here*?

A desktop troubleshooter for Linux travelers. Hotel Wi-Fi says "connected" but
nothing loads, the café network is painfully slow, the airline site won't open —
nwsolver explains in plain words **what is broken**, **where**, and **what to
do**, without terminal archaeology or guessing.

It answers three questions:

| Tab | Question it answers | What it does |
|---|---|---|
| **Connection** | Why is there no internet? | Walks the real path — adapter → link → IP address → route → router → internet → DNS → web — and names the **first broken step** as the cause. Later failures are shown as consequences, not as separate problems. Detects airplane mode, missing drivers, an unplugged cable, DHCP failure, a dead router, an ISP outage, broken DNS, hotel/café sign-in pages, a wrong clock, broken IPv6. |
| **Speed** | Why is it so slow? | Measures each segment — Wi-Fi signal / cable speed, the local network (to the router), the provider's path — then real download/upload speed and latency under load. Names the bottleneck: weak Wi-Fi, a crowded channel, a 100 Mbit cable, packet loss at the provider, bufferbloat, background downloads, slow DNS. |
| **Website** | Why doesn't *this* site open? | Checks one address step by step: `/etc/hosts`, DNS through your resolver *and* public DNS (to spot DNS blocking), TCP to every IPv4/IPv6 address, the TLS certificate, the HTTP answer, and where the route stops. Tells you whether it is your side, a block along the way, or the server. |

Only interfaces that can actually carry internet traffic are inspected.
Docker, libvirt, VirtualBox bridges, veths and similar are ignored — unless the
system really routes internet traffic through them (a VPN does).

## When you're travelling

- **Hotel / café / airport Wi-Fi with a sign-in page.** The Connection check
  reaches the *Web* step and reports a captive portal instead of pretending
  you're online — so you know to open the login page first.
- **"Connected", but nothing loads.** The chain shows the first broken step:
  no IP from DHCP, no default route, unreachable router, dead DNS…
- **A VPN or proxy left over from the last country.** The app follows the
  route the kernel actually uses, so a stale VPN tunnel is visible in the
  chain, not hidden behind a "connected" Wi-Fi icon.
- **Painfully slow hotel Wi-Fi.** The Speed check says whether the limit is
  the Wi-Fi link, the hotel's local network, or the provider's uplink — and
  suggests a less crowded channel where possible.
- **One site won't open** (airline, booking, bank, streaming). The Website
  check distinguishes a DNS block, a filtered port, TLS/SNI interception, an
  HTTP 403/451, and a dead server.
- **Wrong clock after crossing time zones.** Expired-looking certificates and
  HTTPS failures are explained as clock skew.

## Install

Requires Ubuntu 22.04+ / Debian 12+ and Python 3.10+.

### .deb package (recommended)

```sh
./packaging/build_deb.sh            # builds dist/nwsolver_<version>_amd64.deb
sudo apt install ./dist/nwsolver_0.2.0_amd64.deb
nwsolver
```

The package bundles PySide6 (Ubuntu doesn't ship it) and depends on
`iproute2`, `iputils-ping` and `iw`. `network-manager`, `iputils-tracepath`
(or `traceroute`) and `pciutils` are recommended and add extra detail. It
installs a menu entry, so you can also start it from the app grid.

### From source (development)

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./start.sh
```

## Terminal mode (no GUI)

Useful over SSH, in a minimal install, or when the desktop itself is
misbehaving:

```sh
./start.sh --selftest                      # why is there no internet?
./start.sh --selftest --speed              # why is it slow?
./start.sh --selftest --check example.com  # why doesn't this site open?
```

## Using the app

- The connection check runs on start. Each step is a card: status, what was
  found, and **→ what to do** when something is wrong.
- **Details** on a card shows the raw command output; right-click a card to
  copy it or ask the AI about it.
- **Copy for AI** (Ctrl+Shift+C) / **Save for AI…** (Ctrl+E) — produces a short
  text with what is wrong, the environment (OS, Wi-Fi/cable, IP, router, DNS,
  VPN/proxy), the problems found with brief evidence, and a request for
  step-by-step fix instructions. Paste it into any AI chat. Host name, MAC
  and public IP are left out.
- **Ask AI** (Ctrl+Shift+A) — optional; configure an OpenAI-compatible API or
  a local Ollama in *Tools → AI assistant settings…*. Only the current tab's
  results are sent.
- **View → Larger / Smaller text** (Ctrl + / Ctrl − / Ctrl 0) scales the whole
  UI; the window always fits the screen and nothing scrolls sideways.
- **Run as root** — only adds detail (e.g. some Wi-Fi data); everything works
  without it.

## Notes

- The speed test downloads from Cloudflare (fallbacks: OVH, Tele2) for about
  8 s and uploads for about 6 s; it uses as much data as your connection
  delivers in that time. Keep it in mind on metered mobile tethering.
- Probes use plain IP addresses where possible, so they still work when DNS
  is broken. ICMP is optional: if ping is blocked (common on public Wi-Fi),
  TCP handshakes are used instead.
- Nothing is sent anywhere unless you explicitly use the AI features; the
  diagnostic engine itself is offline-only and standard-library Python. Only
  the GUI needs PySide6.

See [`docs/PLAN.md`](docs/PLAN.md) for the design and the full list of checks.
