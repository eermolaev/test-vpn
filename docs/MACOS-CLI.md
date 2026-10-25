# Console version for macOS (no Apple Developer account)

The app with the Network Extension needs a paid Apple Developer membership.
The console version does not: a small background service running as root
creates the tunnel interface itself, and a terminal dashboard controls it.

```
testvpn daemon (root, launchd)          testvpn (your user)
├─ utun interface, routes, DNS          ├─ dashboard: traffic, connections,
├─ pf kill switch                       │  profiles, exclusions, settings
├─ Go core: AmneziaWG / VLESS+REALITY,  └─ exit check (IP, country, leaks)
│  exclusions, fallback, split DNS
└─ /var/run/testvpn.sock  ◄──────────── JSON over a unix socket
```

## Install

Requirements: macOS 13 or newer, Go (`brew install go`).

```sh
git clone https://github.com/eermolaev/test-vpn && cd test-vpn/core
go build -o testvpn ./cmd/testvpn
sudo ./testvpn install      # copies to /usr/local/bin, starts the LaunchDaemon
testvpn                     # opens the dashboard
```

To update, rebuild and run `sudo ./testvpn install` again: it stops the
running service, waits for it to exit, replaces the binary, starts the new
service and prints its build (also shown by `testvpn status` and in the
dashboard header). A connected VPN stays blocked during the swap and
reconnects by itself.

The service starts at boot (`/Library/LaunchDaemons/com.testvpn.daemon.plist`)
and keeps running when the dashboard is closed. Profiles and settings are
stored in `/Library/Application Support/TestVPN/config.json`, readable by
root only. The socket accepts only root and the user who ran `install`.

## Dashboard

| Key | Action |
| --- | --- |
| `c` | connect / disconnect |
| `r` | re-check the tunnel now |
| `p` | profiles: `i` import (paste, or `@~/path/file.conf`), `a` add transports to the selected profile, `enter` select, `t` pin a transport, `n` rename, `g` expected country, `d` delete |
| `e` | domain exclusions (`ctrl+s` saves) |
| `v` | VPN list: which sites use the VPN (see [Which traffic uses the VPN](#which-traffic-uses-the-vpn)) |
| `s` | settings: DNS (Google by default, Cloudflare, Quad9, custom), QUIC blocking, local network |
| `x` | check exit IP, country and leaks |
| `↑ ↓` | select a connection |
| `?` | help |
| `q` | quit the dashboard (the VPN keeps running) |

The command line works too: `testvpn status`, `testvpn connect`,
`testvpn disconnect`, `testvpn import profile.conf`, `testvpn check`,
`testvpn logs [-f]` (also written to `/Library/Logs/testvpn.log`).

## Which traffic uses the VPN

Two lists decide it: **exclusions** (`e`, always direct) and the **VPN list**
(`v`, through the tunnel, blocked while it is down).

| VPN list | Result |
| --- | --- |
| empty or `*` | everything goes through the VPN except exclusions |
| `youtube.com`, `x.com`, … | only these sites use the VPN; everything else goes direct |

When both lists cover a site, the more specific rule wins (`full:x` beats
`x`, `mail.ru` beats `ru`, any domain beats `*`); on a tie the VPN wins.
Examples:

- exclusions `ru`, VPN list `*` and `mail.ru`: `yandex.ru` direct, `e.mail.ru`
  through the VPN, everything else through the VPN;
- exclusions empty, VPN list `youtube.com`: only YouTube uses the VPN.

Exit-IP check services always use the VPN. Traffic whose site cannot be
identified follows the default: VPN with `*`, direct with a site list.

## Connect on startup

Settings (`s`) → "Connect on startup", or `testvpn autoconnect MODE`:

| Mode | After the Mac boots |
| --- | --- |
| `last` (default) | connects to the last selected profile, even if you disconnected before shutting down |
| `restore` | connects only if the VPN was on at shutdown |
| `off` | stays disconnected |

A restart of the service within the same boot (crash, `sudo testvpn install`)
always restores the previous state, so a crash never lifts the kill switch.

## Switching to another profile

With several profiles, the VPN moves to the next one (in import order, round
robin) after 5 failed connection attempts in a row, or when a profile has
tried all its transports. The kill switch stays on while it switches, and the
new profile becomes the selected one. Change the limit in Settings (`s`) →
"Next profile after" or with `testvpn failover N|off`. With a single profile
a failed tunnel is retried every 30 seconds.

## How traffic is protected

- **Kill switch (pf).** When you connect, rules are loaded into the pf
  anchor `com.apple/250.TestVPN` *before* the tunnel starts. Only the
  tunnel, the VPN servers, addresses of excluded domains (added right before
  each direct connection), DHCP and IPv6 link-local may leave the Mac.
- **Crash = blocked.** If the service crashes, the rules stay and the tunnel
  interface disappears, so nothing leaks. launchd restarts the service and it
  reconnects. While disconnected by you, nothing is blocked.
- **IPv6** is routed into the tunnel and dropped there (the servers have no
  IPv6) and is also blocked by pf.
- **DNS** of the primary network service is set to the selected resolver
  (8.8.8.8 by default) and restored on disconnect.

## Verify

```sh
testvpn status
sudo tcpdump -ni en0 'not host <server-ip>'   # only excluded domains may appear
```

Press `x` in the dashboard: exit country, IPv6 blocked, WebRTC = exit IP,
"direct bypass: blocked".

Crash test:

```sh
sudo pkill -9 -f 'testvpn daemon'   # internet stays blocked…
testvpn status                      # …until launchd restarts the service
```

## Emergency: get the internet back

```sh
sudo testvpn unblock
```

It disconnects through the service if it runs, otherwise removes the pf
rules, restores DNS, deletes server routes and marks the state as
disconnected. Without the binary, the same by hand:

```sh
sudo pfctl -a com.apple/250.TestVPN -F all
```

## Uninstall

```sh
sudo testvpn uninstall           # keeps profiles
sudo testvpn uninstall --purge   # deletes profiles and settings too
```

## Speed

What the client does:

- the tunnel interface uses MTU 9000: traffic ends in the local stack, so
  big packets just mean fewer system calls;
- 4 MB TCP buffers that grow with the read rate and a 4096-packet queue, so
  bursts are not dropped;
- with no exclusions and VPN list `*`, connections skip the domain sniffing
  step (it delayed protocols where the server speaks first, e.g. SMTP);
- AmneziaWG profiles without an `MTU` use 1420 minus the S4 padding (it was
  1280).

If it is still slow:

| Symptom | Likely cause | Try |
| --- | --- | --- |
| fast at first, then a connection stalls | the ISP throttles or freezes long TLS connections to foreign IPs | an XHTTP transport, or AmneziaWG |
| everything is slow on VLESS, AWG is fine (or the other way) | the protocol is throttled | pin the faster transport (`p` → `t`) |
| video/QUIC sites are slow on VLESS | QUIC is carried over TCP | Settings → "Block QUIC in VLESS" on, so browsers use TCP |
| slow only on some networks | MTU on the path to the server | set `MTU = 1280` in the AmneziaWG profile |
| speed tops out on AmneziaWG on long distances | its built-in TCP stack has a fixed 1 MB window (about 80 Mbit/s at 100 ms) | use VLESS for big downloads |
| server is far away or loaded | latency and the server's uplink | a closer server |

Compare with `testvpn disconnect` and the same speed test; the tunnel panel
shows the current rate.

## Other VPN apps (Amnezia, V2Box, …)

Disconnect other VPN apps before connecting and turn off their "connect on
demand"/"always on". A connected VPN — especially one using the Network
Extension "include all networks" mode — captures the service's own
connections to your server, which then time out. The service detects
connected VPN configurations (`scutil --nc list`), foreign tunnel default
routes and other pf anchors, and shows them as warnings in the dashboard,
in `testvpn status` and in the log.

```sh
scutil --nc list | grep Connected     # must print nothing
netstat -rn -f inet | grep utun       # only the TestVPN utun may hold 0/1 and 128/1
```

## Limitations

- If DNS servers are set manually in System Settings → Network for the
  active interface, they take precedence over the override. Public resolvers
  still work (all DNS goes through the tunnel); a resolver in your local
  network is blocked by the kill switch.
- The kill switch relies on pf; disabling pf by hand (`pfctl -d`) removes
  the protection.
- Logs of the service: `/Library/Logs/testvpn.log` and the dashboard log
  panel (secrets are redacted).
