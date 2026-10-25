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
| `s` | settings: DNS (Google by default, Cloudflare, Quad9, custom), QUIC blocking, local network |
| `x` | check exit IP, country and leaks |
| `↑ ↓` | select a connection |
| `?` | help |
| `q` | quit the dashboard (the VPN keeps running) |

The command line works too: `testvpn status`, `testvpn connect`,
`testvpn disconnect`, `testvpn import profile.conf`, `testvpn check`.

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
