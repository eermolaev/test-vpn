# testvpn: console client for macOS, Linux and Windows

A small background service with administrator rights creates the tunnel
interface itself, and a terminal dashboard controls it. No Apple Developer
account, Network Extension or GUI is needed.

```
testvpn daemon (root / LocalSystem)      testvpn (your user)
├─ tunnel interface, routes, DNS         ├─ dashboard: traffic, connections,
├─ kill switch (pf / nftables / WFP)     │  profiles, exclusions, settings
├─ Go core: AmneziaWG / VLESS+REALITY,   └─ exit check (IP, country, leaks)
│  exclusions, fallback, split DNS
└─ local socket  ◄────────────────────── JSON over a unix socket
```

The command line and the dashboard are the same on every system; only the
privileged commands differ: `sudo testvpn …` on macOS and Linux, `testvpn …`
in an **Administrator** terminal on Windows.

| | macOS | Linux | Windows |
|---|---|---|---|
| Service | LaunchDaemon `com.testvpn.daemon` | systemd unit `testvpn.service` | service `TestVPN` |
| Binary | `/usr/local/bin/testvpn` | `/usr/local/bin/testvpn` | `C:\Program Files\TestVPN\testvpn.exe` + `wintun.dll` |
| Profiles and settings (admin only) | `/Library/Application Support/TestVPN` | `/var/lib/testvpn` | `C:\ProgramData\TestVPN` |
| Socket | `/var/run/testvpn.sock` | `/run/testvpn.sock` | `C:\ProgramData\TestVPN\testvpn.sock` |
| Service log | `/Library/Logs/testvpn.log` | `journalctl -u testvpn` | `C:\ProgramData\TestVPN\testvpn.log` |
| Tunnel interface | `utunN` | `testvpnN` | Wintun adapter `TestVPN` |
| Kill switch | pf anchor `com.apple/250.TestVPN` | nftables table `inet testvpn` | Windows Filtering Platform |
| DNS | resolver of the primary network service | systemd-resolved (link `testvpnN`) or `/etc/resolv.conf` | DNS servers of the `TestVPN` adapter |

Only administrators and the user who ran `install` may talk to the service.
`testvpn logs [-f]` and the dashboard log panel work everywhere, for that user
too.

## Install

Build with Go 1.26 or newer (`brew install go`, your distribution's package or
<https://go.dev/dl/>). Cross-compiling works from any system:
`GOOS=linux GOARCH=amd64 go build ./cmd/testvpn`,
`GOOS=windows GOARCH=amd64 go build ./cmd/testvpn`.

### macOS

Requirements: macOS 13 or newer.

```sh
git clone https://github.com/eermolaev/test-vpn && cd test-vpn/core
go build -o testvpn ./cmd/testvpn
sudo ./testvpn install      # copies to /usr/local/bin, starts the LaunchDaemon
testvpn                     # opens the dashboard
```

### Linux

Requirements: kernel TUN support (`/dev/net/tun`), `iproute2`, `nftables`
(`nft`) and systemd. Debian/Ubuntu: `sudo apt install iproute2 nftables`;
Fedora: `sudo dnf install iproute nftables`.

```sh
git clone https://github.com/eermolaev/test-vpn && cd test-vpn/core
go build -o testvpn ./cmd/testvpn
sudo ./testvpn install      # copies to /usr/local/bin, enables testvpn.service
testvpn                     # opens the dashboard
```

Run `install` with `sudo` from your own account: the socket is given to that
user (`SUDO_UID`). Without systemd, start the service yourself with
`sudo testvpn daemon` (for example from your init system).

### Windows

Requirements: Windows 10 1803 or newer (for unix sockets), and `wintun.dll`
from <https://www.wintun.net> (take `bin\amd64\wintun.dll`, or `bin\arm64`
on ARM).

```powershell
git clone https://github.com/eermolaev/test-vpn; cd test-vpn\core
go build -o testvpn.exe .\cmd\testvpn
# put wintun.dll next to testvpn.exe, then in an Administrator terminal:
.\testvpn.exe install       # copies both to C:\Program Files\TestVPN, starts the service
```

Open the dashboard in a normal terminal (Windows Terminal recommended):
`& "C:\Program Files\TestVPN\testvpn.exe"`, or add that folder to `PATH`.
The service starts automatically at boot and is restarted if it crashes.

### Updating

Rebuild and run `install` again: it stops the running service, waits for it
to exit, replaces the binary, starts the new service and prints its build
(also shown by `testvpn status` and in the dashboard header). A connected VPN
stays blocked during the swap and reconnects by itself.

## Supported profiles

| Format | Transport | Used automatically |
|---|---|---|
| `vless://…` links, xray JSON, Amnezia `vpn://` keys | VLESS + REALITY / TLS | REALITY yes, TLS only when pinned |
| `trojan://…`, `vmess://…` (v2rayN), xray JSON | Trojan, VMess (AEAD) over REALITY, TLS or, for VMess, bare TCP; raw, ws, gRPC, xhttp | over REALITY yes, otherwise only when chosen |
| AmneziaWG `.conf` | AmneziaWG | yes |
| WireGuard `.conf` (no obfuscation) | WireGuard | only if the profile has nothing stronger |
| `.ovpn` | OpenVPN (UDP or TCP) | only if the profile has nothing stronger |
| `socks5://user:pass@host:port`, `http://…`, `https://…` | SOCKS5, HTTP(S) proxy | only if the profile has nothing stronger |
| `ss://…` (SIP002 or legacy) | Shadowsocks (AEAD and 2022 ciphers) | only if the profile has nothing stronger |
| `hysteria2://…`, `hy2://…` | Hysteria 2 (QUIC; Salamander, port hopping) | yes, after VLESS and AmneziaWG; `insecure=1` without a pin only when chosen |
| `ssh://user:pass@host:port` | SSH tunnel (TCP only, like `ssh -D`) | only if the profile has nothing stronger |

WireGuard, OpenVPN, proxies and SSH are easy to recognise on the wire, so the
client never falls back to them from VLESS or AmneziaWG; a profile made only of
them is used as it is. Several links on separate lines become one profile.

### Mux (VLESS without flow, Trojan, VMess)

Add `mux=8` to a `vless://` or `trojan://` link (or `"mux": {"enabled": true}`
in xray JSON) to carry up to 8 connections over one connection to the server
(xray mux.cool, with XUDP for UDP). New pages then open without a new TCP and
TLS handshake each, which helps a lot on networks that lose handshakes to the
server. It needs an xray server and does not work with
`flow=xtls-rprx-vision` (the server must have a user without flow); xhttp and
gRPC multiplex by themselves and ignore it. To turn it on for a transport you
already have, import the same link with `mux=8` into the profile
(`testvpn import --into ID -` or `a` in the dashboard): a transport with the
same server, port and network is updated, not duplicated.

### Hysteria 2

```
hysteria2://password@host:443/?sni=example.com&obfs=salamander&obfs-password=…&pinSHA256=…#name
```

- `hy2://` is the same; `user:pass@` is sent as is (userpass auth);
- port hopping: `host:443,20000-30000` or `mport=20000-30000`;
- `pinSHA256` pins the server certificate (hex SHA-256, colons allowed):
  `openssl x509 -in cert.pem -noout -fingerprint -sha256`;
- `insecure=1` accepts any certificate. Such a transport is not used as an
  automatic fallback, and the log reminds to add a pin.

Hysteria 2 runs over UDP and carries UDP natively, so QUIC and calls work
through it. Networks that slow down or block UDP to foreign servers make it
fail; then VLESS over TCP is the better choice.

### SSH

Any SSH server with TCP forwarding enabled (`AllowTcpForwarding yes`, the
OpenSSH default) works; nothing is installed on the server. The link:

```
ssh://user:password@host:22?hostkey=SHA256:…&pk=BASE64#name
```

- the port defaults to 22;
- `pk` is a private key file (OpenSSH or PEM) in base64, for example
  `base64 < ~/.ssh/id_ed25519 | tr -d '\n'`; with `pk` the password is the
  key passphrase and may be left out for an unencrypted key;
- `hostkey` pins the server key; get it with
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server. Without it
  the key seen on the first connection is remembered, and a different key later
  stops the connection (possible interception).

SSH carries only TCP. DNS goes over TCP through the server; UDP apps and QUIC
do not work, and browsers fall back to TCP by themselves.

OpenVPN uses the `openvpn` binary (`brew install openvpn`, `apt install
openvpn`); it is not supported on Windows yet. The client keeps
control of routes, DNS and the kill switch: directives that run scripts or
change routes, DNS or the interface (`up`, `route`, `redirect-gateway`,
`dhcp-option`, …) are dropped. Files the config refers to (`ca`, `cert`, `key`,
`tls-auth`, `auth-user-pass`, …) are embedded when you import the file from
disk. If the server asks for a user name and password:

    testvpn import --user alice client.ovpn

The daemon runs `openvpn` as root. A Homebrew binary belongs to your user, so
anything running as your user could replace it; on macOS install it only on a
Mac you alone use. Binaries writable by other users are refused.

## When a network blocks VLESS

If a VLESS attempt fails in a way that looks like DPI (the handshake gets no
answer or is cut off, or nothing comes back through the server), the next
attempt splits the TLS ClientHello into several pieces, trying presets in
turn: `tlshello 100-200`, `tlshello 10-30` (small TLS records sent in one
piece, no delay), `tlshello 10-30 slow` (each record in its own TCP segment,
about a second per connection), `tcp 1-5`. A server that refuses the TCP
connection does not trigger a split. The split that worked is remembered for
that network. Each failure is explained stage by stage in the
log (TCP, handshake, a DNS query through the server).

## Dashboard

| Key | Action |
| --- | --- |
| `c` | connect / disconnect |
| `r` | reconnect: restart the tunnel with the stored profile and settings (applies a newly pinned transport; the kill switch stays on) |
| `p` | profiles: `i` import (paste, or `@~/path/file.conf`), `a` add transports to the selected profile, `enter` select, `t` pin a transport, `n` rename, `g` expected country, `d` delete |
| `e` | exclusions: domains, IPv4 addresses (`31.172.77.119`) and subnets (`31.172.77.0/24`); `ctrl+s` saves |
| `v` | VPN list: which sites use the VPN (see [Which traffic uses the VPN](#which-traffic-uses-the-vpn)) |
| `s` | settings: DNS (Google by default, Cloudflare, Quad9, custom), QUIC blocking, local network |
| `x` | check exit IP, country and leaks |
| `↑ ↓` | select a connection |
| `?` | help |
| `q` | quit the dashboard (the VPN keeps running) |

The command line works too: `testvpn status`, `testvpn connect`,
`testvpn disconnect`, `testvpn import profile.conf`, `testvpn check`,
`testvpn logs [-f]` (see the table above for the service log file).

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

An address or subnet in exclusions (`31.172.77.119`, `10.20.0.0/16`) always
goes direct, whatever name the connection has, and keeps working while the
VPN is down; use it for SSH or other servers you reach by IP. IPv6 addresses
are not supported (IPv6 is blocked). `ping` does not work through the
client either way: only TCP and UDP are handled.

Exit-IP check services always use the VPN. Traffic whose site cannot be
identified follows the default: VPN with `*`, direct with a site list.

## Connect on startup

Settings (`s`) → "Connect on startup", or `testvpn autoconnect MODE`:

| Mode | After the computer boots |
| --- | --- |
| `last` (default) | connects to the last selected profile, even if you disconnected before shutting down |
| `restore` | connects only if the VPN was on at shutdown |
| `off` | stays disconnected |

A restart of the service within the same boot (crash, `install`)
always restores the previous state, so a crash never lifts the kill switch.

## Switching to another profile

With several profiles, the VPN moves to the next one (in import order, round
robin) after 5 failed connection attempts in a row, or when a profile has
tried all its transports. The kill switch stays on while it switches, and the
new profile becomes the selected one. Change the limit in Settings (`s`) →
"Next profile after" or with `testvpn failover N|off`. With a single profile
a failed tunnel is retried every 30 seconds.

## How traffic is protected

- **Kill switch.** When you connect, filter rules are installed *before* the
  tunnel starts. Only the tunnel, the VPN servers, addresses of excluded
  domains (added right before each direct connection), DHCP, loopback and
  IPv6 link-local/multicast may leave the computer.
  - macOS: pf anchor `com.apple/250.TestVPN`.
  - Linux: nftables table `inet testvpn` (an `output` chain ending in `drop`).
    Local container bridges (`docker0`, `br-*`, `veth*`, `cni*`, `podman*`,
    `virbr*`) are always allowed, so containers keep reaching host services
    (e.g. Open WebUI → Ollama); their own internet traffic goes into the tunnel.
  - Windows: Windows Filtering Platform filters that permit the `TestVPN`
    adapter, loopback, DHCP, neighbor discovery and the service itself (it
    makes the server and excluded-domain connections); everything else is
    blocked.
- **Crash = blocked.** On macOS and Linux the rules stay if the service
  crashes and the tunnel interface disappears, so nothing leaks; launchd or
  systemd restarts the service and it reconnects. On Windows the filters
  belong to the service process, so they go with it; the service manager
  restarts it within a second and it blocks again before reconnecting. While
  you are disconnected, nothing is blocked.
- **IPv6** is routed into the tunnel and dropped there (the servers have no
  IPv6), and the kill switch blocks it outside the tunnel.
- **DNS** is set to the selected resolver (8.8.8.8 by default) and restored
  on disconnect. On Linux the tunnel link gets the servers and the `~.`
  routing domain when `/etc/resolv.conf` points to systemd-resolved
  (`127.0.0.53`); otherwise `/etc/resolv.conf` is rewritten and the original
  is put back on disconnect (also by `unblock`). All DNS queries that reach
  the tunnel are answered by the client either way.

## Verify

```sh
testvpn status
sudo tcpdump -ni en0 'not host <server-ip>'    # macOS: only excluded domains may appear
sudo tcpdump -ni eth0 'not host <server-ip>'   # Linux (use your interface name)
```

Press `x` in the dashboard: exit country, IPv6 blocked, WebRTC = exit IP,
"direct bypass: blocked".

Crash test (macOS, Linux):

```sh
sudo pkill -9 -f 'testvpn daemon'   # internet stays blocked…
testvpn status                      # …until the service is restarted
```

## Emergency: get the internet back

```sh
sudo testvpn unblock        # macOS, Linux
testvpn unblock             # Windows, Administrator terminal
```

It disconnects through the service if it runs, otherwise removes the filter
rules, restores DNS, deletes server routes (and on Windows a leftover
`TestVPN` adapter) and marks the state as disconnected. Without the binary,
the same by hand:

```sh
sudo pfctl -a com.apple/250.TestVPN -F all     # macOS
sudo nft delete table inet testvpn             # Linux
```

On Windows stopping the service (`sc stop TestVPN`) removes its filters.

## Uninstall

```sh
sudo testvpn uninstall           # keeps profiles
sudo testvpn uninstall --purge   # deletes profiles and settings too
```

On Windows run the same commands without `sudo` in an Administrator
terminal.

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

## Other VPN apps

Disconnect other VPN apps before connecting and turn off their "connect on
demand"/"always on". A connected VPN captures the service's own connections
to your server, which then time out. The service looks for such conflicts and
shows them as warnings in the dashboard, in `testvpn status` and in the log:

- macOS: connected VPN configurations (`scutil --nc list`), foreign `utun`
  default routes and other pf anchors;
- Linux: other interfaces holding a default or split-default route (`wg0`,
  `tun0`, …) and policy routing rules (`ip rule`) such as wg-quick's;
- Windows: other adapters holding split-default routes (`0.0.0.0/1`,
  `128.0.0.0/1`).

```sh
scutil --nc list | grep Connected     # macOS: must print nothing
ip -4 route; ip -4 rule               # Linux: only testvpnN may hold 0/1 and 128/1
```

## Limitations

- Amnezia **subscription keys** (Amnezia Premium / Free, `vpn://` keys
  without servers) cannot be imported: the official app gets the servers
  from Amnezia's gateway with credentials that only it has. With Amnezia
  Premium: in AmneziaVPN open Settings → Servers → your subscription server
  (Настройки → Серверы → сервер; or tap the server name on the home screen)
  → "Configuration files" («Файлы конфигурации»), download the `.conf` for a
  location and import it (`p` → `i` → `@~/Downloads/file.conf`, or
  `testvpn import file.conf`). Amnezia Free has no configuration files, so
  it cannot be used outside the official app.
- macOS: if DNS servers are set manually in System Settings → Network for
  the active interface, they take precedence over the override. Public
  resolvers still work (all DNS goes through the tunnel); a resolver in your
  local network is blocked by the kill switch. Disabling pf by hand
  (`pfctl -d`) removes the protection.
- Linux: NetworkManager or a DHCP client may rewrite `/etc/resolv.conf`;
  the service puts its version back within a few seconds. Firewall managers
  that flush the whole nftables ruleset (`nft flush ruleset`) remove the
  kill switch until the next reconnect.
- Windows: "Allow local network" is not supported (the kill switch blocks
  the LAN); the OpenVPN transport is not supported yet.
- Logs of the service: see the table at the top, and the dashboard log
  panel (secrets are redacted).
