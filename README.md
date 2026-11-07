# test-vpn

Personal VPN client for macOS, Linux, Windows (console), Android and iOS with AmneziaWG and
VLESS + REALITY, automatic fallback between them, a strict kill switch,
domain exclusions and exit verification (IP, country, DNS/IPv6/WebRTC
leaks). A privileged background service runs the tunnel; `testvpn` opens a
terminal dashboard and has the same commands on every system.

- Install and use: [docs/CLI.md](docs/CLI.md) (desktop), [docs/ANDROID.md](docs/ANDROID.md),
  [docs/IOS.md](docs/IOS.md)
- Specification: [docs/spec/03-stealth-and-egress.md](docs/spec/03-stealth-and-egress.md)
- Source: [core/](core) (Go; the command is [core/cmd/testvpn](core/cmd/testvpn),
  the gomobile API is [core/bridge](core/bridge)), [android/](android) (Kotlin),
  [apple/](apple) (Swift, iOS)
