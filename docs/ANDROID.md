# Android app

The same Go core as the desktop client, built with `gomobile bind` into an
AAR and driven by a small Kotlin app (Jetpack Compose) through `VpnService`.
Android 8.0 or newer, arm64 phones and x86_64 emulators.

```
TestVPN app (one process)
├─ UI: status, profiles, exclusions / VPN list, settings, log
└─ TestVpnService (VpnService)
   ├─ TUN interface: all IPv4 and IPv6 of other apps, DNS 8.8.8.8
   └─ Go core (vpncore.aar): AmneziaWG / VLESS+REALITY / proxies,
      fallback, exclusions, split DNS, in-core kill switch
```

## Build

Requirements: Go, JDK 17, the Android SDK with platform 34 and an NDK, and
`gomobile` at the version in `core/go.mod`:

```sh
sdkmanager --install "platforms;android-34" "build-tools;34.0.0" "ndk;27.2.12479018"
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
./scripts/build-android.sh            # → android/app/build/outputs/apk/debug/app-debug.apk
./scripts/build-android.sh release    # signed with the debug key, for personal use
```

Install on a phone with USB debugging: `adb install -r app-debug.apk`, or copy
the APK to the phone and open it (allow installing from this source).

## Use

1. **Профили → Импорт**: paste a `vless://` link, an AmneziaWG/WireGuard
   `.conf`, an Amnezia `vpn://` key, `vmess://`, `trojan://`, `ss://`, `socks5://`, `hysteria2://` or `ssh://` (see
   [CLI.md](CLI.md#ssh)), take it from the
   clipboard, pick a file, **scan a QR code** with the camera («Сканировать
   QR») or **pick a QR image from the gallery** («QR из галереи», e.g. a
   screenshot of the key). A QR code is imported at once.
2. **VPN → Подключить**. The first time Android asks to allow the VPN.
3. **Правила**: exclusions — domains, zones, IPv4 addresses and subnets that always go
   direct; the VPN list limits the VPN to some sites. Changes apply without
   reconnecting.
4. **Настройки → Открыть настройки VPN**: turn on "Always-on VPN" and "Block
   connections without VPN" for TestVPN. Android then starts the VPN at boot
   (with the selected profile) and blocks the internet whenever it is down.

## How it works

- Android creates the TUN interface, routes and DNS; the core gets its
  descriptor (`detachFd()`) and owns it.
- The app excludes **itself** from the VPN (`addDisallowedApplication`), so
  the core's own connections — to the server and to excluded domains — use
  the physical network without per-socket `protect()`. Other apps' traffic
  to excluded domains enters the tunnel and the core connects it directly.
- **Kill switch.** While the server cannot be reached the interface stays up
  and the core rejects connections, so nothing leaks. If the app process is
  killed, only Android's "Block connections without VPN" keeps traffic
  blocked — turn it on.
- When every transport has failed, the app retries every 30 seconds (the
  kill switch stays on meanwhile), like the desktop service.
- IPv6 is captured and dropped (the servers have none).
- Network switches (Wi-Fi ↔ mobile) are reported to the core, which
  re-checks the tunnel at once.
- Profiles (with keys) and settings live in app-private storage, which
  other apps cannot read; backups are disabled.
- QR codes are decoded on the device with ZXing (no Google Play services
  needed). The gallery uses the system photo picker, so the app gets only
  the chosen image and needs no storage permission; the camera permission is
  asked when the scanner opens.

## Limitations

- OpenVPN profiles are not supported (there is no `openvpn` binary).
- No exit check screen yet; the log shows the core's messages (secrets
  redacted).
- One profile is used at a time; switching to the next profile after
  failures (desktop `failover`) is not implemented.
