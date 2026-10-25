# Building and running

The project has two parts:

- `core/` — the Go core: userspace network stack, router with domain
  exclusions, split DNS, xray-core (VLESS + REALITY) and amneziawg-go
  engines, fallback, kill switch, exit verification. It is tested on Linux
  and macOS without any Apple tooling.
- `apple/` — the SwiftUI app for iOS 26+ and macOS 26+ and the packet tunnel
  extension. It links the core as `Vpncore.xcframework` built with gomobile.

## Requirements

- macOS 26 with Xcode 26.
- Go (the version in `core/go.mod`; `GOTOOLCHAIN=auto` downloads it).
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`.
- A **paid** Apple Developer Program membership. The Network Extension
  entitlement (`packet-tunnel-provider`) is not available to the free
  Personal Team.

## Core tests

```sh
./scripts/test-core.sh
```

Packages whose test binaries link xray-core run without the race detector:
xray-core has a known data race in its XHTTP client. End-to-end tests start
in-process AmneziaWG and VLESS + REALITY servers; tests that need a
non-loopback IPv4 address are skipped on machines without one.

## App

1. Set your team and bundle prefix in `apple/Config/Base.xcconfig`:

   ```
   DEVELOPMENT_TEAM = ABCDE12345
   BUNDLE_PREFIX = com.yourname.vpn
   ```

2. Build the framework and the project:

   ```sh
   ./scripts/build-xcframework.sh
   cd apple && xcodegen generate && open VPN.xcodeproj
   ```

3. In Xcode, select `VPNApp_iOS` or `VPNApp_macOS` and run. With automatic
   signing Xcode registers the App ID, the App Group (`group.<prefix>`) and
   the Network Extension capability.

   - **iPhone:** register the device in your developer account (Xcode does it
     when the phone is connected), enable Developer Mode on the phone, run.
     Alternatively upload to TestFlight (internal testing); builds expire
     after 90 days.
   - **Mac:** run from Xcode. The app and the extension are sandboxed app
     extensions; no System Extension approval is needed.

   Development provisioning profiles expire after a year; Xcode renews them
   on the next build.

## Using the app

1. **Import a profile:** paste a `vless://` link (several lines become one
   profile with several transports), an AmneziaWG `.conf`, an Amnezia
   `vpn://` key or an xray JSON config; or open a file, an image with a QR
   code, or scan a QR code (iPhone). Use "Add transports to this profile" to
   combine, e.g., AmneziaWG and REALITY for automatic fallback.
2. **Profile details:** set the expected country (ISO code) used by the exit
   check; optionally pin a transport.
3. **Exclusions:** one domain per line; `example.com` covers subdomains,
   `full:example.com` matches only that name.
4. **Settings:** DNS resolver (default Google 8.8.8.8 / 8.8.4.4), how excluded
   domains are resolved, QUIC blocking, local network, on-demand.
5. **Diagnostics:** "Update GeoIP database" once, then "Check exit and leaks"
   while connected.

## Verifying leaks (spec 8.4)

- **Mac:** `sudo tcpdump -ni en0 not host <server-ip>` while connected. Only
  traffic to excluded domains and their DNS queries may appear.
- **iPhone:** connect it to a Mac, then

  ```sh
  rvictl -s <UDID>          # creates rvi0
  sudo tcpdump -ni rvi0 not host <server-ip>
  rvictl -x <UDID>
  ```

- Public DNS leak test (browserleaks.com/dns, dnsleaktest.com): only the
  selected resolver must appear.

## Known limitations of this version

- Packets cross the Go/Swift boundary one by one (callback mode). The core
  also supports reading the utun file descriptor directly
  (`StartWithFD`), which is faster; switching to it is a follow-up.
- On iOS the extension cannot read the network's DNS servers, so excluded
  domains are resolved with the selected public resolver directly.
- The network identity for transport memory is coarse (interface type and
  name); Wi-Fi SSIDs need location permission.
- Memory use of the iOS extension (PLAT-002) must be measured on a device
  with Instruments.
