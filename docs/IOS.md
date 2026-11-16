# iOS app

The same Go core as the desktop and Android clients, built with `gomobile
bind` into `Vpncore.xcframework`, driven by a SwiftUI app and a packet
tunnel extension (Network Extension). iOS 18 or newer.

```
VPN.app (SwiftUI)                    PacketTunnel.appex (NEPacketTunnelProvider)
├─ connection, profiles, import      ├─ tunnel settings: all IPv4/IPv6, DNS
│  (text, file, QR: camera,          └─ Go core (Vpncore.xcframework):
│   Photos, Files)                      AmneziaWG / VLESS+REALITY / proxies,
├─ exclusions, settings, diagnostics    fallback, exclusions, split DNS,
└─ profiles in the Keychain, shared     in-core kill switch
   with the extension (App Group)
```

## Requirements

- macOS with Xcode 26 (iOS 18 SDK or newer).
- Go (the version in `core/go.mod`).
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`.
- A **paid** Apple Developer Program membership to run on an iPhone: the
  Network Extension entitlement (`packet-tunnel-provider`) is not available
  to the free Personal Team.
- The iOS Simulator runs the app but **not the tunnel**: Apple does not
  support packet tunnel extensions there. Use it for the UI only.

## Build and run

1. Set your team and bundle prefix in `apple/Config/Base.xcconfig`:

   ```
   DEVELOPMENT_TEAM = ABCDE12345
   BUNDLE_PREFIX = com.yourname.vpn
   ```

2. Build the framework and generate the project:

   ```sh
   ./scripts/build-xcframework.sh
   cd apple && xcodegen generate && open VPN.xcodeproj
   ```

3. In Xcode select the `VPNApp` scheme and your iPhone, and run. With
   automatic signing Xcode registers the App ID, the App Group
   (`group.<prefix>`) and the Network Extension capability. Register the
   phone in your developer account (Xcode does it when it is connected) and
   enable Developer Mode on it. Alternatively upload to TestFlight (internal
   testing); builds expire after 90 days.

Unsigned build for checking that everything compiles (as CI does):

```sh
cd apple && xcodebuild -project VPN.xcodeproj -scheme VPNApp \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

## Use

1. **Import a profile:** paste a `vless://` link (several lines become one
   profile with several transports), an AmneziaWG `.conf`, an Amnezia
   `vpn://` key, a `hysteria2://` or `ssh://` link (see [CLI.md](CLI.md#hysteria-2)) or an xray JSON
   config; open a file; **scan a QR code** with
   the camera; or pick an image with a QR code from **Photos** (for example
   a screenshot of a key) or from **Files**. A QR code is imported at once.
   "Add transports to this profile" combines, e.g., AmneziaWG and REALITY
   for automatic fallback.
2. **Profile details:** expected country (ISO code) for the exit check;
   optionally pin a transport.
3. **Exclusions:** one domain per line; `example.com` covers subdomains,
   `full:example.com` matches only that name.
4. **Settings:** DNS resolver (Google 8.8.8.8 / 8.8.4.4 by default), how
   excluded domains are resolved, QUIC blocking, local network, on-demand.
5. **Diagnostics:** "Update GeoIP database" once, then "Check exit and
   leaks" while connected.

## How it works

- The extension routes all IPv4 and IPv6 into the tunnel; IPv6 is dropped
  by the core (the servers have none). DNS goes to the tunnel resolver.
- Packets cross the Swift/Go boundary through callbacks; the core keeps the
  memory-saving stack settings needed under the extension's memory limit
  (30 MB soft limit set at start).
- **Kill switch:** while the server cannot be reached the tunnel stays up
  and the core rejects connections. After every transport has failed the
  extension retries every 30 seconds, like the desktop service.
- Network changes (Wi-Fi ↔ cellular) and wake from sleep make the core
  re-check the tunnel at once.
- QR codes are decoded on the device (VisionKit for the camera, Core Image
  for images). Photos are picked with the system picker, which gives the app
  only the chosen image, so no photo library permission is needed.

## Verifying leaks

Connect the iPhone to a Mac, then

```sh
rvictl -s <UDID>          # creates rvi0
sudo tcpdump -ni rvi0 not host <server-ip>
rvictl -x <UDID>
```

Only traffic to excluded domains and their DNS queries may appear. Public
DNS leak tests (browserleaks.com/dns, dnsleaktest.com) must show only the
selected resolver.

## Limitations

- OpenVPN profiles are not supported.
- The UI is in English.
- On iOS the extension cannot read the network's DNS servers, so excluded
  domains are resolved with the selected public resolver directly.
- The network identity for transport memory is coarse (interface type and
  name); Wi-Fi SSIDs need location permission.
- Memory use of the extension must be measured on a device with
  Instruments.
