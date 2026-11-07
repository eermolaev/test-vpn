#!/usr/bin/env bash
# Builds apple/Frameworks/Vpncore.xcframework from the Go core with gomobile.
# Requires macOS with Xcode and Go (see docs/IOS.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/core"
# gomobile must match golang.org/x/mobile in core/go.mod.
mobile="$(go list -m -f '{{.Version}}' golang.org/x/mobile)"
command -v gomobile >/dev/null || go install "golang.org/x/mobile/cmd/gomobile@$mobile"
command -v gobind >/dev/null || go install "golang.org/x/mobile/cmd/gobind@$mobile"
gomobile init
mkdir -p "$root/apple/Frameworks"
rm -rf "$root/apple/Frameworks/Vpncore.xcframework"
gomobile bind \
  -target=ios,iossimulator \
  -iosversion=17.0 \
  -ldflags="-s -w" \
  -trimpath \
  -o "$root/apple/Frameworks/Vpncore.xcframework" \
  ./bridge
echo "Built $root/apple/Frameworks/Vpncore.xcframework"
