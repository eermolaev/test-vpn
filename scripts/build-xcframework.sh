#!/usr/bin/env bash
# Builds apple/Frameworks/Vpncore.xcframework from the Go core with gomobile.
# Requires macOS with Xcode and Go (see docs/BUILD.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/core"
command -v gomobile >/dev/null || go install golang.org/x/mobile/cmd/gomobile@latest
command -v gobind >/dev/null || go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
mkdir -p "$root/apple/Frameworks"
rm -rf "$root/apple/Frameworks/Vpncore.xcframework"
gomobile bind \
  -target=ios,iossimulator,macos \
  -iosversion=17.0 \
  -ldflags="-s -w" \
  -trimpath \
  -o "$root/apple/Frameworks/Vpncore.xcframework" \
  ./bridge
echo "Built $root/apple/Frameworks/Vpncore.xcframework"
