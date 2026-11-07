#!/usr/bin/env bash
# Builds the Android app: the Go core as an AAR (gomobile bind), then the APK.
# Needs the Android SDK with an NDK, JDK 17 and gomobile
# (go install golang.org/x/mobile/cmd/gomobile@<version from core/go.mod>).
#
#   ANDROID_HOME=~/Library/Android/sdk ./scripts/build-android.sh [debug|release]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
variant="${1:-debug}"

: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
if [[ -z "$ANDROID_HOME" ]]; then
  for d in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" /opt/homebrew/share/android-commandlinetools; do
    [[ -d "$d" ]] && ANDROID_HOME="$d" && break
  done
fi
[[ -d "${ANDROID_HOME:-}" ]] || { echo "set ANDROID_HOME to the Android SDK" >&2; exit 1; }
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[[ -d "${ANDROID_NDK_HOME:-}" ]] || { echo "no NDK: sdkmanager --install 'ndk;27.2.12479018'" >&2; exit 1; }
export ANDROID_HOME ANDROID_NDK_HOME

cd "$root/core"
mkdir -p "$root/android/app/libs"
# The ABIs must match abiFilters in android/app/build.gradle.kts.
gomobile bind -target=android/arm64,android/amd64 -androidapi 24 \
  -javapkg com.testvpn.core -ldflags="-s -w" \
  -o "$root/android/app/libs/vpncore.aar" ./bridge

cd "$root/android"
echo "sdk.dir=$ANDROID_HOME" > local.properties
task="assemble$(tr '[:lower:]' '[:upper:]' <<<"${variant:0:1}")${variant:1}"
./gradlew "$task"
ls -lh "app/build/outputs/apk/$variant/"*.apk
