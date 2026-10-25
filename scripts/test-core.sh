#!/usr/bin/env bash
# Runs the Go core tests. Test binaries that link xray-core run without the
# race detector: xray-core has a known data race in its XHTTP client and uses
# unsafe pointer arithmetic that checkptr rejects.
set -euo pipefail
cd "$(dirname "$0")/../core"
go vet ./...
race=() plain=()
for pkg in $(go list ./...); do
  deps=$(go list -test -deps "$pkg")
  if grep -qx "github.com/xtls/xray-core/core" <<<"$deps"; then
    plain+=("$pkg")
  else
    race+=("$pkg")
  fi
done
go test -race "${race[@]}"
go test "${plain[@]}"
