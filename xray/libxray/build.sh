#!/usr/bin/env bash
# Builds app/libs/libxray.aar with gomobile (needs Go + Android NDK). Used by CI.
set -euo pipefail
cd "$(dirname "$0")"
XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"
# Xray tags (vYY.M.D) are not semver-major-compatible; `go get @tag` maps them to a pseudo-version.
go get github.com/xtls/xray-core@"$XRAY_VERSION"
go get golang.org/x/mobile/bind@latest golang.org/x/mobile/cmd/gomobile@latest
go mod tidy
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
"$(go env GOPATH)/bin/gomobile" init
mkdir -p ../../app/libs
"$(go env GOPATH)/bin/gomobile" bind -v -target=android/arm64,android/arm,android/amd64 -androidapi 24 \
  -trimpath -ldflags='-s -w -buildid=' -o ../../app/libs/libxray.aar .
ls -la ../../app/libs/libxray.aar
