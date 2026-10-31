#!/bin/bash
set -eu

# Source and toolchain are immutable inputs. Only the MIT-licensed client is built.
archive=$1
output=$2
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
echo "1ce54898001c959449be0109a0afc0e9f4d4d206b566ac2013418895a921f7a0  $archive" | sha256sum -c -
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT
tar -xzf "$archive" --strip-components=1 -C "$source_dir"
cd "$source_dir"
git apply --check "$root/control-plane-limits.patch"
git apply "$root/control-plane-limits.patch"
cp "$root/httpapi_limits_test.go.txt" internal/oss/httpapi/tr_limits_test.go
cp "$root/secretmanager_limits_test.go.txt" internal/oss/secretmanager/tr_limits_test.go
export GOTOOLCHAIN=local CGO_ENABLED=0
# The pinned upstream source predates GO-2026-6866. Keep the security override
# explicit and checksum-verified without changing the reviewed source archive.
go mod edit -require=golang.org/x/net@v0.62.0
cat "$root/security-go.sum" >> go.sum
go mod download golang.org/x/net
# Tests run on the builder architecture; production output uses the caller's target.
target_os=${GOOS:-linux}
target_arch=${GOARCH:-amd64}
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go test -tags contrast_unstable_api \
    ./internal/oss/httpapi ./internal/oss/secretmanager ./privatemode-proxy/cmd
GOOS=$target_os GOARCH=$target_arch go build -trimpath -buildvcs=false \
    -tags contrast_unstable_api \
    -ldflags '-s -w -X github.com/edgelesssys/continuum/internal/oss/constants.version=v1.60.0' \
    -o "$output" ./privatemode-proxy
cp LICENSE.MIT "${output}.LICENSE"
