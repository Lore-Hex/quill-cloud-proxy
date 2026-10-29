#!/bin/sh
set -eu
cd "$(dirname "$0")"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
revision=c668d817dceec5c2e7390de7c68a581c88ea2eea
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 3 --max-time 300 \
    "https://codeload.github.com/MaplePrivacyLabs/Maple/tar.gz/$revision" \
    -o "$stage/source.tar.gz"
expected=d4d1f3ec633d1e16dfd095c6134c62af0cb18b707235de4ec1e1cc1bcb893e7a
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$stage/source.tar.gz" | cut -d ' ' -f1)
else
    actual=$(shasum -a 256 "$stage/source.tar.gz" | cut -d ' ' -f1)
fi
test "$actual" = "$expected"
mkdir "$stage/sdk"
tar -xzf "$stage/source.tar.gz" -C "$stage/sdk" --strip-components=3 "Maple-$revision/sdk/rust"
patch --batch --forward --fuzz=0 -p1 -d "$stage/sdk" < sdk-dependencies.patch
# This generated dependency is rebuilt from the verified archive every time.
# The workspace lockfile is authoritative; do not scan a stale nested lockfile.
rm "$stage/sdk/Cargo.lock"
rm -f "$stage/sdk/Cargo.toml.orig"
rm -rf .vendor-sdk
mv "$stage/sdk" .vendor-sdk
