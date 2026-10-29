#!/bin/sh
set -eu

sh prepare-sdk.sh
cargo test --locked --workspace --lib --bins
cargo build --locked --release --bin maple-transport
# The runtime is scratch: a dynamic interpreter would make the helper unusable.
if readelf -l target/release/maple-transport | grep -q INTERP; then
    echo 'Maple transport must be statically linked' >&2
    exit 1
fi
mkdir -p /out
cp target/release/maple-transport /out/maple-transport
