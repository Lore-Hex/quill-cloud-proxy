#!/bin/sh
# Builds the classifier and proves it is the right model before it enters the
# image. Weights arrive at /weights through checksum-pinned Docker ADDs.
set -eu

cargo test --locked --release
cargo build --locked --release --bin polyphemus-classifier
# The runtime is scratch: a dynamic interpreter would make the helper unusable.
if readelf -l target/release/polyphemus-classifier | grep -q INTERP; then
    echo 'Polyphemus classifier must be statically linked' >&2
    exit 1
fi
# Reproduces the model card's published example within its printed precision.
target/release/polyphemus-classifier --self-test /weights
mkdir -p /out/model
install -m 0755 target/release/polyphemus-classifier /out/polyphemus-classifier
# URL ADDs arrive as 0600 root files; the helper runs as a non-root user.
install -m 0644 /weights/model.safetensors /weights/tokenizer.json /out/model/
for file in /out/model/model.safetensors /out/model/tokenizer.json; do
    if [ "$(stat -c %a "$file")" != 644 ]; then
        echo "$file must be world-readable for the helper's user" >&2
        exit 1
    fi
done
