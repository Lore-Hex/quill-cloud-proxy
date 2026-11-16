#!/bin/sh
set -eu
mkdir -p /rootfs/rampart /rootfs/licenses
cp /usr/local/bin/node /rootfs/rampart/node
cp -R node_modules model worker.mjs package.json /rootfs/rampart/
cp model/LICENSE /rootfs/licenses/rampart-CC-BY-4.0.txt
cp node_modules/@nationaldesignstudio/rampart/LICENSE /rootfs/licenses/rampart-runtime-CC-BY-4.0.txt
cp /usr/local/LICENSE /rootfs/licenses/node-LICENSE
# Preserve the base distribution's notices for the copied native libraries.
mkdir -p /rootfs/usr/share
cp -RL /usr/share/doc /usr/share/common-licenses /rootfs/usr/share/
# Copy only the dynamic runtime closure into the existing scratch image.
# ONNX Runtime loads its shared library at inference time, not at node startup.
{ ldd /usr/local/bin/node; find node_modules -type f \( -name '*.so*' -o -name '*.node' \) -exec ldd '{}' \; 2>/dev/null; } |
  awk '/=> \/|^\s*\// { for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i }' |
  sort -u | while IFS= read -r library; do cp -L --parents "$library" /rootfs; done
# The ELF interpreter is an absolute path, not an ordinary DT_NEEDED entry.
for loader in /lib64/ld-linux-*.so.* /lib/ld-linux-*.so.*; do
  if [ -e "$loader" ]; then cp -L --parents "$loader" /rootfs; fi
done
