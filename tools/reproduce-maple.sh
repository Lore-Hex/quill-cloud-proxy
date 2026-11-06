#!/usr/bin/env bash
# Run only in the credential-free ARM64 reproduction job, never in a deploy job.
set -euo pipefail
test "$#" = 3
vendor=$(cd "$1" && pwd)
source=$2
output=$3
[[ "$source" =~ ^[0-9a-f]{40}$ ]]
test "$(uname -s)/$(uname -m)" = Linux/aarch64
test "$(git -C "$vendor" rev-parse HEAD)" = "$source"
test -z "$(git -C "$vendor" status --porcelain)"
export NIX_CONFIG=$'experimental-features = nix-command flakes\nsandbox = true\nsandbox-fallback = false\naccept-flake-config = false\nsubstituters = https://cache.nixos.org\nextra-substituters =\nmax-jobs = 2\ncores = 4\nhttp2 = false'
test "$(nix config show sandbox)" = true
test "$(nix config show sandbox-fallback)" = false
test "$(nix config show substituters)" = https://cache.nixos.org
case "$(nix --version)" in
  'nix (Determinate Nix 3.23.3) 2.35.3') ;;
  *) echo 'Unreviewed Nix version' >&2; exit 1 ;;
esac
# Real derivation, not just a configured setting. Use the vendor's locked
# nixpkgs solely to obtain a shell; no Maple/FlakeHub output cache is trusted.
probe=$(nix build --impure --no-link --print-out-paths --expr "
  let f = builtins.getFlake \"path:$vendor/services/opensecret\";
      p = import f.inputs.nixpkgs { system = \"aarch64-linux\"; };
  in p.runCommand \"tr-maple-sandbox-${source:0:12}\" {} \"pwd > \$out\"")
test "$(cat "$probe")" = /build
# Whitelist the build environment. No GitHub token, cloud credential, OIDC
# request token or Actions command file is exposed to the vendor build script.
env -i HOME="$HOME" PATH="$PATH" NIX_CONFIG="$NIX_CONFIG" \
  OPENSECRET_DEV_POSTGRES=0 OPENSECRET_DEV_ENV=0 OPENSECRET_DEV_CONTAINERS=0 \
  bash "$vendor/scripts/ci/build_opensecret_eif.sh" prod "$output"
test -z "$(git -C "$vendor" status --porcelain)"
