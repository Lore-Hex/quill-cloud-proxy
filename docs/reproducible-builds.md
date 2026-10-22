# Reproducing the measured gateway image

## Scope

The `trustedrouter-reproducible-image/1` recipe reconstructs the complete
single-platform OCI image, not only the main Go executable. It covers executable
bytes, every layer, file metadata, certificates, entrypoint, environment and
labels. GCP release jobs build on two independent runner VMs with fresh BuildKit
stores. Neither build reuses a compilation or image-layer cache. Image promotion,
trust publication and rollout require identical image digests.

Older releases without `reproducible_build.schema` in their signed release record
do not have this guarantee. Do not interpret a binary match as whole-image proof,
or a signature on a source-to-image mapping as independent build reproduction.

## Verify a GCP release

Requirements: Git, Python 3.12+, Docker with a local Unix socket and linux/amd64
support, and cosign 2.6.5+ on 2.x or 3.1.3+ on 3.x. No cloud account or API key
is needed. The helper runs digest-pinned build containers on your Docker engine;
use an isolated build machine as you would for any third-party Docker build.

```sh
git clone https://github.com/Lore-Hex/quill-cloud-proxy.git
cd quill-cloud-proxy
bash tools/verify-build.sh
```

The verifier fetches the release JSON and its signature, checks the exact GCP
publisher identity, resolves the full source commit, builds a Git archive of
that commit, and compares the complete image manifest digest. It rejects dirty
checkouts, legacy releases, signature failures and digest mismatches. A release
newer than your clone requires `git fetch origin main` first.

Then verify fresh attestation against the digest printed by the rebuild:

```sh
uv run --locked tools/verify-attestation.py \
  --api-host api.trustedrouter.com \
  --expect-digest sha256:REPLACE_WITH_THE_VERIFIED_IMAGE_DIGEST
```

This checks the issuer, nonce and TLS connection binding, not just a digest in an
unsigned JSON response. During a rolling release, an older accepted image may
still answer. Verify that older release separately or wait for the rollout to
complete. An arbitrary accepted digest is not a substitute for the one rebuilt.
The live verifier proves only the connections it samples, not every fleet member.

## Build and compare locally

From a clean committed checkout:

```sh
COMMIT=$(git rev-parse HEAD)
python3 tools/reproducible_build.py build --plane gcp --commit "$COMMIT" --output-dir /tmp/tr-build-a
python3 tools/reproducible_build.py build --plane gcp --commit "$COMMIT" --output-dir /tmp/tr-build-b
```

Compare `image_digest` in the two `reproduction.json` files. For independent
verification, run on separate machines, not merely twice on one Docker host.
`image.tar` is a complete OCI archive. `build-metadata.json` holds detached
BuildKit provenance, including non-deterministic invocation details. The tar
archive itself is packaging, not the measured image hash.

## Fixed inputs

- Go toolchain and Privatemode proxy images are pinned by digest in each Dockerfile.
- The Dockerfile frontend, Docker/Buildx client and BuildKit engine are pinned.
- Go modules use committed manifests/checksums, read-only module mode and no
  automatic toolchain upgrades. Vendored code comes from the same Git archive.
- Certificates come from the pinned Go builder, not a live package repository.
- Source revision is the full commit; timestamps use its committer timestamp.
- Layer rewriting, compression and OCI media types are explicit.
- Signatures, SBOMs and variable build-provenance records are external to the
  measured image. They must not be inserted into its OCI index after verification.

Pin updates remain normal security maintenance: review them, rebuild twice,
publish the new measured digest, then use the existing staged deployment gates.
Do not keep vulnerable dependencies merely to preserve an old hash.

## Privatemode dependency

`/privatemode-proxy` is a vendor client running **inside** the measured enclave.
It verifies Privatemode's attested service and encrypts only Privatemode traffic.
Other providers do not pass through it. The supervisor drops privileges, grants
no inherited credentials and uses certificate-pinned loopback TLS. Failure does
not enable a plaintext fallback. See [the boundary and pins](runbooks/privatemode.md).

The vendor's v1.59.0 linux/amd64 executable was independently rebuilt on
2026-10-22 from public commit `17ad265a79a39f30596ae2f12ec64ccbd9127275`.
The rebuilt executable and the executable extracted from the pinned vendor image
match byte-for-byte, with SHA-256
`0113ea23b7035fd3e3dd078cbb0d5ddc9471cfeac44a49c392802e55ee7f6487`.
The vendor image was never executed to obtain this comparison.

Repeat that check without API keys or cloud access:

```sh
python3 tools/verify_privatemode_binary.py --output-dir /tmp/privatemode-verification
```

This uses the vendor's committed Nix lockfile and build recipe inside a pinned
build container. Only the official Nix cache supplies general build dependencies;
the vendor's Cachix cache and flake-provided cache settings are disabled. The
source build has no host Docker socket or credential mounts. The helper compares
both executables to our reviewed checksum and writes `verification.json` only
after all comparisons pass. Use a new output directory for each run.

All three production Dockerfiles verify that executable checksum before copying
it into the runtime. PR image comparison, GCP production release, and the shared
manual AWS/Azure/GCP release command require a successful source rebuild. A vendor
upgrade requires updating the source/image/checksum pins together and passing
these gates again. This proves the executable corresponds to the specified
source under the declared build toolchain, not that the source is bug-free or
that the entire upstream inference deployment has been reproduced. The compiler,
Nix dependencies and remote-attestation checks remain separate trust inputs.

## AWS and Azure

The shared recipe also builds the AWS and Azure OCI images (`--plane aws|azure`).
Their manual release paths compare two fresh isolated builders before promoting
an image. These two local builders are not independent machines.

An AWS image digest is not Nitro PCR0: the latter also measures Nitro's kernel,
initramfs and EIF tooling. Azure's hostdata measures its generated CCE policy,
including region-specific configuration and other containers. Reproducing the
application image alone must not be represented as reproducing either entire
cloud measurement. Keep the existing PCR0/hostdata, nonce and TLS verification
gates; no build result authorizes bypassing them.

## Release evidence

GCP keeps both JSON build records and detached provenance as small workflow
artifacts (14 days). The signed public release record preserves the full commit,
image digest and recipe identity. Third parties can rebuild without those
transient workflow artifacts. Nothing in the image reproduction step needs
customer prompts, provider credentials, billing access or inference traffic.
