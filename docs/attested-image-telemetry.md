# Attested image telemetry dependency policy

The attestation sidecar previously linked OpenTelemetry through this chain:

`Tinfoil verifier -> sigstore-go -> Rekor verify -> generated HTTP client -> go-openapi runtime/client -> OpenTelemetry`

SDK presence was confirmed in the executable. It was not evidence of telemetry
export, and this repair does not claim a historical export occurred.

## Repair

`enclave-go/third_party/rekor-offline` preserves pinned upstream Rekor v1.5.0
verification and model code. Only two unused online helpers and their client
imports are omitted. Its generator verifies the Go module checksum and exact
source equality. Upstream cryptographic verification is retained, not replaced
by a hand-written verifier or success-returning stubs. Hardware evidence,
certificate chains, signatures, transparency proofs, identity, measurements
and TLS binding keep their existing checks and fail-closed behavior.

The generated HTTP clients remain as source for unchanged upstream Sigstore
tests. They no longer appear in the runtime dependency closure. Module graphs
can include test/tool-only telemetry dependencies; runtime build information
is the relevant evidence for what ships.

## Release gate

All three production Dockerfiles inspect their assembled scratch rootfs before
the final image can be produced. The gate requires the exact three reviewed
static Go executables: `/quill-enclave`, `/attest-sidecar`, `/privatemode-proxy`.
It rejects missing build information, dynamic libraries, unknown executables,
symlinks and known telemetry modules, including replacement-module paths.
`/telemetry-audit.json` records executable hashes and Go versions in the measured
image. The gate does not rely on stripped symbol tables or scanning go.sum.

CI builds GCP, AWS and Azure images and runs upstream inclusion/checkpoint,
Sigstore bundle verification and sidecar regressions. The gate has also been
checked against the previous executable, which fails on
`go.opentelemetry.io/auto/sdk`.

This is an executable inventory and known-SDK policy, not proof that arbitrary
code could never export data. Source review, provider verification and egress
controls remain necessary. New runtime executables, SDKs or dependency updates
require review; do not relax the gate just to complete a release.

Release through the existing per-cloud measurement-transition process. Publish
and verify the accepted old/new measurements before serving a candidate, roll
one region at a time, and narrow accepted measurements only after all regions
verify. A green local image or merged PR does not establish production rollout.
