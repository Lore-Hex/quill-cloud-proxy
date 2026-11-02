# Privatemode v1.61 deployment review

Status: independent policy/image reproduction and local encrypted qualification
passed. Regional production deployment is not established by this document yet.

## Root cause

The provider moved from immutable deployment `continuum-551e7c` to
`continuum-e8a714`. Our v1.60 manifest correctly rejected that change during
secret initialization with HTTP 401 / `attestation_manifest_mismatch`. The API
key was valid. Retrying credentials, widening measurements, or falling back to
ordinary HTTPS would not be an acceptable repair.

## Immutable inputs

- Public source v1.61.0: `1d35fd8496b6fbd88d95e201f292a19ea7f6e5b3`.
- Source archive SHA-256: `d6ef061c5d7430b44d66c6754b86ec8a287630c560fde9968fb0d4214f310036`.
- Reviewed manifest SHA-256: `cb8fe2f3b8973b8d12f99c3340d4102c642e6be40e26c2a9070e1a630e420bab`.
- Previous manifest SHA-256: `b47473de3d4246903490bcb2e9aa99e9d296d12c2c357b5aa4f438fb3e655e9f`.
- Contrast v1.26.0 Linux CLI SHA-256: `fe4fcac0cd81e7385a59b923a20dc41fdd1e01cbd2073caa45b6038bf91dbae3`.
- Locally built, hardened Linux amd64 client SHA-256:
  `af9448e93231efd839369f11ffd155fdcfdf676b98be16794ee719d1d18ed052`.

The production client is built from source with pinned Go 1.26.10, the existing
bounded control-plane patch, and the explicit checksum-verified x/net v0.62.0
security override. It is intentionally not byte-identical to the upstream Nix
binary. The separate unmodified Nix rebuild below verifies upstream provenance.

## Independent reproduction

Cloud Build `7a80af14-d639-45de-b7d6-35a28bb81174` independently generated all
eight policies and hardware reference values from the pinned deployment YAML.
After the pinned `scripts/adjust-manifest.sh` transformations and removal of the
Milan entry for the deployed Genoa fleet, the generated document exactly matches
the published manifest except for `SeedshareOwnerPubKeys`. That recovery key is
a deployment-specific public identity, not reproducible source output.

- Raw generated manifest: `2ae275b0145ba44315a629d1c9a40552dbdb72cbc58d3c00c64b116c6cb82f37`.
- Adjusted manifest: `8715c1a31c0b71707890da443402474fb6d04895e494c1ec92b0f5779ea84c64`.
- Retained raw evidence:
  `gs://44325983244.cloudbuild-logs.googleusercontent.com/privatemode-policy-audit/7a80af14-d639-45de-b7d6-35a28bb81174/`.

Reproduction uses `contrast generate --disable-updates
--reference-values=metal-qemu-snp-gpu
--reference-value-patches=scripts/snp-guestpolicy-patch.json
--collateral-proxy=http://collateral-proxy.continuum-infra.svc deployment.yaml`.
Set the two secret-service SAN variables for namespace `continuum-e8a714` when
running the adjustment script. No generated hash or measurement is copied from
the published manifest to make the comparison pass.

Cloud Build `90f20969-b833-42af-acb9-86db9e672046` rebuilt the public Nix
`privatemode-container-images.oss-oci-images` output using only
`https://cache.nixos.org`, with vendor flake-cache configuration disabled.
Every security-component digest matches the deployment:

| Component | OCI SHA-256 |
| --- | --- |
| attestation-agent | `1ca9efe1600238037c4bf954d5cc289c49a541cbfa93fc144a6ce7b2c083554f` |
| disk-mounter | `f66f2ea5feb4a39ec4f8ec1e464e7d911ee2f67ef468603cb80fbcbf341ec931` |
| inference-proxy | `687228cc72cc66fa5ca45856eff3bf9b55c148d7efad00273bbae847460965ba` |
| kernel-log | `a32e11e7ee2961f2e0de4080f6dffecfdc7d64232f3f34f898ed9a91492219e2` |
| secret-service | `67d506d6aa231ecf8954feed154b56fb445c80444a27f3aa142a0108b15bafde` |

The proxy OCI index reproduced as `ec97e6a3cd4867bdedc0c928672926e1f15b15c3ec204534dffb9beb8dbf93df`.
The upstream Nix client binary SHA-256 is
`fae8ce385e16eeea14b5e945e2151d6284492a4ac0ad69905fa69ece2af82315`.
These are audit artifacts, not the hardened client shipped by TrustedRouter.
Retained image evidence uses the corresponding `privatemode-image-audit/`
prefix and build ID in the same bucket.

## Security and privacy review

The v1.60 to v1.61 diff strengthens OCSP root/chain binding, responder
authorization, CertID matching, and validity intervals. RIM parsing now uses
only signature-covered XML and rejects duplicate attributes and signatures.
The strict OCSP request policy moves into authenticated encrypted metadata.
Unknown or absent policy does not enable permissive GPU acceptance.

Minimum TCB, non-debug enforcement, hardware allowlists and immutable-update
restrictions remain unchanged. Contrast 1.26 supplies the reproduced new SNP
measurement and TDX RTMR2. The three explicit false TDX optional restrictions
have the same semantics as their omitted Go bool defaults in Contrast 1.25.1;
they are not newly disabled requirements.

Independent source review flagged the new `--kv-cache-metrics` setting for
follow-up. The pinned engine is upstream vLLM v0.31.0, not an unidentified fork.
At source `db9527a46873454610df6dbedf79a36d6bf1a7f6`,
`vllm/v1/core/kv_cache_metrics.py` emits eviction events containing only lifetime,
idle duration and reuse gaps. The local block ID is not exported. The three
Prometheus histograms in `vllm/v1/metrics/loggers.py` are labelled only by model
and engine. Sampling is per block, not per request. No prompt, token IDs, prefix
hashes, or request identifier is introduced by this setting.

Scope limits remain explicit: the custom stat-logger and several serving
patches/templates are hash-pinned but not present in the public tree; this is
not a claim to have reproduced all inference dependencies or proprietary GPU
drivers. The existing OTLP forwarder does not enforce an attribute allowlist.
Plaintext upstream error bodies are still untrusted and discarded/redacted by
our integration. These residual limitations are not removed by successful
hardware attestation.

## Local qualification

- Source-build tests cover bounded HTTP reads, refresh deadlines, proxy server,
  encrypted-body handling and OCSP policy handling.
- Linux amd64 source-mode `govulncheck v1.9.0` reports zero reachable
  vulnerabilities and zero affected imported packages. One required module has
  an advisory outside the imported client path; do not call all dependencies
  advisory-free.
- Packaged Linux encrypted streaming passed for GPT OSS 120B, GLM 5.3 and
  GLM 5.3 Flash, with nonempty PONG output and final usage.
- Packaged encrypted embeddings passed at 1,024 and 2,560 dimensions; synthetic
  OCR passed. No customer prompts were used.
- Removing the coordinator from the expected manifest returns HTTP 401 before
  inference. Required strict flags, sealed-FD immutability, UID/GID 65532,
  no capabilities, `no_new_privs`, and zero core-file limits remain enforced.

Deployment still requires CI, the shared cloud reservation, staged regional
drains, signed trust publication, fresh gateway hardware attestation, and
provider-only encrypted probes. Local inference is not production evidence.

References: [public release](https://github.com/edgelesssys/privatemode-public/releases/tag/v1.61.0),
[policy reproduction](https://docs.privatemode.ai/cookbook/verify-source/),
[vLLM metrics source](https://github.com/vllm-project/vllm/blob/db9527a46873454610df6dbedf79a36d6bf1a7f6/vllm/v1/core/kv_cache_metrics.py).
