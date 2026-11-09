# Privatemode v1.63 deployment review

Status: candidate only. Independent policy and security-component image
reproduction and packaged encrypted positive/negative qualification passed.
Operator approval of the exact changed recovery identity, current-head release
checks, and guarded regional deployment remain required before promotion.
This document does not authorize the new manifest or claim production recovery.

## Root cause and immutable inputs

Privatemode moved from immutable deployment `continuum-012cc6` to
`continuum-a225c8`. The approved v1.62 pin rejects the new deployment with
`attestation_manifest_mismatch` before inference. The same condition affected
the isolated AWS candidate for the unrelated Anthropic effort release; that
candidate was withdrawn without replacing a serving AWS enclave.

- Public v1.63 source: `2634ffb82c72339902f26ae071db513add2bdc2f`.
- Source archive SHA-256: `d76de0050c7e3d16a0938bdc4d2f87f4008ed67fd2e2312b587f0d340540da5d`.
- Candidate manifest SHA-256: `5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1`.
- Previous manifest: `ac2bb4c5dc2aba45bdff1a7f44b8e9ad2f2b4666c5957f54d9a821ac596dca40`.
- Contrast verifier: v1.26.1. Official Darwin arm64 executable SHA-256:
  `db84dcd02f2968895ccec3c5f69d42804fda2c616ba58aa30014a507278f90cb`.
- Hardened source-built Linux amd64 client SHA-256:
  `dd412ee064d3d3396c092be804e2ce0aea5bc9fa02372b80f55ef89c2131419d`.

The client retains the pinned Go 1.27.3 builder, explicit x/net v0.62.0
security override, module checksums, bounded control-plane patch and MIT notice.
No runtime manifest refresh, plaintext fallback or expanded model allowlist is
introduced. The local candidate includes Anthropic effort source `78158eee`.

## Security-sensitive changes

All eight workload policies change. Hardware reference changes are limited to
the SNP trusted measurement and TDX RTMR1/RTMR2. Minimum TCB values, chip/PIID
allowlists, other reference fields and the manifest-adjustment script are
unchanged. Contrast v1.26.1 updates the guest kernel from 6.18.35 to 6.18.60
for its published security fix. Independent reproduction established the new
measurements as recorded below; source inspection alone was not accepted.

The recovery owner changes. SHA-256 fingerprints of the public-key strings:

- Previous: `485a9b9e76c06d98059ac38048771869d9480b6cc25d992f79aa7f88fcfdce63`.
- Candidate: `178755e374568f2508b7b89c614dfec96054bad3734f28314dab345fe1672fc9`.

This deployment-specific identity is not reproducible from source. Approval
must include this exact recovery identity and manifest, not just the client
version or the earlier Anthropic feature approval.

The client now authenticates its version inside encrypted metadata alongside
the strict NVIDIA OCSP policy. The inference proxy uses authenticated metadata
for version-dependent behavior. A v1.63-or-newer HTTP version without an
authenticated version is rejected; an authenticated v1.63 version without an
authenticated OCSP policy is rejected. Legacy compatibility remains present
upstream, but cannot replace our authenticated policy without invalidating
the encrypted request.

The GLM and GPT OSS workloads add native KV offload to guest memory. Their
bootstrap gains `SYS_ADMIN` to enlarge `/dev/shm`; before inference it drops
to a model-specific UID, clears all capability sets and enables no-new-privs.
The disk-mounter disables kernel core dumps. Hash-checked serving patches and
network restrictions remain in place. The public vLLM v0.31.0 native allocator
creates mode-0600 shared mappings under `/dev/shm`, unlinks them after the
worker barrier and copies between CPU tensors and GPU memory. It does not
select an external offload service. This is source inspection, not independent
reproduction of the serving image or evidence about host swap configuration;
the exact deployment policy was independently reproduced as recorded below.

Known scope limits from v1.62 remain: not every serving patch or model artifact
is public, and successful attestation is not proof that arbitrary OTLP
attributes are content-free. The source diff does not remove these limitations.

## Evidence and remaining gates

- The source-built client passed HTTP read-limit, refresh-deadline, server,
  encrypted-body and OCSP policy tests.
- The manifest checker unit tests passed.
- Full gateway race suites passed for GCP, AWS and Azure. The first Azure run
  was blocked by the local sandbox's loopback socket restriction; the complete
  run with local networking enabled passed without changing tests.
- The packaged source-built client rejected an intentionally altered
  coordinator policy with HTTP 401 before inference.
- Upstream encrypted-version, OCSP and forwarding race tests passed with the
  exact production `v1.63.0` linker version. An initial unversioned audit build
  used upstream's `0.0.0-dev` default and failed its token-version fixture;
  the failure was traced to that build input, not bypassed or retried blindly.
- Source-mode govulncheck v1.9.0 reports zero reachable vulnerabilities and
  zero affected imported packages in the hardened client. One required module
  has an advisory outside the imported path; dependencies are not advisory-free.
- Independent policy generation and all five Nix image reproductions passed
  in [workflow 42560621245](https://github.com/Lore-Hex/quill-cloud-proxy/actions/runs/42560621245)
  at candidate head `3d9be373a2539eef98b9d9d38f72f425b8a689ba`.
  Images completed at 2026-11-09T04:21:47Z and policies at 04:30:21Z.
  All eight policies and hardware references match structurally, with only
  `SeedshareOwnerPubKeys` excluded from reproduction because it requires
  explicit operator approval. The comparison records that approval as false.
  The image rebuild rejects vendor flake-cache settings and verifies that the
  effective binary-substituter list is exactly `https://cache.nixos.org`.
- `.github/workflows/reproduce-privatemode-v163.yml` provides credential-free
  reproduction of these exact inputs and retained comparison artifacts. It
  neither approves recovery ownership nor publishes pins or deploys. Its
  image job uses the repository's pinned Determinate Nix v3.23.3 installer,
  with per-build sandboxing required and sandbox fallback disabled.
  The first workflow attempt failed before policy generation because release
  downloads did not follow redirects; unchanged SHA-256 pins now verify with
  redirect-following. Its unsandboxed image job also stopped on Nix's shared
  home-directory purity check. The sandboxed replacement passed; neither
  failed attempt is accepted as reproduction evidence. A redundant query for
  `extra-substituters` emitted an error because it is a configuration modifier,
  not an effective setting. That query was removed; the independent exact
  effective-substituter assertion remains and passed in the successful run.
- Packaged live qualification passed after independent policy verification:
  encrypted streaming and billable usage for GPT OSS 120B, GLM 5.3 and
  GLM 5.3 Flash; reasoning-off with zero reasoning tokens for both GLM models;
  encrypted embeddings at 1024 and 2560 dimensions; and synthetic OCR.
  These were bounded direct-provider tests using the actual privilege-dropping
  launcher, not public TrustedRouter feature tests. Each suite confirmed
  UID/GID 65532, zero capabilities, no-new-privs and disabled core dumps.
  Streaming started at 2026-11-09T04:49:01Z, reasoning-off at 04:49:51Z,
  and media at 04:52:24Z; all passed without retries or skipped tests.
- The requested secondary Claude CLI review could not start because its
  OAuth session expired. No successful secondary review is claimed.
- No new provider pin or gateway image has been promoted by this review.

### Retained reproduction evidence

Both successful workflow artifacts were downloaded before the repository's
one-day retention expired and rechecked locally against the exact source and
candidate manifest. Their GitHub artifact archive SHA-256 values are:

- Policies, artifact `13650395238`:
  `729716640223ee4785ed83b9784da99c7641e606ed5a4fc8e35e907cdc8535aa`.
- Images, artifact `13649461842`:
  `a5812171e588e187ae1b1847e5bae6e9e08374e0d6fe1e27a3ca76d0e3917c73`.

The raw generated manifest SHA-256 is
`4e5ba307a610129758d05463ee9b44ec053b8e7db85c263109bd7a2d2ef887e0`;
after the documented namespace/reference adjustments it is
`a20ca331dac9f505be9c0a679fc070da4f5d61e6d34418fccde1ced76ff66f18`.
These byte hashes identify generated evidence; the structural comparison,
excluding only the explicit recovery identity, establishes equivalence to the
candidate manifest. The builder was Determinate Nix 3.23.3 / Nix 2.35.3.

| Reproduced security component | OCI manifest SHA-256 |
| --- | --- |
| attestation-agent | `f1b67d1d22246ffcf76c5b4379a4ff2a6b340f679e64c030bf84981f296d8da8` |
| disk-mounter | `f66f2ea5feb4a39ec4f8ec1e464e7d911ee2f67ef468603cb80fbcbf341ec931` |
| inference-proxy | `f7c2b213a0bb34b1289bf2c3a18bcc44f241ae622c961c36bc44d13820d63f92` |
| kernel-log | `55561e652ff9672f7a9304592a0ea3a9478ef0acc6a33243cc5697e76b95256a` |
| secret-service | `26c797bbde03151b1ae29fec1618dc74b67ba5a7b08f0bc1f20a9d90df06ec7b` |

GitGuardian incident `39839829` flagged the last public OCI checksum as a
generic high-entropy secret in the reproduction workflow. It is the immutable
image digest in upstream `deployment.yaml` line 25, not a credential, and
the independent rebuild matched it. The finding is documented for scoped
false-positive review; no detector, protection rule or hash check was disabled.

Preserve the existing shared rollout guard, fresh per-instance hardware and
channel-binding checks, signed old/new release windows, and regional inference
gates. A successful local build is not regional production verification.

References: [public source](https://github.com/edgelesssys/privatemode-public/tree/2634ffb82c72339902f26ae071db513add2bdc2f),
[Contrast release](https://github.com/edgelesssys/contrast/releases/tag/v1.26.1).
