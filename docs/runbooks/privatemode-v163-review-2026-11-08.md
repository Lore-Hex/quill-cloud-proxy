# Privatemode v1.63 deployment review

Status: candidate only. Policy and security-component image reproduction,
encrypted positive/negative qualification, operator approval of the changed
recovery identity, and regional deployment are required before promotion.
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
for its published security fix. Independent reproduction must establish the
new measurements; these observations alone are not sufficient evidence.

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
the exact deployment policy must still reproduce.

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
- Independent policy generation and Nix image reproduction are in progress.
  The image rebuild rejects vendor flake-cache settings and uses only
  `https://cache.nixos.org` as a binary substituter.
- `.github/workflows/reproduce-privatemode-v163.yml` provides credential-free
  reproduction of these exact inputs and retained comparison artifacts. It
  neither approves recovery ownership nor publishes pins or deploys. Its
  image job uses the same pinned Nix 2.31.2 used for the previous review.
- Packaged positive encrypted qualification remains pending independent
  policy reproduction.
- The requested secondary Claude CLI review could not start because its
  OAuth session expired. No successful secondary review is claimed.
- No new provider pin or gateway image has been promoted by this review.

Preserve the existing shared rollout guard, fresh per-instance hardware and
channel-binding checks, signed old/new release windows, and regional inference
gates. A successful local build is not regional production verification.

References: [public source](https://github.com/edgelesssys/privatemode-public/tree/2634ffb82c72339902f26ae071db513add2bdc2f),
[Contrast release](https://github.com/edgelesssys/contrast/releases/tag/v1.26.1).
