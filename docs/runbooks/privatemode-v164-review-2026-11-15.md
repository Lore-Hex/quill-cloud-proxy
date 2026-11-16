# PrivateMode v1.64 recovery review

Status: conditionally approved identity, not a production trust pin. Reproduction and
encrypted positive/negative qualification are required before promotion.

## Cause and recurrence

The provider published v1.64 on November 14, 2026, replacing deployment
`continuum-a225c8` with `continuum-13d78c`. Our approved v1.63 static manifest
correctly rejects its changed policies. This is deployment drift, not an API
key error. The existing scheduled drift monitor failed; detecting drift after
the provider switches does not provide an approved overlap window.

The gateway regression test passed with race detection on November 15 using
`cloud_gcp,llm_multi`: buffered and streaming PrivateMode HTTP 401 rejection
retry an authorized simulated Tinfoil candidate, while single-provider requests
fail closed without emitting output. This is not a live forced-outage test or
proof of the alternative provider's remote attestation. Explicit model requests
must not silently switch to another model.

## Immutable candidate inputs

- Public source: `3c98e0abf3219a6ebcc29112867a5f004605041b` (v1.64.0).
- Source archive SHA256: `d7712bfbea9d61cc36372ab30f3d8b989e4f34d89ab70abcefe1852060d044ff`.
- Candidate manifest SHA256: `d63eb5cf91cb3079fe25a848573a4d0e9d869f462dab4f71fd02bdb372f8e833`.
- Previous production manifest: `5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1`.
- Contrast: v1.26.2; Linux CLI SHA256 `0524c388d60425e7771083d667bc384c1df31ee397e6f2bdcd76157677f6a1d6`.

All eight policies change. SNP measurement and TDX RTMR2 change; SNP minimum
firmware rises from 28 to 30 and minimum mitigation vector from 15 to 1023.
Chip and PIID allowlists are unchanged. Contrast release notes reference
GHSA-7p6m-2ccv-jv97, but the advisory API returned 404 during this review;
do not claim its details were verified.

Recovery-owner public-key SHA256 changes from
`178755e374568f2508b7b89c614dfec96054bad3734f28314dab345fe1672fc9` to
`e734bea0d88af2fae66bbab9466552f98eff746d3ae2080094f8629cc654f53f`.
This identity cannot be reproduced from source and needs explicit approval.
The evidence file is separate from the embedded runtime path. After independent
reproduction and conditional identity approval, the candidate branch updates
the runtime pin too. Merging it is a production release action and remains
blocked on all remaining qualification and release gates.

Joseph approved this exact recovery key and manifest on November 15, conditional
on independent reproduction, security review and encrypted qualification. That
approval does not mark any pending gate passed or authorize runtime refresh.

The upstream client diff retains static-manifest verification. Manifest logging
changes affect dynamic mode; do not enable that mode as a recovery shortcut.
The serving release also changes vLLM, GPU-copy and transfer-related patches.
Reviewed changes disable GPU UVA, stage encrypted GPU transfers on separate
streams, and reject late KV reads after lease expiry. Existing network
restriction hashes, privilege dropping, logging flags and native guest-memory
offload selection are unchanged. The anonymization patch is rebased for vLLM
0.32. NIXL telemetry capture was already enabled upstream; this review is not
proof that every vendor metric is content-free. Not every serving component is
independently rebuilt; retain the same scope limitations as the v1.63 review.

## Recovery and prevention gates

1. Independently reproduce policies, hardware references and all five security
   component images using the credential-free v164 workflow. Retain artifacts.
2. Review source changes and obtain the exact recovery-owner approval above.
3. Qualify the hardened source-built client with positive encrypted inference
   and negative altered-manifest tests, without runtime manifest refresh.
4. Exercise a controlled first-provider rejection followed by a real attested
   confidential provider in isolation; never disable production verification.
5. Use the existing protected release and regional qualification process.
6. Arrange advance provider manifests and a reviewed deployment overlap window.
   Until available, keep independent confidential alternatives and separately
   monitor provider readiness: HTTP 200/top-level health is insufficient.

## Qualification completed so far

- Hardened client built with the current pinned Go 1.27.4 image and existing
  response-limit/deadline patch. HTTP limits, secret-manager limits, client,
  encrypted server/body and OCSP-header suites passed. Linux amd64 client SHA256:
  `d32ccaf8662203490ce84d64650deeac1bb00382f228d092f4aa2a5c63860e51`.
- Contrast v1.26.2 source diff disables `systemd-gpt-auto-generator` via
  `systemd.gpt_auto=0`: the host-controlled backing partition table must not
  cause unmeasured partitions to be mounted or activated. This explains the
  guest-reference change; it does not substitute for reproduction.
- An opt-in local gateway test injected only the PrivateMode 401 rejection and
  used the unmodified real Tinfoil adapter and full-verification sidecar for the
  alternative. Buffered and streaming cases returned PONG, each with 75 input
  and 24 output tokens; both selected Tinfoil with exactly one fallback.
  Full proof cross-check and TLS public-key pin enforcement succeeded.
  This is live alternative-provider inference, not an end-to-end production
  control-plane authorization or forced production outage test.
- Initial harness attempts exposed startup-readiness and bootstrap-key-field
  mistakes (no inference on those failures). Subsequent successful provider
  calls exposed a harness assertion that did not join split SSE text chunks.
  The structured SSE parser and its split-chunk regression test now pass.
  Failed harness attempts are not counted as passing qualification.
- Reproduction workflow `43789562675` passed both policies and images. All
  eight policies and hardware reference values match structurally after the
  documented namespace/SAN adjustments, excluding only the separately approved
  recovery identity. All five security-component OCI digests match. Downloaded
  evidence is retained at `/Users/jperla/claude/privatemode-v164-evidence`.
  The reproduction artifact deliberately records owner approval as false:
  operator approval is separate evidence, not something the build can grant.
- Secret scan flagged the public secret-service image digest as a generic API
  key. The exception is limited to that exact independently reproduced digest
  in the v164 reproduction workflow; the detector remains enabled everywhere.
- The candidate branch now updates the source archive, version and embedded
  pin together for qualification. No candidate image has been promoted.
- Linux preliminary qualification with the actual launcher and source-built
  vendor client passed: altered coordinator policy rejected with HTTP 401;
  encrypted PONG and usage passed for GPT OSS 120B (76/19 tokens), GLM 5.3
  (21/4), and GLM 5.3 Flash (21/10). UID/GID 65532, zero capabilities,
  no-new-privs and zero core limits were asserted. This used a Debian test
  container with mounted binaries; the full scratch-image gate is separate.
- Historical v163 reproduction now reads its own unchanged evidence manifest,
  not the mutable current runtime pin. Its expected hash and comparisons are
  unchanged, avoiding a false failure on legitimate newer pin releases.
- The actual scratch-image positive/negative qualification also passed with its
  packaged client and launcher: altered manifest HTTP 401; encrypted PONG with
  GPT OSS 120B (76/33 tokens), GLM 5.3 (21/4), GLM 5.3 Flash (21/10), plus all
  privilege-isolation assertions. This preceded the merge of main's separate
  provider-egress hardening; repeat relevant qualification on the merged head.
- Read-only Claude Opus review identified stale candidate-vs-production wording
  and a missing automatic image-to-deployment linkage assertion. Wording is
  corrected and the workflow now parses pinned deployment YAML and checks each
  expected security-image reference. Retained evidence avoids artifact expiry.
  Client CLI flags are unchanged upstream; runtime-refresh is still disabled.
  The injected-rejection live test remains explicitly scoped as such, not a
  production authorization test or a real first-provider outage.

No serving production pins, transport origins or fallback eligibility changed
in this review. No user-session mutation was performed. Isolated fallback
sidecars were stopped. Redundant local policy generation was stopped after the
independent CI result; it is not counted as completed reproduction.

## Combined-head qualification

After merging main's provider-egress hardening, the rebuilt actual scratch image
passed all three encrypted model checks again: GPT OSS 120B (76/21 tokens),
GLM 5.3 (21/4), GLM 5.3 Flash (21/11). Altered-manifest rejection returned
HTTP 401, and the privilege-isolation assertions passed.

The real-rejection fallback test also passed, buffered and streaming. An isolated
test binary embedded the previously approved v1.63 manifest through a Go overlay;
the real packaged v1.64 proxy rejected it before emitting content. The gateway
then used real Tinfoil attestation, proof cross-check and pinned TLS to return
PONG (75/43 and 75/45 tokens), with exactly one rejection and one fallback each.
Neither provider response was mocked in this mode. Production pins and services
were not modified. This proves the isolated gateway retry path, not production
control-plane authorization, customer request attribution, or a forced fleet outage.

The combined scratch runtime manifest was
`0a3d6ec2f6445ad8c26ff1d49fd7d917e5cdfe70868d6817e220db78ed2c8483`.
This is qualification evidence, not a production release provenance claim.
