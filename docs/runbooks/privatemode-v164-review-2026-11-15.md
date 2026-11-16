# PrivateMode v1.64 recovery review

Status: unapproved candidate, not a production trust pin. Reproduction and
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
- Approved manifest remains `5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1`.
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
The candidate evidence file is deliberately outside the embedded runtime path.

The upstream client diff retains static-manifest verification. Manifest logging
changes affect dynamic mode; do not enable that mode as a recovery shortcut.
The serving release also changes vLLM, GPU-copy and transfer-related patches;
review and reproduction remain incomplete, not implicitly approved here.

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

No production pins, transport origins or fallback eligibility changed in this
review. No live paid inference or user-session mutation was performed.
