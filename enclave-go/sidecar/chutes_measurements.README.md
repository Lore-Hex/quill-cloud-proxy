# Chutes TEE measurement snapshot

`chutes_measurements.json` contains the release-pinned snapshot fetched from
`https://api.chutes.ai/servers/tee/measurements` on 2026-08-15, plus the eight
live-verified 1.4.1 profiles and the single reviewed 1.5.0 profile described below.

SHA-256: `447bf6b9e74a6fbc818998852ccbc80cbff6f6d479a1b839e4064469e72f273c`

The verifier accepts only an exact MRTD and runtime RTMR0 through RTMR3 match
from this file. A Chutes measurement change therefore fails closed until the
new public snapshot is reviewed, tested, committed, and deployed in a newly
attested TrustedRouter image.

## November 3, 2026 Kimi K3 investigation

The only advertised Kimi K3 TEE instance returned its CPU quote in signed
`evidence.quote`, while older instances still returned signed
`evidence.tdx_quote`. The release verifier understood only the latter and
rejected the request before any prompt was sent. Supporting both signed names
exposed a second, independent gate: this instance runs a new 1.5.0 workload.

Only the live-verified `8xb300 [10.2.1, flat-252c-1944g]` 1.5.0 profile is
added here. MRTD, RTMR0, and RTMR1 match that hardware profile's prior release;
RTMR2 and RTMR3 changed. All five measurements must still match exactly.
The downloaded public reference-manifest SHA-256 was
`d675fbfd6ace09f02e2145f4737964ea49bca41ce5211c12204436a517fbdf73`.
No other 1.5.0 profile is accepted, and the older reviewed profiles are retained.

Reviewed immutable upstream source at the `v1.5.0` release commit
`a526aef429e96f07a8971483736c4c000dcbf07a`:

- [Attestation response and quote format](https://github.com/chutesai/sek8s/blob/a526aef429e96f07a8971483736c4c000dcbf07a/src/sek8s/sek8s/services/attestation.py)
- [Signed evidence proxy](https://github.com/chutesai/sek8s/blob/a526aef429e96f07a8971483736c4c000dcbf07a/src/attestation-proxy/attestation_proxy/service.py)
- [Measured root-filesystem verification](https://github.com/chutesai/sek8s/blob/a526aef429e96f07a8971483736c4c000dcbf07a/ansible/guest/roles/rootfs-measure/files/rootfs-verify)
- [Release changelog](https://github.com/chutesai/sek8s/blob/a526aef429e96f07a8971483736c4c000dcbf07a/changelogs/vm/CHANGELOG.md)

The generic quote name does not add SEV-SNP support to TrustedRouter. The
verified bytes must still be a non-debug Intel TDX v4 quote with current
collateral, a trusted workload, and the correct fresh nonce, ML-KEM key, and
certificate-key bindings. Conflicting signed aliases are rejected, and the
unsigned outer `quote` field is never used as a substitute.

The new-format and exact-measurement regression tests failed on the old code.
The repaired sidecar suite passes with the race detector, including rejection
of tampered signatures, wrong keys/nonces, debug mode, unpinned measurements,
outdated TCB, non-TDX quotes, failed NVIDIA evidence, and mutation of each of
the five measurement registers. Real Intel and NVIDIA verification passed.
`TestLiveChutesE2EEAttestedPong` passed against `moonshotai/Kimi-K3-TEE` in
11.67 seconds using the local sidecar with these embedded pins and no candidate
override. The canary sent only a synthetic PONG request.

This is verification against provider-published reference measurements, not an
independent rebuild of the guest image. The local canary is not evidence of a
production rollout. Merging and deploying this new workload pin requires the
operator's explicit approval of this exact reviewed update.

## October 8, 2026 pool-wide investigation

Fresh nonce-bound evidence from the live TEE catalog found six additional
1.4.1 profiles in active pools. Every profile below passed real Intel TDX,
nonce/key binding, and NVIDIA verification before being pinned:

- `8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]`
- `8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]`
- `8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]`
- `8xb300 [10.2.1, flat-252c-1944g]`
- `8xb300 [10.2.1, numa-flatpci-252c-2304g]`
- `8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)`

These use the immutable 1.4.1 source linked below. The downloaded reference
manifest SHA-256 was
`2ef4fa820fd2339b7da647d77d1f0738714a677c5b88f6c07cc7970e081dc0ef`.
Only these live-verified additions are trusted; this is not automatic acceptance
of the provider's entire manifest or an independent guest-image rebuild.
Tests mutate MRTD and each runtime register separately for all six profiles.

The B300 pool's signed NRAS hardware claim is the exact literal `GB110`.
The verifier now recognizes that label only for B300 profiles, rejects
`GB112` and `GB110 unknown`, and still requires every signed security claim
and the pinned CPU workload measurements. This does not independently certify
a retail GPU SKU. NVIDIA's public architecture list identifies GB110 as
[Blackwell](https://github.com/NVIDIA/open-gpu-doc/blob/master/classes/3d/README.txt).

With the release-pinned verifier, encrypted PONG canaries passed for both
Qwen3.5 397B and Kimi K3, which previously failed before inference.
Qwen3 235B Thinking still cannot supply evidence (`chutes_version >= 0.6.0`
required) and is held out of routing. Unreviewed older and newer profiles
remain rejected, including an observed 1.4.0 pool member; callers may retry
another independently verified instance before sending any prompt.

## October 5, 2026 Mistral Nemo investigation

Fresh evidence for `unsloth/Mistral-Nemo-Instruct-2407-TEE` identified another
1.4.1 profile missing from the August snapshot:
`8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)`.
The candidate passed the real Intel and NVIDIA verification, including
nonce/key binding. Only that exact profile was added. A regression test
failed before the addition and rejects mutation of each measured register.
The reference-manifest JSON captured for this review has SHA-256
`1ee0b619fefef03eaea89acdc9e714eb260a05651036fb9205376662bfad314c`.
Release provenance is the same immutable 1.4.1 source reviewed below.

The full `TestLiveChutesE2EEAttestedPong` passed in 11.65 seconds with the
release-pinned verifier, fresh nonce, verified CPU/GPU evidence, encrypted
invocation, and authenticated response decryption. No candidate override was
used for this canary.

The provider also intermittently returned 502 while fetching evidence.
That remains an upstream availability failure, not permission to bypass
verification. Qwen3 235B Thinking's three advertised instances instead
returned 400 requiring `chutes_version >= 0.6.0`; updating workload pins
cannot repair their missing evidence capability.

## October 4, 2026 GLM-5.2 investigation

Fresh evidence for `zai-org/GLM-5.2-TEE` reproduced the production failure:
Intel TDX verification and nonce/key binding passed, but the workload was not
in the August allowlist. The matching public profile was version `1.4.1`,
`8xb200 [10.2.1, flat-272c-1536g]`. With that exact profile, the same evidence
passed the full verifier, including every NVIDIA GPU security claim. The
regression test failed before adding the profile and checks that mutating any
of MRTD or RTMR0 through RTMR3 still fails closed.

`TestLiveChutesE2EEAttestedPong` then passed against GLM-5.2 in 17.16 seconds
using the real sidecar with the new pin, a fresh nonce, verified CPU/GPU
evidence, ML-KEM encrypted invocation, and authenticated response decryption.
This proves the tested path, not every Chutes instance or production rollout.

Only that profile was added. The downloaded manifest also advertised other
1.4.x and 1.5.0 profiles; this change does not automatically trust them. Its
source SHA-256 was
`641e5548949ad85ffec02eff4b2621ea6f284eac5a59745e41607e10395ad1b5`.

Reviewed release provenance:

- [Immutable 1.4.1 source and changelog](https://github.com/chutesai/sek8s/blob/66ac30dc45b1ea1f1da46d573681649ded5e41c6/changelogs/vm/CHANGELOG.md)
- [Reproducible-build procedure](https://github.com/chutesai/sek8s/blob/66ac30dc45b1ea1f1da46d573681649ded5e41c6/docs/reproducing-measurements.md)

This is verification against the provider-published reference measurements,
not a claim that TrustedRouter independently rebuilt the guest image.

`gpu_count` is server capacity, not the number of GPUs allocated to every chute.
The signed instance evidence is filtered to `CHUTES_NVIDIA_DEVICES`, so a
single-GPU model on an eight-GPU server returns one GPU report. The verifier
requires 1 through `gpu_count` reports and independently verifies every report
with NVIDIA NRAS, including nonce, signature, security claims, and hardware
model checks. Empty, oversized, tampered, or partially verified sets fail closed.

Reviewed upstream implementation:

- [Chutes instance evidence request](https://github.com/chutesai/chutes/blob/08d79872854a664de16b32b14cd0bf947e427517/chutes/entrypoint/verify.py#L327)
- [sek8s allocation filtering](https://github.com/chutesai/sek8s/blob/168804d44aec62546f601d53f565cb0f3b963cf8/src/sek8s/sek8s/providers/nvtrust.py#L68)

NVIDIA's signed `hwmodel` for the RTX PRO 6000 instance tested on 2026-09-09
is `GB20X`, not the marketing name `pro_6000` or the die name `GB202`.
The verifier accepts that exact literal for this profile, not arbitrary
`GB20*` values. A hardware-family claim does not independently prove an exact
retail SKU; the pinned TDX measurements and signed NVIDIA security verdicts
are also required. See the [RTX PRO 6000 attestation report](https://github.com/NVIDIA/nvtrust/issues/150)
and the [provider's live attestation example](https://docs.verda.com/cpu-and-gpu-instances/confidential-computing/#run-nvidia-gpu-attestation).

## Live verification

`TestLiveChutesEvidence` verifies an evidence envelope with the real Intel and
NVIDIA services. Supply a JSON object with `chute_id`, `instance_id`, `nonce`,
`e2e_pubkey`, and `evidence`, obtained using a newly generated challenge nonce.
Run from this directory:

```sh
TR_LIVE_CHUTES_EVIDENCE_PATH=/path/to/evidence.json \
  go test -tags gcp . -run '^TestLiveChutesEvidence$' -count=1 -v
```

This verifies captured evidence only; the production client must generate its
own fresh nonce and bind the verified key to its encrypted invocation. The
gateway's `TestLiveChutesE2EEAttestedPong` exercises that full path. It passed
against `unsloth/Mistral-Nemo-Instruct-2407-TEE` with this verifier on
2026-09-09 UTC, including fresh TDX/NVIDIA verification and an encrypted PONG.
Neither live test runs in ordinary CI without its explicit opt-in environment.

To diagnose a newer published profile without changing production trust,
`TestLiveChutesEvidence` also accepts
`TR_LIVE_CHUTES_CANDIDATE_MEASUREMENTS_PATH`. This test-only override still runs
all Intel, nonce/key binding, and NVIDIA checks. It is not a runtime setting and
must not substitute for reviewing and pinning a release.
