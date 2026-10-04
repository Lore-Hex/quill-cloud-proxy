# Chutes TEE measurement snapshot

`chutes_measurements.json` contains the release-pinned snapshot fetched from
`https://api.chutes.ai/servers/tee/measurements` on 2026-08-15, plus the single
live-verified 1.4.1 profile described below.

SHA-256: `d7cf642a0e6f544adc3905740ef40a7434df4bf431b2696199526e4dbee17449`

The verifier accepts only an exact MRTD and runtime RTMR0 through RTMR3 match
from this file. A Chutes measurement change therefore fails closed until the
new public snapshot is reviewed, tested, committed, and deployed in a newly
attested TrustedRouter image.

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
