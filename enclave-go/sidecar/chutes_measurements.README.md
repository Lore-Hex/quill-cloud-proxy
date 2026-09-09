# Chutes TEE measurement snapshot

`chutes_measurements.json` is the release-pinned snapshot fetched from
`https://api.chutes.ai/servers/tee/measurements` on 2026-08-15.

SHA-256: `8b4fec0e6b0e5d133c5354fd88d4ea9a338f9fca13b3d8ec2a61925f3007b704`

The verifier accepts only an exact MRTD and runtime RTMR0 through RTMR3 match
from this file. A Chutes measurement change therefore fails closed until the
new public snapshot is reviewed, tested, committed, and deployed in a newly
attested TrustedRouter image.

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
