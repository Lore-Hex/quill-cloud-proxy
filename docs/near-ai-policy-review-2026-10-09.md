# NEAR AI queue-limit deployment review, October 9, 2026

## Decision

Approve only gpu03's exact v0.0.481 deployment history. This supersedes its
October 8 history, which stopped matching production when NEAR updated the
four model replicas between 02:03 and 03:28 UTC on October 9. Earlier live
probes passed; a fresh production probe correctly failed closed after that
upstream change. Do not loosen verification, approve gpu04, or clear the three
Qwen platform-TCB safety holds.

## Source and evidence

Fresh read-only reports were collected at 06:50 UTC from both DNS-advertised
addresses using independent random nonces, verified TLS hostnames, Ed25519
mode, and the actual connection's certificate SPKI. Inference credentials
were held in memory and are absent from the public fixtures.

gpu03 retains compose
`55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179`.
Only its source and complete-history pins change:

- Commit: `b9acc8f208409daa2c35d26f0b7bbd93ecc5eef5`.
- Deployment SHA256: `a49d9c15e866c6f569655fb506a0c60cf97e70c01a6de580c1a4fac0a1e334be`.
- Complete actions SHA256: `232ae6c935e27f5fd256936b8ddba67ebe8b7ff984eb8d753524b43ff59f62ac`.

The [immutable deployment file](https://github.com/nearai/cvm-compose-files/blob/b9acc8f208409daa2c35d26f0b7bbd93ecc5eef5/prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8.yaml)
was fetched by commit and independently hashed. Its only diff from the
[October 8 reviewed source](near-ai-policy-review-2026-10-08.md) is
`--max-queued-requests 8` becoming `--max-queued-requests 32`. All four engines
have explicit matching deployment actions. The metrics and telemetry services
remain on their separately reviewed October 8 deployment.

Images, immutable image digests, executable code, mounts, environments, model
weights, logging, isolation, and network configuration are unchanged. The
previous signed-image provenance review therefore applies to identical image
bytes; this is not a new independent reproducible-build claim. CPU boot pins,
GPU policy, nonce/TLS binding, runtime event replay, and same-connection
inference requirements are unchanged.

gpu04 reports a different complete history:
`4c6eb48f299c533df1ed2b79d098333a0d694bbfe6c8b23b71da882689ea177b`.
Its prior peer-KV transition has not received an independent release approval;
this narrow review does not approve that host just because its latest action
references the same file. Its policy remains unchanged and fresh-history
regression coverage requires rejection.

## Verification

- Complete sidecar race suite: pass.
- Real `TestLiveNearAIEvidence` for the fresh gpu03 report: pass, including
  both CPU quotes, NVIDIA proofs, event replay, nonce and TLS binding.
- Real `TestLiveNearAIDirectAttestedPong` with the new GCP sidecar: pass in
  5.88 seconds. The first backend was refused; the next was fully verified
  before receiving the PONG prompt. No inference retry or unverified fallback.
- Regression fixtures bind the complete current history and all four engine
  actions, preserve the older telemetry provenance, reject the superseded
  gpu03 history, and reject the fresh unreviewed gpu04 history.

These are local release-qualification results, not proof of production
deployment. A new gateway rollout and fresh production probes are required.
