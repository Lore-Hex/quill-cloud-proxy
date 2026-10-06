# NEAR AI policy review, October 3, 2026

This updates the two GLM 5.3 Flash pool histories reviewed on
[October 2](near-ai-policy-review-2026-10-02.md). It does not relax any verifier
check, add an unencrypted fallback, or enable other NEAR models.

## Reviewed Change

The live pool advanced to `v0.0.466`, commit
`93aa1121f736406acd10730fa9f8caf2fe045aa3`, deployment file
`prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8.yaml`.
Its independently computed file SHA256 is
`e3c487c72189010f5afadc486c8c04ffb3a49a4d485827844e7c8fd105729359`.

The exact diff against `ddec8d8c4f637d16884ca949e43c51582d8ed858` adds
`--max-mamba-cache-size 165` and `--mamba-ssm-dtype bfloat16`, with matching
comments and telemetry labels. Engine/proxy/management image digests, pinned
weights and chat template, local backend topology, volumes, network paths,
request logging configuration and host-cache isolation are unchanged. Image
provenance is the same as the October 2 review, not newly inferred from a tag.

The signed histories include partial replica updates and a registrar restart.
All four engine services on both hosts now have a matching v0.0.466 action.
Full action histories, not just the latest action, remain pinned per host:

| Compose SHA256 prefix | Entire action-history SHA256 |
| --- | --- |
| `55db164f` | `a6cfc9a3f78e6010023ef835ec7850f888da08e8a374d54344eb08108608268d` |
| `c82b1a2e` | `281432886e04b7b19bc55793085fcbdf812eb2d7479e409e4a7b283e21ac069d` |

## Evidence

Fresh random-nonce reports were captured over verified TLS and bound to the
connected certificate SPKI. The production verifier passed both complete
evidence sets: Intel CPU chain/TCB, NVIDIA GPU proofs, nonce and TLS/signing-key
binding, both CPU quotes, pinned boot measurements, complete runtime-event
replay and exact deployment histories.

Three real local streaming PONG probes through the production adapter and real
sidecar passed, covering both hosts (6.03, 8.45 and 7.18 seconds including
verification). No application prompt was used.

Public action/event fixtures are retained in `testdata/near-ai-2026-10-03`.
Regression coverage rejects the superseded history, a cross-host history,
changed runtime measurements and any later unreviewed partial deployment.
Future changes still require review before promotion; discovery is not approval.
