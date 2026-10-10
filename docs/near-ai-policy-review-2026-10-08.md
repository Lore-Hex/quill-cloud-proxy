# NEAR AI policy review, October 8, 2026

## Decision and scope

Approve only the observed gpu03 GLM 5.3 Flash deployment history below. Keep
gpu04's last reviewed October 3 policy unchanged; its current mixed deployment
remains rejected. Keep all three Qwen attestation safety holds unchanged.
This is a partial repair, not a claim that the entire load-balanced GLM route
or all four catalog routes are usable. This sidecar review changes no verifier
logic, CPU/GPU policy, boot/event checks, transport behavior, other provider,
or router file. The separately owned client retry work is outside this scope.

## Fresh evidence

Read-only reports were captured on October 8 at 21:45-21:48 UTC, using independent
32-byte random nonces, verified TLS hostnames and certificates, Ed25519 mode,
and the SHA256 of the certificate SPKI on the actual report connection.
Both DNS-advertised GLM IPs were sampled without changing the TLS hostname.
Fresh captures of both GLM hosts at 21:55 UTC confirmed the same histories.
Credentials remained in memory and were not included in retained evidence.
Compose-manifest and canonical action-history hashes were independently
recomputed. Catalog presence was used for discovery only.

The existing real sidecar tests, using live Intel collateral and NVIDIA
verification, found:

| Direct model | Platform result | Original full-policy result |
| --- | --- | --- |
| `z-ai/glm-5.3-flash`, gpu03 and gpu04 | CPU and eight H200 proofs pass | Deployment history outside reviewed policy |
| `Qwen/Qwen3.6-35B-A3B-FP8` | Intel TDX module `OutOfDate` | Workload identity outside pinned policy |
| `Qwen/Qwen3.8-27B` | Intel TDX module `OutOfDate` | Workload identity outside pinned policy |
| `Qwen/Qwen3-VL-30B-A3B-Instruct` | Intel TDX module `OutOfDate` | Intel TDX module `OutOfDate` |

All three Qwen endpoints now report compose
`d4c89033fb55cdac9db00c775fbbbeff6319fba7249344b2dca99b23ff048479`.
Their shared latest action references `prod/small-models.yaml` at
`cda2032fa8f8638639d858703b6de4d76c2118e8`, independently hashed as
`635f30f97e7189b545e08b85afada9d75f53a72aabc19455d7031aad811b1e33`.
The observed history hash is
`b26d5784cc3e2c130b8ef076b61c331b0e26ee9b48532e5312e8731f67c17f8f`.
These observations are not approval. The first two routes also have stale
compose pins, but changing those pins cannot repair the real CPU TCB failure.
Platform tests stop before GPU verification on those CPU failures.

## Reviewed gpu03 pin

Compose remains
`55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179`.
App, OS, independent boot measurements, and runtime-event rules remain unchanged.
Only three policy fields change:

- Deployment commit: `1121ee56851dcec7dc89e60099d7be28fc51a73e`.
- Deployment file SHA256: `b0077025ac5f099ca6b30dd21a2605e3ba600b01be38e1605b5ec93f69a125da`.
- Complete action-history SHA256: `cca6a43ace213e309dc9483adf895f98cde49551c7dd7eaeefcb40afde0ce980`.

The [immutable deployment file](https://github.com/nearai/cvm-compose-files/blob/1121ee56851dcec7dc89e60099d7be28fc51a73e/prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8.yaml)
is not trusted by its v0.0.480 tag. All four engines have explicit matching
actions at 20:02, 20:28, 20:50 and 21:12 UTC, followed by the aggregate-cache
metrics process and telemetry updates at 21:29 and 21:30 UTC. This is not a
latest-action-only inference about the running engines.

Compared with the October 3 source, YAML parsing and a service/config comparison
show unchanged proxy, nginx, downloader, DCGM, weights, chat template and local
inference topology. The four engine commands/images/environments change; a new
CPU-only cache-metrics process, a tmpfs volume and telemetry scrape are added.
The engine uses FP8 KV, 64 running requests, 380 mamba slots, no overlap
scheduler, HiCache disabled, four preprocessing workers with a 60-second
deadline, and tool-schema depth/node limits. Request logging remains level 0;
self-profiling, preprocessing test hooks and peer-KV are not enabled here.

The new engine and metrics process use the immutable image
`nearaidev/sglang@sha256:fa730e6e62b2ae8058114ce540487ade33ab93bc42b1179ae78edc92bd563fc5`.
Cosign verification passed with the exact publish-workflow identity and GitHub
OIDC issuer. GitHub SLSA provenance verification passed constrained to source
and signer revision `29a7db96822caedff38c571dfef8942110702a23`,
[build 37693106399](https://github.com/nearai/cvm-compose-files/actions/runs/37693106399).
The image config and BuildKit evidence identify that same recipe revision;
its recipe is byte-identical at the deployment commit. Recipe checksum checks
passed. This is a signed provider build on self-hosted infrastructure, not an
independent reproducible build. Upstream CPU-test artifacts report successful
tests; they are supporting evidence, not locally rerun GPU qualification.

The new cache metrics source uses chained keyed BLAKE2b page digests, a random
key on a mode-0700 tmpfs volume, and an in-CVM Unix datagram socket. Its exported
metrics are aggregate counts, not page digests or token content. Preprocessing
uses local process socketpairs, and its new size-summary logging counts
messages, characters, tools and images rather than logging their content.

## Unapproved gpu04 history

Compose `c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86`
has current history hash
`f683de2f8e143bc4337c178af952a28ff4a9c53bd09b7cd2bf8f71f74ce88abc`.
Its latest v0.0.480 action updates only replica r3. Replica r2 still references
peer-KV commit `c7fe1da23c3d8a7e76542ba6dd1f8af94f4ed7d1`, file SHA256
`31ac486a847608136b00971123fdfb6a64e94e076b3493b8d27ec43982450376`;
r1 and r4 reference `98d7f6869c6e82d09adadf19472f992b59855a15`, file SHA256
`8db23a202cdc965d924c62856990ec0a74f75369dec176abf70e945f446c463c`.
Both hashes were independently verified against immutable source.

That [peer-KV deployment](https://github.com/nearai/cvm-compose-files/blob/98d7f6869c6e82d09adadf19472f992b59855a15/prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V7-HiCacheOff-PeerKV.yaml)
adds embedded startup patches, peer GPU visibility, host PID/IPC namespaces,
Unix-socket pickle IPC, CUDA memory-handle sharing and cross-replica prefix
fetching. Hot reload exists but defaults off. These are material changes to
data handling and isolation, not telemetry-only drift. They need a separate
review and qualification, or an upstream return to the reviewed uniform
deployment followed by fresh evidence. No claim of exploitability is made.

A scratch-only exact-pin overlay passed the full real verifier for both
histories, including both CPU quotes, boot/event replay, nonce/TLS binding and
NVIDIA proofs. This authenticates their contents; it does not approve the
unreviewed code. The gpu04 overlay is not part of the production policy.

## Regression coverage and limits

Public gpu03 action/event fixtures and the rejected gpu04 action history are
retained under `sidecar/testdata/near-ai-2026-10-08`. Tests require all four gpu03
engine actions and exact source/history pins, reject the superseded October 3
history, and reject the current mixed gpu04 history. Existing cross-host,
future-partial-update, quote/event-tamper and retired-compose tests remain.
Offline tests use explicit crypto doubles; real verification uses the opt-in
live tests. All three fixtures were created with `apply_patch`, are present
and not git-ignored, and contain only public action/event arrays. A scan against
the in-memory NEAR credential and private-key/authorization markers passed.
No credential was written into a fixture or test log.

Final verification of this sidecar change:

- Focused `go test -count=1 -run 'TestNearAI' .`: pass.
- Full `go test -race -count=1 ./...`: pass (2.759 seconds).
- `go vet ./...` and `git diff --check`: pass.
- Real `TestLiveNearAIEvidence` with the edited policy and no overlay: gpu03
  passes, including the final 21:55 capture; current gpu04 history is rejected.
- Real `TestLiveNearAIPlatformEvidence`: both GLM hosts pass. All three Qwen
  routes fail Intel TDX module `OutOfDate` before NVIDIA verification.

A separately built sidecar containing these exact pins was used with
`TestLiveNearAIDirectAttestedPong`. Two ordinary-DNS runs each selected gpu04
on all three pre-inference attempts and correctly failed closed at the history
gate. Neither run sent inference, and no live PONG is claimed here. This exposes
a route-availability limitation of reconnecting with the same preferred DNS
address; client-side DNS-address rotation and its live qualification are owned
separately. No additional gpu03 sidecar pins are needed for that qualification.

No catalog refresh can clear Qwen's holds. NEAR must update the platform TCB
before those routes can be reviewed with full evidence. GLM remains partially
available at best: a connection to the unreviewed host must fail closed, with
no inference sent and no unverified redial or fallback. No deployment or commit
was performed during this review.

## Companion adapter qualification

The production adapter now allows up to three pre-inference verification
attempts under one total attestation deadline. Each attempt uses a fresh nonce,
a separate TLS connection, and complete verification. DNS-advertised IPs are
deduplicated and sorted, then rotated by attempt, while TLS continues to verify
the original pinned domain. A rejected connection is closed before trying the
next address. No inference is retried, and an attested connection still cannot
redial. Tests cover new nonces/fingerprints, connection closure, exhaustion,
cancellation, authentication failure, connection changes and inference errors.

After this change, `TestLiveNearAIDirectAttestedPong` passed in 9.74 seconds
with the release-pinned sidecar and updated adapter. Its first connection
reached gpu04 and was refused; the second reached gpu03, passed full verification
and returned PONG. This qualifies the tested path, not production deployment
or every future backend. The unreviewed gpu04 history remains rejected.
