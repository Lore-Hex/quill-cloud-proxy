# Settlement HTTP 500 during control-plane rollout

## Evidence

Cloud Monitoring incident `0.oe312v9ji1rh` reported one billing-path HTTP 500
at 2026-10-21 13:26:37 UTC. Cloud Run attributed it to
`trusted-router-01670-dhf` in us-central1, for `/internal/gateway/settle`.
The request log has zero latency, no container instance ID, and no matching
application exception. The old revision's instances shut down around 13:20:24
through 13:20:33; the service was ready at 100% on `01671-54s` at 13:20:36.
This establishes a failed request against the retired revision, not the exact
internal Cloud Run routing mechanism that selected it.

The correlated gateway event records successful OpenAI inference followed by
an empty HTTP 500 settlement response, then a customer-facing HTTP 502. The
gateway clock was approximately 11 seconds behind the control-plane clock.
The affected authorization was still unsettled when checked; its Spanner
reservation had zero credit reserved and no actual charge. Do not infer
successful settlement or zero customer impact from healthy later requests.

## Recovery defect

`postSettlementJSON` froze the settlement body and pinned billing authority,
but its retry classifier accepted only connection resets, broken pipes and
truncated/lost replies. Temporary HTTP failures were not retried. A successful
model call could therefore become a client error after a single transient
settlement HTTP failure.

## Fix

Retry settlement HTTP 500, 502, 503 and 504 using the existing three-attempt,
28-second maximum budget, bounded backoff and caller deadline. Preserve the
original serialized body, authorization ID and billing authority. Never repeat
inference or switch to a different billing database. Permanent errors,
including 4xx and 501, and unpinned multi-authority calls remain non-retryable.
Persistent failures still return errors after the budget; this is not a claim
that settlement always succeeds.

Regression tests first failed on the prior code for all four status codes and
for an HTTP failure after a simulated committed settlement. Tests verify
identical replay bodies, no authority changes, one simulated charge, bounded
attempts, caller cancellation and non-retryable errors. Cloud Monitoring
thresholds and rollout/attestation gates are unchanged.

## Release verification

Require the full gateway CI matrix, protected-branch review, and the normal
attested rollout before calling this deployed. Verify fresh billing-path logs,
regional health and published attestation measurements after release. A
temporary platform error may still alert; the fix prevents a recoverable
settlement failure from unnecessarily failing the customer request.
