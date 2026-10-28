# Phala GLM 5.2 Route Correction

The control-plane catalog authorizes `z-ai/glm-5.2` as Phala's upstream ID,
with Standard route privacy. The gateway's older model map replaced that ID
with `phala/glm-5.2`, a distinct historical confidential alias. Catalog refresh
therefore did not update the route actually invoked by the gateway.

The gateway now preserves either of those two reviewed IDs when explicitly
authorized. An unknown or different-model ID fails closed. An older caller
without an upstream ID retains the historical alias. This does not change the
inference host, attestation policy, billing rates, or route privacy labels.

## Evidence

On October 28, direct benign canaries with the configured confidential key
showed both successful completions and an HTTP 429 from the historical alias.
The 429 lacked Retry-After and rate-limit headers. A control model using the
same key succeeded, as did the currently authorized `z-ai/glm-5.2` ID.

Separately, a provider-locked TrustedRouter canary timed out before any output
tokens. Its reservation was refunded. These observations establish a valid
credential, intermittent upstream failure, and our route-selection mismatch.
They do not prove that the mismatch caused every timeout or that upstream
capacity is repaired. Keep the provider incident open until live verification
and subsequent probes establish recovery.

## Regression Coverage

The route-selection regression failed on the previous implementation for the
current ID and for unreviewed IDs. It now checks both reviewed IDs, legacy
behavior, rejection of unknown IDs, and the final Chat and Responses provider
wire model. Other Phala model mappings remain unchanged.
