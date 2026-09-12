# Provider-Independent Deployment Gates

The rollout checks router correctness separately from upstream availability.

| Observation | Release decision |
| --- | --- |
| Attested TLS and exact PONG | Continue, subject to durable billing evidence |
| Gateway HTTP error with `error.source=provider` | Report provider failure separately; still require billing evidence |
| Fresh synthetic PONG sample with `provider_error` and a failing HTTP status | Accept request-path responsiveness, not model success |
| Router error or unattributed HTTP error | Block |
| Transport failure, invalid JSON or missing stream terminal | Block |
| Attestation failure or missing fresh required sample | Block or wait |
| Missing settlement/refund, wrong boot key or missing required usage heartbeat | Block |

`provider_probe_status.py` does not infer origin from status code or message
text. An ordinary 503 can be our router failing. The gateway must explicitly
attribute the failure to the provider. Public synthetic samples remain down;
only their eligibility to block a deployment changes.

The direct streaming probe continues through the existing authorization lookup
after a provider error. Its settled state, request ID, authorization kind, and
required Stage D evidence are still checked. A provider error is not permission
to skip money correctness or attestation.

Deploy the `quill-router` SDK-probe attribution change before this consumer.
Old samples lacking explicit attribution remain blocking until replaced with
fresh classified samples. Existing provider-only post-deploy watchdog exclusions
and the separate non-blocking production model smoke remain intact.

Run the offline regressions with:

```sh
python3 tools/test_provider_probe_status.py
python3 tools/test_synthetic_gate_status.py
python3 tools/test_stage_d_stream.py
python3 tools/test_rollout_safety.py
bash tools/tests/test-stage-d-gates.sh
```
