# Enclave shutdown

SIGTERM stops listener admission and makes the load-balancer health endpoint
return 503. Idle connections close immediately. Existing authenticated requests
retain their contexts, including billing and settlement, while the process waits
for handlers to finish. A persistent connection cannot start another request
after draining begins, even if the client already pipelined its bytes.

GCP Confidential Space allows up to 120 seconds for workload cleanup. The
gateway spends at most 90 seconds draining requests, then 10 seconds waiting
for forced-cancellation cleanup, then 3 seconds flushing queued settlement
retries. Other builds use a 15-second request grace period. These bounds do not
extend normal inference timeouts. A host crash or SIGKILL can still interrupt
requests; this is not a durable replay mechanism.

The settlement worker is not canceled by the initial SIGTERM. Its idle check
runs between attempts, so an empty channel with a settlement still in flight
does not count as drained. Existing durable billing reconciliation remains
necessary when the host deadline is reached or the control plane is unavailable.

Check these metadata-only logs during a regional rollout:

* `enclave.shutdown_drain`: active connections and grace period.
* `enclave.shutdown_forced`: the request deadline was exhausted.
* `enclave.shutdown_handlers_pending`: cancellation cleanup exceeded its bound.
* `enclave.shutdown_settlement_pending`: queued or in-flight billing did not drain.
* `enclave.shutdown_complete`: process shutdown finished, not proof that every
  request completed successfully. Inspect the preceding forced/pending logs.

Keep canonical DNS draining, regional staging, attestation and rollback gates.
Application draining supplements those gates for existing and region-pinned
connections; it does not replace them.

Reference: [Confidential Space workload shutdown](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-customize-workloads).
