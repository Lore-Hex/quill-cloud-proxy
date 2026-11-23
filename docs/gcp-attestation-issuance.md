# GCP attestation issuance

Public `/attestation` and workload identity tokens share the Confidential Space
launcher. They do not share token responses. Every public response binds its
own nonce, workload TLS certificate, and same-session TLS exporter.

The October 2026 incident showed launcher issuance completing after our old
five-second client deadline. An unbounded mutex queue amplified that delay, and
canceled workload-identity callers could still mint after acquiring the mutex.
This establishes an issuance availability failure, not invalid hardware evidence.

The workload now admits one active mint and at most four waiting callers. Queue
wait is limited to fifteen seconds; issuance is limited to thirty seconds. Both
honor an earlier caller deadline, and public `/attestation` sets one: eighteen
seconds for queue wait plus its own mint, so a client with a twenty-second
timeout always receives the document or the retryable 503. No automatic issuer
retries are made. The
HTTP transport is reused, redirects are rejected, and successful token bodies
are capped at 64 KiB. Error bodies are not logged or sent to callers.

The initial two-second queue deadline rejected ordinary admitted bursts in
production despite healthy issuance. Four waiting callers need about 2.8 seconds
when each mint takes 700 milliseconds. The five-second queue budget accommodates
that burst without increasing concurrency or waiter capacity. A regression test
exercises all five admitted callers and distinct nonce-bound responses.

In November 2026 Google's issuer in us-central1 occasionally took eight to
fifteen seconds for a single mint, on old and new instances alike, while other
regions stayed near one second. Callers queued behind such a mint hit the
five-second queue limit and answered 503 although that mint then succeeded;
those 503s also failed GCP enclave canaries. The queue wait became fifteen
seconds, with waiter capacity and concurrency unchanged. This reduces queue
timeouts behind one slow mint; it does not remove failures when mints are
slow back to back, and longer waits can turn a burst during a slow mint into
`queue_full` sooner.

The DNS reconciler verifies confidential hostnames sequentially on each gateway,
while checking different gateways in parallel. Previously its four simultaneous
hostname checks consumed most of a gateway's queue and competed with live
callers. Every hostname still receives an independent fresh proof and policy
check. Any failed hostname excludes that gateway from confidential DNS; pacing
does not cache evidence or relax the all-hostnames requirement.

Temporary issuance failures return 503. The caller must obtain fresh, verified
evidence before sending a prompt; it must not bypass verification or reuse a
token with different nonce or channel binding. No nonce-bound evidence is cached.

`attestation.gcp_issuer` records queue and issuance milliseconds and one of:
`ok`, `queue_full`, `queue_timeout`, `issuer_timeout`, `issuer_error`, `canceled`.
It records no token, nonce, user prompt, or workload identity audience. Existing
HTTP failure alerts and trust checks remain enabled. Use these timings to
separate local admission pressure from Google's launcher latency.

The launcher may finish its own work after client cancellation. These bounded
limits reduce backlog; they do not guarantee Google will issue within budget.
If issuer timeouts persist, correlate launcher challenge/quote timestamps and
raise that evidence with Google. Do not increase queue capacity or weaken trust
validation to conceal the failure.
