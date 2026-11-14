# Streaming reliability and reconciliation

Chat Completions and Responses streams send `: keepalive` SSE comments every
15 seconds while waiting for output, once the response has passed its header
checks. A comment is emitted only between complete SSE events. Comments are
transport liveness, not model tokens, usage, receipt events, or completion.
Clients must ignore comments and require the route's real terminal framing.

HTTP 200 is not sent before authorization, route acceptance and any required
initial usage heartbeat succeed. This preserves meaningful HTTP failures.
Legacy upstreams that do not signal acceptance still release headers on their
first event. Keepalives cannot repair a failed TCP/TLS handshake or upload.

When requested, terminal streaming usage includes `cost_status`:

- `final`: the returned amount belongs to the control plane's terminal result.
- `pending`: a durable settlement intent has an amount but is not finalized.
- `estimated`: the amount is computed from the approved frozen price; it is not
  proof of durable settlement.
- `unknown`: no trustworthy amount was available. Missing cost is not zero.

Chat clients still opt in with `stream_options.include_usage=true`.
Reconcile using the response request ID at
`GET https://trustedrouter.com/v1/requests/{gateway_request_id}/billing` with the
same inference key. Do not treat missing Observability or a 404 as unbilled.

Before a success header, provider/heartbeat failure or a failed header write
attempts a refund. Failed delivery uses the existing frozen-terminal retry queue
and durable outbox. Settlement and refund remain first-terminal-winner operations:
a previously settled or snapshot-reaped charge is not silently overwritten.
This change does not credit historical incidents.

Generic router errors now include a bounded `error.code`. Upload failures
distinguish `incomplete_request_body`, `ambiguous_request_framing`,
`unsupported_transfer_encoding`, `request_body_too_large`, and
`request_headers_too_large`. No prompt, credential or raw parsing exception is
added to the response. The fixed-length upload limit remains 10 MiB; no unsafe
Content-Length/Transfer-Encoding fallback is introduced.

DNS withdrawal is not connection drainage: clients can retain old addresses and
existing HTTP/1.1 sockets. Shutdown tests cover partial uploads, direct dials to
cached addresses, idle/pipelined connections, and completion of active requests
and settlement within the existing grace period. These are local transport tests,
not proof of the cause of a customer's historical network failure. Deployment
must retain the normal DNS, health, grace, ownership and attestation gates.
