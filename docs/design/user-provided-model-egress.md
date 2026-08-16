# User-provided model egress

Requests for `trustedrouter/user-*` user-provided models enter through the same
attested gateway as other inference requests, but their owner endpoint is
outside TrustedRouter's attested boundary. The enclave resolves the model and
authorizes its billing hold with the control plane, then sends one signed
OpenAI-compatible `/chat/completions` request directly to the owner's HTTPS
endpoint. It does not retry owner requests.

The outbound request is deliberately smaller than the caller request. The
enclave forwards only the documented OpenAI chat allowlist, replaces `model`
with the owner's upstream model id, forces `stream` to the owner's declared
capability, and strips TrustedRouter routing and attribution fields. The
`TR-Signature` HMAC covers the exact bytes sent. Optional endpoint credentials
and the required signing secret use the `user_model` envelope namespace and
are decrypted only inside the enclave.

Direct dispatch uses a per-request transport with no proxy and no redirects.
It resolves every A and AAAA answer and refuses the endpoint if any address is
loopback, private, link-local, multicast, unspecified, reserved, or an
IPv4-mapped form of one of those classes. The connection is pinned to a vetted
IP while TLS SNI and certificate verification continue to use the registered
hostname, preventing DNS rebinding without weakening HTTPS authentication.
Connect, first-byte, post-first-byte idle, and total budgets are enforced
separately.

GCP Confidential Space and Azure Confidential Containers use this direct
public-egress path. The Azure ACI deployment has a public container-group
network and does not configure a VNet or egress restriction; Azure also builds
the ordinary `!cloud_aws` HTTP client. AWS Nitro is intentionally excluded:
its enclave has no NIC or DNS and egresses only through statically allowlisted
per-host vsock tunnels. The AWS build therefore rejects a user-provided model
after resolution but before authorization, so no billing hold or owner strike
is created.

The community-operated endpoint is not attested and is not covered by
TrustedRouter's zero-data-retention promise. The attested enclave protects the
caller-facing TLS hop, avoids prompt logging, confines secret decryption, and
measures the egress policy; it cannot extend those guarantees into owner code.
