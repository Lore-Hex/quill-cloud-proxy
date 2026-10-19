# New York Token Exchange API aliases

The GCP attested gateway also serves `api.nytokenexchange.com` and
`api.confidential.nytokenexchange.com`. Both terminate TLS inside the same
measured workload as `api.trustedrouter.com`, use the same account/key and
balance, and expose `/v1/models` and `/attestation`.

The regular alias preserves the normal API's request semantics. The
confidential alias has the same Host-or-SNI enforcement as
`api.confidential.trustedrouter.com`: every supported inference request must
explicitly send `provider.min_privacy: "confidential"`. Weaker/missing settings
and unsupported operations fail closed. A hostname alias alone does not turn
ordinary upstream providers into confidential providers.

All `nyte/` model IDs canonicalize to `trustedrouter/` before authorization,
privacy checks, orchestration and idempotency. The namespace changes neither
the selected routing policy nor pricing. Canonical entries advertise aliases
in the catalog's `trustedrouter.aliases` field.

## DNS and release safety

The `exchange-nytokenexchange-com` zone contains independent API A records.
The reconciler bootstraps only the two subdomain ACME challenge CNAMEs into the
existing enclave-controlled `trustedrouter-com` zone. It preserves the apex,
www, mail and website certificate-manager records.

Each new API name is published only after certificate and signed, nonce/channel
bound attestation verification for that exact SNI. Confidential publication also
requires its privacy-policy probe. Only nondrained, nonpending canonical fleet
members are considered. No eligible member removes that alias's A record.
New-name readiness does not shrink the existing TrustedRouter confidential set.

The ordinary NYTE name also bootstraps from DNS-01, avoiding premature TLS-ALPN
orders while it has no published address. TLS private keys stay in the enclave
and its existing sealed certificate cache. No new parent/CDN TLS terminator is
introduced. The apex website is a separate surface, not an inference proxy.

After the normal CI-gated sequential GCP rollout, verify public HTTPS, catalog
and browser preflight on both names. Run `tools/verify-attestation.py` with each
`--api-host`, adding `--require-confidential-host` for the confidential name.
Use a small streamed `nyte/auto` request and inspect the terminal usage/response;
include the confidential privacy field for the confidential origin. Confirm
missing/weaker privacy is rejected without contacting a provider.

Public request documentation: https://trustedrouter.com/docs#nyte-api
