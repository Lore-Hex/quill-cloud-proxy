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

The existing four-host confidential TXT IAM condition does not cover NYTE.
The enclave workload needs the existing `confidentialAcmeTxtWriter` role on
`trustedrouter-com`, restricted to these two additional TXT records and their
enclosing Change resources:

- `_acme-challenge.api-nytokenexchange.trustedrouter.com.`
- `_acme-challenge.api-confidential-nytokenexchange.trustedrouter.com.`

Preview the exact additive grant with a separately authenticated deploy identity:

```sh
python3 tools/nyte_acme_iam.py --account tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com
```

Only after explicit approval for that IAM change, repeat with `--apply`.
The helper verifies the role has exactly the three certificate-write permissions,
preserves unrelated bindings, and retains the policy etag to reject concurrent
updates. It does not grant project-wide DNS access or alter the ops identity.
Certificate renewal retries happen inside the enclave; do not mint certificates
on an operator machine, copy private keys, or publish an unqualified API record.

After the normal CI-gated sequential GCP rollout, verify public HTTPS, catalog
and browser preflight on both names. Run `tools/verify-attestation.py` with each
`--api-host`, adding `--require-confidential-host` for the confidential name.
Use a small streamed `nyte/auto` request and inspect the terminal usage/response;
include the confidential privacy field for the confidential origin. Confirm
missing/weaker privacy is rejected without contacting a provider.

Public request documentation: https://trustedrouter.com/docs#nyte-api

## Trusted-only gateway names

The stronger host policy is selected by `api.trusted.` on each of
`trustedrouter.com`, `quillrouter.com`, `allyrouter.com`, `uptimerouter.com`
and `nytokenexchange.com`. Publication is gated separately from ordinary and
Confidential DNS; the presence of this source change is not a rollout record.
Use the usual inference key, balance, prices and limits. The supported writes
are chat completions, Messages and Responses, with an explicit
`"provider":{"min_privacy":"trusted"}`. Omitted or lower floors and other
writes fail closed. Reads such as `/attestation` and `/v1/models` are discovery,
not a claim that every listed model is available at this floor.

Trusted requires the control plane's endpoint-specific verified compute,
provider E2EE, ZDR and curated operator checks on the primary and fallback
routes. Either the HTTP or TLS hostname can require Trusted; the stricter one
wins. Subcalls must retain that floor. The gateway checks every authorized
operator before dispatch, including Maple's single managed workload.

Bootstrap uses the existing restricted certificate role with a separate
five-record condition: `python3 tools/nyte_acme_iam.py --trusted-api --account ACCOUNT`
previews it; `--apply` requires explicit operator authorization. Private keys
stay inside the enclave. The canonical Trusted membership requires each IP to
present all five public certificates, match signed GCP trust, bind its TLS
session and reject a Confidential-only request with fallbacks enabled before
authentication. The Route53 mirrors use only that Trusted membership. Never
point these names at ordinary or Confidential DNS during bootstrap or rollback.
