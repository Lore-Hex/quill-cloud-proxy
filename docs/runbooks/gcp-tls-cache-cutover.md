# GCP gateway TLS cache cutover

Do not merge an image that selects an empty cache into the ordinary release
train until the operations below have been qualified. Creating a bucket and a
KMS key is not a cutover. This runbook does not change AWS or Azure.

### Production IAM gate

The destination is `us-central1/keyRings/trusted-router-tls`. Do not use the
similarly named key in the shared `trusted-router` ring or tag that ring.
The [deny policy](../../infra/gcp/tls-cache/deny-direct-decrypt.json) is
attached to project 44325983244 and matches a tag by its permanent key and
value IDs. Verify the tag is assigned directly to the TLS ring and is absent
from every other ring (including inherited tags). Do not reuse this tag.
The exception for the attestation pool is **not a grant**. Verify the pool's
providers and each effective allow binding separately; grant only reviewed
image digests. Never exempt a human or a blanket service-account group.

Require both `useToEncrypt` and `useToDecrypt` to be denied to other principals.
The encrypted format provides no separate proof of who wrapped the data key.
Use a fresh `acme-workload-wrap-v2` created only after both denials are
effective. Never use the prior `acme-workload-wrap`, import an earlier
envelope, or accept ciphertext encrypted for another KMS key.

Use an existing authorized administrator in the project's parent organization
(currently `256036015125`). The predefined
[`roles/iam.denyAdmin`](https://docs.cloud.google.com/iam/docs/roles-permissions/iam#iam.denyAdmin)
can be granted only on an organization, even though **the policy below
attaches only to this project**. Do not grant organization-wide permissions
or move the attachment point to the organization for this cutover.
Preflight create/get/update/delete rights on the target project and
record baseline permissions on existing keys. Validate scope and rollback
before creation. From the repository root:

```sh
gcloud iam policies create tr-tls-ring-direct-decrypt \
  --kind=denypolicies --project=quill-cloud-proxy \
  --attachment-point=cloudresourcemanager.googleapis.com/projects/44325983244 \
  --policy-file=infra/gcp/tls-cache/deny-direct-decrypt.json
```

If the decrypt-only policy is already installed, do not create a duplicate.
Read its exact rules, UID and etag. Update that policy in place with the
reviewed file and the observed etag; preserve the original rule for rollback.
Read the installed policy back, compare the actual rule, and wait for IAM
propagation. Before admitting a workload, verify both denials for a human
using synthetic inputs, unchanged permissions on existing keys, and
approved-enclave success using synthetic data. Do not inspect or
reuse production TLS key material. A tag binding with no deny policy does
not restrict access.

### Gateway cutover

1. Inventory public hostnames, aliases, current public leaf serials, SPKI
   fingerprints, expiration and every serving fleet. Use the public TLS
   handshakes, release manifests and inventory, not the old cache objects.
2. Verify the measured resource names and the actual workload identity pool:
   one intended issuer/provider, stable production Confidential Space,
   debug disabled, correct project and workload account, digest mapped from
   the signed container measurement. Review effective KMS permissions including
   inherited grants. An empty key-level IAM policy does not imply no human can
   decrypt. Test both the deny and the approved digest on synthetic data.
   A principal that can change policy remains an administrator; do not market
   this as protection against that principal changing the rules.
3. Use the normal measured build plus independently approved reference digest.
   Authorize only that measured identity on the separate ciphertext bucket and
   wrapping key. Do not grant the whole pool, the VM account, object-storage
   service agents, or an older image just to get a deployment through startup.
   Launch the same production-mode Confidential Space image by its approved
   digest in an isolated instance with `tee-env-QUILL_GCP_ACME_TASK=gcp-acme-custody-check`.
   Before granting access, inspect the published linux/amd64 image config by
   digest. Its `tee.launch_policy.allow_env_override` must include
   `QUILL_GCP_ACME_TASK` and must **not** include `QUILL_TLS_MODE`. Do not use
   an older image without this selector, a debug image, or an alternate entrypoint.
   This branch exits before normal bootstrap or opening any listener. It
   writes, reads, compares and deletes a fresh synthetic object using the
   actual serving cache and WIF identity. Require independent verification of
   the instance, release digest, non-debug measurement and the corresponding
   workload identity and KMS data-access evidence. A local pass, a host
   service-account operation, or a standalone log line is not that proof.
   Before taking the GCP rollout lease, the release runs
   `python3 tools/check_gcp_tls_admission.py <image-digest>`. This only reads
   the two resource policies. A miss stops before drain; it is not a request
   to authorize a superseded image. Once the key administrator has approved
   the selected digest and the bindings are effective, retry the failed gate.
   This check does not prove effective IAM, custody or attestation.
4. In an isolated rehearsal, prove DNS-01 issuance into an empty cache, cold
   restart, a second replica reading the issued certificate, and renewal.
   Include the primary hostname as well as shared aliases. Legacy replicas
   cannot answer a new cache's TLS-ALPN challenges. Use a single issuer,
   qualified DNS validation and an explicit CA order budget; do not start
   parallel empty-cache replicas as a bootstrap strategy. Never import the
   old certificates or ACME private keys.
5. Pre-issue new production keys and certificates inside the authorized
   workload before admitting traffic. Independently compare *public* SPKIs
   against the old inventory. Verify every SNI's chain, expiry, same-socket
   attestation, image, regional health, billing and standard cloud holdbacks.
   Prove the candidate can restart without the legacy bucket or credentials.
   If a gate fails, stop; do not repopulate from the legacy bucket.
6. Retire superseded certificates and ACME authorizations only after all
   consumers, including other clouds sharing hostnames, have moved. Remove
   obsolete grants and handle old versions, retention, soft-deletes, backups
   and existing copies under the incident retention policy. Preserve access
   audit evidence separately. Do not describe deletion or revocation as
   undoing any past access.

Ordinary browsers still rely on the site's JavaScript, Web PKI and DNS.
Changing server key custody does not turn a separate attestation request
into proof about the connection carrying a prompt.

### Single issuer before serving

Run one isolated workload at a time, with no restart, no inbound traffic and
no other issuer. Before granting access, inventory every SNI from the actual
serving templates. Verify the authoritative challenge records and the issuer's
record-specific TXT permissions. QuillRouter base and regional names use
`quillrouter-com`; the other delegated names use `trustedrouter-com`.
The plain AllyRouter and UptimeRouter names require their own explicit
`_acme-challenge.api` CNAME delegations. A working traffic record or an
existing certificate is not proof of either delegation.

Set the existing measured launch override `QUILL_API_HOST` to one exact
gateway hostname, not the comma-separated serving list. The following
`QUILL_GCP_ACME_TASK` values exit before opening a listener or loading provider
credentials. Each invocation can submit at most one order, to one fixed CA.

| Mode | Cache | Action |
|---|---|---|
| `gcp-acme-rehearse` | Dedicated rehearsal bucket | Issue using Let's Encrypt staging; verify the cached hostname and key pair. |
| `gcp-acme-rehearse-read` | Dedicated rehearsal bucket | Compare the public SPKI on a cold start and second replica, without DNS, orders or writes. Grant only read and unwrap. |
| `gcp-acme-rehearse-renew` | Dedicated rehearsal bucket | Replace an existing staging leaf, once. |
| `gcp-acme-preissue` | Sealed serving bucket | Issue using Let's Encrypt production only on a confirmed miss. An invalid entry stops the task; a valid existing entry spends no order. |

The rehearsal bucket is `quill-cloud-proxy-acme-rehearsal-v1`, not a prefix
in the serving bucket. Bind the staging subject only to that bucket, using
the same private-access and retention controls; do not grant a rehearsal VM
access to the serving bucket. Use separate, bounded VM authorizations and
order budgets for staging and production. The serving cache rejects staging
directory overrides. A PASS marker is not proof of public trust or of a live
rollout. Check the public chain and SPKI independently, exercise cold replica
recovery, and verify the exact measured release before shifting traffic.

### DNS visibility before acceptance

Check a direct validation name for conflicts at the authoritative zone; do
not ask a public recursive resolver for an absent name immediately before
publishing its TXT. For a mirror, confirm its existing CNAME as well. Check
the zones' negative-cache TTLs; stop if they exceed the issuer's five-minute
window. The first production attempt received NXDOMAIN even though the zone
accepted the TXT change. Which cache the CA used was not observed.

For a pending challenge the single issuer keeps the TXT published through
that window and checks both Google Public DNS and Cloudflare (DNS over HTTPS
on port 443). Both must answer the CA-facing name with the expected TXT,
following the configured CNAME for a mirror. A mismatch, truncation, or
resolver outage cannot authorize an early challenge submission. The existing
eight-minute order deadline remains in force; a timed-out attempt must not
be replayed automatically. A CA-reused, already-valid authorization has no
pending challenge to submit. These checks reduce propagation races; they
do not prove what every CA validation location can see.
