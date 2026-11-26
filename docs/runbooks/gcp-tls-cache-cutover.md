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

Read the installed policy back, compare the actual rule, and wait for IAM
propagation. Before admitting a workload, verify denial for a human on a
synthetic ciphertext on the new ring, unchanged permissions on existing
keys, and approved-enclave success using synthetic data. Do not inspect or
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
