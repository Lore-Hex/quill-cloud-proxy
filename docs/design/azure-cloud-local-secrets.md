# Azure cloud-local secret boundary

## Decision

An Azure TrustedRouter enclave must not use a Google credential or call a GCP
secret, storage, DNS, or KMS API at runtime. Each cloud receives an independent
copy of the values it needs and reads only its own cloud-native stores.

This is an availability boundary and a security boundary. A second cloud that
needs the first cloud to boot is not a failover plane, and a long-lived foreign
service-account key inside an enclave unnecessarily expands compromise scope.

## Azure storage model

| Material | Azure location | Runtime reader |
|---|---|---|
| Provider API keys, device keys, private prompts | One encrypted Key Vault bundle | Attested enclave after Secure Key Release |
| ACME cache encryption key | Same encrypted Key Vault bundle | Attested enclave |
| ACME account, challenge, and certificate objects | Azure Blob Storage, AES-256-GCM ciphertext | Regional managed identities transport ciphertext |
| BYOK envelopes | Not yet available on Azure | Fail closed |

The bundle is sealed to the public half of an Azure Key Vault RSA-HSM key. Key
Vault releases the private half only when Microsoft Azure Attestation reports
the expected confidential-container policy hash. Pinning the immutable bundle
version in the measured container environment prevents silent bundle rollback
or replacement.

The Blob identity has `Storage Blob Data Contributor` only on the ACME storage
account. It never receives the ACME encryption key. AES-GCM associated data
binds each ciphertext to the storage account, container, and `autocert` cache
key, so an object cannot be replayed under another hostname or cache.

## Provisioning and rotation

The operator's restricted local source file is the cloud-neutral input. It is
copied independently into GCP Secret Manager and the sealed Azure Key Vault
bundle. Neither cloud is a source of truth for the other cloud.

1. Provision the Azure storage account, private container, regional identity
   roles, and an Azure-only cache key with
   `tools/provision-azure-acme-cache.sh --apply`.
2. Migrate existing certificate objects once with
   `tools/migrate-acme-cache-gcs-to-azure.py --apply`.
3. Seal and upload a new Azure bundle with
   `tools/azure-sync-secrets.sh --apply`.
4. Pin the returned bundle version and deploy one Azure region at a time.
5. Verify live attestation, TLS, and a prepaid PONG before moving to the next
   region.

The migration tool uses both operator logins, but that is a one-time control
operation. The deployed workload does not receive either operator credential.
GCP keeps its GCS cache; Azure keeps its Blob copy.

After every source object has been read back and verified, the migration writes
a non-secret completion marker and source-object count into the Azure
container's ARM metadata. The deploy preflight requires that marker, so an
empty or newly recreated container cannot replace a healthy TLS deployment.

## Enforced failure modes

The Azure build exits before serving if any of these are present:

- `BootstrapData.GCPServiceAccountKeyJSON`
- `GOOGLE_APPLICATION_CREDENTIALS`
- `QUILL_ACME_CACHE_GCS_BUCKET`
- `QUILL_ACME_DNS_GCP_PROJECT`
- `QUILL_ACME_DNS_MANAGED_ZONE`

The deploy preflight enforces the same environment boundary and verifies that
the Azure storage account is private, shared-key access is disabled, HTTPS and
TLS 1.2 are required, the container has a valid migration marker, and the
regional identity has the required data-plane role. It runs before the release
policy is widened or a healthy container is deleted.

## BYOK follow-up

Current BYOK and user-secret envelopes use GCP KMS. Azure must not unwrap them
through GCP. The Azure build therefore leaves the BYOK cache disabled and
returns an ordinary unavailable-key error for those routes while prepaid routes
continue.

Full Azure BYOK requires the control plane to write one envelope per enabled
cloud, with cloud-specific key identifiers and identical secret revision
semantics. Authorization should return only the envelope for the serving cloud.
That change needs its own migration, rotation, replay, and deletion tests; it
must not be approximated by restoring a cross-cloud credential.
