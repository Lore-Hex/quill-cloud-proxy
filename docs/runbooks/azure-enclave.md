# Runbook — Azure confidential enclaves (SEV-SNP / MAA)

The single source of truth for standing up, deploying and verifying an Azure
enclave region. Everything here is current and working; commands are meant to be
run as written.

Azure differs from AWS in one way that shapes the whole procedure: the workload
is measured by the **CCE policy hash**, carried in SEV-SNP `HOST_DATA` and
attested through **MAA**. Key Vault releases the secret bundle only to a
workload whose `HOST_DATA` matches the wrapping key's release policy. So the
release policy and the deployed container must be changed **together**, in a
fixed order — that is what `deploy-azure-aci.sh`'s phases enforce.

---

## 1. What exists

| | |
|---|---|
| regions | `uaenorth` (rg `TR-TEE-DUBAI`), `australiaeast` (rg `tr-tee-sydney`) |
| API hosts | `api-azure.trustedrouter.com`, `api-azure-syd.trustedrouter.com` |
| observer/status | Container App `tr-azure-vnet` → `azure.trustedrouter.com` |
| vault (shared) | `trquillkv` in `TR-TEE-DUBAI`, Premium |
| wrapping key (shared) | `tr-bootstrap-wrap` — one clause per region's MAA authority |
| bundle secret (shared) | `tr-bootstrap-bundle` |
| registry (shared) | `trquillacr` |
| ACME cache (shared) | Azure Blob `trquillacmecache/acme-cache`, client-side encrypted |
| per region | resource group, MAA instance, managed identity `tr-skr-identity`, container group `quill-enclave-<region>` |

**Shared on purpose.** One wrapping key and one bundle means one secret set. Per
region keys would require per region re-sealing, and a bundle that drifts
between regions is a provider that 401s in one region only.

**The cost of sharing, stated honestly:** the vault is in UAE North, so a UAE
North *vault* outage blocks a **cold start** everywhere. It does not affect a
running enclave, which holds its unsealed secrets in memory.

---

## 2. Cloud-local secrets and certificates

**A deploy must READ its certificate from the shared cache, never mint one.**

Every Azure enclave uses the Azure Blob container `trquillacmecache/acme-cache`.
The enclave encrypts each `autocert` object with AES-256-GCM before the managed
identity writes it. The encryption key is inside the attestation-gated Key
Vault bundle. The storage identity can move ciphertext but cannot recover the
TLS private key.

Azure does not accept `GOOGLE_APPLICATION_CREDENTIALS`, a GCS cache, or GCP DNS
credentials. The executable rejects them at boot and the deploy preflight
rejects them before changing a live region. GCP and Azure hold independent
copies of provider secrets; neither cloud reads the other cloud at runtime.

Without it, every deploy mints a new certificate, and Let's Encrypt allows
**5 per exact set of identifiers per 168h** with no override and nothing to buy.
Exhaust it and the region serves nothing until the window rolls — the CA's rate
limit becomes your uptime ceiling.

Provision the storage and both regional grants once:

```bash
./tools/provision-azure-acme-cache.sh --apply
```

The one-time migration tool reads the old GCS cache as an operator, encrypts it
locally, writes Azure Blob, and verifies every object byte-for-byte after
decrypting it. This is a migration operation, not an enclave dependency:

```bash
python3 tools/migrate-acme-cache-gcs-to-azure.py --apply
```

After the read-back checks pass, the migration writes a non-secret completion
marker and source-object count to the Azure container. The deploy preflight
refuses an unmarked or empty cache.

Do not delete the GCS objects after migration. GCP continues to use its own GCS
copy while Azure uses its Azure copy.

### Current BYOK boundary

Existing BYOK envelopes are wrapped by GCP KMS. Azure does not call GCP to open
them. Azure therefore serves prepaid routes and fails BYOK routes closed until
the control plane can emit an Azure-local envelope. Do not describe Azure BYOK
as available before that second envelope format ships.

---

## 3. Standing up a region from scratch

### 3.1 Create the regional resources

```bash
az group create --name TR-TEE-<REGION> --location <region>
```

```bash
az attestation create --name trquill<short> --resource-group TR-TEE-<REGION> --location <region>
```

Note the `attestUri` — it is this region's MAA authority and every later command
needs it.

### 3.2 Grant the identity (one-time, human-run)

Creating identities and role assignments from a deploy script turns the deploy
pipeline into a subscription admin, so this is deliberately separate:

```bash
LOCATION=<region> RESOURCE_GROUP=TR-TEE-<REGION> ./tools/bootstrap-azure-region.sh --apply
```

Dry-runs by default and prints the exact grants first. It creates
`tr-skr-identity` and grants, on the shared vault, *Key Vault Crypto Service
Release User* + *Crypto Officer* + *Secrets User*, and `AcrPull` on the
registry. It does not return until it has **proven** the grants propagated — a
not-yet-propagated Key Vault 403 is byte-identical to a `HOST_DATA` mismatch,
and guessing wrong costs a deploy cycle in each direction.

Requires an operator with User Access Administrator; `tr-deploy` cannot create
service accounts or identities.

Grant the regional identity access to the Azure-local certificate cache:

```bash
./tools/provision-azure-acme-cache.sh --apply
```

### 3.3 Seal the bundle (only when the secret set changes)

The provider keys, device keys, private prompts, and Azure cache key are copied
from the operator's restricted local source into an Azure-only encrypted Key
Vault bundle. No cloud secret store is read to create another cloud's copy:

```bash
RESOURCE_GROUP=TR-TEE-DUBAI ./tools/azure-sync-secrets.sh --apply
```

It prints the new version. **Pin it** — the version is part of the container's
env and therefore part of the measurement. Shred the values file afterwards.

### 3.4 Deploy

```bash
LOCATION=<region> RESOURCE_GROUP=TR-TEE-<REGION> MAA_ENDPOINT=<attest host> API_HOST=<api host> QUILL_AZURE_BUNDLE_VERSION=<version> TR_CONTROL_PLANE_BASE_URL="https://trustedrouter.com" ./tools/deploy-azure-aci.sh --apply all
```

`azure.trustedrouter.com` is the observer/status service, not a billing
authority. Do not put it in `TR_CONTROL_PLANE_BASE_URL`.

`all` runs `preflight → build → template → policy → bind → deploy → verify → narrow`. The
order is load-bearing:

* **bind before deploy** — an enclave that comes up against a stale binding
  attests correctly, is refused by Key Vault, and exits.
* **bind widens** the release policy to `{old, new}` rather than replacing, so a
  failed create can still be rolled back.
* **verify** fetches a real attestation and compares it to what the *key*
  requires, not to what the script believes it generated.
* **narrow** closes the window — and only runs after `verify` passes.

Dry run is the default; only `--apply` touches Azure.

### 3.5 Publish the region

Add the API host to Cloud DNS pointing at the container group's IP (the deploy
does this and then waits for propagation), and add the region to the control
plane's probe targets — see §5.

---

## 4. Routine operations

| task | command |
|---|---|
| deploy a new image | `./tools/deploy-azure-aci.sh --apply all` (env as §3.4) |
| re-verify a live region | `./tools/deploy-azure-aci.sh --apply verify` |
| **audit a region** | `./tools/deploy-azure-aci.sh audit` (read-only) |
| close a window left open | `./tools/deploy-azure-aci.sh --apply narrow-live` |
| container logs | `./tools/deploy-azure-aci.sh logs` |

### `audit` — run this before believing a green dashboard

Read-only, and it asks the two questions nothing else asks about a region that
is already up:

1. **Is the running workload still authorized?** It holds its unsealed secrets
   in memory, so it survives losing its key release and dies at its next **cold
   start** — at no time of your choosing.
2. **Is a bind window still open?** A deploy that dies at `verify` leaves it
   open by design so rollback stays possible. If nobody then runs `narrow`, a
   retired measurement keeps the right to unseal every current credential.

Both describe a fleet that is serving, green, and wrong about what happens next.

### `narrow-live`

`narrow` narrows to what the local workspace built, which is unavailable when a
deploy failed weeks ago on another machine. `narrow-live` narrows to what is
**running**, after proving it attests — narrowing to an unverified measurement
is worse than the open window it replaces.

---

## 5. Verification

Derive `HOST_DATA` **independently** of the token, or you are checking the token
against itself:

```bash
HD=$(az container show --name quill-enclave-<region> --resource-group TR-TEE-<REGION> --query confidentialComputeProperties.ccePolicy -o tsv | base64 -d | shasum -a 256 | cut -d' ' -f1)
```

```bash
python3 tools/verify-attestation.py --api-host <api host> --expected-maa-issuer https://<attest host> --expected-hostdata "$HD"
```

Negative control — a deliberately wrong measurement **must** fail, or the check
proves nothing:

```bash
python3 tools/verify-attestation.py --api-host <api host> --expected-maa-issuer https://<attest host> --expected-hostdata 00000000000000000000000000000000000000000000000000000000000000ff
```

### Control-plane probes

Region probe targets live in `scripts/deploy/azure_control_plane.sh`
(`GATEWAY_REGION_TARGETS`) in the **quill-router** repo, as
`name=connect_host[@public_host]`. The name binds the endpoint to its public
status component in `synthetic/components.py`.

The `@public_host` suffix is required wherever a region serves its own hostname
rather than the canonical one — without it the probe presents an SNI the region
has no certificate for and a healthy region publishes as **down**.

A region missing from these targets is not probed at all, and an unprobed
component renders blank, which reads as "no incidents" rather than "unknown".
Two structural tests enforce that the component list and this variable agree.

Deploy the control plane with `bash scripts/deploy/azure_control_plane.sh`.

---

## 6. Invariants, and what enforces them

| invariant | enforced by |
|---|---|
| release policy and container change together, in order | `deploy-azure-aci.sh` phases + `tools/test_deploy_azure_aci.py` |
| a deploy reuses the shared certificate | encrypted Azure Blob cache set in every region |
| a fault restarts instead of becoming permanent | `restartPolicy: OnFailure` (override `RESTART_POLICY` only to debug) |
| a crash-loop fails the deploy fast | rising-restart-count check in `verify` |
| DNS is a precondition, not an assumption | resolution gate before the `/attestation` wait |
| every region is probed, at a name it serves | `tests/test_per_enclave_probes.py` (quill-router) |
| GCP and Azure map the same logical provider secrets | `enclave-go/internal/bootstrap/provider_parity_test.go` |
| grants exist before a deploy needs them | `bootstrap-azure-region.sh` prerequisite check |
| Azure has no GCP runtime credential | Azure build-tag boundary tests + deploy `preflight` |

Run the tool tests directly:

```bash
python3 tools/test_deploy_azure_aci.py && python3 tools/test_bootstrap_azure_region.py
```

---

## 7. Known gaps

* **Azure BYOK is intentionally disabled.** Existing envelopes use GCP KMS.
  Add cloud-specific envelopes before enabling BYOK on Azure; do not restore a
  Google credential as a shortcut.
* **Traffic Manager is availability routing, not attestation routing.** The
  shared hostname fails between UAE North and Southeast Asia, but each backend
  still needs independent attestation probes before it remains eligible.
* **Attestation is probed by nonce only.** The full binding — cert fingerprint
  in the MAA document, exporter channel binding, same-socket follow-up — is
  checked by `verify-attestation.py`, not by the status page.
