# trustedrouter.com multi-vendor DNS — Terraform

Single source of truth for the trustedrouter.com zone. Drives BOTH
Cloudflare AND Google Cloud DNS from one HCL file so the two
vendors can't silently drift apart (as they did on 2026-05-14,
prompting Cloudflare's "no longer using our nameservers" email).

## First-time setup (one-off, ~10 minutes)

1. **Install Terraform** locally (`brew install terraform`).

2. **Cloudflare API token.** In Cloudflare dash → My Profile → API
   Tokens → Create Token, with template "Edit zone DNS". Scope to
   the trustedrouter.com zone only. Save to
   `~/.quill_cloud_keys.private` as `CLOUDFLARE_API_TOKEN=...` (the
   secrets.sh + sync-secrets-to-aws.sh already understands this key).

3. **Cloudflare zone IDs.** From each zone's Overview page in
   Cloudflare dash, copy the 32-char hex Zone ID. Save both as
   `CLOUDFLARE_ZONE_ID_TRUSTEDROUTER=...` and
   `CLOUDFLARE_ZONE_ID_QUILLROUTER=...` in the keyfile.

4. **GCP auth.** Use either Workload Identity (CI) or your personal
   `gcloud auth application-default login`. The SA / user needs
   `roles/dns.admin` on project `quill-cloud-proxy`.

5. **Initialize Terraform.**
   ```bash
   cd tools/dns
   terraform init
   ```

6. **Import existing records.** Each existing DNS record needs to be
   imported once so Terraform doesn't try to recreate it (which
   would drop the live record momentarily and break resolution).
   See the import block at the bottom of this README.

7. **Sanity-check.**
   ```bash
   export CLOUDFLARE_API_TOKEN=$(grep -E "^CLOUDFLARE_API_TOKEN=" ~/.quill_cloud_keys.private | sed 's/^[^=]*=//')
   export TF_VAR_cloudflare_zone_id=$(grep -E "^CLOUDFLARE_ZONE_ID_TRUSTEDROUTER=" ~/.quill_cloud_keys.private | sed 's/^[^=]*=//')
   export TF_VAR_cloudflare_zone_id_quillrouter=$(grep -E "^CLOUDFLARE_ZONE_ID_QUILLROUTER=" ~/.quill_cloud_keys.private | sed 's/^[^=]*=//')
   terraform plan
   ```
   Plan output should say "No changes". Anything else means the
   imports were incomplete or the records have actually drifted.

## Day-to-day: changing a DNS record

1. Edit `main.tf`. Change the local variable or resource block.
2. `terraform plan` — confirms the diff matches what you expected.
3. `terraform apply` — applies the same change to both vendors
   atomically. If one vendor's API fails, Terraform fails the apply
   so the two zones don't drift.
4. Verify with the dig commands in the `verification_commands`
   output.

## Import block (one-time, paste each line one by one)

```bash
# Cloudflare records — get the record IDs from the API:
#   curl -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
#     "https://api.cloudflare.com/client/v4/zones/$TF_VAR_cloudflare_zone_id/dns_records" \
#     | jq -r '.result[] | "\(.id)\t\(.type)\t\(.name)"'
# Then for each record you want under Terraform control:
terraform import 'cloudflare_record.apex_a'          "$TF_VAR_cloudflare_zone_id/<record_id>"
terraform import 'cloudflare_record.apex_txt_verify' "$TF_VAR_cloudflare_zone_id/<record_id>"
terraform import 'cloudflare_record.trust_cname'     "$TF_VAR_cloudflare_zone_id/<record_id>"
terraform import 'cloudflare_record.www_cname'       "$TF_VAR_cloudflare_zone_id/<record_id>"

# Cloud DNS imports use the rrset format
# projects/<proj>/managedZones/<zone>/rrsets/<name>./<type>
terraform import 'google_dns_record_set.apex_a'         projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/trustedrouter.com./A
terraform import 'google_dns_record_set.apex_txt_verify' projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/trustedrouter.com./TXT
terraform import 'google_dns_record_set.trust_cname'    projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/trust.trustedrouter.com./CNAME
terraform import 'google_dns_record_set.www_cname'      projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/www.trustedrouter.com./CNAME
terraform import 'google_dns_record_set.status_cname'   projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/status.trustedrouter.com./CNAME
terraform import 'google_dns_record_set.apex_ns'        projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/trustedrouter.com./NS

# quillrouter.com — Cloudflare side (run after fix-quillrouter-dns.sh
# has populated Cloud DNS so plan/apply doesn't trigger more churn).
terraform import 'cloudflare_record.quill_api_a'           "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_eu_a'        "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_us_east4_a'  "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_cold_alias["us-central1"]'         "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_cold_alias["asia-northeast1"]'     "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_cold_alias["asia-southeast1"]'     "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"
terraform import 'cloudflare_record.quill_api_cold_alias["southamerica-east1"]'  "$TF_VAR_cloudflare_zone_id_quillrouter/<record_id>"

# quillrouter.com — Cloud DNS side
terraform import 'google_dns_record_set.quill_api_a'          projects/quill-cloud-proxy/managedZones/quillrouter-com/rrsets/api.quillrouter.com./A
terraform import 'google_dns_record_set.quill_api_eu_a'       projects/quill-cloud-proxy/managedZones/quillrouter-com/rrsets/api-europe-west4.quillrouter.com./A
terraform import 'google_dns_record_set.quill_api_us_east4_a' projects/quill-cloud-proxy/managedZones/quillrouter-com/rrsets/api-us-east4.quillrouter.com./A
for region in us-central1 asia-northeast1 asia-southeast1 southamerica-east1; do
  terraform import "google_dns_record_set.quill_api_cold_alias[\"$region\"]" \
    "projects/quill-cloud-proxy/managedZones/quillrouter-com/rrsets/api-${region}.quillrouter.com./CNAME"
done
terraform import 'google_dns_record_set.quill_apex_ns'  projects/quill-cloud-proxy/managedZones/quillrouter-com/rrsets/quillrouter.com./NS
```

## Don'ts

- **Don't hand-edit Cloudflare or Cloud DNS records via the web UI
  after this is set up.** Any out-of-band change will trigger drift
  on the next `terraform plan`. If you genuinely need an emergency
  fix, edit main.tf to match what you intended, run `terraform plan`,
  and re-apply.

- **Don't put the Cloudflare API token or zone ID in
  terraform.tfvars committed to git.** The vars are loaded from env;
  Terraform will refuse to apply if either is missing.

- **Don't terraform destroy this module.** It would delete every
  record on both vendors and trustedrouter.com would go dark for
  resolvers until the imports re-ran. The state is treated as
  immutable-by-default; only `terraform apply` after a diff is
  expected to mutate live records.

## Followups

- **State backend**: currently local state (`terraform.tfstate` in
  this dir). For team use, move to GCS:
  ```hcl
  terraform {
    backend "gcs" {
      bucket = "quill-cloud-proxy-tfstate"
      prefix = "dns/trustedrouter-com"
    }
  }
  ```
  with the bucket provisioned via `gcloud storage buckets create
  gs://quill-cloud-proxy-tfstate --uniform-bucket-level-access` and
  pinned to versioning.

- **CI integration**: a GitHub Actions workflow on push to `main`
  that touches `tools/dns/**` could run `terraform plan` in PR
  mode and post the diff as a comment. Don't auto-apply — DNS
  changes deserve human eyes.

- **quillrouter.com**: the sister zone has its own multi-vendor
  setup; once trustedrouter.com is stable, mirror this module
  shape there too.

- **Registrar-NS-change alarm**: this Terraform doesn't watch the
  registrar's NS list (where the original Cloudflare email came
  from). Add a periodic synthetic monitor (e.g. Cloud Scheduler →
  Cloud Run Job) that does `dig +trace NS trustedrouter.com` and
  alerts on diff vs the expected 6-NS set.
