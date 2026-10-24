// Durable settle outbox bucket (quill-cloud-proxy E4 E3 + E4).
//
// The enclave parks a settle or refund it could not deliver as one object
// here (enclave-go/internal/settleoutbox). A sweeper in a sibling enclave
// (settleoutbox.Sweeper, E4) lists v1/pending/, takes a time lease on an
// object (a sibling object under v1/lease/, written with generation
// preconditions), replays the exact bytes to the router and moves the
// object, unchanged, to v1/done/, v1/dead/ or v1/quarantine/. Objects hold
// frozen billing terminals: an authorization id, token counts, model and
// endpoint names. No prompt, output, key or token.
//
// Identity: the enclave writes with a federated token from its Confidential
// Space attestation through the Batch workload identity pool
// (tools/provision-gcp-batch-resources.sh creates the pool). The provider's
// attribute condition admits CONFIDENTIAL_SPACE, debug disabled since boot,
// the STABLE support track, this project number and the workload service
// account. It does NOT gate on the image digest; Batch gets that from
// per-digest grants on its bucket made by the release workflow
// (tools/reconcile-gcp-batch-image-access.sh). The grants are to the whole
// pool. Consequence: any image launchable under the workload service account
// in this project may create objects here, approved or not. An object is
// therefore untrusted until its boot_auth verifies against a boot the
// control plane registered, and the sweeper and the router must refuse an
// unsigned or unverifiable object rather than replay it as trusted.
//
// The sweeper grant (E4) widens the pool from create-only to get, list and
// delete. What bounds that: objects are immutable bytes (create-only, moved
// with generation preconditions, never rewritten), and they hold no prompt,
// output, key or token. A malicious workload admitted by the pool could at
// most read authorization ids and token counts, or delete or misfile an
// object, which loses or delays one parked charge: the same loss the outbox
// exists to recover, bounded and visible as a missing object. It cannot
// make the router accept a replay it would otherwise refuse: the router
// verifies boot_auth against the authorizing boot, and the sweeper sends
// only the bytes the object holds.
//
// Not applied by the PR that adds it. Run from this directory:
//   terraform init
//   terraform plan -var project_number=<number>
//   terraform apply
//
// Enable the writer by setting tee-env-QUILL_SETTLE_OUTBOX_BUCKET to the
// bucket name on the GCP instance templates (tools/deploy-gcp-mig.sh); an
// enclave without it never writes. Enable the sweeper separately with
// tee-env-QUILL_SETTLE_OUTBOX_SWEEP=on once this file's sweeper grant is
// applied; the bucket alone leaves it off.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "quill-cloud-proxy"
}

variable "project_number" {
  type        = string
  description = "Numeric project id; part of the workload identity pool principal."
}

variable "bucket_name" {
  type    = string
  default = "quill-cloud-proxy-settle-outbox"
}

variable "location" {
  type        = string
  description = "Multi-region, like the Batch bucket: a region's outage must not take the outbox down with the enclaves that would park into it."
  default     = "US"
}

variable "workload_identity_pool" {
  type        = string
  description = "The Confidential Space pool Batch provisioned; the outbox reuses it."
  default     = "trustedrouter-batch"
}

provider "google" {
  project = var.project_id
}

resource "google_storage_bucket" "settle_outbox" {
  name                        = var.bucket_name
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = false
  }

  // Pending, dead and quarantined terminals are never auto-deleted: an
  // object that outlives its sweeper is a charge nobody has booked, and a
  // dead or quarantined one waits for a human. The sweeper moves what it
  // has replayed to v1/done/; the rule below ages those out, mirroring the
  // router's 30-day retention of done outbox rows.
  soft_delete_policy {
    retention_duration_seconds = 0
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age            = 30
      matches_prefix = ["trustedrouter-settle-outbox/v1/done/"]
    }
  }
}

// Create-only for every enclave the pool's attribute condition admits.
resource "google_storage_bucket_iam_member" "enclave_create" {
  bucket = google_storage_bucket.settle_outbox.name
  role   = "roles/storage.objectCreator"
  member = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool}/*"
}

// The sweeper (E4): read and list to find and decode pending objects and
// leases, delete to move them. Create is the grant above. A custom role
// rather than roles/storage.objectAdmin, which would also carry update and
// the IAM-on-objects permissions nothing here needs. The widening and what
// bounds it are in the header comment.
resource "google_project_iam_custom_role" "settle_outbox_sweeper" {
  role_id     = "settleOutboxSweeper"
  title       = "Settle outbox sweeper"
  description = "Get, list and delete objects in the settle outbox bucket; create comes from objectCreator."
  permissions = [
    "storage.objects.get",
    "storage.objects.list",
    "storage.objects.delete",
  ]
}

resource "google_storage_bucket_iam_member" "enclave_sweep" {
  bucket = google_storage_bucket.settle_outbox.name
  role   = google_project_iam_custom_role.settle_outbox_sweeper.id
  member = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool}/*"
}

output "bucket" {
  value = google_storage_bucket.settle_outbox.name
}
