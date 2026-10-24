// Durable settle outbox bucket (quill-cloud-proxy E4 E3).
//
// The enclave parks a settle or refund it could not deliver as one object
// here (enclave-go/internal/settleoutbox). A sweeper in a sibling enclave
// replays and removes them in a later increment. Objects hold frozen billing
// terminals: an authorization id, token counts, model and endpoint names.
// No prompt, output, key or token.
//
// Identity: the enclave writes with a federated token from its Confidential
// Space attestation through the Batch workload identity pool
// (tools/provision-gcp-batch-resources.sh creates the pool; its provider's
// attribute condition admits only CONFIDENTIAL_SPACE, debug disabled, the
// STABLE track, this project and the workload service account). Batch grants
// its bucket per image digest from the release workflow
// (tools/reconcile-gcp-batch-image-access.sh). The outbox grants the whole
// pool create-only access instead: every approved enclave image may park a
// terminal, none may read one back or delete it. Read and delete for the
// sweeper come with the sweeper.
//
// Not applied by the PR that adds it. Run from this directory:
//   terraform init
//   terraform plan -var project_number=<number>
//   terraform apply
//
// Enable the writer by setting tee-env-QUILL_SETTLE_OUTBOX_BUCKET to the
// bucket name on the GCP instance templates (tools/deploy-gcp-mig.sh); an
// enclave without it never writes.

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

  // Pending terminals are never auto-deleted: an object that outlives its
  // sweeper is a charge nobody has booked. The sweeper deletes what it has
  // replayed.
  soft_delete_policy {
    retention_duration_seconds = 0
  }
}

// Create-only for every enclave the pool's attribute condition admits.
resource "google_storage_bucket_iam_member" "enclave_create" {
  bucket = google_storage_bucket.settle_outbox.name
  role   = "roles/storage.objectCreator"
  member = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool}/*"
}

output "bucket" {
  value = google_storage_bucket.settle_outbox.name
}
