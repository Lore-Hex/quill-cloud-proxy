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
//   terraform init    # state: gs://quill-cloud-proxy-tfstate/settle-outbox
//   terraform plan -var project_number=<number>
//   terraform apply
//
// Enable the writer by setting tee-env-QUILL_SETTLE_OUTBOX_BUCKET to the
// bucket name on the GCP instance templates (tools/deploy-gcp-mig.sh); an
// enclave without it never writes. Enable the sweeper separately with
// tee-env-QUILL_SETTLE_OUTBOX_SWEEP=on, but only after this file's sweeper
// grant is applied AND the serving image carries QUILL_SETTLE_OUTBOX_SWEEP in
// its tee.launch_policy.allow_env_override label (Confidential Space refuses
// to launch an unlisted tee-env name). The bucket alone leaves it off.
//
// HARD RULE: QUILL_SETTLE_OUTBOX_SWEEP=on must never be set before the
// router's verify-when-present increment (quill-router R3: X-TR-Boot-Auth
// verified on /settle and /refund when present) is deployed on the plane
// the sweeper replays to. Until then the router accepts any shaped header
// under the sweeper's own internal token, so an object any pool-admitted
// workload created would settle as trusted. The sweeper refuses unsigned
// objects itself; only the router can refuse a forged signature.
// See docs/runbooks/settle-outbox.md.

terraform {
  required_version = ">= 1.5"
  // State lives in the project's shared Terraform state bucket (the same one
  // tools/dns documents), under its own prefix, so an apply from any machine
  // sees the bucket, roles and alert this root already created.
  backend "gcs" {
    bucket = "quill-cloud-proxy-tfstate"
    prefix = "settle-outbox"
  }
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

// The sweeper (E4): get and list to find and decode pending objects and
// leases; delete to finish a move (the pending object goes once its copy
// under done/, dead/ or quarantine/ exists) and to drop a lease. The lease
// rewrite (a Put with ifGenerationMatch=<generation>, Batch's claim) also
// needs storage.objects.delete: GCS treats replacing an object as delete
// plus create. Create itself is the grant above. A custom role rather than
// roles/storage.objectAdmin, which would also carry update and the
// IAM-on-objects permissions nothing here needs. The widening and what
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

// Alerting. The enclave writes its log lines to the Confidential Space
// launcher log (tools/dx/enclave-logs.sh reads the same stream). Every
// sweep that saw pending objects logs one counter line,
//   settle_outbox.sweep owner=... pending=N claimed=N settled=N dead=N quarantined=N retried=N skipped=N orphan_leases=N
// A non-zero dead or quarantined count is a charge a human has to look at
// (v1/dead/) or an object that must not be replayed (v1/quarantine/): the
// metric below counts those lines and the policy pages on any. The sender
// refusal line is included too: a sweeper the router no longer admits
// recovers nothing until its token is fixed.
variable "alert_notification_channels" {
  type        = list(string)
  description = "Cloud Monitoring notification channel ids the outbox alert pages. Empty means the policy exists and is visible in the console but pages nobody."
  default     = []
}

resource "google_logging_metric" "settle_outbox_attention" {
  name        = "settle_outbox_attention"
  description = "Settle outbox sweeps that filed an object under dead/ or quarantine/, or were refused by the router."
  filter      = <<-EOT
    logName="projects/${var.project_id}/logs/confidential-space-launcher"
    AND (
      textPayload=~"settle_outbox\.sweep .*(dead|quarantined)=[1-9]"
      OR jsonPayload.MESSAGE=~"settle_outbox\.sweep .*(dead|quarantined)=[1-9]"
      OR textPayload:"settle_outbox.sweep_sender_refused"
      OR jsonPayload.MESSAGE:"settle_outbox.sweep_sender_refused"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "settle_outbox_attention" {
  display_name = "Settle outbox: dead or quarantined objects"
  combiner     = "OR"

  conditions {
    display_name = "Any sweep filed dead/quarantine or was refused"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.settle_outbox_attention.name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
      trigger {
        count = 1
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "An enclave settle outbox sweep moved an object to v1/dead/ (the router refused the authorization: 404 or 409) or v1/quarantine/ (unsigned, malformed or boot-auth refused), or the router refused the sweeper's internal token. Runbook: docs/runbooks/settle-outbox.md."
    mime_type = "text/markdown"
  }
}

output "bucket" {
  value = google_storage_bucket.settle_outbox.name
}
