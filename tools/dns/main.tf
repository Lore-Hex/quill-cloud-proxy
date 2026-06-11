// trustedrouter.com / quillrouter.com DNS, driven from a single Terraform
// source so Cloud DNS records and any retained Cloudflare mirror records do
// not silently drift.
//
// Background: Cloudflare's email on 2026-05-14 ("trustedrouter.com stopped
// using Cloudflare's nameservers") surfaced a partial multi-vendor setup.
// The current registrar delegation is intentionally Google Cloud DNS only
// for both trustedrouter.com and quillrouter.com. Cloudflare records may
// still exist as a retained mirror/operator surface, but they are not part
// of the parent-zone authoritative NS set.
//
// Core trustedrouter.com records in Cloud DNS:
//   apex A         → 35.241.14.18 (TR control plane, GCP global LB)
//   apex TXT       → google-site-verification (Search Console ownership)
//   trust CNAME    → lore-hex.github.io. (GitHub Pages trust page)
//   www CNAME      → apex (semantic redirect)
//   eu A           → 35.241.14.18 (EU landing page on same control plane)
//
// Cloud DNS-only records:
//   status CNAME   → trustedrouter.com. (status page on Cloud Run)
//
// Apex NS records list the delegated Google Cloud DNS nameservers only.
//
// Auth:
//   - CLOUDFLARE_API_TOKEN env: API token scoped to DNS:Edit on trustedrouter.com.
//     Source: GCP Secret Manager (`cloudflare-api-token`) or
//     ~/.quill_cloud_keys.private.
//   - GOOGLE_APPLICATION_CREDENTIALS env: a key for a SA with
//     `roles/dns.admin` on project quill-cloud-proxy. Personal account works
//     in dev; for CI use a dedicated SA.
//
// Usage:
//   cd tools/dns
//   terraform init
//   terraform plan      # confirms expected state
//   terraform apply     # applies in lockstep on both vendors
//
// Importing existing records (one-time per record):
//   terraform import 'cloudflare_record.quill_api_eu_a' <zone_id>/<record_id>
//   terraform import 'google_dns_record_set.apex_a' projects/quill-cloud-proxy/managedZones/trustedrouter-com/rrsets/trustedrouter.com./A
//   ... (one import per resource block below)

terraform {
  required_version = ">= 1.5"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  // Reads CLOUDFLARE_API_TOKEN from env. Don't put the token in tfvars or
  // any committed file.
}

provider "google" {
  project = var.gcp_project
}

variable "gcp_project" {
  type        = string
  default     = "quill-cloud-proxy"
  description = "GCP project hosting the Cloud DNS managed zones."
}

variable "cloudflare_zone_id_quillrouter" {
  type        = string
  description = "Cloudflare zone ID for quillrouter.com (the API/inference domain)."
}

locals {
  // ─── trustedrouter.com ─────────────────────────────────────────────
  apex_ip                  = "35.241.14.18" // TR Cloud Run global LB
  google_site_verification = "google-site-verification=n2y7GA2FN8RxHA1aO7r_JueOsymAgBjhqWgwRn7G8cU"
  trust_page_origin        = "lore-hex.github.io." // GitHub Pages
  cloud_dns_zone           = "trustedrouter-com"

  // Authoritative nameservers delegated at the registrar for trustedrouter.com.
  all_nameservers = [
    "ns-cloud-b1.googledomains.com.",
    "ns-cloud-b2.googledomains.com.",
    "ns-cloud-b3.googledomains.com.",
    "ns-cloud-b4.googledomains.com.",
  ]

  // ─── quillrouter.com ───────────────────────────────────────────────
  // API/inference domain. Per-region direct endpoints route to each
  // enclave MIG's regional LB IP (warm regions get an A; cold regions
  // CNAME back to the canonical api.quillrouter.com so they ride the
  // global LB to whichever warm enclave is closest).
  quill_canonical_api_ip = "34.61.11.3"   // us-central1 enclave LB
  quill_eu_api_ip        = "34.13.202.2"  // europe-west4 enclave LB
  quill_us_east4_api_ip  = "34.11.96.117" // us-east4 enclave LB
  quill_cloud_dns_zone   = "quillrouter-com"

  // Cold regions whose api-<region>.quillrouter.com CNAMEs back to the
  // canonical (no dedicated enclave MIG there yet — Cloud Run falls
  // back to the nearest warm region via the global LB).
  quill_cold_region_aliases = [
    "us-central1",
    "us-west1",
    "asia-northeast1",
    "asia-southeast1",
    "australia-southeast1",
    "europe-west2",
    "northamerica-northeast1",
    "southamerica-east1",
  ]

  // Authoritative nameservers delegated at the registrar for quillrouter.com.
  quill_all_nameservers = [
    "ns-cloud-d1.googledomains.com.",
    "ns-cloud-d2.googledomains.com.",
    "ns-cloud-d3.googledomains.com.",
    "ns-cloud-d4.googledomains.com.",
  ]
}

// ─── Cloudflare records ─────────────────────────────────────────────────
//
// trustedrouter.com is authoritative on Google Cloud DNS ONLY (its NS moved
// off Cloudflare on 2026-05-14), so all of its records live in the
// google_dns_record_set blocks below — there is intentionally no
// trustedrouter.com Cloudflare mirror. The only Cloudflare records this
// config manages are the quillrouter.com API/LB set (quillrouter.com section).

// ─── Google Cloud DNS records ───────────────────────────────────────────

resource "google_dns_record_set" "apex_a" {
  name         = "trustedrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = [local.apex_ip]
}

resource "google_dns_record_set" "apex_txt_verify" {
  name         = "trustedrouter.com."
  type         = "TXT"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = ["\"${local.google_site_verification}\""]
}

resource "google_dns_record_set" "trust_cname" {
  name         = "trust.trustedrouter.com."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = [local.trust_page_origin]
}

resource "google_dns_record_set" "www_cname" {
  name         = "www.trustedrouter.com."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = ["trustedrouter.com."]
}

resource "google_dns_record_set" "eu_a" {
  // EU landing page hosted on the same control-plane global LB as the
  // apex. The app dispatches by Host header and renders the EU page at
  // eu.trustedrouter.com; production cert config must include this host.
  name         = "eu.trustedrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = [local.apex_ip]
}

resource "google_dns_record_set" "trustedrouter_api_cname" {
  name         = "api.trustedrouter.com."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = ["api.quillrouter.com."]
}

resource "google_dns_record_set" "status_a" {
  // Status page hosted on TR Cloud Run; both vendors keep this as
  // an A record pointing at the same global LB as the apex. (The
  // Cloud Run service dispatches by Host header.)
  name         = "status.trustedrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = [local.apex_ip]
}

// Apex NS record matching the registrar-delegated Google Cloud DNS set.
resource "google_dns_record_set" "apex_ns" {
  name         = "trustedrouter.com."
  type         = "NS"
  ttl          = 21600
  managed_zone = local.cloud_dns_zone
  rrdatas      = local.all_nameservers
}

// ─── quillrouter.com — Cloudflare ───────────────────────────────────────
// Cloudflare already has the regional record set. These blocks are for
// import-only; no record drift on Cloudflare's side today.
//
// NOTE: `api.quillrouter.com` is NOT a DNS record in Cloudflare — it's
// a Cloudflare Load Balancer (Stage 4f multi-cloud failover, pools
// GCP us-central1 + AWS us-west-2). That LB synthesizes the A record
// dynamically based on origin-pool health. Managing it requires a
// `cloudflare_load_balancer` resource which depends on the
// `cloudflare_load_balancer_pool` + `cloudflare_load_balancer_monitor`
// resources upstream — out of scope for this initial import. For now
// the LB stays unmanaged (an operator-only surface in the Cloudflare
// dashboard); Cloud DNS keeps a static A → us-central1-IP for
// resolvers caching Cloud DNS NS.

resource "cloudflare_record" "quill_api_eu_a" {
  zone_id = var.cloudflare_zone_id_quillrouter
  name    = "api-europe-west4"
  type    = "A"
  content = local.quill_eu_api_ip
  ttl     = 1
  proxied = false
  comment = "EU enclave direct — terraformed"
}

resource "cloudflare_record" "quill_api_us_east4_a" {
  zone_id = var.cloudflare_zone_id_quillrouter
  name    = "api-us-east4"
  type    = "A"
  content = local.quill_us_east4_api_ip
  ttl     = 1
  proxied = false
  comment = "us-east4 enclave direct — terraformed"
}

resource "cloudflare_record" "quill_api_cold_alias" {
  for_each = toset(local.quill_cold_region_aliases)
  zone_id  = var.cloudflare_zone_id_quillrouter
  name     = "api-${each.key}"
  type     = "CNAME"
  content  = "api.quillrouter.com"
  ttl      = 1
  proxied  = false
  comment  = "Cold-region alias → canonical — terraformed"
}

// ─── quillrouter.com — Google Cloud DNS ─────────────────────────────────
// Mirror of the Cloudflare records so resolvers caching Cloud DNS
// resolve the regional endpoints instead of NXDOMAIN-ing.

resource "google_dns_record_set" "quill_api_a" {
  name         = "api.quillrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.quill_cloud_dns_zone
  rrdatas      = [local.quill_canonical_api_ip]
}

resource "google_dns_record_set" "quill_api_eu_a" {
  name         = "api-europe-west4.quillrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.quill_cloud_dns_zone
  rrdatas      = [local.quill_eu_api_ip]
}

resource "google_dns_record_set" "quill_api_us_east4_a" {
  name         = "api-us-east4.quillrouter.com."
  type         = "A"
  ttl          = 300
  managed_zone = local.quill_cloud_dns_zone
  rrdatas      = [local.quill_us_east4_api_ip]
}

resource "google_dns_record_set" "quill_api_cold_alias" {
  for_each     = toset(local.quill_cold_region_aliases)
  name         = "api-${each.key}.quillrouter.com."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.quill_cloud_dns_zone
  rrdatas      = ["api.quillrouter.com."]
}

resource "google_dns_record_set" "quill_apex_ns" {
  name         = "quillrouter.com."
  type         = "NS"
  ttl          = 21600
  managed_zone = local.quill_cloud_dns_zone
  rrdatas      = local.quill_all_nameservers
}

output "verification_commands" {
  description = "After apply, run these and verify delegated Google Cloud DNS nameservers answer expected records."
  value       = <<-EOT
    # trustedrouter.com
    for ns in ns-cloud-b1.googledomains.com ns-cloud-b2.googledomains.com; do
      echo "  via $ns:"
      echo "    apex A → $(dig +short trustedrouter.com @$ns)"
      echo "    trust  → $(dig +short trust.trustedrouter.com @$ns)"
      echo "    www    → $(dig +short www.trustedrouter.com @$ns)"
      echo "    eu     → $(dig +short eu.trustedrouter.com @$ns)"
      echo "    TXT    → $(dig +short TXT trustedrouter.com @$ns | head -1)"
    done

    # quillrouter.com — regional endpoints + cold-region aliases
    for ns in ns-cloud-d1.googledomains.com ns-cloud-d2.googledomains.com; do
      echo "  via $ns:"
      for ep in api api-europe-west4 api-us-east4 api-us-central1 \
                api-asia-northeast1 api-asia-southeast1 api-southamerica-east1; do
        echo "    $ep.quillrouter.com → $(dig +short "$ep.quillrouter.com" @$ns | head -1)"
      done
    done
  EOT
}
