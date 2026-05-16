// trustedrouter.com multi-vendor DNS (Cloudflare primary + Google Cloud DNS
// secondary), driven from a single Terraform source so the two zones can't
// silently drift.
//
// Background: Cloudflare's email on 2026-05-14 ("trustedrouter.com stopped
// using Cloudflare's nameservers") surfaced a partial multi-vendor setup
// where Cloud DNS records had drifted from Cloudflare's. The one-shot fix
// at tools/fix-trustedrouter-dns.sh brought them back in sync; this file
// is the durable pin. Re-run on every change to either zone to keep both
// vendors synchronized.
//
// Records mirrored to both vendors:
//   apex A         → 35.241.14.18 (TR control plane, GCP global LB)
//   apex TXT       → google-site-verification (Search Console ownership)
//   trust CNAME    → lore-hex.github.io. (GitHub Pages trust page)
//   www CNAME      → apex (semantic redirect)
//
// Cloud DNS-only records (Cloudflare doesn't have these — they're
// non-marketing endpoints the operator didn't add to Cloudflare):
//   status CNAME   → trustedrouter.com. (status page on Cloud Run)
//
// Apex NS records (the "child zone" NS the resolver learns on first
// hit) explicitly list all 6 nameservers on the Cloud DNS side so a
// resolver caching Cloud DNS knows about Cloudflare's NS too.
// Cloudflare-side NS records can't be replaced on free/pro tier (Cloudflare
// auto-injects its own NS at apex); accepted asymmetry.
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
//   terraform import 'cloudflare_record.apex_a'   <zone_id>/<record_id>
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

variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare zone ID for trustedrouter.com (visible in the zone's Overview page)."
}

variable "cloudflare_zone_id_quillrouter" {
  type        = string
  description = "Cloudflare zone ID for quillrouter.com (the API/inference domain)."
}

locals {
  // ─── trustedrouter.com ─────────────────────────────────────────────
  apex_ip                     = "35.241.14.18" // TR Cloud Run global LB
  google_site_verification    = "google-site-verification=n2y7GA2FN8RxHA1aO7r_JueOsymAgBjhqWgwRn7G8cU"
  trust_page_origin           = "lore-hex.github.io." // GitHub Pages
  cloud_dns_zone              = "trustedrouter-com"

  // All 6 authoritative nameservers for trustedrouter.com.
  all_nameservers = [
    "ns-cloud-b1.googledomains.com.",
    "ns-cloud-b2.googledomains.com.",
    "ns-cloud-b3.googledomains.com.",
    "ns-cloud-b4.googledomains.com.",
    "dom.ns.cloudflare.com.",
    "harmony.ns.cloudflare.com.",
  ]

  // ─── quillrouter.com ───────────────────────────────────────────────
  // API/inference domain. Per-region direct endpoints route to each
  // enclave MIG's regional LB IP (warm regions get an A; cold regions
  // CNAME back to the canonical api.quillrouter.com so they ride the
  // global LB to whichever warm enclave is closest).
  quill_canonical_api_ip      = "34.61.11.3"   // us-central1 enclave LB
  quill_eu_api_ip             = "34.13.202.2"  // europe-west4 enclave LB
  quill_us_east4_api_ip       = "34.11.96.117" // us-east4 enclave LB
  quill_cloud_dns_zone        = "quillrouter-com"

  // Cold regions whose api-<region>.quillrouter.com CNAMEs back to the
  // canonical (no dedicated enclave MIG there yet — Cloud Run falls
  // back to the nearest warm region via the global LB).
  quill_cold_region_aliases = [
    "us-central1",
    "asia-northeast1",
    "asia-southeast1",
    "southamerica-east1",
  ]

  // All 6 authoritative nameservers for quillrouter.com (different
  // Cloudflare assignment than trustedrouter.com — Cloudflare picks
  // NS pair per zone).
  quill_all_nameservers = [
    "ns-cloud-d1.googledomains.com.",
    "ns-cloud-d2.googledomains.com.",
    "ns-cloud-d3.googledomains.com.",
    "ns-cloud-d4.googledomains.com.",
    "brynne.ns.cloudflare.com.",
    "keaton.ns.cloudflare.com.",
  ]
}

// ─── Cloudflare records ─────────────────────────────────────────────────

resource "cloudflare_record" "apex_a" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  type    = "A"
  content = local.apex_ip
  ttl     = 1 // 1 = Cloudflare "Auto" (proxy-managed TTL)
  proxied = true
  comment = "TR control plane — terraformed; do not hand-edit"
}

resource "cloudflare_record" "apex_txt_verify" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  type    = "TXT"
  content = local.google_site_verification
  ttl     = 1
  proxied = false
  comment = "Google Search Console domain verification — terraformed"
}

resource "cloudflare_record" "trust_cname" {
  zone_id = var.cloudflare_zone_id
  name    = "trust"
  type    = "CNAME"
  content = trimsuffix(local.trust_page_origin, ".")
  ttl     = 1
  proxied = false // GitHub Pages requires unproxied
  comment = "Trust page (GitHub Pages) — terraformed"
}

resource "cloudflare_record" "www_cname" {
  zone_id = var.cloudflare_zone_id
  name    = "www"
  type    = "CNAME"
  content = "trustedrouter.com"
  ttl     = 1
  proxied = true
  comment = "www redirect — terraformed"
}

// NOTE: Cloudflare's apex NS records can't be set declaratively on free/
// pro tier (Cloudflare auto-injects). If we move to Enterprise + use
// Secondary DNS, add a cloudflare_zone_settings_override or use the
// cf-terraforming tool to import the auto-injected NS records here.

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

resource "google_dns_record_set" "status_cname" {
  // status.trustedrouter.com isn't on Cloudflare (only the marketing
  // pages are). Cloud DNS keeps it pointing at the apex via CNAME so it
  // hits whatever the apex resolves to today (Cloud Run global LB).
  name         = "status.trustedrouter.com."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.cloud_dns_zone
  rrdatas      = ["trustedrouter.com."]
}

// Apex NS record listing ALL 6 NS — what resolvers caching Cloud DNS
// learn as the authoritative set. Cloudflare can't mirror this on
// free/pro (see note above), so this is one-sided multi-vendor advertisement.
resource "google_dns_record_set" "apex_ns" {
  name         = "trustedrouter.com."
  type         = "NS"
  ttl          = 21600
  managed_zone = local.cloud_dns_zone
  rrdatas      = local.all_nameservers
}

// ─── quillrouter.com — Cloudflare ───────────────────────────────────────
// Cloudflare already has the full record set. These blocks are for
// import-only; no record drift on Cloudflare's side today.

resource "cloudflare_record" "quill_api_a" {
  zone_id = var.cloudflare_zone_id_quillrouter
  name    = "api"
  type    = "A"
  content = local.quill_canonical_api_ip
  ttl     = 1
  proxied = false // attested-TLS enclave — Cloudflare can't terminate
  comment = "Canonical inference endpoint (us-central1 enclave) — terraformed"
}

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
  description = "After apply, run these and verify both vendors agree on every record."
  value = <<-EOT
    # trustedrouter.com
    for ns in ns-cloud-b1.googledomains.com dom.ns.cloudflare.com; do
      echo "  via $ns:"
      echo "    apex A → $(dig +short trustedrouter.com @$ns)"
      echo "    trust  → $(dig +short trust.trustedrouter.com @$ns)"
      echo "    www    → $(dig +short www.trustedrouter.com @$ns)"
      echo "    TXT    → $(dig +short TXT trustedrouter.com @$ns | head -1)"
    done

    # quillrouter.com — regional endpoints + cold-region aliases
    for ns in ns-cloud-d1.googledomains.com brynne.ns.cloudflare.com; do
      echo "  via $ns:"
      for ep in api api-europe-west4 api-us-east4 api-us-central1 \
                api-asia-northeast1 api-asia-southeast1 api-southamerica-east1; do
        echo "    $ep.quillrouter.com → $(dig +short "$ep.quillrouter.com" @$ns | head -1)"
      done
    done
  EOT
}
