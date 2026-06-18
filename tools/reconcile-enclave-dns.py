#!/usr/bin/env python3
"""Control-plane health + DNS reconciler for the attested enclave fleet.

Why this exists
---------------
The enclave terminates TLS *inside* the Confidential VM so the attestation
document binds to the live cert. That forbids any L7/proxy load balancer, and
GCP's L4 passthrough-NLB health check has proven unreliable against the enclave
(see ENCLAVE_LB_TEARDOWN_HANDOFF). Confidential-VM capacity is also chronically
scarce, so a design that assumes instant instance replacement is wrong.

So instead of a cloud LB, the control plane *is* the load balancer's brain:
this reconciler probes every enclave instance with the REAL signal — a full
attestation verification over its serving TLS socket — and publishes only the
healthy instances into a low-TTL DNS record. Clients hit `api.quillrouter.com`,
get healthy IPs, and connect directly to an enclave (TLS terminates in-enclave,
attestation intact). A dead/unhealthy instance is dropped from DNS within a
reconcile cycle + TTL; the MIG recreates dead VMs; other regions keep serving.

It is intentionally NOT in the serving path: if this reconciler stops, DNS
freezes at the last-good set (no new failover, but serving continues).

Run
---
  # read-only: show what DNS *would* become
  uv run --script tools/reconcile-enclave-dns.py --dry-run
  # actually reconcile the record
  uv run --script tools/reconcile-enclave-dns.py --apply

Health signal = tools/verify-attestation.py --connect-ip <IP> against the
canonical hostname, requiring the trust-page image digest, cert-binding, and
dbgstat disabled. An instance is healthy only if it passes.
"""
# /// script
# requires-python = ">=3.11"
# ///
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

PROJECT = os.environ.get("QUILL_PROJECT", "quill-cloud-proxy")
DNS_ZONE = os.environ.get("QUILL_DNS_ZONE", "quillrouter-com")
API_HOST = os.environ.get("QUILL_API_HOST", "api.quillrouter.com")
RECORD = API_HOST.rstrip(".") + "."
TTL = int(os.environ.get("QUILL_DNS_TTL", "60"))
TRUST_DIGEST_URL = os.environ.get(
    "QUILL_TRUST_DIGEST_URL", "https://trust.trustedrouter.com/image-digest-gcp.txt"
)
# Network tag every enclave instance carries (MIG + standalone). Discovery is
# attestation-gated, so a tagged-but-wrong instance is simply excluded.
ENCLAVE_TAG = os.environ.get("QUILL_ENCLAVE_TAG", "quill-enclave")
# Never let DNS drop below this many healthy backends. If a reconcile finds
# fewer (e.g. a probe-side network blip), it refuses to shrink the record —
# stale-but-serving beats blanking the API.
MIN_HEALTHY = int(os.environ.get("QUILL_MIN_HEALTHY", "2"))
VERIFIER = Path(__file__).parent / "verify-attestation.py"
# Artifact Registry repo holding the enclave image. The reconciler also accepts
# the newest gcp-release-* digest from here (the release a deploy is rolling TO,
# before the trust page publishes it) so DNS never blanks mid-roll.
AR_IMAGE = os.environ.get(
    "QUILL_AR_IMAGE",
    "us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi",
)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def gcloud_json(args: list[str]) -> object:
    out = subprocess.run(
        ["gcloud", *args, "--project", PROJECT, "--format=json"],
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out or "[]")


def discover_instances() -> list[dict]:
    """RUNNING enclave instances (any region) with an external IP."""
    rows = gcloud_json([
        "compute", "instances", "list",
        "--filter", f"tags.items={ENCLAVE_TAG} AND status=RUNNING",
    ])
    fleet = []
    for r in rows:
        ip = None
        for nic in r.get("networkInterfaces", []):
            for ac in nic.get("accessConfigs", []) or []:
                if ac.get("natIP"):
                    ip = ac["natIP"]
        zone = (r.get("zone") or "").rsplit("/", 1)[-1]
        if ip:
            fleet.append({"name": r["name"], "zone": zone,
                          "region": zone.rsplit("-", 1)[0], "ip": ip})
    return fleet


def trust_digest() -> str:
    with urllib.request.urlopen(TRUST_DIGEST_URL, timeout=10) as resp:
        d = resp.read().decode().strip()
    if not d.startswith("sha256:"):
        sys.exit(f"[FAIL] trust digest looks wrong: {d!r}")
    return d


def newest_release_digest() -> str | None:
    """Digest of the newest gcp-release-* image in Artifact Registry — the
    release a deploy is rolling TO, before the trust page has published it.

    Accepted IN ADDITION to the live trust digest. A rolling deploy legitimately
    spans two digests at once (old draining, new booting); gating DNS on only
    the published trust digest rejects the whole incoming fleet mid-roll and
    blanks DNS (the 2026-06-18 near-outage). The strict single-digest guarantee
    still holds CLIENT-side against the published trust page; this only governs
    DNS membership. Best-effort: None (→ trust digest only) if AR can't be read."""
    try:
        out = subprocess.run(
            ["gcloud", "artifacts", "docker", "images", "list", AR_IMAGE,
             "--include-tags", "--filter", "tags~gcp-release",
             "--sort-by=~UPDATE_TIME", "--limit", "1",
             "--format=value(version)", "--project", PROJECT],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        return out if out.startswith("sha256:") else None
    except Exception:
        return None


def attest(ip: str, digest: str) -> bool:
    """True iff the instance at `ip` passes full attestation for API_HOST."""
    try:
        p = subprocess.run(
            ["uv", "run", "--script", str(VERIFIER),
             "--api-host", API_HOST, "--connect-ip", ip,
             "--expect-digest", digest, "--samples", "2"],
            capture_output=True, text=True, timeout=45,
        )
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def current_dns_ips() -> list[str]:
    rows = gcloud_json([
        "dns", "record-sets", "list", "--zone", DNS_ZONE,
        "--name", RECORD, "--type", "A",
    ])
    for r in rows:
        if r.get("name") == RECORD and r.get("type") == "A":
            return list(r.get("rrdatas", []))
    return []


def set_dns_ips(ips: list[str]) -> None:
    """Idempotent transactional replace of the A record."""
    cur = current_dns_ips()
    base = ["gcloud", "dns", "record-sets", "transaction"]
    subprocess.run([*base, "start", "--zone", DNS_ZONE, "--project", PROJECT], check=True,
                   capture_output=True, text=True)
    try:
        if cur:
            subprocess.run([*base, "remove", "--zone", DNS_ZONE, "--project", PROJECT,
                            "--name", RECORD, "--type", "A", "--ttl", str(TTL), *cur],
                           check=True, capture_output=True, text=True)
        subprocess.run([*base, "add", "--zone", DNS_ZONE, "--project", PROJECT,
                        "--name", RECORD, "--type", "A", "--ttl", str(TTL), *ips],
                       check=True, capture_output=True, text=True)
        subprocess.run([*base, "execute", "--zone", DNS_ZONE, "--project", PROJECT],
                       check=True, capture_output=True, text=True)
    except Exception:
        subprocess.run([*base, "abort", "--zone", DNS_ZONE, "--project", PROJECT],
                       capture_output=True, text=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True,
                   help="(default) print the would-be healthy set; change nothing")
    g.add_argument("--apply", action="store_true", help="reconcile the DNS record")
    args = ap.parse_args()

    # DNS membership is gated on attestation against a SET of acceptable
    # digests: the published trust digest PLUS the newest release in Artifact
    # Registry (the digest a deploy is rolling to before the trust page
    # publishes). Keeps the fleet servable across the entire rollout window.
    trusted = trust_digest()
    incoming = newest_release_digest()
    allowed = [trusted] + ([incoming] if incoming and incoming != trusted else [])
    digest = ",".join(allowed)
    fleet = discover_instances()
    log(f"reconcile: {len(fleet)} running enclave instances; accepting digest(s) "
        + " + ".join(d[:23] + "…" for d in allowed))
    if not fleet:
        sys.exit("[FAIL] no running enclave instances discovered")

    # Attest all instances concurrently.
    healthy: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(lambda i: (i, attest(i["ip"], digest)), fleet))
    by_region: dict[str, int] = {}
    for inst, ok in results:
        mark = "ok " if ok else "FAIL"
        log(f"  [{mark}] {inst['region']:14s} {inst['ip']:15s} {inst['name']}")
        if ok:
            healthy.append(inst)
            by_region[inst["region"]] = by_region.get(inst["region"], 0) + 1

    healthy_ips = sorted({i["ip"] for i in healthy})
    regions = sorted(by_region)
    log(f"reconcile: {len(healthy_ips)} healthy across {len(regions)} regions {regions}")

    if len(healthy_ips) < MIN_HEALTHY:
        sys.exit(f"[FAIL] only {len(healthy_ips)} healthy (< MIN_HEALTHY={MIN_HEALTHY}); "
                 "refusing to shrink DNS — leaving last-good record in place")

    cur = sorted(current_dns_ips())
    if cur == healthy_ips:
        log(f"reconcile: DNS already correct ({len(healthy_ips)} A records) — no change")
        return 0

    log(f"reconcile: DNS {RECORD} {cur} -> {healthy_ips}")
    if args.apply:
        set_dns_ips(healthy_ips)
        log("reconcile: APPLIED")
    else:
        log("reconcile: DRY-RUN (pass --apply to change DNS)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
