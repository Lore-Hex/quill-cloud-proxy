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

DEFERRED (review 2026-06-21): the v5 source tidy-ups live here, but the
DEPLOYED reconciler image is still v4 — behavior is unchanged by the tidy-ups,
so the image rebuild was skipped. Source thus runs ahead of the running image
until the next *functional* reconciler change triggers a rebuild.

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
# Per-REGION floor for the region-pinned retry hostnames. Each region has only 2
# VMs, so the canonical floor of 2 is wrong here (a region at 1 healthy should
# publish that 1, not freeze on a dead pair). Default 1 = publish whatever is
# healthy, never blank (0 healthy is skipped). Raise it to refuse shrinking a
# regional record below N.
MIN_HEALTHY_REGIONAL = int(os.environ.get("QUILL_MIN_HEALTHY_REGIONAL", "1"))
VERIFIER = Path(__file__).parent / "verify-attestation.py"
# Artifact Registry repo holding the enclave image. The reconciler also accepts
# a short window of recent gcp-release-* digests from here. That covers both
# normal rolling deploy overlap and the recovery case where trust artifacts were
# published for a release whose rollout later failed, leaving the fleet on the
# prior still-good digest.
AR_IMAGE = os.environ.get(
    "QUILL_AR_IMAGE",
    "us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi",
)
ACCEPT_RECENT_RELEASE_DIGESTS = int(os.environ.get("QUILL_ACCEPT_RECENT_RELEASE_DIGESTS", "4"))
# Per-region retry hostnames. Each enclave only whitelists its OWN region's
# regional SNI (a us VM rejects api-us-east4.* with a TLS alert), so these MUST
# resolve to ONLY that region's VMs — not the canonical all-region set. When
# enabled, the reconciler also publishes api-<gcp-region>.<suffix> A = that
# region's healthy IPs. Suffix is quillrouter.com because that is the name baked
# into each enclave's autocert HostWhitelist (QUILL_API_HOST); trustedrouter
# regional names would need an enclave whitelist change first.
PUBLISH_REGIONAL = os.environ.get("QUILL_PUBLISH_REGIONAL", "0") == "1"
REGIONAL_ZONE = os.environ.get("QUILL_REGIONAL_ZONE", "quillrouter-com")
REGIONAL_SUFFIX = os.environ.get("QUILL_REGIONAL_SUFFIX", "quillrouter.com")


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
                    break  # first external IP wins — deterministic on multi-NIC
            if ip:
                break
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


def recent_release_digests() -> list[str]:
    """Recent gcp-release-* image digests in Artifact Registry.

    Accepted IN ADDITION to the live trust digest. A rolling deploy legitimately
    spans two digests at once (old draining, new booting); a failed deploy can
    also publish trust artifacts for an image that never became the fleet's
    serving digest. Gating DNS on only the published trust digest then rejects
    the still-good fleet and blocks the next rollout. Keeping this window short
    preserves a bounded release set while letting operators recover. Best-effort:
    [] (→ trust digest only) if AR can't be read."""
    try:
        out = subprocess.run(
            ["gcloud", "artifacts", "docker", "images", "list", AR_IMAGE,
             "--include-tags", "--filter", "tags~gcp-release",
             "--sort-by=~UPDATE_TIME", "--limit", str(ACCEPT_RECENT_RELEASE_DIGESTS),
             "--format=value(version)", "--project", PROJECT],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        return [line for line in out.splitlines() if line.startswith("sha256:")]
    except Exception:
        return []


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
    except (subprocess.TimeoutExpired, OSError) as e:
        # A probe failure (timeout, or an OSError such as a missing `uv`/verifier
        # or EMFILE under the thread pool) is a LOCALIZED unhealthy, not a crash
        # of the whole reconcile — every other instance must still be evaluated.
        log(f"  [probe-error] {ip}: {type(e).__name__}: {e}")
        return False


def current_dns_ips(zone: str, record: str) -> list[str]:
    rows = gcloud_json([
        "dns", "record-sets", "list", "--zone", zone,
        "--name", record, "--type", "A",
    ])
    for r in rows:
        if r.get("name") == record and r.get("type") == "A":
            return list(r.get("rrdatas", []))
    return []


def set_dns_ips(zone: str, record: str, ips: list[str]) -> None:
    """Atomically set the A record to `ips` (replace; no transaction race).

    `record-sets update` overwrites the record's rrdatas + ttl regardless of the
    current value, so we never read-then-`remove` the old IPs. The old
    transactional path raced: it `remove`d the exact ttl+rrdatas it had read a
    moment earlier, and if the record drifted in between — a concurrent reconcile
    tick, or simply a pre-existing different TTL — the `remove` failed on an exact
    mismatch and aborted the whole reconcile. That is what failed the 2026-06-19
    deploy at the "Reconcile DNS before us-east4 canary" step."""
    cur = current_dns_ips(zone, record)

    def _run(verb: str):
        return subprocess.run(
            ["gcloud", "dns", "record-sets", verb, record,
             "--zone", zone, "--project", PROJECT,
             "--type", "A", "--ttl", str(TTL), "--rrdatas", ",".join(ips)],
            capture_output=True, text=True)

    verb = "update" if cur else "create"
    p = _run(verb)
    if p.returncode != 0:
        # Record existence flipped under us (a concurrent writer created/deleted
        # it between our read and write): try the other verb once.
        p = _run("create" if verb == "update" else "update")
        if p.returncode != 0:
            raise RuntimeError(
                f"set_dns_ips({record}) failed: {(p.stderr or p.stdout).strip()}")


def reconcile_regional(by_region: dict[str, list[str]], apply: bool) -> None:
    """Publish api-<gcp-region>.<suffix> A = that region's healthy IPs.

    Region-pinned retry hostnames must resolve only to VMs that whitelist the
    regional SNI (i.e. that region's VMs). Safety floor: never SHRINK a regional
    record below MIN_HEALTHY_REGIONAL (default 1) — a region with 0 healthy IPs,
    or fewer than the floor when it currently has more, is left at last-good
    rather than blanked/shrunk. Growing a record is always allowed."""
    for region in sorted(by_region):
        ips = sorted(set(by_region[region]))
        if not ips:
            continue  # never publish/blank to an empty record
        record = f"api-{region}.{REGIONAL_SUFFIX}".rstrip(".") + "."
        cur = sorted(current_dns_ips(REGIONAL_ZONE, record))
        if len(ips) < MIN_HEALTHY_REGIONAL and len(ips) < len(cur):
            log(f"  regional {record}: {len(ips)} healthy < floor "
                f"{MIN_HEALTHY_REGIONAL} and < current {len(cur)} — leaving last-good")
            continue
        if cur == ips:
            log(f"  regional {record} already correct ({len(ips)} A)")
            continue
        log(f"  regional {record} {cur} -> {ips}")
        if apply:
            set_dns_ips(REGIONAL_ZONE, record, ips)
            log(f"  regional {record} APPLIED")


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True,
                   help="(default) print the would-be healthy set; change nothing")
    g.add_argument("--apply", action="store_true", help="reconcile the DNS record")
    args = ap.parse_args()

    # DNS membership is gated on attestation against a SET of acceptable
    # digests: the published trust digest PLUS recent release images in Artifact
    # Registry. Keeps the fleet servable across the entire rollout window and
    # lets the operator recover when a prior rollout published trust artifacts
    # but failed before the MIG reached that digest.
    trusted = trust_digest()
    allowed = list(dict.fromkeys([trusted, *recent_release_digests()]))
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
    by_region: dict[str, list[str]] = {}
    for inst, ok in results:
        mark = "ok " if ok else "FAIL"
        log(f"  [{mark}] {inst['region']:14s} {inst['ip']:15s} {inst['name']}")
        if ok:
            healthy.append(inst)
            by_region.setdefault(inst["region"], []).append(inst["ip"])

    healthy_ips = sorted({i["ip"] for i in healthy})
    regions = sorted(by_region)
    log(f"reconcile: {len(healthy_ips)} healthy across {len(regions)} regions {regions}")

    if len(healthy_ips) < MIN_HEALTHY:
        sys.exit(f"[FAIL] only {len(healthy_ips)} healthy (< MIN_HEALTHY={MIN_HEALTHY}); "
                 "refusing to shrink DNS — leaving last-good record in place")

    cur = sorted(current_dns_ips(DNS_ZONE, RECORD))
    if cur == healthy_ips:
        log(f"reconcile: canonical {RECORD} already correct ({len(healthy_ips)} A) — no change")
    else:
        log(f"reconcile: canonical {RECORD} {cur} -> {healthy_ips}")
        if args.apply:
            set_dns_ips(DNS_ZONE, RECORD, healthy_ips)
            log("reconcile: APPLIED canonical")
        else:
            log("reconcile: DRY-RUN canonical (pass --apply to change DNS)")

    if PUBLISH_REGIONAL:
        reconcile_regional(by_region, args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
