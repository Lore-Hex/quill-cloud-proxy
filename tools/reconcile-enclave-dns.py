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
freezes membership at the last-good set. In GEO mode Cloud DNS independently
checks TCP liveness and fails over between the admitted locations.

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
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Iterator, NamedTuple

from cloud_dns_records import record_ips
from dns_geo_health import verify_health_check

GCP_ENCLAVE_INVENTORY = Path(__file__).with_name("gcp-enclave-migs.txt")
# Regions that are being bootstrapped (docs/runbooks/README.md, "Adding a
# gateway region"). The first-time-region design needs this reconciler to know
# such a region from its first rollout: it holds the cold CNAME while the
# rollout drain is set, promotes it only when the workflow says the direct
# canary passed, and afterwards keeps api-<region> equal to the attested VMs.
# Left out, the regional name would sit on the one bootstrap IP for ever, and a
# re-roll would leave it on a deleted VM.
GCP_ENCLAVE_PENDING_INVENTORY = Path(__file__).with_name(
    "gcp-enclave-migs-pending.txt"
)


def _inventory_regions(path: Path) -> list[str]:
    regions: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        region, separator, mig = line.partition(":")
        if not separator or not region or not mig:
            raise ValueError(f"invalid GCP enclave inventory entry: {line!r}")
        regions.append(region)
    return regions


def gcp_enclave_regions() -> frozenset[str]:
    """Return regions allowed to contribute to canonical or regional DNS."""
    regions = _inventory_regions(GCP_ENCLAVE_INVENTORY)
    if not regions or len(regions) != len(set(regions)):
        raise ValueError("GCP enclave inventory must contain unique regions")
    return frozenset(regions)


def gcp_enclave_pending_regions(serving: frozenset[str]) -> frozenset[str]:
    """Return regions that get a regional record but never canonical traffic."""
    # No file means no pending regions: an image or checkout from before the
    # file existed must behave exactly as it did then.
    if not GCP_ENCLAVE_PENDING_INVENTORY.exists():
        return frozenset()
    regions = _inventory_regions(GCP_ENCLAVE_PENDING_INVENTORY)
    if len(regions) != len(set(regions)):
        raise ValueError("pending GCP enclave inventory must contain unique regions")
    # "Serves canonical traffic" and "must never serve it" cannot both hold, and
    # guessing which one was meant is how an unverified region gets traffic.
    both = sorted(serving.intersection(regions))
    if both:
        raise ValueError(
            f"GCP enclave region(s) listed as both serving and pending: {both}"
        )
    return frozenset(regions)


GCP_ENCLAVE_REGIONS = gcp_enclave_regions()
GCP_ENCLAVE_PENDING_REGIONS = gcp_enclave_pending_regions(GCP_ENCLAVE_REGIONS)


def known_enclave_regions() -> frozenset[str]:
    """Regions whose instances are attested and whose regional name is published."""
    return GCP_ENCLAVE_REGIONS | GCP_ENCLAVE_PENDING_REGIONS


def canonical_excluded_regions() -> set[str]:
    """Regions kept out of the canonical answer whatever their health.

    A pending region joins QUILL_EXCLUDE_CANONICAL_REGIONS here, at the one
    place the canonical set is filtered, so it cannot be re-admitted by leaving
    that variable unset. Promotion into the main inventory is the only way in.
    """
    return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS


PROJECT = os.environ.get("QUILL_PROJECT", "quill-cloud-proxy")
DNS_ZONE = os.environ.get("QUILL_DNS_ZONE", "quillrouter-com")
API_HOST = os.environ.get("QUILL_API_HOST", "api.quillrouter.com")
RECORD = API_HOST.rstrip(".") + "."
TTL = int(os.environ.get("QUILL_DNS_TTL", "60"))
# Independent of the enclave/billing rollout. All writers must use the same
# value; unset/0 preserves the existing flat canonical answer.
CANONICAL_GEO = os.environ.get("QUILL_CANONICAL_GEO", "0") == "1"
GEO_HEALTH_CHECK = os.environ.get("QUILL_GEO_HEALTH_CHECK", "").strip()
GCLOUD_ATTEMPTS = int(os.environ.get("QUILL_GCLOUD_ATTEMPTS", "3"))
GCLOUD_TIMEOUT_SECONDS = float(os.environ.get("QUILL_GCLOUD_TIMEOUT_SECONDS", "10"))
ATTESTATION_SAMPLES = int(os.environ.get("QUILL_ATTESTATION_SAMPLES", "1"))
ATTESTATION_TIMEOUT_SECONDS = float(
    os.environ.get("QUILL_ATTESTATION_TIMEOUT_SECONDS", "30")
)
RECONCILE_LOCK_BUCKET = os.environ.get("QUILL_RECONCILE_LOCK_BUCKET", "").strip()
RECONCILE_LOCK_OBJECT = os.environ.get(
    "QUILL_RECONCILE_LOCK_OBJECT",
    "enclave-dns-reconciler/singleflight.json",
).strip()
RECONCILE_LOCK_LEASE_SECONDS = float(
    os.environ.get("QUILL_RECONCILE_LOCK_LEASE_SECONDS", "240")
)
RECONCILE_MIN_INTERVAL_SECONDS = float(
    os.environ.get("QUILL_RECONCILE_MIN_INTERVAL_SECONDS", "90")
)
RECONCILE_FAILURE_COOLDOWN_SECONDS = float(
    os.environ.get("QUILL_RECONCILE_FAILURE_COOLDOWN_SECONDS", "30")
)
_METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)
_STORAGE_API = "https://storage.googleapis.com/storage/v1"
_STORAGE_UPLOAD_API = "https://storage.googleapis.com/upload/storage/v1"


class ReconcileLease(NamedTuple):
    owner: str
    generation: int
    acquired_at: float


def parse_canonical_mirrors(value: str) -> list[tuple[str, str]]:
    """Parse `zone:record` mirrors that must match canonical membership."""
    mirrors: list[tuple[str, str]] = []
    for raw_entry in value.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        zone, separator, record = entry.partition(":")
        zone = zone.strip()
        record = record.strip().rstrip(".") + "."
        if not separator or not zone or record == ".":
            raise ValueError(
                "QUILL_CANONICAL_DNS_MIRRORS entries must be zone:record"
            )
        mirrors.append((zone, record))
    return mirrors


def default_canonical_mirrors(api_host: str) -> str:
    """Keep the canonical and permanent compatibility names symmetric."""
    if api_host == "api.trustedrouter.com":
        return "quillrouter-com:api.quillrouter.com."
    if api_host == "api.quillrouter.com":
        return "trustedrouter-com:api.trustedrouter.com."
    return ""


# api.quillrouter.com is a published permanent compatibility hostname. Every
# attested membership update, including rollout drains, must update it from the
# exact same healthy set as api.trustedrouter.com. The mapping is symmetric so
# either historical reconciler configuration self-heals both names. Regional or
# non-canonical invocations do not gain side effects.
CANONICAL_MIRRORS = parse_canonical_mirrors(
    os.environ.get(
        "QUILL_CANONICAL_DNS_MIRRORS",
        default_canonical_mirrors(API_HOST),
    )
)
TRUST_DIGEST_URL = os.environ.get(
    "QUILL_TRUST_DIGEST_URL",
    "https://trust.trustedrouter.com/accepted-image-digests-gcp.txt",
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
EXCLUDE_CANONICAL_REGIONS = {
    r.strip()
    for r in os.environ.get("QUILL_EXCLUDE_CANONICAL_REGIONS", "").split(",")
    if r.strip()
}
# A newly promoted region can begin life as a cold-region CNAME to the
# canonical API. During that region's first rollout, keep the CNAME in place
# while the canonical rollout drain is set. The deploy workflow performs a
# direct, per-instance attestation + inference canary first, then explicitly
# allows the atomic CNAME -> A promotion while the region remains excluded
# from canonical traffic.
ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS = {
    r.strip()
    for r in os.environ.get(
        "QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS", ""
    ).split(",")
    if r.strip()
}
# A persistent canonical drain is shared by the deploy workflow and scheduled
# Cloud Run reconciler. Without it, a scheduler tick can re-add a region that a
# canary rollout deliberately removed from canonical DNS. The TXT record lives
# in the same managed zone and uses the same DNS-admin permission as A-record
# reconciliation, avoiding another state service in this trust-critical path.
DRAIN_RECORD = os.environ.get(
    "QUILL_DRAIN_RECORD",
    f"_rollout-drain.{API_HOST.rstrip('.')}.",
)
DRAIN_TTL = int(os.environ.get("QUILL_DRAIN_TTL", "30"))
_REGION_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_DRAIN_VERSION = "v2"
_LEGACY_DRAIN_VERSION = "v1"
_DRAIN_ORIGIN_RE = re.compile(r"^(?:operator|rollout:[1-9][0-9]*)$")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _storage_access_token() -> str:
    request = urllib.request.Request(
        _METADATA_TOKEN_URL,
        headers={"Metadata-Flavor": "Google"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read())
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("metadata server returned no storage access token")
    return token


def _storage_request(
    url: str,
    *,
    token: str,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, bytes]:
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _lock_object_url(*, media: bool = False, generation: int | None = None) -> str:
    bucket = urllib.parse.quote(RECONCILE_LOCK_BUCKET, safe="")
    name = urllib.parse.quote(RECONCILE_LOCK_OBJECT, safe="")
    query: dict[str, str] = {}
    if media:
        query["alt"] = "media"
    if generation is not None:
        query["generation"] = str(generation)
    suffix = "?" + urllib.parse.urlencode(query) if query else ""
    return f"{_STORAGE_API}/b/{bucket}/o/{name}{suffix}"


def _read_reconcile_lock(token: str) -> tuple[dict[str, object], int] | None:
    status, raw_metadata = _storage_request(_lock_object_url(), token=token)
    if status == 404:
        return None
    if status != 200:
        raise RuntimeError(f"lock metadata read failed with HTTP {status}")
    metadata = json.loads(raw_metadata)
    generation = int(metadata["generation"])
    status, raw_payload = _storage_request(
        _lock_object_url(media=True, generation=generation),
        token=token,
    )
    if status in {404, 412}:
        return None
    if status != 200:
        raise RuntimeError(f"lock payload read failed with HTTP {status}")
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        raise RuntimeError("reconcile lock payload must be a JSON object")
    owner = payload.get("owner")
    expires_at = payload.get("expires_at")
    if not isinstance(owner, str) or not owner:
        raise RuntimeError("reconcile lock payload has no owner")
    if not isinstance(expires_at, (int, float)):
        raise RuntimeError("reconcile lock payload has no numeric expiry")
    return payload, generation


def _write_reconcile_lock(
    token: str,
    payload: dict[str, object],
    *,
    if_generation_match: int,
) -> int | None:
    bucket = urllib.parse.quote(RECONCILE_LOCK_BUCKET, safe="")
    query = urllib.parse.urlencode(
        {
            "uploadType": "media",
            "name": RECONCILE_LOCK_OBJECT,
            "ifGenerationMatch": str(if_generation_match),
        }
    )
    status, raw = _storage_request(
        f"{_STORAGE_UPLOAD_API}/b/{bucket}/o?{query}",
        token=token,
        method="POST",
        body=json.dumps(payload, sort_keys=True).encode(),
    )
    if status == 412:
        return None
    if status not in {200, 201}:
        raise RuntimeError(f"lock write failed with HTTP {status}")
    metadata = json.loads(raw)
    return int(metadata["generation"])


def _delete_reconcile_lock(token: str, generation: int) -> bool:
    url = _lock_object_url() + "?" + urllib.parse.urlencode(
        {"ifGenerationMatch": str(generation)}
    )
    status, _raw = _storage_request(url, token=token, method="DELETE")
    if status in {404, 412}:
        return False
    if status not in {200, 204}:
        raise RuntimeError(f"stale lock delete failed with HTTP {status}")
    return True


def acquire_reconcile_lease(*, now: float | None = None) -> ReconcileLease | None:
    if not RECONCILE_LOCK_BUCKET:
        return ReconcileLease(owner="lock-disabled", generation=0, acquired_at=0)
    if not RECONCILE_LOCK_OBJECT:
        raise ValueError("QUILL_RECONCILE_LOCK_OBJECT must not be empty")
    if RECONCILE_LOCK_LEASE_SECONDS <= 180:
        raise ValueError("reconcile lock lease must exceed the 180-second job timeout")
    if RECONCILE_MIN_INTERVAL_SECONDS < 0:
        raise ValueError("reconcile minimum interval must not be negative")
    if RECONCILE_FAILURE_COOLDOWN_SECONDS < 0:
        raise ValueError("reconcile failure cooldown must not be negative")

    acquired_at = time.time() if now is None else now
    owner = os.environ.get("CLOUD_RUN_EXECUTION") or (
        f"manual-{os.getpid()}-{uuid.uuid4().hex}"
    )
    token = _storage_access_token()
    for _attempt in range(3):
        current = _read_reconcile_lock(token)
        if current is not None:
            payload, generation = current
            expires_at = float(payload["expires_at"])
            if expires_at > acquired_at:
                log(
                    "reconcile: single-flight skip; "
                    f"owner={payload['owner']} state={payload.get('state', 'unknown')} "
                    f"expires_in={expires_at - acquired_at:.1f}s"
                )
                return None
            if not _delete_reconcile_lock(token, generation):
                continue

        payload = {
            "owner": owner,
            "state": "running",
            "acquired_at": acquired_at,
            "expires_at": acquired_at + RECONCILE_LOCK_LEASE_SECONDS,
        }
        generation = _write_reconcile_lock(
            token,
            payload,
            if_generation_match=0,
        )
        if generation is not None:
            log(f"reconcile: single-flight acquired owner={owner}")
            return ReconcileLease(
                owner=owner,
                generation=generation,
                acquired_at=acquired_at,
            )
    log("reconcile: single-flight contention; another execution won")
    return None


def finish_reconcile_lease(lease: ReconcileLease, *, succeeded: bool) -> None:
    if not RECONCILE_LOCK_BUCKET:
        return
    now = time.time()
    expires_at = (
        max(now, lease.acquired_at + RECONCILE_MIN_INTERVAL_SECONDS)
        if succeeded
        else now + RECONCILE_FAILURE_COOLDOWN_SECONDS
    )
    payload = {
        "owner": lease.owner,
        "state": "cooldown" if succeeded else "failed",
        "acquired_at": lease.acquired_at,
        "completed_at": now,
        "expires_at": expires_at,
    }
    token = _storage_access_token()
    generation = _write_reconcile_lock(
        token,
        payload,
        if_generation_match=lease.generation,
    )
    if generation is None:
        raise RuntimeError("reconcile lease ownership changed before completion")
    log(
        "reconcile: single-flight released into "
        f"{'cooldown' if succeeded else 'failure cooldown'} "
        f"for {max(0.0, expires_at - now):.1f}s"
    )


@contextlib.contextmanager
def reconcile_singleflight() -> Iterator[bool]:
    lease = acquire_reconcile_lease()
    if lease is None:
        yield False
        return
    try:
        yield True
    except BaseException:
        try:
            finish_reconcile_lease(lease, succeeded=False)
        except Exception as exc:
            log(f"reconcile: failed to close failed lease: {exc}")
        raise
    else:
        finish_reconcile_lease(lease, succeeded=True)


def gcloud_json(args: list[str]) -> object:
    """Run a bounded read with retries and preserve the useful error text.

    The reconciler is a fail-closed control loop, but one transient metadata,
    token, or Google API timeout must not discard a complete attestation pass.
    Every attempt is bounded so retries cannot outlive the Cloud Run job.
    """
    if GCLOUD_ATTEMPTS < 1:
        raise ValueError("QUILL_GCLOUD_ATTEMPTS must be positive")
    if GCLOUD_TIMEOUT_SECONDS <= 0:
        raise ValueError("QUILL_GCLOUD_TIMEOUT_SECONDS must be positive")

    command = ["gcloud", *args, "--project", PROJECT, "--format=json"]
    last_error = "unknown gcloud failure"
    for attempt in range(1, GCLOUD_ATTEMPTS + 1):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=GCLOUD_TIMEOUT_SECONDS,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout or "[]")
                except json.JSONDecodeError as exc:
                    last_error = f"invalid JSON: {exc}"
            else:
                last_error = (result.stderr or result.stdout).strip() or (
                    f"exit status {result.returncode}"
                )
        log(
            "reconcile: gcloud read failed "
            f"attempt={attempt}/{GCLOUD_ATTEMPTS} error={last_error[:500]}"
        )
        if attempt < GCLOUD_ATTEMPTS:
            time.sleep(0.5 * (2 ** (attempt - 1)))
    raise RuntimeError(
        f"gcloud {' '.join(args[:3])} failed after {GCLOUD_ATTEMPTS} attempts: "
        f"{last_error}"
    )


def discover_instances() -> list[dict]:
    """RUNNING enclave instances, in a serving or pending region, with an external IP."""
    rows = gcloud_json([
        "compute", "instances", "list",
        "--filter", f"tags.items={ENCLAVE_TAG} AND status=RUNNING",
    ])
    known_regions = known_enclave_regions()
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
        region = zone.rsplit("-", 1)[0]
        if region not in known_regions:
            log(
                f"reconcile: ignoring {r['name']} in non-inventory region "
                f"{region}"
            )
            continue
        if ip:
            fleet.append({"name": r["name"], "zone": zone,
                          "region": region, "ip": ip})
    return fleet


def trust_digests() -> list[str]:
    with urllib.request.urlopen(TRUST_DIGEST_URL, timeout=10) as resp:
        raw = resp.read().decode().strip()
    digests = [value.strip().lower() for value in raw.split(",") if value.strip()]
    if not digests or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", d) for d in digests):
        sys.exit(f"[FAIL] trust digest set looks wrong: {raw!r}")
    return list(dict.fromkeys(digests))


def recent_release_digests() -> list[str]:
    """Recent gcp-release-* image digests in Artifact Registry.

    Accepted IN ADDITION to the live trust digest. A rolling deploy legitimately
    spans two digests at once (old draining, new booting); a failed deploy can
    also publish trust artifacts for an image that never became the fleet's
    serving digest. Gating DNS on only the published trust digest then rejects
    the still-good fleet and blocks the next rollout. Keeping this window short
    preserves a bounded release set while letting operators recover. Best-effort:
    [] (→ trust digest only) if AR can't be read."""
    command = [
        "gcloud", "artifacts", "docker", "images", "list", AR_IMAGE,
        "--include-tags",
        "--filter", "tags~gcp-release",
        "--sort-by=~UPDATE_TIME",
        "--limit", str(ACCEPT_RECENT_RELEASE_DIGESTS),
        "--format=value(version)",
        "--project", PROJECT,
    ]
    for attempt in range(3):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log(
                "reconcile: recent release tag lookup failed "
                f"attempt={attempt + 1}/3 error={type(exc).__name__}"
            )
        else:
            if result.returncode == 0:
                return [
                    line
                    for line in result.stdout.strip().splitlines()
                    if line.startswith("sha256:")
                ]
            log(
                "reconcile: recent release tag lookup failed "
                f"attempt={attempt + 1}/3 exit={result.returncode}"
            )
        if attempt < 2:
            time.sleep(0.5 * (2**attempt))
    return []


def attest(ip: str, digest: str, api_host: str = API_HOST, *, confidential_host: str | None = None) -> bool:
    """True iff the instance at `ip` passes full attestation for `api_host`."""
    try:
        # DNS membership gates on image-digest attestation identity + liveness:
        # a relay cannot forge a Google-signed token carrying an accepted digest
        # and the live cert/fresh nonce. RFC 9266 exporter binding is the
        # client-connect confidentiality proof; requiring it here fails closed
        # against not-yet-upgraded instances before the MIG can roll, recreating
        # the G6 deploy deadlock. Strict binding remains covered by client
        # --samples / --binding-stress and the standalone trust check.
        p = subprocess.run(
            ["uv", "run", "--script", str(VERIFIER),
             "--api-host", api_host, "--connect-ip", ip,
             "--expect-digest", digest, "--samples", str(ATTESTATION_SAMPLES),
             "--no-require-exporter-binding",
             *(["--require-confidential-host", confidential_host] if confidential_host else [])],
            capture_output=True, text=True, timeout=ATTESTATION_TIMEOUT_SECONDS,
        )
        return p.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as e:
        # A probe failure (timeout, or an OSError such as a missing `uv`/verifier
        # or EMFILE under the thread pool) is a LOCALIZED unhealthy, not a crash
        # of the whole reconcile — every other instance must still be evaluated.
        log(f"  [probe-error] {ip}: {type(e).__name__}: {e}")
        return False


def _attest_instances(
    fleet: list[dict],
    digest: str,
) -> list[tuple[dict, bool]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        return list(ex.map(lambda instance: (instance, attest(instance["ip"], digest)), fleet))


def attest_fleet_with_release_fallback(
    fleet: list[dict],
    trusted: list[str],
) -> tuple[list[tuple[dict, bool]], list[str]]:
    """Attest against signed trust first; consult Artifact Registry only on failure."""
    allowed = list(dict.fromkeys(trusted))
    results = _attest_instances(fleet, ",".join(allowed))
    failed_indices = [index for index, (_instance, ok) in enumerate(results) if not ok]
    if not failed_indices:
        return results, allowed

    expanded = list(dict.fromkeys([*allowed, *recent_release_digests()]))
    if expanded == allowed:
        return results, allowed

    failed_instances = [fleet[index] for index in failed_indices]
    retries = _attest_instances(failed_instances, ",".join(expanded))
    for index, (_instance, ok) in zip(failed_indices, retries, strict=True):
        results[index] = (fleet[index], ok)
    return results, expanded


def current_dns_record(
    zone: str,
    record: str,
    record_type: str,
) -> dict | None:
    rows = gcloud_json([
        "dns", "record-sets", "list", "--zone", zone,
        "--name", record, "--type", record_type,
    ])
    for r in rows:
        if r.get("name") == record and r.get("type") == record_type:
            return dict(r)
    return None


def current_dns_ips(zone: str, record: str) -> list[str]:
    row = current_dns_record(zone, record, "A")
    if row is not None:
        return record_ips(row)
    return []


def current_dns_txt(zone: str, record: str) -> list[str]:
    rows = gcloud_json([
        "dns", "record-sets", "list", "--zone", zone,
        "--name", record, "--type", "TXT",
    ])
    for row in rows:
        if row.get("name") == record and row.get("type") == "TXT":
            return list(row.get("rrdatas", []))
    return []


def parse_drain_rrdatas(rrdatas: list[str]) -> dict[str, str]:
    """Decode the single versioned TXT value used for persistent drains.

    Version 1 carried only region names. Treat every such entry as an operator
    drain so upgrading this controller can never re-enable an existing drain.
    """
    if not rrdatas:
        return {}
    if len(rrdatas) != 1:
        raise RuntimeError(
            f"{DRAIN_RECORD} must contain exactly one TXT value, got {len(rrdatas)}"
        )
    payload = rrdatas[0].strip().strip('"')
    parts = payload.split(";")
    if not parts or parts[0] not in {_LEGACY_DRAIN_VERSION, _DRAIN_VERSION}:
        raise RuntimeError(f"{DRAIN_RECORD} has unsupported payload {payload!r}")

    drains: dict[str, str] = {}
    if parts[0] == _LEGACY_DRAIN_VERSION:
        drains = {part: "operator" for part in parts[1:] if part}
    else:
        for entry in parts[1:]:
            if not entry:
                continue
            region, separator, origin = entry.partition("=")
            if not separator or region in drains:
                raise RuntimeError(
                    f"{DRAIN_RECORD} has invalid drain entry {entry!r}"
                )
            drains[region] = origin

    invalid = sorted(region for region in drains if not _REGION_RE.fullmatch(region))
    if invalid:
        raise RuntimeError(f"{DRAIN_RECORD} has invalid region(s): {invalid}")
    invalid_origins = sorted(
        f"{region}={origin}"
        for region, origin in drains.items()
        if not _DRAIN_ORIGIN_RE.fullmatch(origin)
    )
    if invalid_origins:
        raise RuntimeError(
            f"{DRAIN_RECORD} has invalid drain origin(s): {invalid_origins}"
        )
    return drains


def encode_drain_rrdatas(drains: dict[str, str]) -> list[str]:
    invalid = sorted(region for region in drains if not _REGION_RE.fullmatch(region))
    if invalid:
        raise ValueError(f"invalid drain region(s): {invalid}")
    invalid_origins = sorted(
        f"{region}={origin}"
        for region, origin in drains.items()
        if not _DRAIN_ORIGIN_RE.fullmatch(origin)
    )
    if invalid_origins:
        raise ValueError(f"invalid drain origin(s): {invalid_origins}")
    entries = [f"{region}={drains[region]}" for region in sorted(drains)]
    payload = ";".join([_DRAIN_VERSION, *entries])
    return [f'"{payload}"']


def set_dns_txt(zone: str, record: str, rrdatas: list[str]) -> None:
    cur = current_dns_txt(zone, record)

    def _run(verb: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "gcloud", "dns", "record-sets", verb, record,
                "--zone", zone, "--project", PROJECT,
                "--type", "TXT", "--ttl", str(DRAIN_TTL),
                "--rrdatas", ",".join(rrdatas),
            ],
            capture_output=True,
            text=True,
        )

    verb = "update" if cur else "create"
    result = _run(verb)
    if result.returncode != 0:
        result = _run("create" if verb == "update" else "update")
        if result.returncode != 0:
            raise RuntimeError(
                f"set_dns_txt({record}) failed: "
                f"{(result.stderr or result.stdout).strip()}"
            )


def persistent_drains() -> dict[str, str]:
    return parse_drain_rrdatas(current_dns_txt(DNS_ZONE, DRAIN_RECORD))


def persistent_drain_regions() -> set[str]:
    return set(persistent_drains())


class DrainsChangedError(Exception):
    """The persistent drain set changed after this pass read it.

    Deliberately not a RuntimeError: the confidential phase's except clause in
    _main_unlocked treats a RuntimeError as a failed confidential update and
    carries on to the ordinary records. A stale drain snapshot is not that;
    nothing computed from it may be written.
    """


def _describe_drains(drains: dict[str, str]) -> str:
    if not drains:
        return "<none>"
    return ", ".join(f"{region} ({drains[region]})" for region in sorted(drains))


def require_drains_unchanged(snapshot: dict[str, str]) -> None:
    """Re-read the persistent drains and refuse if they differ from `snapshot`.

    A pass reads the drains once and then spends tens of seconds attesting
    (23-40 s between that read and its canonical write in every two-minute
    pass, job logs 2026-09-22). A deploy or the stockout-relief workflow can
    set a drain in that time: their `--set-drain-region` never takes the
    reconcile lease, and this job runs outside the workflows' concurrency
    group, so nothing else keeps the two apart. A pass that wrote the answer
    it had computed from the old snapshot put the drained region's VMs back
    into canonical DNS just after the drain.

    So the drains are re-read immediately before each mutating gcloud call,
    every attempt of it. What is left between a re-read being answered and
    that call's change landing is the rest of the read's round trip plus the
    call itself, which is untimed for an A-record create or update and for a
    transaction's execute (the confidential delete does pass a timeout);
    Cloud DNS has no conditional write to close it. If the
    reading differs from the snapshot, in either direction, the pass writes
    nothing more: it does not know which of its inputs the change invalidated,
    and the next pass, normally the next two-minute tick, reads the new set.
    """
    current = persistent_drains()
    if current != snapshot:
        raise DrainsChangedError(
            "persistent drains changed during this pass: "
            f"{_describe_drains(snapshot)} -> {_describe_drains(current)}"
        )


# The snapshot the current pass computed its membership from, while its
# writes run; None outside a pass (the drain flags, direct callers).
_PINNED_DRAINS: dict[str, str] | None = None


@contextlib.contextmanager
def pinned_drains(snapshot: dict[str, str]) -> Iterator[None]:
    """Make every membership write in this block re-check `snapshot` first."""
    global _PINNED_DRAINS
    _PINNED_DRAINS = dict(snapshot)
    try:
        yield
    finally:
        _PINNED_DRAINS = None


def _check_pinned_drains() -> None:
    if _PINNED_DRAINS is not None:
        require_drains_unchanged(_PINNED_DRAINS)


def update_persistent_drain(
    region: str,
    *,
    enabled: bool,
    origin: str = "operator",
) -> dict[str, str]:
    if not _REGION_RE.fullmatch(region):
        raise ValueError(f"invalid drain region: {region!r}")
    if not _DRAIN_ORIGIN_RE.fullmatch(origin):
        raise ValueError(f"invalid drain origin: {origin!r}")
    drains = persistent_drains()
    if enabled:
        # A rollout must never overwrite an operator's intentional drain.
        # An explicit operator drain, however, takes ownership from a stale
        # rollout entry and remains until an operator clears it.
        if origin == "operator" or drains.get(region) != "operator":
            drains[region] = origin
    else:
        drains.pop(region, None)
    set_dns_txt(DNS_ZONE, DRAIN_RECORD, encode_drain_rrdatas(drains))
    return drains


def replace_cname_with_ips(
    zone: str,
    record: str,
    cname: dict,
    ips: list[str],
) -> None:
    """Atomically replace an existing CNAME with an attested A record."""
    cname_values = [str(value) for value in cname.get("rrdatas", [])]
    cname_ttl = int(cname.get("ttl") or TTL)
    if not cname_values:
        raise RuntimeError(f"CNAME {record} has no rrdatas")

    with tempfile.TemporaryDirectory(prefix="quill-dns-transaction-") as temp_dir:
        transaction_file = str(Path(temp_dir) / "transaction.yaml")

        def _run(args: list[str]) -> None:
            result = subprocess.run(
                [
                    "gcloud", "dns", "record-sets", "transaction", *args,
                    "--zone", zone,
                    "--project", PROJECT,
                    "--transaction-file", transaction_file,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"DNS transaction for {record} failed: "
                    f"{(result.stderr or result.stdout).strip()}"
                )

        _run(["start"])
        _run([
            "remove", *cname_values,
            "--name", record,
            "--type", "CNAME",
            "--ttl", str(cname_ttl),
        ])
        _run([
            "add", *ips,
            "--name", record,
            "--type", "A",
            "--ttl", str(TTL),
        ])
        # The transaction file is local until this call; nothing has changed
        # in the zone yet, so this is the last moment the drains can be checked.
        _check_pinned_drains()
        _run(["execute"])


def set_dns_ips(zone: str, record: str, ips: list[str]) -> None:
    """Atomically set the A record to `ips` (replace; no transaction race).

    `record-sets update` overwrites the record's rrdatas + ttl regardless of the
    current value, so we never read-then-`remove` the old IPs. The old
    transactional path raced: it `remove`d the exact ttl+rrdatas it had read a
    moment earlier, and if the record drifted in between — a concurrent reconcile
    tick, or simply a pre-existing different TTL — the `remove` failed on an exact
    mismatch and aborted the whole reconcile. That is what failed the 2026-06-19
    deploy at the "Reconcile DNS before us-east4 canary" step."""
    # Cloud DNS forbids a CNAME and any other record type at the same name.
    # Cold regional endpoints are CNAMEs, so their first attested deployment
    # must replace CNAME -> A in ONE authoritative transaction. A separate
    # delete/create would introduce an avoidable NXDOMAIN window.
    cname = current_dns_record(zone, record, "CNAME")
    if cname is not None:
        try:
            replace_cname_with_ips(zone, record, cname, ips)
            return
        except RuntimeError:
            # A concurrent reconciler may have completed the promotion. Re-read
            # once; if the CNAME still exists, surface the original failure.
            refreshed = current_dns_record(zone, record, "CNAME")
            if refreshed is not None:
                raise

    cur = current_dns_ips(zone, record)

    def _run(verb: str):
        # Inside the runner, so the retry below is checked as well: it is a
        # second attempt to change the record, seconds later, and the reason it
        # exists — the record changed under us — is exactly when a drain may
        # have been set too.
        _check_pinned_drains()
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


def reconcile_dns_record(
    zone: str,
    record: str,
    healthy_ips: list[str],
    *,
    apply: bool,
    label: str,
    current_ips: list[str] | None = None,
) -> None:
    """Reconcile one canonical or compatibility record to one healthy set."""
    current = sorted(current_dns_ips(zone, record) if current_ips is None else current_ips)
    if current == healthy_ips:
        log(f"reconcile: {label} {record} already correct ({len(healthy_ips)} A)")
        return

    log(f"reconcile: {label} {record} {current} -> {healthy_ips}")
    if apply:
        set_dns_ips(zone, record, healthy_ips)
        log(f"reconcile: APPLIED {label} {record}")
    else:
        log(f"reconcile: DRY-RUN {label} {record} (pass --apply to change DNS)")


def canonical_geo_record(record: str, healthy: list[dict]) -> dict:
    """Group the already attested, drain/exclusion-filtered canonical fleet."""
    by_region: dict[str, set[str]] = {}
    for instance in healthy:
        by_region.setdefault(instance["region"], set()).add(instance["ip"])
    items = [{"location": region, "healthCheckedTargets": {"externalEndpoints": sorted(ips)}}
             for region, ips in sorted(by_region.items()) if ips]
    if not items:
        raise ValueError("refusing to publish an empty GEO policy")
    # Attestation controls admission; native TCP liveness survives a stopped
    # reconciler. Never fence clients into a failed region.
    return {"name": record, "type": "A", "ttl": TTL,
            "routingPolicy": {"healthCheck": GEO_HEALTH_CHECK,
                              "geo": {"enableFencing": False, "items": items}}}


def verify_geo_zones(healthy: list[dict]) -> None:
    """External endpoint checks require public DNS; enforce DNSSEC item limit."""
    counts: dict[str, set[str]] = {}
    for instance in healthy:
        counts.setdefault(instance["region"], set()).add(instance["ip"])
    for zone in sorted({DNS_ZONE} | {zone for zone, _ in CANONICAL_MIRRORS}):
        config = gcloud_json(["dns", "managed-zones", "describe", zone])
        if not isinstance(config, dict) or config.get("visibility") != "public":
            raise ValueError("GEO external health checks require a public managed zone")
        dnssec = config.get("dnssecConfig", {}).get("state")
        if dnssec not in {"off", "on"}:
            raise ValueError("GEO requires a known managed-zone DNSSEC state")
        if dnssec == "on" and any(len(ips) > 1 for ips in counts.values()):
            raise ValueError("DNSSEC allows at most one health-checked IP per GEO item")


def _dns_record_data(value):
    """Strip output-only DNS metadata, preserving the exact old data for CAS."""
    if isinstance(value, dict):
        return {key: _dns_record_data(item) for key, item in value.items()
                if key not in {"kind", "signatureRrdatas"}}
    if isinstance(value, list):
        return [_dns_record_data(item) for item in value]
    return value


def _same_dns_record(current: dict | None, desired: dict) -> bool:
    if current is None:
        return False
    current = _dns_record_data(current)
    if "routingPolicy" in current:
        current.pop("rrdatas", None)  # API may serialize an empty repeated field
        geo = current["routingPolicy"].get("geo")
        if geo is not None:
            geo.setdefault("enableFencing", False)
            for item in geo.get("items", []):
                if "rrdatas" in item:
                    if item["rrdatas"]:
                        item["rrdatas"] = sorted(item["rrdatas"])
                    else:
                        item.pop("rrdatas")
                targets = item.get("healthCheckedTargets")
                if targets and "externalEndpoints" in targets:
                    targets["externalEndpoints"] = sorted(targets["externalEndpoints"])
            geo["items"] = sorted(geo.get("items", []), key=lambda item: item["location"])
    else:
        current["rrdatas"] = sorted(current.get("rrdatas", []))
    return current == desired


def submit_dns_change(zone: str, change: dict) -> None:
    """One atomic Cloud DNS changes.create, authenticated like the CLI reads.

    gcloud's transaction YAML reader (including SDK 575) discards routingPolicy.
    Send the native API shape instead. Never issue a standalone delete. On an
    ambiguous transport failure the next pass re-reads the authoritative set.
    """
    token = subprocess.run(
        ["gcloud", "auth", "print-access-token", "--project", PROJECT],
        check=True, capture_output=True, text=True, timeout=GCLOUD_TIMEOUT_SECONDS,
    ).stdout.strip()
    if not token:
        raise RuntimeError("gcloud returned no DNS access token")
    url = ("https://dns.googleapis.com/dns/v1/projects/"
           + urllib.parse.quote(PROJECT, safe="") + "/managedZones/"
           + urllib.parse.quote(zone, safe="") + "/changes")
    request = urllib.request.Request(
        url, data=json.dumps(change).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    # Token acquisition can take time; check immediately before the mutation.
    _check_pinned_drains()
    with urllib.request.urlopen(request, timeout=GCLOUD_TIMEOUT_SECONDS) as response:
        result = json.load(response)
    if not result.get("id"):
        raise RuntimeError("Cloud DNS returned no change ID; re-read before retrying")


def replace_dns_record(zone: str, desired: dict) -> None:
    """Replace either A shape in one atomic change, with one conflict re-read."""
    if not record_ips(desired):
        raise ValueError("refusing to publish an empty canonical record")
    for attempt in range(2):
        current = current_dns_record(zone, desired["name"], "A")
        if _same_dns_record(current, desired):
            return
        if current is None:
            current = current_dns_record(zone, desired["name"], "CNAME")
        change = {"additions": [desired],
                  "deletions": [_dns_record_data(current)] if current is not None else []}
        _check_pinned_drains()
        try:
            submit_dns_change(zone, change)
            return
        except urllib.error.HTTPError as exc:
            # An exact deletion mismatch/concurrent change is safe: Cloud DNS
            # rejects the ENTIRE change. Re-read once, never delete separately.
            if attempt or exc.code not in {409, 412}:
                raise


def reconcile_canonical_record(
    zone: str, record: str, healthy_ips: list[str], healthy: list[dict],
    *, apply: bool, label: str, force_flat: bool = False,
) -> None:
    current = current_dns_record(zone, record, "A")
    # Also maintain previously degraded flat records on subsequent passes;
    # no persistent marker is needed. Missing records wait for a valid check.
    if force_flat and current is None:
        log(f"reconcile: REFUSED new canonical {record}: GEO health check invalid")
        return
    if not CANONICAL_GEO and not (current and "routingPolicy" in current):
        # Preserve the default flat writer and logs, including its race retry.
        reconcile_dns_record(zone, record, healthy_ips, apply=apply, label=label,
                             current_ips=record_ips(current) if current else [])
        return
    desired = (canonical_geo_record(record, healthy) if CANONICAL_GEO and not force_flat else
               {"name": record, "type": "A", "ttl": TTL, "rrdatas": healthy_ips})
    if _same_dns_record(current, desired):
        log(f"reconcile: {label} {record} already correct")
        return
    log(f"reconcile: {label} {record} -> {json.dumps(desired, sort_keys=True)}")
    if apply:
        replace_dns_record(zone, desired)
        log(f"reconcile: APPLIED {label} {record}")
    else:
        log(f"reconcile: DRY-RUN {label} {record} (pass --apply to change DNS)")


CONFIDENTIAL_HOSTS = tuple(
    f"api.confidential.{domain}.com"
    for domain in ("trustedrouter", "quillrouter", "allyrouter", "uptimerouter")
)


def provision_confidential_challenge_delegation(*, apply: bool) -> None:
    # Bootstrap certificates via DNS-01 BEFORE publishing any API A record.
    # The other two mirror zones are managed by sync-route53-api-aliases.py.
    if API_HOST not in {"api.trustedrouter.com", "api.quillrouter.com"}:
        return
    record = "_acme-challenge.api.confidential.quillrouter.com."
    target = "_acme-challenge.api-confidential-quillrouter.trustedrouter.com."
    current = current_dns_record("quillrouter-com", record, "CNAME")
    if current and current.get("rrdatas") == [target]:
        return
    log(f"reconcile: confidential certificate delegation {record} -> {target}")
    if apply:
        subprocess.run(
            ["gcloud", "dns", "record-sets", "update" if current else "create", record,
             "--zone", "quillrouter-com", "--project", PROJECT, "--type", "CNAME",
             "--ttl", str(TTL), "--rrdatas", target],
            check=True, capture_output=True, text=True, timeout=GCLOUD_TIMEOUT_SECONDS,
        )


def reconcile_confidential(healthy: list[dict], digest: str, *, apply: bool) -> None:
    """Never mirror old attested binaries that lack confidential-host enforcement.

    Rollout drains also apply here. Unlike the general liveness records, an
    empty policy-qualified set removes the record rather than retaining an
    unsafe last-good set. A failed probe cannot relax the privacy guarantee.
    """
    if API_HOST not in {"api.trustedrouter.com", "api.quillrouter.com"}:
        return
    host = CONFIDENTIAL_HOSTS[0]
    checks = [(instance["ip"], name) for instance in healthy for name in CONFIDENTIAL_HOSTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        eligible = list(executor.map(
            lambda check: (check[0], attest(check[0], digest, api_host=check[1], confidential_host=check[1])),
            checks,
        ))
    failed = {ip for ip, ok in eligible if not ok}
    ips = sorted({ip for ip, ok in eligible if ok} - failed)
    for zone, record in (
        ("trustedrouter-com", host + "."),
        ("quillrouter-com", "api.confidential.quillrouter.com."),
    ):
        if ips:
            reconcile_dns_record(zone, record, ips, apply=apply, label="confidential-only")
        elif current_dns_ips(zone, record):
            log(f"reconcile: confidential-only {record} has no qualified instances; removing A record")
            if apply:
                _check_pinned_drains()
                subprocess.run(
                    ["gcloud", "dns", "record-sets", "delete", record, "--zone", zone,
                     "--project", PROJECT, "--type", "A", "--quiet"],
                    check=True, capture_output=True, text=True, timeout=GCLOUD_TIMEOUT_SECONDS,
                )


def regional_host(region: str) -> str:
    return f"api-{region}.{REGIONAL_SUFFIX}".rstrip(".")


def attest_regional_instances(
    healthy: list[dict],
    digest: str,
) -> dict[str, list[str]]:
    """Return region->IP list proven with each region's own SNI.

    Passing canonical attestation is not enough for regional DNS. Fresh
    Confidential Space VMs can become healthy for api.trustedrouter.com before
    their regional autocert path is ready. Publishing them to
    api-<region>.quillrouter.com at that point creates regional-only
    RemoteProtocolError failures during deploys.
    """
    known_regions = known_enclave_regions()
    regional_candidates = [
        (inst, regional_host(inst["region"]))
        for inst in healthy
        if inst["region"] in known_regions
    ]
    if not regional_candidates:
        return {}

    by_region: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(
            ex.map(
                lambda item: (
                    item[0],
                    item[1],
                    attest(item[0]["ip"], digest, item[1]),
                ),
                regional_candidates,
            )
        )
    for inst, host, ok in results:
        mark = "ok " if ok else "FAIL"
        log(
            f"  [regional {mark}] {inst['region']:14s} "
            f"{inst['ip']:15s} {host}"
        )
        if ok:
            by_region.setdefault(inst["region"], []).append(inst["ip"])
    return by_region


def reconcile_regional(
    by_region: dict[str, list[str]],
    apply: bool,
    *,
    drained_regions: set[str] | None = None,
) -> None:
    """Publish api-<gcp-region>.<suffix> A = that region's healthy IPs.

    Region-pinned retry hostnames must resolve only to VMs that whitelist the
    regional SNI (i.e. that region's VMs). Safety floor: never SHRINK a regional
    record below MIN_HEALTHY_REGIONAL (default 1) — a region with 0 healthy IPs,
    or fewer than the floor when it currently has more, is left at last-good
    rather than blanked/shrunk. Growing a record is always allowed."""
    drained = drained_regions or set()
    # A pending region is published here like a serving one: same cold-CNAME
    # hold, same promotion override, same floor. Only canonical DNS differs.
    known_regions = known_enclave_regions()
    ignored_regions = set(by_region) - known_regions
    for region in sorted(ignored_regions):
        log(f"  regional {region}: retired/non-inventory region ignored")
    for region in sorted(set(by_region) & known_regions):
        ips = sorted(set(by_region[region]))
        if not ips:
            continue  # never publish/blank to an empty record
        record = regional_host(region) + "."
        # First-deploy safety: do not turn a cold alias into a live regional
        # endpoint until the deploy workflow has directly attested and invoked
        # every new instance. Existing A records continue normal reconciliation
        # during later rollouts.
        if (
            region in drained
            and region not in ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS
            and current_dns_record(REGIONAL_ZONE, record, "CNAME") is not None
        ):
            log(
                f"  regional {record}: rollout drain holds cold CNAME until "
                "the direct canary passes"
            )
            continue
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


def _main_unlocked() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true",
                   help="(default) print the would-be healthy set; change nothing")
    g.add_argument("--apply", action="store_true", help="reconcile the DNS record")
    g.add_argument(
        "--set-drain-region",
        metavar="REGION",
        help="persistently exclude REGION from canonical DNS",
    )
    g.add_argument(
        "--clear-drain-region",
        metavar="REGION",
        help="remove REGION from the persistent canonical-DNS drain set",
    )
    g.add_argument(
        "--list-drain-regions",
        action="store_true",
        help="print REGION<TAB>ORIGIN for the persistent drain set",
    )
    ap.add_argument(
        "--drain-origin",
        choices=("operator", "rollout"),
        default="operator",
        help="origin for --set-drain-region (default: operator)",
    )
    ap.add_argument(
        "--github-run-id",
        help="GitHub run ID required when --drain-origin=rollout",
    )
    ap.add_argument(
        "--regions-only",
        action="store_true",
        help="with --list-drain-regions, print only region names",
    )
    args = ap.parse_args()

    if args.set_drain_region:
        if args.drain_origin == "rollout":
            if not args.github_run_id or not re.fullmatch(
                r"[1-9][0-9]*", args.github_run_id
            ):
                ap.error(
                    "--drain-origin=rollout requires a numeric --github-run-id"
                )
            origin = f"rollout:{args.github_run_id}"
        else:
            if args.github_run_id:
                ap.error("--github-run-id requires --drain-origin=rollout")
            origin = "operator"
        drains = update_persistent_drain(
            args.set_drain_region,
            enabled=True,
            origin=origin,
        )
        log(
            "persistent canonical drains: "
            + ", ".join(f"{region} ({drains[region]})" for region in sorted(drains))
        )
        return 0
    if args.clear_drain_region:
        if args.drain_origin != "operator" or args.github_run_id:
            ap.error("--drain-origin/--github-run-id require --set-drain-region")
        drains = update_persistent_drain(args.clear_drain_region, enabled=False)
        log(
            "persistent canonical drains: "
            + (
                ", ".join(
                    f"{region} ({drains[region]})" for region in sorted(drains)
                )
                if drains
                else "<none>"
            )
        )
        return 0
    if args.list_drain_regions:
        if args.drain_origin != "operator" or args.github_run_id:
            ap.error("--drain-origin/--github-run-id require --set-drain-region")
        drains = persistent_drains()
        if args.regions_only:
            print("\n".join(sorted(drains)))
        else:
            print(
                "\n".join(
                    f"{region}\t{drains[region]}" for region in sorted(drains)
                )
            )
        return 0
    if args.regions_only:
        ap.error("--regions-only requires --list-drain-regions")
    if args.drain_origin != "operator" or args.github_run_id:
        ap.error("--drain-origin/--github-run-id require --set-drain-region")

    # DNS membership is gated first on the signed trust digest set. Artifact
    # Registry is a recovery-only fallback: consult it only when a live instance
    # fails the signed set, rather than scanning release history every two
    # minutes during steady state.
    confidential_failed = False
    try:
        provision_confidential_challenge_delegation(apply=args.apply)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        confidential_failed = True
        log(f"reconcile: confidential certificate delegation failed: {exc}")
    trusted = trust_digests()
    fleet = discover_instances()
    if not fleet:
        sys.exit("[FAIL] no running enclave instances discovered")

    results, allowed = attest_fleet_with_release_fallback(fleet, trusted)
    digest = ",".join(allowed)
    log(f"reconcile: {len(fleet)} running enclave instances; accepting digest(s) "
        + " + ".join(d[:23] + "…" for d in allowed))

    healthy: list[dict] = []
    by_region: dict[str, list[str]] = {}
    for inst, ok in results:
        mark = "ok " if ok else "FAIL"
        log(f"  [{mark}] {inst['region']:14s} {inst['ip']:15s} {inst['name']}")
        if ok:
            healthy.append(inst)
            by_region.setdefault(inst["region"], []).append(inst["ip"])

    # One snapshot of the drains feeds every write below. The attestation
    # rounds between here and those writes take tens of seconds, and a deploy
    # can set a drain meanwhile, so every write re-reads and compares first
    # (pinned_drains -> _check_pinned_drains); a pass whose snapshot went
    # stale stops there.
    persistent = persistent_drains()
    persistent_excludes = set(persistent)
    canonical_excludes = canonical_excluded_regions() | persistent_excludes
    canonical_healthy = [
        i for i in healthy if i["region"] not in canonical_excludes
    ]
    healthy_ips = sorted({i["ip"] for i in canonical_healthy})
    regions = sorted(by_region)
    log(f"reconcile: {len(healthy_ips)} healthy across {len(regions)} regions {regions}")
    if GCP_ENCLAVE_PENDING_REGIONS:
        log(
            "reconcile: pending regions get regional DNS only, never canonical: "
            + ", ".join(sorted(GCP_ENCLAVE_PENDING_REGIONS))
        )
    if canonical_excludes:
        log(
            "reconcile: excluding from canonical "
            + ", ".join(sorted(canonical_excludes))
        )
    if persistent_excludes:
        log(
            "reconcile: persistent drains "
            + ", ".join(
                f"{region} ({persistent[region]})"
                for region in sorted(persistent)
            )
        )

    try:
        with pinned_drains(persistent):
            try:
                reconcile_confidential(canonical_healthy, digest, apply=args.apply)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                confidential_failed = True
                log(f"reconcile: confidential membership update failed: {exc}")

            if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):
                sys.exit(f"[FAIL] only {len(healthy_ips)} healthy (< MIN_HEALTHY={MIN_HEALTHY}); "
                         "refusing to shrink DNS — leaving last-good record in place")

            geo_degraded = False
            if CANONICAL_GEO:
                try:
                    verify_health_check(GEO_HEALTH_CHECK, PROJECT, gcloud_json)
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                    geo_degraded = True
                    log(f"reconcile: ERROR: GEO health check invalid: {exc}; "
                        "reconciling existing canonical records as flat attested survivors")
            # The filtered survivor set is shared with OFF. Its minimum also
            # applies when degrading to flat; healthy GEO keeps its own floor.
            if geo_degraded and len(healthy_ips) < MIN_HEALTHY:
                sys.exit(f"[FAIL] only {len(healthy_ips)} healthy (< MIN_HEALTHY={MIN_HEALTHY}); "
                         "refusing to shrink DNS — leaving last-good record in place")
            if CANONICAL_GEO and not geo_degraded:
                verify_geo_zones(canonical_healthy)

            reconcile_canonical_record(
                DNS_ZONE,
                RECORD,
                healthy_ips,
                canonical_healthy,
                apply=args.apply,
                label="canonical",
                force_flat=geo_degraded,
            )
            for mirror_zone, mirror_record in CANONICAL_MIRRORS:
                reconcile_canonical_record(
                    mirror_zone,
                    mirror_record,
                    healthy_ips,
                    canonical_healthy,
                    apply=args.apply,
                    label="compatibility mirror",
                    force_flat=geo_degraded,
                )

            if PUBLISH_REGIONAL:
                regional_by_region = attest_regional_instances(healthy, digest)
                reconcile_regional(
                    regional_by_region,
                    args.apply,
                    drained_regions=persistent_excludes,
                )
    except DrainsChangedError as exc:
        log(
            f"reconcile: REFUSED: {exc}. A drain was set or cleared after this "
            "pass read the drain set, so nothing more is written from that "
            "snapshot; the next pass reads the new set."
        )
        # Raised, not returned: main() turns it into exit 1 after the lease
        # has been released through its failure path.
        raise
    # Surface failures to monitoring, but only after ordinary DNS is reconciled.
    return 1 if confidential_failed or geo_degraded else 0


def main() -> int:
    drain_flags = {
        "--set-drain-region",
        "--clear-drain-region",
        "--list-drain-regions",
    }
    if any(arg.split("=", 1)[0] in drain_flags for arg in sys.argv[1:]):
        return _main_unlocked()
    try:
        with reconcile_singleflight() as acquired:
            if not acquired:
                return 0
            return _main_unlocked()
    except DrainsChangedError:
        # The lease was released with succeeded=False on the way out, so the
        # next execution may retry after the failure cooldown, not the
        # success interval.
        return 1


if __name__ == "__main__":
    sys.exit(main())
