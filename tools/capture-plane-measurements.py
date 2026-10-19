#!/usr/bin/env python3
"""Read every serving plane's live measurement; produce the AWS and Azure records.

THIS IS THE MISSING PRODUCER. Before this script, trust-page/pcr0.txt had a
publisher but no producer: the Makefile and the deploy workflow both copied it
to S3, and nothing anywhere wrote it. It carried the same value from the initial
commit onward, matching no running enclave, and no procedure existed to change
that — the AWS runbook does not mention the trust page at all.

PCR0 cannot be known before an instance boots (release-aws-enclave.sh says so in
its own output), so the only source for it is a live attestation. Same for
Azure's hostdata. That makes capture-then-publish the honest shape: measure what
is actually running, write it down, and let CI refuse to publish if the two ever
disagree.

    # inspect what is running without touching the repo
    python3 tools/capture-plane-measurements.py

    # write trust-page/trust/{aws,azure}-release.json and the .txt files
    python3 tools/capture-plane-measurements.py --write --source-commit 1a2b3c4

    # during a bind window, keep the outgoing measurement acceptable
    python3 tools/capture-plane-measurements.py --write --keep-accepted \
        --source-commit 1a2b3c4

    # an Azure-only release: read and write ONLY the Azure files, and name the
    # build each region now runs (Key Vault bundle version, build commit, digest)
    python3 tools/capture-plane-measurements.py --plane azure --write --keep-accepted \
        --source-commit 1a2b3c4 \
        --azure-region quill-enclave-uaenorth=<bundle-version>,<build-commit>,<image-digest>

--plane scopes BOTH reads and writes. `--plane azure` never reads or rewrites the
AWS files and `--plane aws` never touches Azure's; `--plane all` (the default,
which the freshness check relies on to report every plane) writes both records
and stamps the same --source-commit on both, so write with it only when both
planes were released from one commit. An Azure release that ran with `all`
re-asserted the AWS record's commit and, under --keep-accepted, widened the AWS
accepted set with a stale monitor pin — neither of which that release touched.

The Azure record carries per-region provenance (bundle_version,
image_build_commit, image_digest, source_commit) because the regions do not
necessarily run one build: a roll upgrades one region at a time. A region whose
hostdata is unchanged keeps the provenance already published; a region with a
new hostdata needs --azure-region, or its fields record not-configured. While
the regions' builds differ, the top-level source_commit must be the OLDEST build
still serving — quill-router's check_format_ordering.py reads it as the
capability every enclave has, and a newer value would let the control plane
assume a format the lagging region cannot read. The checkable form of that
rule is enforced: the top-level commit must be an ancestor of (or equal to)
every commit any region block names; a newer one is refused, an even older one
is accepted as merely over-conservative.

Both records now carry source_commit, which they did not before: aws-release.json
and azure-release.json had no such key at all, so their running measurements were
unmappable to source. gcp-release.json has always carried one because its producer
is a deploy pipeline that knows the commit it is rolling. Here the producer is a
capture, so the commit is an assertion by the operator rather than a measurement —
see resolve_source_commit for what that does and does not establish.

--source-commit HAS NO DEFAULT and deliberately so. It used to default to HEAD
whenever enclave-go was clean, which is the normal state, and this script runs
against an already-running enclave at an arbitrary later time: a clean tree is
no evidence that HEAD is the released build. Run without it and the record says
`not-configured`, which the downstream deploy gate treats as a refusal. That is
the intended outcome — a true measurement with no provenance still publishes,
and the party that must not proceed on it fails closed on its own.

GCP is REPORTED but never written: its record is produced by the deploy
pipeline, which is the correct producer because it knows which digest it is
rolling to and maintains the accepted set across a bind window. Reporting it here
is what lets the freshness gate check the plane that carries every prompt — until
now the only one with no drift check at all.

Nothing here is billed and no prompt is sent: every endpoint used is an
unauthenticated attestation route.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import cbor2
import aws_fargate_pins

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "trust-page" / "trust"

GCP_ATTESTATION_URL = "https://api.trustedrouter.com/attestation"
GCP_ATTESTATION_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_ATTESTATION_AUDIENCE = "quill-cloud"
AWS_ATTESTATION_URL = "https://api-aws.trustedrouter.com/attestation"
# Azure serves from more than one region and each region runs its OWN CCE
# policy, so hostdata DIFFERS per region. Capturing only one region publishes a
# set that rejects the other, and a verifier routed there reads that as
# tampering. Every SERVING region must be polled.
#
# southeastasia (api-azure-sea) was retired on 2026-08-21 and its resource group
# deleted; australiaeast replaced it. Every configured origin is mandatory so a
# stale hostname or retired region fails capture instead of silently preserving
# obsolete evidence.
AZURE_ATTESTATION_ORIGINS = (
    (
        "https://api-azure.trustedrouter.com/attestation",
        "quill-enclave-uaenorth.uaenorth.azurecontainer.io",
        "https://trquilluaen.uaen.attest.azure.net",
    ),
    (
        "https://api-azure-syd.trustedrouter.com/attestation",
        "quill-enclave-australiaeast.australiaeast.azurecontainer.io",
        "https://trquillsyd.eau.attest.azure.net",
    ),
)
AZURE_ATTESTATION_URLS = tuple(origin[0] for origin in AZURE_ATTESTATION_ORIGINS)
TIMEOUT_SECONDS = 25


class AzureOriginIdentityError(ValueError):
    """A regional origin answered with another region's attestation identity."""


ATTESTED_GATEWAY_REPO = "https://github.com/Lore-Hex/quill-cloud-proxy"
AWS_API_HOSTNAME = "api-aws.trustedrouter.com"
AZURE_API_HOSTNAME = "api-azure.trustedrouter.com"
AWS_ATTESTATION_ROOT = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"

# What a record says when nobody could name the commit. Chosen to match the
# sentinel gcp-release.json already uses for an unset measurement, so a
# consumer has one string to test rather than two.
SOURCE_COMMIT_UNSET = "not-configured"
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")

# How strong the source_commit in a record is. Published in the record itself
# because "which commit" and "how do you know" are different questions, and a
# reader holding only the bytes cannot ask the second one otherwise.
#
#   operator-asserted -- supplied by whoever ran the release and checked only
#                        against this repository's history. NOT reproduced from
#                        the measurement; `reproduce` names the tool that can.
#   none              -- no commit; the record is unmappable to source.
PROVENANCE_ASSERTED = "operator-asserted"
PROVENANCE_NONE = "none"


def _provenance(source_commit: str) -> str:
    return PROVENANCE_NONE if source_commit == SOURCE_COMMIT_UNSET else PROVENANCE_ASSERTED


# Per-region provenance for the Azure record. The regions run their own builds
# during a roll, so these are stated per region. Like source_commit they are
# OPERATOR ASSERTIONS checked against this repository, never measurements:
# hostdata carries no commit, no digest and no bundle version.
AZURE_PROVENANCE_FIELDS = ("bundle_version", "image_build_commit", "image_digest", "source_commit")
_BUNDLE_VERSION_RE = re.compile(r"^[0-9a-f]{32}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _repo_commit(candidate: str, label: str) -> str:
    """The full object id of a commit that exists here and is reachable from HEAD."""
    if not _COMMIT_RE.fullmatch(candidate):
        raise ValueError(f"{label} {candidate!r} is not a git object id")
    full = _git("rev-parse", "--verify", f"{candidate}^{{commit}}")
    if full is None:
        raise ValueError(
            f"{label} {candidate!r} is not a commit in this repository. A sha that resolves "
            "nowhere here names a build nobody can reproduce from this source."
        )
    if _git("merge-base", "--is-ancestor", full, "HEAD") is None:
        raise ValueError(
            f"{label} {candidate!r} is not reachable from HEAD. An enclave release is built from "
            "this history, so a commit outside it is the wrong sha or a tree that never merged."
        )
    return full


def parse_azure_region_provenance(specs: list[str]) -> dict[str, dict[str, str]]:
    """--azure-region GROUP=BUNDLE_VERSION,BUILD_COMMIT,IMAGE_DIGEST, keyed by GROUP.

    GROUP is the container group, i.e. the first label of the region's origin
    hostname (quill-enclave-uaenorth, quill-enclave-australiaeast). Every value
    is validated here, before any plane is read, so a typo fails before a write.
    """
    provenance: dict[str, dict[str, str]] = {}
    configured = {hostname.split(".")[0] for _, hostname, _ in AZURE_ATTESTATION_ORIGINS}
    for spec in specs:
        group, separator, rest = spec.partition("=")
        parts = [part.strip() for part in rest.split(",")]
        if not separator or not group or len(parts) != 3:
            raise ValueError(
                f"--azure-region {spec!r}: expected GROUP=BUNDLE_VERSION,BUILD_COMMIT,IMAGE_DIGEST"
            )
        if group not in configured:
            # Checked here, against the configured origins, so a typo fails on
            # a dry run too — not only once a record is being built.
            raise ValueError(
                f"--azure-region {group}: not a configured Azure region (one of {', '.join(sorted(configured))})"
            )
        bundle, commit, digest = parts
        if not _BUNDLE_VERSION_RE.fullmatch(bundle):
            raise ValueError(
                f"--azure-region {group}: bundle version {bundle!r} is not a 32-hex Key Vault version"
            )
        if not _IMAGE_DIGEST_RE.fullmatch(digest):
            raise ValueError(f"--azure-region {group}: image digest {digest!r} is not sha256:<64 hex>")
        full = _repo_commit(commit, f"--azure-region {group}: build commit")
        if group in provenance:
            raise ValueError(f"--azure-region {group} given twice")
        provenance[group] = {
            "bundle_version": bundle,
            "image_build_commit": full,
            "image_digest": digest,
            "source_commit": full,
        }
    return provenance


def _region_group(region: dict[str, str]) -> str:
    return region["origin_hostname"].split(".")[0]


def _published_regions(path: Path) -> dict[str, dict[str, Any]]:
    """The published record's per-region blocks, keyed by origin hostname."""
    if not path.is_file():
        return {}
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    regions = record.get("regions", []) if isinstance(record, dict) else []
    if not isinstance(regions, list):
        return {}
    return {
        region["origin_hostname"]: region
        for region in regions
        if isinstance(region, dict) and isinstance(region.get("origin_hostname"), str)
    }


def _region_provenance(
    region: dict[str, str],
    explicit: dict[str, dict[str, str]],
    published: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """What this region's block says about its build.

    Explicit wins. Otherwise a region whose hostdata is unchanged since the
    published record keeps what was published: the measurement did not move,
    so the build behind it did not either. A region with a NEW hostdata and no
    --azure-region records the sentinel, loudly — the same choice source_commit
    makes: a true measurement with weak provenance beats an invented value, and
    the party that must not proceed on it fails closed on its own.
    """
    group = _region_group(region)
    if group in explicit:
        return dict(explicit[group])
    previous = published.get(region["origin_hostname"])
    if previous is not None and previous.get("hostdata") == region["hostdata"]:
        # Field by field, never all-or-nothing: a block that names its build
        # commit but not its digest still constrains the record's commit, and
        # dropping the commit because the digest is missing would let a newer
        # top-level commit through check_oldest_build unopposed.
        carried: dict[str, str] = {}

        def known(value: Any) -> bool:
            # The sentinel is "not known", not a value to carry: a block that
            # says not-configured for one commit field but names the other
            # still constrains the record's commit through the one it names.
            return isinstance(value, str) and bool(value) and value != SOURCE_COMMIT_UNSET

        for field in AZURE_PROVENANCE_FIELDS:
            value = previous.get(field)
            if not known(value):
                # A region's source_commit IS its build commit; either stands in
                # for the other when only one was published.
                twin = {"source_commit": "image_build_commit", "image_build_commit": "source_commit"}.get(field)
                value = previous.get(twin) if twin else None
            carried[field] = value if known(value) else SOURCE_COMMIT_UNSET
        missing = [field for field, value in carried.items() if value == SOURCE_COMMIT_UNSET]
        if missing:
            print(
                f"      WARNING {group}: hostdata unchanged, but the published block lacks "
                f"{', '.join(missing)}; carrying what it has and recording not-configured for the "
                f"rest. Pass --azure-region {group}=<bundle>,<commit>,<digest> to complete it.",
                file=sys.stderr,
            )
        return carried
    print(
        f"      WARNING {group} attests hostdata {region['hostdata'][:12]}… that the published "
        f"record carries no provenance for, and no --azure-region {group}=<bundle>,<commit>,<digest> "
        "was given; recording not-configured for its build.",
        file=sys.stderr,
    )
    return {field: SOURCE_COMMIT_UNSET for field in AZURE_PROVENANCE_FIELDS}


def check_oldest_build(source_commit: str, region_commits: list[str]) -> None:
    """The record's one commit must be an ancestor of (or equal to) every region's build.

    quill-router's check_format_ordering.py reads the top-level source_commit
    as the capability EVERY enclave behind this record has. During a roll that
    is the build the lagging region still runs, never the one just deployed: a
    newer value would let the control plane assume a format the old region
    cannot read. What is enforced is ancestry — the checkable form of "the
    oldest build still serving": a commit newer than, or unrelated to, any
    region's build is refused; an even older one passes, over-conservative but
    safe. Refused rather than warned, because the reader is a machine that
    cannot tell.
    """
    known = [commit for commit in region_commits if commit != SOURCE_COMMIT_UNSET]
    if source_commit == SOURCE_COMMIT_UNSET or not known:
        return
    top = _repo_commit(source_commit, "--source-commit")
    for commit in known:
        if top != commit and _git("merge-base", "--is-ancestor", top, commit) is None:
            raise ValueError(
                f"--source-commit {source_commit!r} is newer than, or unrelated to, a region's build "
                f"{commit[:12]}. While the regions run different builds the record's source_commit "
                "must be an ancestor of (or equal to) every region's build commit — in practice the "
                "OLDEST build still serving."
            )


# The serving monitor and API pin consumers are the two Fargate services.
# App Runner tr-eu was retired; never fall back to a deleted legacy surface.
AWS_FARGATE_PIN_SURFACES = aws_fargate_pins.SURFACES


def monitor_pin_verdict(live_pcr0: str, pin_value: str | None, pin_error: str | None) -> tuple[str, str]:
    """Compare required PCR0s with a serving surface's accepted set."""
    if pin_error is not None:
        return ("unknown", "could not read the AWS monitor's PCR0 pin (NOT evidence it matches): " + pin_error)
    if pin_value is None or not pin_value.strip():
        return ("unknown", "AWS monitor has no PCR0 pin set (binding-only mode)")
    try:
        required = aws_fargate_pins.pin_set(live_pcr0)
        accepted = aws_fargate_pins.pin_set(pin_value)
    except ValueError:
        return ("unknown", "missing or malformed AWS PCR0 set")
    if required <= accepted:
        return ("ok", "AWS monitor pin accepts every required PCR0")
    return (
        "mismatch",
        f"pins {pin_value.strip()[:16]}... but requires {live_pcr0[:16]}...; "
        "use --repin-aws-monitor with --keep-accepted during a transition.",
    )


def check_aws_pins(required: str, *, repin: bool, keep: bool) -> str:
    """Preflight both regions before any mutation; return the preserved set."""
    evidence = [aws_fargate_pins.serving_pin(*surface) for surface in AWS_FARGATE_PIN_SURFACES]
    if len({(item["release"], item["digest"]) for item in evidence}) != 1:
        raise ValueError("AWS control-plane regions serve different releases/images")
    pins = aws_fargate_pins.pin_set(required)
    if keep:
        for item in evidence:
            pins |= aws_fargate_pins.pin_set(item["pin"])
    target = ",".join(sorted(pins))
    for surface, item in zip(AWS_FARGATE_PIN_SURFACES, evidence):
        if repin:
            aws_fargate_pins.repin(*surface, target, expected=item)
        state, message = monitor_pin_verdict(
            target, aws_fargate_pins.serving_pin(*surface)["pin"] if repin else item["pin"], None
        )
        print(f"AWS   {surface[2]} {message}")
        if state != "ok":
            raise ValueError(f"{surface[2]} does not accept the required PCR0 set")
    return target


def _git(*args: str) -> str | None:
    """Run git in this repository. None on any failure — never a guess."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(REPO_ROOT), *args],  # noqa: S607 - git from PATH is intended
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def resolve_source_commit(explicit: str | None = None) -> str:
    """The commit whose enclave-go tree built what is running. NO DEFAULT.

    THIS IS AN ASSERTION, NOT A MEASUREMENT. PCR0 and hostdata are
    measurements and neither carries a commit; whoever ran the release is the
    only party that knows which source produced them. What makes the assertion
    checkable afterwards is `reproduce` — tools/verify-pcr0.sh rebuilds PCR0
    from a commit — and what makes it necessary is that a measurement with no
    commit is unmappable to source, so nothing downstream can ask what that
    build ACCEPTS.

    That downstream question is quill-router's scripts/check_format_ordering.py,
    a CI check that refuses any pull request changing the control plane's
    written envelope format set until every enclave's declaration shows the new
    format is readable. It fails closed on a
    missing or not-configured source_commit rather than assuming a superset,
    which is why recording a wrong value here is worse than recording none.

    THIS DEFAULTED TO HEAD AND MUST NOT. The argument for that default was that
    release-aws-enclave.sh refuses to BUILD from a dirty enclave-go, so a clean
    tree means HEAD is the build. The two are not the same moment. That guard
    runs when HEAD IS the build; this script runs against an already-running
    enclave at an arbitrary later time, and a clean enclave-go says nothing
    about whether main has moved since the release. Worse, the flow that most
    often runs this — the freshness check's auto-filed drift issue — fires
    precisely BECAUSE what is published no longer matches what is running, i.e.
    exactly when HEAD is not the released commit. The default therefore
    manufactured, unattended, the "real file at the wrong commit" this
    docstring already called worse than reading nothing.

    So: the commit must be supplied. Absent, the record says `not-configured`
    and the deploy gate fails closed, which is the outcome the whole design
    prefers. Supplied, it is checked against this repository — a real object,
    of type commit, reachable from HEAD — so a typo, a sha from another clone,
    or a commit that was never merged is refused rather than published.

    What none of that establishes is the binding between the commit and the
    MEASUREMENT. Only tools/verify-pcr0.sh can do that, by rebuilding PCR0 from
    the commit on Nitro-capable hardware, and it is not run here. The record
    therefore also carries `source_commit_provenance` naming what this is:
    operator-asserted.
    """
    if not explicit:
        print(
            "      WARNING no --source-commit given, so this record cannot be mapped to source. "
            "Recording not-configured. quill-router's check_format_ordering.py fails closed "
            "against it on any format-changing pull request, by design. "
            "Pass --source-commit <sha of the enclave release>.",
            file=sys.stderr,
        )
        return SOURCE_COMMIT_UNSET

    candidate = explicit.strip()
    if candidate == SOURCE_COMMIT_UNSET:
        return candidate
    if not _COMMIT_RE.fullmatch(candidate):
        raise ValueError(f"--source-commit {candidate!r} is not a git object id")
    kind = _git("cat-file", "-t", f"{candidate}^{{commit}}")
    if kind != "commit":
        raise ValueError(
            f"--source-commit {candidate!r} is not a commit in this repository. A sha that "
            "resolves nowhere here names a build nobody can reproduce from this source."
        )
    if _git("merge-base", "--is-ancestor", candidate, "HEAD") is None:
        raise ValueError(
            f"--source-commit {candidate!r} is not reachable from HEAD. An enclave release is "
            "built from this history; a commit outside it is either the wrong sha or a tree that "
            "was never merged, and either way the record would point auditors at the wrong source."
        )
    return candidate


def _fetch(url: str, *, verify_tls: bool = True) -> bytes:
    context: ssl.SSLContext | None = None
    if not verify_tls:
        # Reserved for attested-cert-only standalone enclaves. What replaces
        # chain validation there is the binding in the attestation's user_data,
        # which this script does not check. Treat such a result as an
        # unauthenticated read; use tools/verify-attestation.py to authenticate
        # the enclave.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch non-HTTPS URL {url!r}")
    request = urllib.request.Request(url, headers={"accept": "*/*"})  # noqa: S310
    with urllib.request.urlopen(  # noqa: S310 - scheme checked above
        request, timeout=TIMEOUT_SECONDS, context=context
    ) as response:
        return response.read()


def _fetch_at_origin(url: str, origin_hostname: str) -> bytes:
    """Fetch ``url`` from one named origin while retaining URL-host TLS SNI.

    The UAE client hostname is Traffic Manager fronted, so a normal fetch may
    reach Sydney during a UAE rollout. The ACI FQDN is stable across container
    recreates; connecting through it while keeping the public API hostname for
    TLS and Host verifies the intended regional origin without pinning an IP.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"refusing to fetch non-HTTPS URL {url!r}")
    if not origin_hostname:
        raise ValueError("Azure attestation origin hostname is empty")

    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port=parsed.port or 443,
        timeout=TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )

    def create_origin_connection(
        address: tuple[str, int], timeout: float, source_address: tuple[str, int] | None
    ) -> socket.socket:
        return socket.create_connection(
            (origin_hostname, address[1]), timeout=timeout, source_address=source_address
        )

    # HTTPSConnection keeps parsed.hostname as the TLS server name and Host
    # header while this hook changes only the TCP destination.
    connection._create_connection = create_origin_connection  # type: ignore[attr-defined]
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request("GET", path, headers={"accept": "*/*", "connection": "close"})
        response = connection.getresponse()
        body = response.read()
        if not 200 <= response.status < 300:
            raise ValueError(
                f"Azure attestation origin {origin_hostname!r} returned HTTP {response.status}"
            )
        return body
    finally:
        connection.close()


def live_aws(*, forward_port: int | None = None) -> dict[str, str]:
    """PCR0 and module id from the running Nitro enclave. Fails closed."""
    raw = (
        _fetch_at_origin(f"https://{AWS_API_HOSTNAME}:{forward_port}/attestation", "127.0.0.1")
        if forward_port else _fetch(AWS_ATTESTATION_URL)
    )
    envelope = cbor2.loads(raw)
    if not isinstance(envelope, list) or len(envelope) != 4:
        raise ValueError("AWS attestation is not a 4-element COSE_Sign1 envelope")
    document = cbor2.loads(envelope[2])
    if not isinstance(document, dict):
        raise ValueError("AWS attestation payload is not a map")
    if document.get("digest") != "SHA384":
        raise ValueError(f"unexpected PCR digest algorithm {document.get('digest')!r}")
    pcrs = document.get("pcrs")
    if not isinstance(pcrs, dict) or 0 not in pcrs:
        raise ValueError("AWS attestation has no PCR0")
    pcr0 = pcrs[0]
    if not isinstance(pcr0, bytes) or len(pcr0) != 48:
        raise ValueError("PCR0 is not 48 bytes; refusing to publish it")
    module_id = document.get("module_id")
    return {
        "pcr0": pcr0.hex(),
        "module_id": module_id if isinstance(module_id, str) else "unknown",
    }


def live_gcp() -> dict[str, str]:
    """Image digest and reference from the running Confidential Space workload.

    Read-only on purpose. gcp-release.json is written by the deploy pipeline,
    which is the right producer for it — the deploy knows which digest it is
    rolling TO, and it maintains the accepted set across a bind window. What was
    missing is not production but comparison: nothing checked the live GCP
    attestation against the published record, so the plane carrying every prompt
    was the only one with no drift check at all.
    """
    # HTTPS uses ordinary DNS for either flat or GEO A records. This observes
    # one selected enclave, not complete fleet membership (discovery does that).
    token = _fetch(GCP_ATTESTATION_URL).decode("ascii").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("GCP attestation is not a three-part JWT")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    if claims.get("iss") != GCP_ATTESTATION_ISSUER:
        raise ValueError(f"unexpected attestation issuer {claims.get('iss')!r}")
    if claims.get("aud") != GCP_ATTESTATION_AUDIENCE:
        raise ValueError(f"unexpected attestation audience {claims.get('aud')!r}")
    container = claims.get("submods", {}).get("container", {})
    digest = container.get("image_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("GCP attestation has no usable container image digest")
    reference = container.get("image_reference")
    return {
        "image_digest": digest,
        "image_reference": reference if isinstance(reference, str) else "unknown",
    }


def _azure_region(
    url: str, *, origin_hostname: str, expected_issuer: str
) -> dict[str, str]:
    """One Azure region's measurement. Fails closed on anything unexpected."""
    token = _fetch_at_origin(url, origin_hostname).decode("ascii").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Azure attestation is not a three-part JWT")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    if claims.get("x-ms-attestation-type") != "sevsnpvm":
        raise ValueError(f"unexpected attestation type {claims.get('x-ms-attestation-type')!r}")
    hostdata = claims.get("x-ms-sevsnpvm-hostdata")
    issuer = claims.get("iss")
    if not isinstance(hostdata, str) or len(hostdata) != 64:
        raise ValueError("Azure attestation has no 32-byte hostdata; refusing to publish")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("Azure attestation has no issuer")
    if issuer != expected_issuer:
        raise AzureOriginIdentityError(
            f"Azure origin {origin_hostname!r} returned issuer {issuer!r}; "
            f"expected {expected_issuer!r}"
        )
    launch = claims.get("x-ms-sevsnpvm-launchmeasurement")
    return {
        "url": url,
        "origin_hostname": origin_hostname,
        "hostdata": hostdata,
        "issuer": issuer,
        "launch_measurement": launch if isinstance(launch, str) else "unknown",
        "compliance": str(claims.get("x-ms-compliance-status", "unknown")),
    }


def live_azure() -> list[dict[str, str]]:
    """Every configured Azure region's measurement, or fail closed."""
    regions: list[dict[str, str]] = []
    errors: list[str] = []
    for url, origin_hostname, expected_issuer in AZURE_ATTESTATION_ORIGINS:
        try:
            regions.append(
                _azure_region(
                    url,
                    origin_hostname=origin_hostname,
                    expected_issuer=expected_issuer,
                )
            )
        except AzureOriginIdentityError:
            # A reachable origin presenting another region's identity is not
            # an outage. It is origin contamination or configuration drift,
            # and preserving old pins must never make that publishable.
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url} via {origin_hostname}: {exc}")
    if errors:
        raise ValueError(
            "not every configured Azure origin answered: " + "; ".join(errors)
        )
    hostdata = {region["hostdata"] for region in regions}
    if len(hostdata) != len(regions):
        raise ValueError(
            "Azure regional capture returned the same hostdata more than once; "
            "refusing to treat duplicate backend evidence as distinct regions"
        )
    return regions


REPO_SLUG = "Lore-Hex/quill-cloud-proxy"
FULCIO_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
REKOR_URL = "https://rekor.sigstore.dev"


def transparency(plane: str, record_filename: str) -> dict[str, Any]:
    """Verification instructions carried inside the record itself.

    A record gets emailed, pasted into a ticket, or read from a cache months
    later. Whoever is holding it then has no page to read, so the bytes have to
    tell them how to catch us out — including the exact identity to pin, since a
    regex over the repo would accept a signature from any workflow here and
    silently discard the per-plane authority the split exists to create.
    """
    identity = (
        f"https://github.com/{REPO_SLUG}/.github/workflows/"
        f"publish-trust-{plane}.yml@refs/heads/main"
    )
    return {
        "certificate_identity": identity,
        "certificate_oidc_issuer": FULCIO_OIDC_ISSUER,
        "transparency_log": REKOR_URL,
        "bundle": f"{record_filename}.bundle",
        "verify": (
            f"cosign verify-blob --bundle {record_filename}.bundle "
            f"--certificate-identity {identity} "
            f"--certificate-oidc-issuer {FULCIO_OIDC_ISSUER} {record_filename}"
        ),
        "newest_check": (
            "The signature proves who wrote this record and when, not that it is "
            "the newest one. Search the transparency log for the identity above; "
            "the log is append-only, so a newer entry cannot be hidden from you. "
            "The bundle carries a Signed Entry Timestamp but no inclusion proof, "
            "so confirming log membership requires querying Rekor."
        ),
        "running_check": (
            "Neither the signature nor the log says this measurement is still what "
            "is RUNNING — an unchanged deployment should carry an old signature, so "
            "age is not drift. Fetch a live attestation from api_base_url and compare "
            "it against the accepted set in this record."
        ),
    }


def _merged(primary: str, existing: list[str], keep: bool) -> list[str]:
    """Accepted set, primary first.

    During a bind window the released key is bound to the outgoing and incoming
    measurement at once, so --keep-accepted preserves what was already published
    instead of narrowing the pin while the old enclave is still serving.
    """
    values = [primary]
    if keep:
        values.extend(v for v in existing if v and v != primary)
    return list(dict.fromkeys(values))


def _existing(path: Path, key: str) -> list[str]:
    if not path.is_file():
        return []
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    values = record.get(key, [])
    return [v for v in values if isinstance(v, str)]


def build_aws_record(
    live: dict[str, str], *, keep: bool, source_commit: str = SOURCE_COMMIT_UNSET
) -> dict[str, Any]:
    accepted = _merged(
        live["pcr0"], _existing(TRUST_DIR / "aws-release.json", "accepted_pcr0s"), keep
    )
    return {
        "platform": "aws-nitro-enclaves",
        "source_repo": ATTESTED_GATEWAY_REPO,
        # gcp-release.json has carried this since its first publish; aws and
        # azure carried NO source_commit key at all, which is what made their
        # running measurements unmappable to source. A verifier could rebuild
        # PCR0 from a commit only by first guessing which commit to try.
        "source_commit": source_commit,
        # What that commit is worth. It is an operator's assertion checked
        # against this repository's history, never a value derived from the
        # measurement: nothing here reproduces PCR0. `reproduce` names the tool
        # that does, and until someone runs it this field says so.
        "source_commit_provenance": _provenance(source_commit),
        "measurement_type": "nitro-pcr0-sha384",
        "pcr0": live["pcr0"],
        "accepted_pcr0s": accepted,
        "release_state": "current" if len(accepted) == 1 else "rolling",
        "observed_module_id": live["module_id"],
        "attestation_format": "cose-sign1-nitro-attestation-document",
        "attestation_root": AWS_ATTESTATION_ROOT,
        "api_base_url": f"https://{AWS_API_HOSTNAME}/v1",
        "tls": {
            "mode": "acme-inside-nitro-enclave",
            "hostname": AWS_API_HOSTNAME,
            "certificate_binding": (
                "user_data[0:32]=SHA-256 of the served certificate (DER), "
                "user_data[64:96]=TLS exporter channel binding"
            ),
        },
        "data_policy": {
            "prompt_output_storage": False,
            "control_plane_prompt_access": False,
            "client_telemetry_content_free": True,
            "client_telemetry_disclosure": "https://trustedrouter.com/docs/telemetry",
        },
        "reproduce": "tools/verify-pcr0.sh",
        "transparency": transparency("aws", "aws-release.json"),
    }


def build_azure_record(
    regions: list[dict[str, str]],
    *,
    keep: bool,
    source_commit: str = SOURCE_COMMIT_UNSET,
    provenance: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Azure record covering EVERY region, because each runs its own CCE policy.

    hostdata is sha256 over the decoded CCE policy and the regions do not share
    one, so this is a genuine set rather than a bind-window artifact: both values
    are correct simultaneously and permanently. Publishing one region's value
    alone tells a verifier routed to the other that the enclave does not match
    its measurement — an accusation of tampering caused entirely by us.

    `provenance` is parse_azure_region_provenance's output: the build each
    region now runs, by container group. Regions it does not name keep their
    published provenance while their hostdata is unchanged (see
    _region_provenance); naming a region that was not captured is refused.
    """
    existing_hostdata = _existing(TRUST_DIR / "azure-release.json", "accepted_hostdata")
    published = _published_regions(TRUST_DIR / "azure-release.json")

    observed_hostdata = [region["hostdata"] for region in regions]
    observed_issuers = [region["issuer"] for region in regions]
    explicit = provenance or {}
    unknown = sorted(set(explicit) - {_region_group(region) for region in regions})
    if unknown:
        raise ValueError(
            "--azure-region names a region this capture did not observe: " + ", ".join(unknown)
        )
    builds = [_region_provenance(region, explicit, published) for region in regions]
    # Both commit fields of every block constrain the record's commit. Explicit
    # --azure-region input writes them equal; a carried block keeps whatever
    # was published, which a hand-edited record can make disagree — and a block
    # that knows only one of them still knows the build.
    check_oldest_build(
        source_commit,
        [build[field] for build in builds for field in ("image_build_commit", "source_commit")],
    )

    accepted = list(dict.fromkeys(observed_hostdata + (existing_hostdata if keep else [])))
    # This is the active serving-region census, not an append-only trust history.
    # Keeping an issuer after its endpoint is retired makes verifiers accept an
    # authority that no published region can present and turns strict coverage
    # checks into permanent false alarms.
    issuers = list(dict.fromkeys(observed_issuers))

    return {
        "platform": "azure-confidential-containers-sev-snp",
        "source_repo": ATTESTED_GATEWAY_REPO,
        # ONE commit for a record that describes TWO regions. Honest while both
        # run the same build, which is the steady state but not the state
        # during a roll; then it must be an ancestor of (or equal to) every
        # build a block names — check_oldest_build enforces exactly that, the
        # checkable form of "the oldest build still serving" — and each
        # region's own build is in its block below. quill-router's ordering
        # gate reads this one value as what every enclave behind the record can
        # read.
        "source_commit": source_commit,
        # See build_aws_record: an assertion checked against this repository,
        # not a value reproduced from the measurement.
        "source_commit_provenance": _provenance(source_commit),
        "measurement_type": "sev-snp-hostdata-sha256",
        # No single scalar is "the" measurement here — which region answers
        # depends on Traffic Manager. The set is the answer.
        "hostdata": observed_hostdata[0],
        "accepted_hostdata": accepted,
        "release_state": "multi-region",
        "regions": [
            {
                "attestation_url": region["url"],
                "origin_hostname": region["origin_hostname"],
                "hostdata": region["hostdata"],
                "attestation_issuer": region["issuer"],
                "launch_measurement": region["launch_measurement"],
                "compliance_status": region["compliance"],
                # The build THIS region runs: Key Vault bundle version, the
                # commit the image was built from, the image digest the CCE
                # policy measured, and the region's source_commit (equal to the
                # build commit when given explicitly; a carried block keeps
                # what was published). Operator-asserted, like the top-level one.
                **build,
            }
            for region, build in zip(regions, builds)
        ],
        "attestation_format": "microsoft-azure-attestation-jwt",
        "attestation_type": "sevsnpvm",
        "attestation_issuers": issuers,
        "api_base_url": f"https://{AZURE_API_HOSTNAME}/v1",
        "tls": {"mode": "acme-inside-confidential-container", "hostname": AZURE_API_HOSTNAME},
        "data_policy": {
            "prompt_output_storage": False,
            "control_plane_prompt_access": False,
            "client_telemetry_content_free": True,
            "client_telemetry_disclosure": "https://trustedrouter.com/docs/telemetry",
        },
        # Said plainly because a uniform green tick across three planes with
        # different evidence strength overstates this one: on AWS the COSE_Sign1
        # chain verifies against a committed root, whereas here Microsoft's
        # attestation service re-attests the SEV-SNP report and a verifier never
        # sees the raw report or the AMD chain.
        "transparency": transparency("azure", "azure-release.json"),
        "evidence_note": (
            "MAA re-attests the SEV-SNP report; verifiers see Microsoft's assertion, "
            "not the raw hardware report or the AMD certificate chain."
        ),
    }


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  wrote {path.relative_to(REPO_ROOT)}")


def _publish(name: str, content: str) -> None:
    """Write one plane file to trust-page/trust/ and, identically, to trust-page/.

    trust-page/trust/<name> is the record path mirrors.json lists. trust-page/
    carries a byte-identical copy of every plane's files, as it always has for
    GCP, so https://trust.trustedrouter.com/<name> answers for all three planes.
    publish-trust-page.yml refuses to publish when a pair differs.
    """
    _write(TRUST_DIR / name, content)
    _write(TRUST_DIR.parent / name, content)


def write_aws_files(record: dict[str, Any]) -> None:
    _publish("aws-release.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
    _publish("pcr0-aws.txt", record["pcr0"] + "\n")
    _publish("accepted-pcr0s-aws.txt", ",".join(record["accepted_pcr0s"]) + "\n")


def write_azure_files(record: dict[str, Any]) -> None:
    _publish("azure-release.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
    _publish("hostdata-azure.txt", record["hostdata"] + "\n")
    _publish("accepted-hostdata-azure.txt", ",".join(record["accepted_hostdata"]) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plane",
        choices=("all", "aws", "azure"),
        default="all",
        help=(
            "which plane to read AND write: aws or azure touches only that plane's files; all "
            "(the default) reports every plane and writes both records with one --source-commit"
        ),
    )
    parser.add_argument("--aws-forward-port", type=int,
                        help="capture one AWS instance through a localhost SSM TCP forward; retains API TLS SNI")
    parser.add_argument("--check-published", action="store_true",
                        help=(
                            "read-only: require the live AWS PCR0 in the local published set and that entire "
                            "set on both Fargate services; for Azure, every live region's hostdata in the "
                            "local published set"
                        ))
    parser.add_argument(
        "--azure-region",
        action="append",
        default=[],
        metavar="GROUP=BUNDLE_VERSION,BUILD_COMMIT,IMAGE_DIGEST",
        help=(
            "the build an Azure region now runs, by container group (quill-enclave-uaenorth, "
            "quill-enclave-australiaeast); repeatable. A region not named keeps its published "
            "provenance while its hostdata is unchanged, else records not-configured."
        ),
    )
    parser.add_argument("--write", action="store_true", help="write the trust-page records")
    parser.add_argument(
        "--keep-accepted",
        action="store_true",
        help="keep already-published measurements in the accepted set (bind window)",
    )
    parser.add_argument(
        "--source-commit",
        default=None,
        help=(
            "commit whose enclave-go tree built the RUNNING enclave. No default: HEAD is not "
            "that commit except by coincidence, and this record is the only thing that maps a "
            "measurement to source. Omit it and the record records not-configured, which the "
            "envelope-format ordering gate treats as a refusal."
        ),
    )
    parser.add_argument(
        "--repin-aws-monitor",
        action="store_true",
        help=(
            "update the two serving Fargate PCR0 pin sets sequentially, preserving all other "
            "task settings and verifying serving health. Requires --plane aws. Use "
            "--keep-accepted during a transition; omit only after every enclave is verified."
        ),
    )
    args = parser.parse_args()
    reads_aws = args.plane in ("all", "aws")
    reads_azure = args.plane in ("all", "azure")
    if args.repin_aws_monitor and args.plane != "aws":
        parser.error("--repin-aws-monitor requires --plane aws")
    if args.aws_forward_port is not None and not reads_aws:
        parser.error("--aws-forward-port reads the AWS plane; use --plane aws or all")
    if args.aws_forward_port is not None and not 1 <= args.aws_forward_port <= 65535:
        parser.error("--aws-forward-port must be between 1 and 65535")
    if args.azure_region and not reads_azure:
        parser.error("--azure-region describes the Azure record; use --plane azure or all")
    if args.check_published and (args.write or args.repin_aws_monitor):
        parser.error("--check-published is read-only")
    try:
        commit = resolve_source_commit(args.source_commit)
        # Validated before any plane is read: a typo here must not cost a
        # capture, and must never reach a write.
        provenance = parse_azure_region_provenance(args.azure_region)
    except ValueError as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 1

    failures = []
    if args.plane == "all":
        try:
            gcp = live_gcp()
            print(f"GCP   digest   {gcp['image_digest']}")
            print(f"      image    {gcp['image_reference']}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"GCP: {exc}")
    aws = None
    if reads_aws:
        try:
            aws = live_aws(forward_port=args.aws_forward_port) if args.aws_forward_port else live_aws()
            print(f"AWS   PCR0     {aws['pcr0']}")
            print(f"      module   {aws['module_id']}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"AWS: {exc}")
            aws = None
    azure = None
    if reads_azure:
        try:
            azure = live_azure()
            for region in azure:
                print(f"Azure hostdata {region['hostdata']}")
                print(f"      issuer   {region['issuer']}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"Azure: {exc}")
    if provenance and not azure:
        # The operator described an Azure build that was not captured. With
        # --plane all that would otherwise go on to write the AWS files and
        # exit 1 — a half-publish nobody asked for. Nothing is written.
        for failure in failures:
            print(f"FAILED {failure}", file=sys.stderr)
        print(
            "REFUSING: --azure-region was given but no Azure measurement was captured; "
            "nothing is written.",
            file=sys.stderr,
        )
        return 1
    if azure and args.check_published:
        # The Azure counterpart of the AWS pin check below: what is RUNNING in
        # every region must already be in what is PUBLISHED locally.
        try:
            published = (TRUST_DIR / "accepted-hostdata-azure.txt").read_text().strip().split(",")
        except OSError:
            published = []
        missing = [region for region in azure if region["hostdata"] not in published]
        if missing:
            failures.append(
                "Azure: live hostdata not in the published accepted set: "
                + ", ".join(f"{_region_group(region)} {region['hostdata'][:12]}" for region in missing)
            )

    aws_record = None
    if aws:
        try:
            aws_record = build_aws_record(aws, keep=args.keep_accepted, source_commit=commit)
            required = ",".join(aws_record["accepted_pcr0s"])
            if args.check_published:
                required = (TRUST_DIR / "accepted-pcr0s-aws.txt").read_text().strip()
                if aws["pcr0"] not in aws_fargate_pins.pin_set(required):
                    raise ValueError("live AWS PCR0 is not in the published accepted set")
            accepted = check_aws_pins(required, repin=args.repin_aws_monitor, keep=args.keep_accepted)
            aws_record["accepted_pcr0s"] = accepted.split(",")
            aws_record["release_state"] = "current" if len(aws_record["accepted_pcr0s"]) == 1 else "rolling"
        except (ValueError, KeyError, TypeError, OSError):
            # Never echo AWS payloads/errors, which can contain secret values.
            failures.append("AWS: serving pin verification failed; no AWS artifacts written")
            aws_record = None

    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    if failures and not (aws or azure):
        return 1
    if args.plane != "all" and failures:
        # A single-plane run has nothing else to fall back on: any failure is
        # the release's failure, and nothing is written.
        return 1

    if not args.write:
        print("\n(dry run — pass --write to update trust-page/trust/)")
        return 1 if failures else 0

    print(f"source commit  {commit}")
    if commit == SOURCE_COMMIT_UNSET:
        # Not fatal. Publishing a TRUE measurement with weak provenance beats
        # publishing nothing — trust-page/pcr0.txt served a value matching no
        # running enclave for months precisely because publishing was easy to
        # skip. The consumer that must not proceed on this is quill-router's
        # format-ordering CI check, and it fails closed there.
        print(
            "      WARNING this record will not support the envelope-format ordering "
            "check; quill-router's check_format_ordering.py fails closed without it.",
            file=sys.stderr,
        )

    azure_record = None
    if azure:
        if len(azure) < len(AZURE_ATTESTATION_URLS) and not args.keep_accepted:
            # Writing now would drop the unreachable region's hostdata from the
            # published set while that region may still be serving traffic.
            print(
                f"REFUSING to write: only {len(azure)} of {len(AZURE_ATTESTATION_URLS)} Azure "
                "regions answered. Narrowing the set on a partial read would de-publish a "
                "measurement that is still live. Re-run when all regions respond, or pass "
                "--keep-accepted to preserve what is already published.",
                file=sys.stderr,
            )
            return 1
        # Built before anything is written so a refused record (a region named
        # that was not captured, a source_commit newer than a region's build)
        # leaves every file, AWS's included, exactly as it was.
        try:
            azure_record = build_azure_record(
                azure, keep=args.keep_accepted, source_commit=commit, provenance=provenance
            )
        except ValueError as exc:
            print(f"REFUSING to write: {exc}", file=sys.stderr)
            return 1

    if aws_record:
        record = aws_record
        write_aws_files(record)
        # trust-page/pcr0.txt is the legacy path, live at
        # https://trust.trustedrouter.com/pcr0.txt and on the S3 mirror. It is
        # the file that served a wrong value for months. Writing it from the
        # same source as the canonical record is the point: two paths that can
        # drift apart is how this broke the first time.
        _write(REPO_ROOT / "trust-page" / "pcr0.txt", record["pcr0"] + "\n")
    if azure_record:
        write_azure_files(azure_record)
        for region in azure_record["regions"]:
            print(
                f"      {_region_group(region)}: build {region['image_build_commit'][:12]} "
                f"bundle {region['bundle_version'][:12]} image {region['image_digest'][:19]}"
            )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
