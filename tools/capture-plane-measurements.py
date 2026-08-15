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
    python3 tools/capture-plane-measurements.py --write

    # during a bind window, keep the outgoing measurement acceptable
    python3 tools/capture-plane-measurements.py --write --keep-accepted

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
import json
import ssl
import sys
import urllib.request
from pathlib import Path
from typing import Any

import cbor2

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "trust-page" / "trust"

GCP_ATTESTATION_URL = "https://api.trustedrouter.com/attestation"
GCP_ATTESTATION_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_ATTESTATION_AUDIENCE = "quill-cloud"
AWS_ATTESTATION_URL = "https://api-aws.trustedrouter.com/attestation"
AZURE_ATTESTATION_URL = "https://api-azure.trustedrouter.com/attestation"
TIMEOUT_SECONDS = 25

ATTESTED_GATEWAY_REPO = "https://github.com/Lore-Hex/quill-cloud-proxy"
AWS_API_HOSTNAME = "api-aws.trustedrouter.com"
AZURE_API_HOSTNAME = "api-azure.trustedrouter.com"
AWS_ATTESTATION_ROOT = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"


def _fetch(url: str, *, verify_tls: bool = True) -> bytes:
    context: ssl.SSLContext | None = None
    if not verify_tls:
        # The AWS enclave serves a certificate it generated itself — that is the
        # design, not a defect, and there is no chain to validate. What replaces
        # chain validation is the binding in the attestation's user_data, which
        # this script does not check. So treat the result as an unauthenticated
        # read: sufficient to record what is running, NOT sufficient to
        # authenticate the enclave. Use tools/verify-attestation.py for that.
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


def live_aws() -> dict[str, str]:
    """PCR0 and module id from the running Nitro enclave. Fails closed."""
    envelope = cbor2.loads(_fetch(AWS_ATTESTATION_URL, verify_tls=False))
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


def live_azure() -> dict[str, str]:
    """hostdata, launch measurement and MAA issuer from the running container."""
    token = _fetch(AZURE_ATTESTATION_URL).decode("ascii").strip()
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
    launch = claims.get("x-ms-sevsnpvm-launchmeasurement")
    return {
        "hostdata": hostdata,
        "issuer": issuer,
        "launch_measurement": launch if isinstance(launch, str) else "unknown",
        "compliance": str(claims.get("x-ms-compliance-status", "unknown")),
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


def build_aws_record(live: dict[str, str], *, keep: bool) -> dict[str, Any]:
    accepted = _merged(
        live["pcr0"], _existing(TRUST_DIR / "aws-release.json", "accepted_pcr0s"), keep
    )
    return {
        "platform": "aws-nitro-enclaves",
        "source_repo": ATTESTED_GATEWAY_REPO,
        "measurement_type": "nitro-pcr0-sha384",
        "pcr0": live["pcr0"],
        "accepted_pcr0s": accepted,
        "release_state": "current" if len(accepted) == 1 else "rolling",
        "observed_module_id": live["module_id"],
        "attestation_format": "cose-sign1-nitro-attestation-document",
        "attestation_root": AWS_ATTESTATION_ROOT,
        "api_base_url": f"https://{AWS_API_HOSTNAME}/v1",
        "tls": {
            "mode": "attested-self-signed-inside-enclave",
            "hostname": AWS_API_HOSTNAME,
            "certificate_binding": (
                "user_data[0:64]=certificate fingerprint, "
                "user_data[64:96]=TLS exporter channel binding"
            ),
        },
        "data_policy": {"prompt_output_storage": False, "control_plane_prompt_access": False},
        "reproduce": "tools/verify-pcr0.sh",
    }


def build_azure_record(live: dict[str, str], *, keep: bool) -> dict[str, Any]:
    accepted = _merged(
        live["hostdata"],
        _existing(TRUST_DIR / "azure-release.json", "accepted_hostdata"),
        keep,
    )
    issuers = _merged(
        live["issuer"], _existing(TRUST_DIR / "azure-release.json", "attestation_issuers"), True
    )
    return {
        "platform": "azure-confidential-containers-sev-snp",
        "source_repo": ATTESTED_GATEWAY_REPO,
        "measurement_type": "sev-snp-hostdata-sha256",
        "hostdata": live["hostdata"],
        "accepted_hostdata": accepted,
        "release_state": "current" if len(accepted) == 1 else "rolling",
        "observed_launch_measurement": live["launch_measurement"],
        "observed_compliance_status": live["compliance"],
        "attestation_format": "microsoft-azure-attestation-jwt",
        "attestation_type": "sevsnpvm",
        # Each serving region runs its own MAA instance, so issuers accumulate
        # rather than being replaced by whichever region answered this time.
        "attestation_issuers": issuers,
        "api_base_url": f"https://{AZURE_API_HOSTNAME}/v1",
        "tls": {"mode": "acme-inside-confidential-container", "hostname": AZURE_API_HOSTNAME},
        "data_policy": {"prompt_output_storage": False, "control_plane_prompt_access": False},
    }


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  wrote {path.relative_to(REPO_ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the trust-page records")
    parser.add_argument(
        "--keep-accepted",
        action="store_true",
        help="keep already-published measurements in the accepted set (bind window)",
    )
    args = parser.parse_args()

    failures = []
    try:
        gcp = live_gcp()
        print(f"GCP   digest   {gcp['image_digest']}")
        print(f"      image    {gcp['image_reference']}")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"GCP: {exc}")
    try:
        aws = live_aws()
        print(f"AWS   PCR0     {aws['pcr0']}")
        print(f"      module   {aws['module_id']}")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"AWS: {exc}")
        aws = None
    try:
        azure = live_azure()
        print(f"Azure hostdata {azure['hostdata']}")
        print(f"      issuer   {azure['issuer']}")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"Azure: {exc}")
        azure = None

    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    if failures and not (aws or azure):
        return 1

    if not args.write:
        print("\n(dry run — pass --write to update trust-page/trust/)")
        return 1 if failures else 0

    if aws:
        record = build_aws_record(aws, keep=args.keep_accepted)
        _write(TRUST_DIR / "aws-release.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
        _write(TRUST_DIR / "pcr0-aws.txt", record["pcr0"] + "\n")
        _write(TRUST_DIR / "accepted-pcr0s-aws.txt", ",".join(record["accepted_pcr0s"]) + "\n")
        # trust-page/pcr0.txt is the legacy path, live at
        # https://trust.trustedrouter.com/pcr0.txt and copied to S3 by both the
        # Makefile and deploy.yml. It is the file that served a wrong value for
        # months. Writing it from the same source as the canonical record is the
        # point: two paths that can drift apart is how this broke the first time.
        _write(REPO_ROOT / "trust-page" / "pcr0.txt", record["pcr0"] + "\n")
    if azure:
        record = build_azure_record(azure, keep=args.keep_accepted)
        _write(
            TRUST_DIR / "azure-release.json", json.dumps(record, indent=2, sort_keys=True) + "\n"
        )
        _write(TRUST_DIR / "hostdata-azure.txt", record["hostdata"] + "\n")
        _write(
            TRUST_DIR / "accepted-hostdata-azure.txt",
            ",".join(record["accepted_hostdata"]) + "\n",
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
