"""Stage CI-authenticated PCR0 admission without claiming a candidate is serving.

This tool writes only local AWS trust files. Publication, runtime pin widening,
candidate verification, and regional fleet rollout remain distinct gates.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from tools import aws_eif_manifest as manifests
from tools import aws_kms_admission

ROOT = Path(__file__).resolve().parents[1]
TRUST = ROOT / "trust-page" / "trust"
PUBLIC_RECORD = "https://trust.trustedrouter.com/trust/aws-release.json"
PUBLIC_IDENTITY = "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-trust-aws.yml@refs/heads/main"
STRICT_BOOTSTRAP_SOURCE = "c1863c2c154b3aadfc3b1ee4b7be0675e29756f8"


def require_strict_source(source: str) -> None:
    """Historical CI signatures remain valid; they must not enable V1 rollback."""
    if not isinstance(source, str) or re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("strict AWS admission requires a full source commit")
    try:
        for ancestor, descendant in ((STRICT_BOOTSTRAP_SOURCE, source), (source, "HEAD")):
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", ancestor, descendant],
                cwd=ROOT, check=True, capture_output=True, timeout=15,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(
            "AWS source must include the strict-bootstrap cutover and belong to this history; "
            "pre-cutover rollbacks and incomplete Git history are refused"
        ) from exc


def verified_snapshot(manifest: Path, signature: Path, source: str) -> tuple[dict[str, Any], bytes, bytes]:
    raw = manifests._read_bytes(manifest, manifests.MAX_MANIFEST_BYTES)
    bundle = manifests._read_bytes(signature, manifests.MAX_BUNDLE_BYTES)
    with tempfile.TemporaryDirectory(prefix="tr-eif-admission-") as directory:
        path = Path(directory) / "manifest.json"
        sig = Path(directory) / "manifest.json.bundle"
        path.write_bytes(raw)
        sig.write_bytes(bundle)
        record = manifests.verify(path, sig, expected_source=source)
    require_strict_source(record["source_commit"])
    return record, raw, bundle


def validate_current(current: Any) -> dict[str, Any]:
    if not isinstance(current, dict) or current.get("platform") != "aws-nitro-enclaves":
        raise ValueError("missing current AWS release")
    accepted = current.get("accepted_pcr0s")
    if not isinstance(accepted, list) or not 1 <= len(accepted) <= 16:
        raise ValueError("invalid current accepted set")
    if any(not isinstance(p, str) or re.fullmatch(r"[0-9a-f]{96}", p) is None or p == "0" * 96 for p in accepted):
        raise ValueError("invalid accepted measurement")
    if len(set(accepted)) != len(accepted):
        raise ValueError("duplicate accepted measurement")
    if current.get("pcr0") not in accepted:
        raise ValueError("current primary measurement is not accepted")
    source = current.get("source_commit")
    if not isinstance(source, str) or not re.fullmatch(r"[0-9a-f]{7,40}", source):
        raise ValueError("current serving source commit must be known before staging")
    return current


def staged_record(current: dict[str, Any], artifact: dict[str, Any], raw: bytes) -> dict[str, Any]:
    validate_current(current)
    manifests.validate(artifact)
    result = copy.deepcopy(current)
    measurement = artifact["measurements"]["PCR0"]
    if measurement == current["pcr0"]:
        raise ValueError("candidate is already the serving primary; do not manufacture a transition")
    reference = {
        "pcr0": measurement,
        "source_commit": artifact["source_commit"],
        "manifest": f"eif/{artifact['source_commit']}/{artifact['eif_sha256']}/manifest.json",
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "signing_identity": manifests.IDENTITY,
        "observed_serving": False,
    }
    existing = result.get("candidate_eif")
    if existing is not None and existing != reference:
        raise ValueError("another candidate admission is active")
    result["candidate_eif"] = reference
    result["accepted_pcr0s"] = sorted(set(result["accepted_pcr0s"]) | {measurement})
    result["release_state"] = "rolling"
    validate_current(result)
    # In particular, do not advance source_commit: the format-ordering gate
    # treats it as the minimum capabilities of EVERY serving enclave.
    return result


def verify_record(record_path: Path) -> dict[str, Any] | None:
    current = validate_current(json.loads(manifests._read_bytes(record_path, 128 << 10)))
    require_strict_source(current["source_commit"])
    candidate = current.get("candidate_eif")
    if candidate is None:
        return None
    if not isinstance(candidate, dict) or set(candidate) != {
        "pcr0", "source_commit", "manifest", "manifest_sha256", "signing_identity", "observed_serving"
    }:
        raise ValueError("invalid candidate reference")
    path = candidate["manifest"]
    if not isinstance(path, str) or not re.fullmatch(r"eif/[0-9a-f]{40}/[0-9a-f]{64}/manifest\.json", path):
        raise ValueError("invalid candidate artifact path")
    manifest = record_path.parent / path
    artifact, raw, _ = verified_snapshot(manifest, Path(str(manifest) + ".bundle"), candidate["source_commit"])
    expected = staged_record({k: v for k, v in current.items() if k != "candidate_eif"}, artifact, raw)
    if expected["candidate_eif"] != candidate or candidate["pcr0"] not in current["accepted_pcr0s"]:
        raise ValueError("candidate reference does not match signed CI artifact")
    return artifact


def verify_primary_build(record_path: Path) -> dict[str, str]:
    """Bind the primary PCR0 and source to the build workflow, not the release signer."""
    current = validate_current(json.loads(manifests._read_bytes(record_path, 128 << 10)))
    source = current["source_commit"]
    if re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("serving build requires the full source commit")
    directory = record_path.parent / "eif" / source
    for path in sorted(directory.glob("*/manifest.json")):
        if not re.fullmatch(r"[0-9a-f]{64}", path.parent.name):
            continue
        artifact, raw, _ = verified_snapshot(path, Path(str(path) + ".bundle"), source)
        if artifact["eif_sha256"] == path.parent.name and artifact["measurements"]["PCR0"] == current["pcr0"]:
            return {
                "source_commit": source,
                "pcr0": current["pcr0"],
                "manifest": str(path.relative_to(record_path.parent)),
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            }
    raise ValueError("no CI-signed EIF build for the primary PCR0 and claimed source commit")


def prepare(manifest: Path, signature: Path, source: str, *, write: bool, trust: Path = TRUST) -> dict[str, Any]:
    artifact, raw, bundle = verified_snapshot(manifest, signature, source)
    current_path = trust / "aws-release.json"
    current = json.loads(manifests._read_bytes(current_path, 128 << 10))
    require_strict_source(validate_current(current)["source_commit"])
    result = staged_record(current, artifact, raw)
    if not write:
        return result
    # No cloud call is made here. Commit these files through reviewed main;
    # the AWS signer independently re-verifies the CI proof before signing.
    for directory in (trust, trust.parent):
        artifact_path = directory / result["candidate_eif"]["manifest"]
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(raw)
        Path(str(artifact_path) + ".bundle").write_bytes(bundle)
        (directory / "aws-release.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        (directory / "accepted-pcr0s-aws.txt").write_text(",".join(result["accepted_pcr0s"]) + "\n")
    return result


def verify_candidate(manifest: Path, signature: Path, source: str, port: int) -> None:
    artifact, _, _ = verified_snapshot(manifest, signature, source)
    if not 1 <= port <= 65535:
        raise ValueError("invalid local SSM forward port")
    subprocess.run([
        "python3", str(ROOT / "tools" / "verify-attestation.py"),
        "--api-host", "api-aws.trustedrouter.com", "--connect-ip", "127.0.0.1", "--port", str(port),
        "--attested-cert-only", "--expected-pcr0", artifact["measurements"]["PCR0"],
    ], check=True, timeout=90)


def require_published(record: Path) -> dict[str, Any]:
    local = manifests._read_bytes(record, 128 << 10)
    with tempfile.TemporaryDirectory(prefix="tr-eif-public-") as directory:
        path = Path(directory) / "aws-release.json"
        signature = Path(directory) / "aws-release.json.bundle"
        for url, target, limit in ((PUBLIC_RECORD, path, 128 << 10),
                                   (PUBLIC_RECORD + ".bundle", signature, manifests.MAX_BUNDLE_BYTES)):
            with urllib.request.urlopen(url, timeout=20) as response:
                data = response.read(limit + 1)
            if not data or len(data) > limit:
                raise ValueError("public trust response size")
            target.write_bytes(data)
        if path.read_bytes() != local:
            raise ValueError("public trust record has not caught up; do not boot candidate")
        subprocess.run([
            "cosign", "verify-blob", "--bundle", str(signature),
            "--certificate-identity", PUBLIC_IDENTITY,
            "--certificate-oidc-issuer", manifests.ISSUER, str(path),
        ], check=True, timeout=60, stdout=subprocess.DEVNULL)
    return validate_current(json.loads(local))


def widen_runtime() -> None:
    record = TRUST / "aws-release.json"
    if verify_record(record) is None:
        raise ValueError("no CI-authenticated candidate staged")
    current = require_published(record)
    # The existing pin updater preflights both Fargate regions and rolls them
    # sequentially, preserving the old sets and restoring on a failed region.
    subprocess.run(["python3", str(ROOT / "tools" / "cloud-rollout.py"),
                    "assert", "--cloud", "aws"], check=True, timeout=90)
    aws_kms_admission.check_keys(current["accepted_pcr0s"])
    subprocess.run([
        "python3", str(ROOT / "tools" / "capture-plane-measurements.py"),
        "--plane", "aws", "--repin-aws-monitor", "--keep-accepted",
        "--source-commit", current["source_commit"],
    ], check=True, timeout=1800)
    subprocess.run([
        "python3", str(ROOT / "tools" / "capture-plane-measurements.py"),
        "--plane", "aws", "--check-published",
    ], check=True, timeout=120)


def check_ready(manifest: Path, signature: Path, source: str) -> None:
    artifact, _, _ = verified_snapshot(manifest, signature, source)
    record = TRUST / "aws-release.json"
    candidate = verify_record(record)
    checked_current = None
    if candidate is not None:
        if candidate != artifact:
            raise ValueError("requested EIF is not the staged CI-authenticated candidate")
    else:
        # A parent-only roll reuses the completed release, not a new candidate.
        # Require its exact CI identity and a fully narrowed current record.
        current = validate_current(json.loads(manifests._read_bytes(record, 128 << 10)))
        pcr0 = artifact["measurements"]["PCR0"]
        if (current.get("release_state") != "current" or current["pcr0"] != pcr0
                or current["accepted_pcr0s"] != [pcr0]
                or current["source_commit"] != artifact["source_commit"]):
            raise ValueError("requested EIF is not the exact current CI-authenticated release")
        checked_current = current
    current = require_published(record)
    if checked_current is not None and current != checked_current:
        raise ValueError("current release changed during verification")
    subprocess.run(["python3", str(ROOT / "tools" / "cloud-rollout.py"),
                    "assert", "--cloud", "aws"], check=True, timeout=90)
    aws_kms_admission.check_keys(current["accepted_pcr0s"])
    subprocess.run([
        "python3", str(ROOT / "tools" / "capture-plane-measurements.py"),
        "--plane", "aws", "--check-published",
    ], check=True, timeout=120)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("widen-runtime")
    for command in ("prepare", "verify-candidate", "check-ready"):
        sub = commands.add_parser(command)
        sub.add_argument("--manifest", type=Path, required=True)
        sub.add_argument("--signature", type=Path, required=True)
        sub.add_argument("--expected-source", required=True)
        if command == "prepare":
            sub.add_argument("--write", action="store_true")
        elif command == "verify-candidate":
            sub.add_argument("--port", type=int, required=True)
    check = commands.add_parser("verify-record")
    check.add_argument("--record", type=Path, default=TRUST / "aws-release.json")
    primary = commands.add_parser("verify-primary-build")
    primary.add_argument("--record", type=Path, default=TRUST / "aws-release.json")
    args = parser.parse_args()
    if args.command == "widen-runtime":
        widen_runtime()
    elif args.command == "verify-record":
        verify_record(args.record)
    elif args.command == "verify-primary-build":
        print(json.dumps(verify_primary_build(args.record), sort_keys=True))
    elif args.command == "verify-candidate":
        verify_candidate(args.manifest, args.signature, args.expected_source, args.port)
    elif args.command == "check-ready":
        check_ready(args.manifest, args.signature, args.expected_source)
    else:
        result = prepare(args.manifest, args.signature, args.expected_source, write=args.write)
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
