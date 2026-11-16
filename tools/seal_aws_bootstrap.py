# /// script
# requires-python = ">=3.11"
# dependencies = ["boto3==1.43.117", "cryptography==50.0.2"]
# ///
"""Off-host, explicit operator publication of one regional sealed bootstrap.

The input is the COMPLETE BootstrapData JSON, not a partial key update. No
plaintext is printed, copied into Terraform state, or sent to a gateway host.
Dry run validates local input without contacting AWS. --apply requires the
operator identity, the AWS rollout fence, and a separately approved write.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import aws_bootstrap_payload
from tools import aws_sealed_bundle as sealing

SECRET_ID = "quill/attested-bootstrap-v2"
OPERATOR = "arn:aws:iam::330422590279:user/jperla"


def read_private(path: Path, maximum: int = sealing.MAX_PLAINTEXT) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("bootstrap input must be an owner-only regular file")
        data = stream.read(maximum + 1)
    if not 0 < len(data) <= maximum:
        raise ValueError("bootstrap input exceeds bundle limit")
    return data


def validate_payload(data: bytes, region: str) -> dict[str, Any]:
    payload = json.loads(data, object_pairs_hook=sealing.unique_object,
                         parse_constant=sealing.reject_constant)
    if not isinstance(payload, dict) or payload.get("region") != region:
        raise ValueError("bootstrap region must match the sealing region")
    if payload.get("trustedrouter_base_url") != "https://trustedrouter.com":
        raise ValueError("bootstrap must use the reviewed billing authority")
    if not isinstance(payload.get("trustedrouter_internal_token"), str) or not payload["trustedrouter_internal_token"].strip():
        raise ValueError("complete bootstrap must contain the internal gateway credential")
    if not isinstance(payload.get("devices"), list):
        raise TypeError("complete bootstrap must contain the devices array")
    # The current measured AWS release uses the GCS ACME cache. Omitting this
    # credential would produce a validly signed bundle that cannot serve TLS.
    service_account = payload.get("gcp_service_account_key_json")
    if not isinstance(service_account, str):
        raise TypeError("complete ACME bootstrap must contain its service account")
    account = json.loads(service_account, object_pairs_hook=sealing.unique_object)
    if not isinstance(account, dict) or account.get("type") != "service_account" or not account.get("private_key"):
        raise ValueError("invalid ACME service account")
    return payload


def publish(
    data: bytes, *, region: str, version: int, key_arn: str, signer_arn: str,
    signer_public_der: bytes, identity: Any, secrets: Any, kms: Any, signer_kms: Any,
) -> dict[str, object]:
    validate_payload(data, region)
    sealing.encryption_context({"region": region, "version": version})
    caller = identity.get_caller_identity()
    if caller.get("Account") != "330422590279" or caller.get("Arn") != OPERATOR:
        raise ValueError("only the named off-host seal operator may publish")
    metadata = secrets.describe_secret(SecretId=SECRET_ID)
    if metadata.get("ReplicationStatus") or metadata.get("PrimaryRegion"):
        raise ValueError("sealed bundles must be independently sealed in each region, never replicated")
    expected = rf"arn:aws:secretsmanager:{region}:330422590279:secret:quill/attested-bootstrap-v2-[A-Za-z0-9]{{6}}"
    if not isinstance(metadata.get("ARN"), str) or re.fullmatch(expected, metadata["ARN"]) is None:
        raise ValueError("unexpected bundle secret")
    if metadata.get("DeletedDate") is not None:
        raise ValueError("bundle secret is scheduled for deletion")
    versions = metadata.get("VersionIdsToStages", {})
    if not isinstance(versions, dict):
        raise TypeError("invalid secret version inventory")
    current = [vid for vid, stages in versions.items() if "AWSCURRENT" in stages]
    if len(current) > 1:
        raise ValueError("ambiguous current bundle version")
    if any("AWSPENDING" in stages and vid not in current for vid, stages in versions.items()):
        raise ValueError("unfinished pending publication requires explicit recovery")
    if current:
        response = secrets.get_secret_value(SecretId=SECRET_ID, VersionId=current[0])
        raw = response.get("SecretString")
        if not isinstance(raw, str) or len(raw.encode()) > sealing.MAX_BUNDLE:
            raise ValueError("current bundle is invalid")
        previous = json.loads(raw, object_pairs_hook=sealing.unique_object)
        previous_version = previous.get("manifest", {}).get("version") if isinstance(previous, dict) else None
        if type(previous_version) is not int or previous_version >= version:
            raise ValueError("bundle version must increase; inspect any partially completed prior publication")
    encrypted = sealing.seal(
        data, region=region, version=version, key_arn=key_arn, signer_arn=signer_arn,
        signer_public_der=signer_public_der, kms=kms, signer_kms=signer_kms,
    )
    # A version number may be published only once, even after an interrupted
    # response. Re-sealing would produce different bytes and AWS must reject it.
    token = hashlib.sha256(f"{sealing.DOMAIN.hex()}:{region}:{version}".encode()).hexdigest()
    result = secrets.put_secret_value(
        SecretId=SECRET_ID, ClientRequestToken=token,
        SecretString=encrypted.decode(), VersionStages=["AWSPENDING"],
    )
    if result.get("VersionId") != token:
        raise ValueError("unexpected published version identifier")
    stored = secrets.get_secret_value(SecretId=SECRET_ID, VersionId=token)
    if stored.get("SecretString") != encrypted.decode():
        raise ValueError("published bundle readback mismatch")
    promote = {"SecretId": SECRET_ID, "VersionStage": "AWSCURRENT", "MoveToVersionId": token}
    if current:
        promote["RemoveFromVersionId"] = current[0]
    # Secrets Manager rejects the move if AWSCURRENT is no longer attached to
    # the observed predecessor (or if a first publisher raced the empty case).
    secrets.update_secret_version_stage(**promote)
    final = secrets.describe_secret(SecretId=SECRET_ID).get("VersionIdsToStages", {})
    if "AWSCURRENT" not in final.get(token, []):
        raise ValueError("bundle promotion could not be confirmed")
    return {"region": region, "bundle_version": version, "secret_version_id": token,
            "ciphertext_bytes": len(encrypted), "bundle_sha256": hashlib.sha256(encrypted).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bootstrap-file", type=Path)
    source.add_argument("--values", type=Path, help="complete local logical-secret values; no cloud reads")
    parser.add_argument("--service-account-file", type=Path, help="unwrapped local ACME key; required with --values")
    parser.add_argument("--omit", action="append", default=[], help="explicitly reviewed inactive logical secret")
    parser.add_argument("--region", choices=sorted(sealing.REGIONS), required=True)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--key-arn", required=True)
    parser.add_argument("--signer-arn", required=True)
    parser.add_argument("--signer-public-key", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.environ.get("AWS_REPLICA_REGIONS"):
        raise ValueError("set AWS_REPLICA_REGIONS to the empty string for sealed bundles")
    if args.values:
        if args.service_account_file is None:
            raise ValueError("--values requires --service-account-file")
        values = json.loads(read_private(args.values, 256 << 10), object_pairs_hook=sealing.unique_object,
                            parse_constant=sealing.reject_constant)
        payload = aws_bootstrap_payload.build(
            values, region=args.region, service_account=read_private(args.service_account_file).decode(),
            omitted=args.omit,
        )
        data = sealing.canonical(payload)
    else:
        if args.omit or args.service_account_file:
            raise ValueError("source-builder options require --values")
        data = read_private(args.bootstrap_file)
    if len(data) > sealing.MAX_PLAINTEXT:
        raise ValueError("complete bootstrap exceeds bundle limit")
    validate_payload(data, args.region)
    with args.signer_public_key.open("rb") as stream:
        public = stream.read(257)
    if not public or len(public) > 256:
        raise ValueError("expected a pinned DER P-384 public key")
    key = sealing.serialization.load_der_public_key(public)
    if not isinstance(key, sealing.ec.EllipticCurvePublicKey) or not isinstance(key.curve, sealing.ec.SECP384R1):
        raise TypeError("expected a pinned DER P-384 public key")
    sealing.encryption_context({"region": args.region, "version": args.version})
    if not args.apply:
        print(json.dumps({"dry_run": True, "region": args.region, "bundle_version": args.version}))
        return 0
    subprocess.run(["python3", str(ROOT / "tools/cloud-rollout.py"), "assert", "--cloud", "aws"],
                   check=True, timeout=90)
    import boto3
    from botocore.config import Config

    config = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1})
    result = publish(
        data, region=args.region, version=args.version, key_arn=args.key_arn,
        signer_arn=args.signer_arn, signer_public_der=public,
        identity=boto3.client("sts", region_name=args.region, config=config),
        secrets=boto3.client("secretsmanager", region_name=args.region, config=config),
        kms=boto3.client("kms", region_name=args.region, config=config),
        signer_kms=boto3.client("kms", region_name="eu-west-1", config=config),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - redact secret-bearing SDK/JSON errors at CLI boundary
        # AWS/JSON errors may echo secret-bearing input. Only the type is safe.
        print(f"Sealed publication failed ({type(exc).__name__}); no plaintext logged.", file=sys.stderr)
        raise SystemExit(1) from None
