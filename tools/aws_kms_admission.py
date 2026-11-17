"""Read-only pre-boot check of both regional recipient-only KMS policies.

Phase 4 enables the committed configuration after approved key provisioning.
No IAM/KMS mutation is performed here; policy widening remains a reviewed
Terraform change. Missing/disabled keys or a mismatched set stop deployment.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

CONFIG = Path(__file__).resolve().parent / "aws-secrets" / "attested-release.json"
REGIONS = {"eu-west-1", "eu-west-3"}


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy/configuration field")
        result[key] = value
    return result


def measurements(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError("invalid KMS admission set")
    if any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{96}", item) is None
           or item == "0" * 96 for item in value) or len(set(value)) != len(value):
        raise ValueError("invalid KMS admission measurement")
    return sorted(value)


def aws_json(region: str, *arguments: str) -> dict[str, Any]:
    response = subprocess.run(
        ["aws", "kms", *arguments, "--region", region, "--output", "json", "--no-cli-pager"],
        check=True, capture_output=True, text=True, timeout=45,
    )
    if len(response.stdout) > 128 << 10:
        raise ValueError("KMS metadata response exceeds limit")
    result = json.loads(response.stdout, object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise TypeError("invalid KMS metadata response")
    return result


def check_policy(policy: str, accepted: list[str]) -> None:
    if not isinstance(policy, str) or len(policy) > 64 << 10:
        raise ValueError("invalid KMS policy response")
    value = json.loads(policy, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or not isinstance(value.get("Statement"), list):
        raise TypeError("invalid KMS policy statements")
    deny = [item for item in value["Statement"] if isinstance(item, dict)
            and item.get("Sid") == "NoUnattestedDecryptEvenViaIAMOrGrant"]
    if len(deny) != 1:
        raise ValueError("recipient-only explicit Deny is missing or ambiguous")
    statement = deny[0]
    try:
        raw_pins = statement["Condition"]["StringNotEqualsIgnoreCase"]["kms:RecipientAttestation:ImageSha384"]
        # KMS normalizes a singleton condition array to its scalar equivalent.
        pins = measurements([raw_pins] if isinstance(raw_pins, str) else raw_pins)
        actions = sorted(statement["Action"])
    except (KeyError, TypeError) as exc:
        raise ValueError("recipient-only explicit Deny is malformed") from exc
    expected = {
        "Sid": "NoUnattestedDecryptEvenViaIAMOrGrant", "Effect": "Deny",
        "Principal": "*", "Action": ["kms:Decrypt", "kms:ReEncrypt*"], "Resource": "*",
        "Condition": {"StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": accepted}},
    }
    statement["Action"] = actions
    statement["Condition"]["StringNotEqualsIgnoreCase"]["kms:RecipientAttestation:ImageSha384"] = pins
    if statement != expected:
        raise ValueError("KMS recipient policy differs from the published admission set")


def configured_keys(config_path: Path = CONFIG) -> dict[str, str]:
    with config_path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("attested key configuration exceeds limit")
    config = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(config, dict) or set(config) != {"schema_version", "required", "key_arns"}:
        raise ValueError("invalid attested key configuration")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1 or type(config["required"]) is not bool:
        raise ValueError("invalid attested key configuration version")
    if not config["required"]:
        if config["key_arns"] != {}:
            raise ValueError("cannot disable a configured attested key gate")
        return {}
    keys = config["key_arns"]
    if not isinstance(keys, dict) or set(keys) != REGIONS:
        raise ValueError("both regional attested keys are required")
    for region, arn in sorted(keys.items()):
        if not isinstance(arn, str) or re.fullmatch(
            rf"arn:aws:kms:{region}:330422590279:key/[a-f0-9]{{8}}-(?:[a-f0-9]{{4}}-){{3}}[a-f0-9]{{12}}", arn,
        ) is None:
            raise ValueError("invalid pinned regional attested key")
    return keys


def check_keys(accepted: list[str], *, config_path: Path = CONFIG) -> None:
    accepted = measurements(accepted)
    keys = configured_keys(config_path)
    for region, arn in sorted(keys.items()):
        metadata = aws_json(region, "describe-key", "--key-id", arn).get("KeyMetadata", {})
        if (metadata.get("Arn") != arn or metadata.get("Enabled") is not True
                or metadata.get("KeyState") != "Enabled" or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
                or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"):
            raise ValueError(f"attested key is not ready in {region}")
        policy = aws_json(region, "get-key-policy", "--key-id", arn, "--policy-name", "default")
        check_policy(policy.get("Policy"), accepted)


def parent_key(region: str, mode: str, *, config_path: Path = CONFIG) -> str:
    if region not in REGIONS or mode not in {"legacy", "dual", "v2-only"}:
        raise ValueError("invalid parent bootstrap mode or region")
    keys = configured_keys(config_path)
    if keys and mode != "v2-only":
        raise ValueError("legacy bootstrap listener is retired; use v2-only")
    if mode == "legacy":
        return ""
    if not keys:
        raise ValueError("attested parent requires the approved pinned regional keys")
    return keys[region]


def require_legacy_provisioning(*, config_path: Path = CONFIG) -> None:
    if configured_keys(config_path):
        raise ValueError("legacy IAM provisioner is retired; use the approved Terraform migration")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("require-legacy-provisioning")
    parent = commands.add_parser("parent-key")
    parent.add_argument("--region", required=True)
    parent.add_argument("--mode", required=True)
    args = parser.parse_args()
    if args.command == "require-legacy-provisioning":
        require_legacy_provisioning()
    else:
        print(parent_key(args.region, args.mode))


if __name__ == "__main__":
    main()
