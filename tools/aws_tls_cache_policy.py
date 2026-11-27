"""Render a policy, or read back a pinned TLS-only key pair without mutating AWS."""

import argparse
import json
import re

from tools.aws_kms_admission import aws_json, unique_object

ACCOUNT = "arn:aws:iam::330422590279:"
OPERATOR = ACCOUNT + "user/jperla"
ADMIN = ACCOUNT + "role/quill-enclave-key-admin"
PARENT = ACCOUNT + "role/quill-enclave-role"
PCR = "kms:RecipientAttestation:ImageSha384"
PURPOSE = "kms:EncryptionContext:purpose"
CONTEXT = "trustedrouter.aws-tls-cache.v1"
PAIR = "kms:GenerateDataKeyPairWithoutPlaintext"


def policy(region, phase, image=None):
    if region not in ("eu-west-1", "eu-west-3") or phase not in (
        "locked",
        "seed",
        "serve",
    ):
        raise ValueError("unknown TLS key region or phase")
    if phase == "serve":
        if (
            not isinstance(image, str)
            or not re.fullmatch("[0-9a-f]{96}", image)
            or image == "0" * 96
        ):
            raise ValueError("a non-debug, independently approved PCR0 is required")
    elif image is not None or (phase == "seed" and region != "eu-west-1"):
        raise ValueError(
            "only Dublin may generate the seed, without decrypt permission"
        )

    rows = []

    def add(sid, effect, principal, actions, condition=None):
        row = {
            "Sid": sid,
            "Effect": effect,
            "Principal": principal,
            "Action": actions,
            "Resource": "*",
        }
        if condition:
            row["Condition"] = condition
        rows.append(row)

    add(
        "ManageOnlyThisKey",
        "Allow",
        {"AWS": [OPERATOR, ADMIN]},
        [
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:PutKeyPolicy",
            "kms:ListResourceTags",
            "kms:ListGrants",
        ],
    )
    if phase == "locked" and region == "eu-west-1":
        add(
            "CreateParisReplica",
            "Allow",
            {"AWS": [OPERATOR, ADMIN]},
            "kms:ReplicateKey",
            {"StringEquals": {"kms:ReplicaRegion": "eu-west-3"}},
        )
    add(
        "NoAlternateDataPath",
        "Deny",
        "*",
        [
            "kms:Encrypt",
            "kms:ReEncrypt*",
            "kms:CreateGrant",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:GenerateDataKeyPair",
        ],
    )
    if phase == "seed":
        add(
            "GenerateWrappedPair",
            "Allow",
            {"AWS": OPERATOR},
            PAIR,
            {
                "StringEquals": {PURPOSE: CONTEXT},
                "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": ["purpose"]},
            },
        )
    else:
        add("NoMoreSeeds", "Deny", "*", PAIR)
    if phase != "serve":
        add("NoDecryption", "Deny", "*", "kms:Decrypt")
    else:
        add(
            "OnlyParent",
            "Deny",
            "*",
            "kms:Decrypt",
            {"ArnNotEquals": {"aws:PrincipalArn": PARENT}},
        )
        add("RequireRecipient", "Deny", "*", "kms:Decrypt", {"Null": {PCR: "true"}})
        add(
            "RejectOtherImages",
            "Deny",
            "*",
            "kms:Decrypt",
            {"StringNotEqualsIgnoreCase": {PCR: image}},
        )
        add(
            "RejectOtherPurposes",
            "Deny",
            "*",
            "kms:Decrypt",
            {"StringNotEquals": {PURPOSE: CONTEXT}},
        )
        add(
            "DecryptForMeasuredRecipient",
            "Allow",
            {"AWS": PARENT},
            "kms:Decrypt",
            {
                "StringEqualsIgnoreCase": {PCR: image},
                "StringEquals": {PURPOSE: CONTEXT},
                "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": ["purpose"]},
            },
        )
    return {"Version": "2012-10-17", "Statement": rows}


def _canon(value):
    # AWS may reorder statements/actions or collapse singleton value lists.
    if isinstance(value, dict):
        return {k: _canon(v) for k, v in value.items()}
    if isinstance(value, list):
        items = sorted(
            (_canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True)
        )
        if len(items) == 1 and isinstance(items[0], str):
            return items[0]
        return items
    return value


def verify_keys(key_id, phase, image=None, *, read=aws_json):
    if not re.fullmatch("mrk-[0-9a-f]{32}", key_id):
        raise ValueError("an independently recorded multi-region key ID is required")
    regions = ("eu-west-1", "eu-west-3")
    members = [
        {"Region": r, "Arn": f"arn:aws:kms:{r}:330422590279:key/{key_id}"}
        for r in regions
    ]
    for idx, m in enumerate(members):
        region, arn = m["Region"], m["Arn"]
        expected = policy(
            region, "locked" if idx == 1 and phase == "seed" else phase, image
        )
        meta = read(region, "describe-key", "--key-id", arn).get("KeyMetadata", {})
        if (
            meta.get("Arn") != arn
            or meta.get("KeyId") != key_id
            or meta.get("Enabled") is not True
            or meta.get("MultiRegion") is not True
            or meta.get("KeyState") != "Enabled"
            or meta.get("KeyManager") != "CUSTOMER"
            or meta.get("Origin") != "AWS_KMS"
            or meta.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or meta.get("KeySpec") != "SYMMETRIC_DEFAULT"
            or meta.get("MultiRegionConfiguration")
            != {
                "MultiRegionKeyType": ("PRIMARY", "REPLICA")[idx],
                "PrimaryKey": members[0],
                "ReplicaKeys": members[1:],
            }
        ):
            raise ValueError(f"unexpected TLS key or replica set in {region}")
        raw = read(
            region, "get-key-policy", "--key-id", arn, "--policy-name", "default"
        ).get("Policy")
        if (
            not isinstance(raw, str)
            or len(raw) > 65536
            or _canon(json.loads(raw, object_pairs_hook=unique_object))
            != _canon(expected)
        ):
            raise ValueError(
                f"TLS key policy differs from the reviewed policy in {region}"
            )
        grants = read(region, "list-grants", "--no-paginate", "--key-id", arn)
        if (
            grants.get("Grants") != []
            or grants.get("Truncated") is not False
            or grants.get("NextMarker")
        ):
            raise ValueError(f"TLS key grants are nonempty or incomplete in {region}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    operation = p.add_mutually_exclusive_group(required=True)
    operation.add_argument("--region", help="render policy for this region; no calls")
    operation.add_argument(
        "--verify-key-id",
        help="check both copies of this independently recorded MRK; read-only",
    )
    p.add_argument("--phase", required=True)
    p.add_argument("--pcr0")
    args = p.parse_args()
    if args.verify_key_id:
        verify_keys(args.verify_key_id, args.phase, args.pcr0)
        print("Both regional TLS key policies, membership and empty grants verified.")
    else:
        print(json.dumps(policy(args.region, args.phase, args.pcr0), indent=2))
