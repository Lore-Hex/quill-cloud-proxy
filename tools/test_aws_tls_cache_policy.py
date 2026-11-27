import json
import unittest
from fnmatch import fnmatchcase

from tools import aws_tls_cache_policy as tls


class PolicyTest(unittest.TestCase):
    image = "a3" * 48

    def rows(self, region, phase):
        return tls.policy(region, phase, self.image if phase == "serve" else None)[
            "Statement"
        ]

    def test_no_unattested_decryption_during_bootstrap(self):
        for region, phase in (
            ("eu-west-1", "locked"),
            ("eu-west-3", "locked"),
            ("eu-west-1", "seed"),
        ):
            rows = self.rows(region, phase)
            self.assertIn(
                {
                    "Sid": "NoDecryption",
                    "Effect": "Deny",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Principal": "*",
                },
                rows,
            )
            self.assertFalse(
                any(
                    r["Effect"] == "Allow" and r["Action"] == "kms:Decrypt"
                    for r in rows
                )
            )
            seeds = [
                r for r in rows if r["Action"] == tls.PAIR and r["Effect"] == "Allow"
            ]
            self.assertEqual(len(seeds), int(phase == "seed"))
            if seeds:
                self.assertEqual(seeds[0]["Principal"], {"AWS": tls.OPERATOR})
                self.assertEqual(
                    seeds[0]["Condition"]["StringEquals"], {tls.PURPOSE: tls.CONTEXT}
                )
            replicas = [r for r in rows if r["Action"] == "kms:ReplicateKey"]
            self.assertEqual(
                len(replicas), int(phase == "locked" and region == "eu-west-1")
            )
            if replicas:
                self.assertEqual(
                    replicas[0]["Condition"],
                    {"StringEquals": {"kms:ReplicaRegion": "eu-west-3"}},
                )

    def test_serving_key_only_releases_to_the_exact_recipient(self):
        for region in ("eu-west-1", "eu-west-3"):
            by_id = {r["Sid"]: r for r in self.rows(region, "serve")}
            self.assertEqual(
                by_id["OnlyParent"]["Condition"],
                {"ArnNotEquals": {"aws:PrincipalArn": tls.PARENT}},
            )
            self.assertEqual(
                by_id["RequireRecipient"]["Condition"], {"Null": {tls.PCR: "true"}}
            )
            self.assertEqual(
                by_id["RejectOtherImages"]["Condition"],
                {"StringNotEqualsIgnoreCase": {tls.PCR: self.image}},
            )
            self.assertEqual(
                by_id["RejectOtherPurposes"]["Condition"],
                {"StringNotEquals": {tls.PURPOSE: tls.CONTEXT}},
            )
            for sid in (
                "OnlyParent",
                "RequireRecipient",
                "RejectOtherImages",
                "RejectOtherPurposes",
            ):
                self.assertEqual(
                    [by_id[sid][k] for k in ("Principal", "Effect", "Action")],
                    ["*", "Deny", "kms:Decrypt"],
                )
            allow = by_id["DecryptForMeasuredRecipient"]
            self.assertEqual(
                [allow[k] for k in ("Principal", "Effect", "Action")],
                [{"AWS": tls.PARENT}, "Allow", "kms:Decrypt"],
            )
            self.assertEqual(
                allow["Condition"],
                {
                    "StringEqualsIgnoreCase": {tls.PCR: self.image},
                    "StringEquals": {tls.PURPOSE: tls.CONTEXT},
                    "ForAllValues:StringEquals": {
                        "kms:EncryptionContextKeys": ["purpose"]
                    },
                },
            )
            self.assertEqual(by_id["NoMoreSeeds"]["Effect"], "Deny")
            self.assertEqual(
                set(by_id["ManageOnlyThisKey"]["Action"]),
                {
                    "kms:PutKeyPolicy",
                    "kms:GetKeyPolicy",
                    "kms:DescribeKey",
                    "kms:ListResourceTags",
                    "kms:ListGrants",
                },
            )

    def test_no_grants_or_unwrapping_via_alternate_operations(self):
        for region, phase in (
            ("eu-west-1", "locked"),
            ("eu-west-3", "locked"),
            ("eu-west-1", "seed"),
            ("eu-west-1", "serve"),
            ("eu-west-3", "serve"),
        ):
            rows = self.rows(region, phase)
            self.assertFalse(
                any(r["Effect"] == "Allow" and r["Principal"] == "*" for r in rows)
            )
            deny = next(r for r in rows if r["Sid"] == "NoAlternateDataPath")
            self.assertEqual(
                (deny["Effect"], deny["Principal"], deny.get("Condition")),
                ("Deny", "*", None),
            )
            for action in (
                "kms:ReEncryptFrom",
                "kms:ReEncryptTo",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyPair",
                "kms:Encrypt",
                "kms:CreateGrant",
            ):
                self.assertTrue(
                    any(fnmatchcase(action, p) for p in deny["Action"]), action
                )

    def test_invalid_phase_region_or_image(self):
        for args in (
            ("eu-west-3", "seed"),
            ("eu-central-1", "locked"),
            ("eu-west-1", "other"),
            ("eu-west-1", "seed", self.image),
            ("eu-west-1", "serve", "0" * 96),
            ("eu-west-1", "serve", self.image + "*"),
            ("eu-west-1", "serve", None),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                tls.policy(*args)

    def test_regional_readback_checks_entire_policy_grants_and_replica_membership(self):
        kid = "mrk-" + "c3" * 16
        members = [
            {"Region": r, "Arn": f"arn:aws:kms:{r}:330422590279:key/{kid}"}
            for r in ("eu-west-1", "eu-west-3")
        ]
        for bad in (
            "none",
            "principal",
            "extraRegion",
            "truncated",
            "grant",
            "extraAllow",
            "replicaOnly",
        ):
            visited = []

            def read(region, command, *args, bad=bad, visited=visited):
                visited.append((region, command))
                idx = int(region == "eu-west-3")
                self.assertIn(members[idx]["Arn"], args)
                if command == "describe-key":
                    rel = {
                        "MultiRegionKeyType": ("PRIMARY", "REPLICA")[idx],
                        "PrimaryKey": members[0],
                        "ReplicaKeys": members[1:],
                    }
                    if idx and bad == "extraRegion":
                        rel["ReplicaKeys"] = [*rel["ReplicaKeys"], members[0]]
                    return {
                        "KeyMetadata": {
                            "Arn": members[idx]["Arn"],
                            "KeyId": kid,
                            "Enabled": True,
                            "MultiRegion": True,
                            "KeyState": "Enabled",
                            "KeyManager": "CUSTOMER",
                            "Origin": "AWS_KMS",
                            "KeySpec": "SYMMETRIC_DEFAULT",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "MultiRegionConfiguration": rel,
                        }
                    }
                if command == "get-key-policy":
                    doc = tls.policy(region, "serve", self.image)
                    if idx and bad == "extraAllow":
                        doc["Statement"].append(
                            {
                                "Sid": "AnotherAllow",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "kms:*",
                                "Resource": "*",
                            }
                        )
                    if idx and bad == "principal":
                        doc["Statement"][-1]["Principal"] = "*"
                    if idx and bad == "replicaOnly":
                        doc = tls.policy(region, "locked")
                    doc["Statement"].reverse()
                    return {"Policy": json.dumps(doc)}
                self.assertEqual(command, "list-grants")
                self.assertIn("--no-paginate", args)
                return {
                    "Grants": [{}] if idx and bad == "grant" else [],
                    "Truncated": bool(idx and bad == "truncated"),
                }

            with self.subTest(case=bad):
                if bad == "none":
                    tls.verify_keys(kid, "serve", self.image, read=read)
                    self.assertEqual(len(visited), 6)
                else:
                    with self.assertRaises(ValueError):
                        tls.verify_keys(kid, "serve", self.image, read=read)


if __name__ == "__main__":
    unittest.main()
