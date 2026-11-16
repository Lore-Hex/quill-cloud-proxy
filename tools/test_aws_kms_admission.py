from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import aws_kms_admission as gate


def policy(pins):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "NoUnattestedDecryptEvenViaIAMOrGrant", "Effect": "Deny", "Principal": "*",
        "Action": ["kms:Decrypt", "kms:ReEncrypt*"], "Resource": "*",
        "Condition": {"StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": pins}},
    }]}


class KMSAdmissionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "keys.json"
        self.disabled_path = Path(directory.name) / "disabled-keys.json"
        self.disabled_path.write_text(json.dumps({"schema_version": 1, "required": False, "key_arns": {}}))
        self.pins = ["a" * 96, "b" * 96]
        self.config = {"schema_version": 1, "required": True, "key_arns": {
            region: f"arn:aws:kms:{region}:330422590279:key/11111111-1111-1111-1111-111111111111"
            for region in gate.REGIONS
        }}
        self.path.write_text(json.dumps(self.config))

    def reply(self, region, command, *args):
        if command == "describe-key":
            return {"KeyMetadata": {"Arn": self.config["key_arns"][region], "Enabled": True,
                                   "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT",
                                   "KeySpec": "SYMMETRIC_DEFAULT"}}
        return {"Policy": json.dumps(policy(self.pins))}

    def test_both_regional_keys_are_checked_without_writes(self):
        with patch.object(gate, "aws_json", side_effect=self.reply) as aws:
            gate.check_keys(self.pins, config_path=self.path)
        self.assertEqual(aws.call_count, 4)
        self.assertEqual({call.args[0] for call in aws.call_args_list}, gate.REGIONS)
        self.assertEqual({call.args[1] for call in aws.call_args_list}, {"describe-key", "get-key-policy"})

    def test_disabled_configuration_performs_no_cloud_calls(self):
        with patch.object(gate, "aws_json") as aws:
            gate.check_keys(self.pins, config_path=self.disabled_path)
        aws.assert_not_called()

    def test_malformed_or_partial_configuration_fails_before_cloud(self):
        changes = [{"required": False}, {"key_arns": {}}, {"required": "false"},
                   {"schema_version": True}, {"key_arns": {"eu-west-1": "wrong"}}]
        for change in changes:
            config = {**self.config, **change}
            self.path.write_text(json.dumps(config))
            with patch.object(gate, "aws_json") as aws, self.assertRaises(ValueError):
                gate.check_keys(self.pins, config_path=self.path)
            aws.assert_not_called()

    def test_missing_disabled_or_inaccessible_key_is_not_legacy_mode(self):
        for fault in (ValueError("disabled"), subprocess.CalledProcessError(1, "aws")):
            with patch.object(gate, "aws_json", side_effect=fault), self.assertRaises(type(fault)):
                gate.check_keys(self.pins, config_path=self.path)
        with patch.object(gate, "aws_json", return_value={"KeyMetadata": {}}), self.assertRaises(ValueError):
            gate.check_keys(self.pins, config_path=self.path)

    def test_missing_extra_or_differing_measurements_fail(self):
        for pins in (["a" * 96], [*self.pins, "c" * 96], ["c" * 96], ["0" * 96], []):
            with self.assertRaises(ValueError):
                gate.check_policy(json.dumps(policy(pins)), self.pins)
        gate.check_policy(json.dumps(policy(list(reversed(self.pins)))), self.pins)

    def test_weakened_denial_cannot_pass(self):
        for change in ({"Effect": "Allow"}, {"Principal": {"AWS": "parent"}},
                       {"Action": ["kms:Decrypt"]}, {"Resource": "key/one"},
                       {"Condition": {"StringNotEqualsIfExists": {"kms:RecipientAttestation:ImageSha384": self.pins}}}):
            candidate = policy(self.pins)
            candidate["Statement"][0].update(change)
            with self.assertRaises(ValueError):
                gate.check_policy(json.dumps(candidate), self.pins)
        candidate = policy(self.pins)
        candidate["Statement"].append(copy.deepcopy(candidate["Statement"][0]))
        with self.assertRaises(ValueError):
            gate.check_policy(json.dumps(candidate), self.pins)

    def test_duplicate_fields_are_rejected(self):
        self.path.write_text('{"schema_version":1,"required":true,"required":false,"key_arns":{}}')
        with patch.object(gate, "aws_json") as aws, self.assertRaises(ValueError):
            gate.check_keys(self.pins, config_path=self.path)
        aws.assert_not_called()

    def test_parent_modes_use_only_pinned_regional_key(self):
        for mode in ("dual", "v2-only"):
            self.assertEqual(gate.parent_key("eu-west-3", mode, config_path=self.path),
                             self.config["key_arns"]["eu-west-3"])
        self.assertEqual(gate.parent_key("eu-west-1", "legacy", config_path=self.path), "")
        with self.assertRaises(ValueError):
            gate.parent_key("eu-west-1", "dual", config_path=self.disabled_path)
        with self.assertRaises(ValueError):
            gate.parent_key("eu-west-1", "legacy; injected", config_path=self.path)
        with self.assertRaises(ValueError):
            gate.parent_key("us-west-2", "dual", config_path=self.path)

    def test_legacy_iam_cannot_be_reintroduced_after_attested_activation(self):
        gate.require_legacy_provisioning(config_path=self.disabled_path)
        with self.assertRaisesRegex(ValueError, "retired"):
            gate.require_legacy_provisioning(config_path=self.path)


if __name__ == "__main__":
    unittest.main()
