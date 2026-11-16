from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools import seal_aws_bootstrap as publish

KEY = "arn:aws:kms:eu-west-1:330422590279:key/11111111-1111-1111-1111-111111111111"
SECRET = "arn:aws:secretsmanager:eu-west-1:330422590279:secret:quill/attested-bootstrap-v2-AbC123"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.dumps({
            "devices": [], "region": "eu-west-1",
            "trustedrouter_base_url": "https://trustedrouter.com",
            "trustedrouter_internal_token": "synthetic-test-only",
            "gcp_service_account_key_json": json.dumps({
                "type": "service_account", "private_key": "synthetic-test-only",
            }),
        }).encode()
        self.identity, self.secrets, self.kms, self.signer = Mock(), Mock(), Mock(), Mock()
        self.identity.get_caller_identity.return_value = {
            "Account": "330422590279", "Arn": publish.OPERATOR,
        }
        self.secrets.describe_secret.return_value = {"ARN": SECRET}
        self.secrets.put_secret_value.side_effect = lambda **kw: {"VersionId": kw["ClientRequestToken"]}
        self.secrets.get_secret_value.return_value = {"SecretString": "{}"}
        def promote(**kwargs):
            self.secrets.describe_secret.return_value["VersionIdsToStages"] = {
                kwargs["MoveToVersionId"]: ["AWSCURRENT", "AWSPENDING"],
            }
        self.secrets.update_secret_version_stage.side_effect = promote

    def run_publish(self):
        return publish.publish(
            self.data, region="eu-west-1", version=7, key_arn=KEY,
            signer_arn=KEY, signer_public_der=b"synthetic-public-key",
            identity=self.identity, secrets=self.secrets, kms=self.kms, signer_kms=self.signer,
        )

    def test_new_regional_secret_is_published_once_and_read_back(self):
        with patch.object(publish.sealing, "seal", return_value=b"{}"):
            result = self.run_publish()
        self.assertEqual(result["bundle_version"], 7)
        call = self.secrets.put_secret_value.call_args.kwargs
        self.assertEqual(call["VersionStages"], ["AWSPENDING"])
        self.assertEqual(len(call["ClientRequestToken"]), 64)
        self.assertEqual(call["SecretString"], "{}")
        self.assertNotIn("synthetic-test-only", json.dumps(result))
        self.secrets.get_secret_value.assert_called_once_with(
            SecretId=publish.SECRET_ID, VersionId=call["ClientRequestToken"],
        )
        self.secrets.update_secret_version_stage.assert_called_once_with(
            SecretId=publish.SECRET_ID, VersionStage="AWSCURRENT",
            MoveToVersionId=call["ClientRequestToken"],
        )

    def test_wrong_identity_replica_and_downgrade_prevent_sealing(self):
        for fault in ("identity", "replica", "wrong region", "downgrade"):
            self.setUp()
            if fault == "identity":
                self.identity.get_caller_identity.return_value["Arn"] = "parent-role"
            elif fault == "replica":
                self.secrets.describe_secret.return_value["ReplicationStatus"] = [{"Region": "eu-west-3"}]
            elif fault == "wrong region":
                self.secrets.describe_secret.return_value["ARN"] = SECRET.replace("eu-west-1", "eu-west-3")
            else:
                self.secrets.describe_secret.return_value["VersionIdsToStages"] = {"current": ["AWSCURRENT"]}
                self.secrets.get_secret_value.return_value = {"SecretString": '{"manifest":{"version":7}}'}
            with patch.object(publish.sealing, "seal") as seal, self.assertRaises(ValueError):
                self.run_publish()
            seal.assert_not_called()
            self.secrets.put_secret_value.assert_not_called()

    def test_incomplete_or_wrong_region_payload_has_no_cloud_access(self):
        self.data = b'{"region":"eu-west-3"}'
        with self.assertRaises(ValueError):
            self.run_publish()
        self.identity.get_caller_identity.assert_not_called()

    def test_failed_seal_never_writes_and_readback_mismatch_fails(self):
        with patch.object(publish.sealing, "seal", side_effect=ValueError("bad signature")), \
             self.assertRaises(ValueError):
            self.run_publish()
        self.secrets.put_secret_value.assert_not_called()
        with patch.object(publish.sealing, "seal", return_value=b'{"ciphertext":"test"}'), \
             self.assertRaisesRegex(ValueError, "readback mismatch"):
            self.run_publish()
        self.secrets.update_secret_version_stage.assert_not_called()

    def test_promotion_compares_the_observed_predecessor(self):
        self.secrets.describe_secret.return_value["VersionIdsToStages"] = {"old": ["AWSCURRENT"]}
        self.secrets.get_secret_value.side_effect = [
            {"SecretString": '{"manifest":{"version":6}}'}, {"SecretString": "{}"},
        ]
        with patch.object(publish.sealing, "seal", return_value=b"{}"):
            self.run_publish()
        self.assertEqual(
            self.secrets.update_secret_version_stage.call_args.kwargs["RemoveFromVersionId"], "old",
        )

    def test_pending_publication_is_not_silently_overwritten(self):
        self.secrets.describe_secret.return_value["VersionIdsToStages"] = {"pending": ["AWSPENDING"]}
        with patch.object(publish.sealing, "seal") as seal, self.assertRaisesRegex(ValueError, "recovery"):
            self.run_publish()
        seal.assert_not_called()
        self.secrets.put_secret_value.assert_not_called()

    def test_plaintext_file_must_be_private_owned_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_bytes(self.data)
            path.chmod(0o600)
            self.assertEqual(publish.read_private(path), self.data)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                publish.read_private(link)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                publish.read_private(fifo)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                publish.read_private(path)
            path.chmod(0o600)
            path.write_bytes(b"x" * (publish.sealing.MAX_PLAINTEXT + 1))
            with self.assertRaises(ValueError):
                publish.read_private(path)

    def test_cli_dry_run_has_no_aws_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_bytes(self.data)
            path.chmod(0o600)
            public = Path(directory) / "public.der"
            signer = publish.sealing.ec.generate_private_key(publish.sealing.ec.SECP384R1())
            public.write_bytes(signer.public_key().public_bytes(
                publish.sealing.serialization.Encoding.DER,
                publish.sealing.serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            argv = ["seal", "--bootstrap-file", str(path), "--region", "eu-west-1",
                    "--version", "7", "--key-arn", KEY, "--signer-arn", KEY,
                    "--signer-public-key", str(public)]
            with patch.object(publish.sys, "argv", argv), \
                 patch.dict(os.environ, {"AWS_REPLICA_REGIONS": ""}), \
                 patch.object(publish, "publish") as cloud, \
                 patch.object(publish.subprocess, "run") as fence:
                self.assertEqual(publish.main(), 0)
            cloud.assert_not_called()
            fence.assert_not_called()

    def test_promotion_failure_preserves_current_and_reports_failure(self):
        self.secrets.describe_secret.return_value["VersionIdsToStages"] = {"old": ["AWSCURRENT"]}
        self.secrets.get_secret_value.side_effect = [
            {"SecretString": '{"manifest":{"version":6}}'}, {"SecretString": "{}"},
        ]
        self.secrets.update_secret_version_stage.side_effect = RuntimeError("predecessor changed")
        with patch.object(publish.sealing, "seal", return_value=b"{}"), self.assertRaises(RuntimeError):
            self.run_publish()
        self.assertEqual(self.secrets.describe_secret.return_value["VersionIdsToStages"], {"old": ["AWSCURRENT"]})
        self.assertEqual(self.secrets.put_secret_value.call_args.kwargs["VersionStages"], ["AWSPENDING"])

    def test_cli_builds_local_values_without_any_aws_calls(self):
        from tools.test_aws_bootstrap_payload import PayloadTests

        fixture = PayloadTests()
        fixture.setUp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values, service_account = root / "values.json", root / "sa.json"
            values.write_text(json.dumps(fixture.values))
            service_account.write_text(fixture.sa)
            values.chmod(0o600)
            service_account.chmod(0o600)
            public = root / "public.der"
            key = publish.sealing.ec.generate_private_key(publish.sealing.ec.SECP384R1())
            public.write_bytes(key.public_key().public_bytes(
                publish.sealing.serialization.Encoding.DER,
                publish.sealing.serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            argv = ["seal", "--values", str(values), "--service-account-file", str(service_account),
                    "--region", "eu-west-1", "--version", "7", "--key-arn", KEY,
                    "--signer-arn", KEY, "--signer-public-key", str(public)]
            with patch.object(publish.sys, "argv", argv), \
                 patch.dict(os.environ, {"AWS_REPLICA_REGIONS": ""}), \
                 patch.object(publish, "publish") as cloud, \
                 patch.object(publish.subprocess, "run") as fence:
                self.assertEqual(publish.main(), 0)
            cloud.assert_not_called()
            fence.assert_not_called()


if __name__ == "__main__":
    unittest.main()
