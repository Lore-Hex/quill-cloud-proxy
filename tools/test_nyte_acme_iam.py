import contextlib
import io
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import nyte_acme_iam as iam


class NYTECertificateIAMTests(unittest.TestCase):
    def setUp(self):
        self.current = {"etag": "current-etag", "version": 3, "bindings": [{
            "role": "existing-role", "members": ["existing-member"],
        }]}

    def test_exact_records_only_no_general_dns_role(self):
        binding = iam.required_binding()
        self.assertEqual(binding["members"], [iam.MEMBER])
        self.assertEqual(binding["role"], iam.ROLE)
        expression = binding["condition"]["expression"]
        self.assertEqual(expression.count("resource.name.endsWith("), 2)
        for record in iam.RECORDS:
            self.assertIn(f"'/rrsets/{record}/TXT'", expression)
        self.assertNotIn("/A'", expression)
        self.assertNotIn("dns.admin", json.dumps(binding))
        self.assertNotIn("tr-ops-local", json.dumps(binding))

    def test_preserves_all_existing_bindings_and_etag(self):
        original = json.loads(json.dumps(self.current))
        updated, changed = iam.updated_policy(self.current)
        self.assertTrue(changed)
        self.assertEqual(updated["etag"], "current-etag")
        self.assertEqual(updated["bindings"][:-1], self.current["bindings"])
        self.assertEqual(self.current, original)
        again, changed = iam.updated_policy(updated)
        self.assertFalse(changed)
        self.assertEqual(again, updated)

    def test_refuses_missing_etag(self):
        with self.assertRaisesRegex(ValueError, "etag"):
            iam.updated_policy({"bindings": []})

    def test_refuses_conflicting_named_binding(self):
        conflicting = iam.required_binding()
        conflicting["members"].append("other-member")
        self.current["bindings"].append(conflicting)
        with self.assertRaisesRegex(ValueError, "differs"):
            iam.updated_policy(self.current)

    def test_cli_dry_run_never_writes(self):
        responses = [
            SimpleNamespace(stdout=json.dumps({"includedPermissions": sorted(iam.PERMISSIONS)})),
            SimpleNamespace(stdout=json.dumps(self.current)),
        ]
        with (
            patch.object(iam.subprocess, "run", side_effect=responses) as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(iam.main(["--account", "deploy@example.com"]), 0)
        self.assertEqual(run.call_count, 2)
        self.assertNotIn("set-iam-policy", str(run.call_args_list))

    def test_apply_preserves_etag_in_submitted_file(self):
        def run(command, **kwargs):
            if "describe" in command:
                body = {"includedPermissions": sorted(iam.PERMISSIONS)}
            elif "get-iam-policy" in command:
                body = self.current
            else:
                self.assertIn("set-iam-policy", command)
                self.assertIn("--policy-file", command)
                body = json.loads(Path(command[command.index("--policy-file") + 1]).read_text())
                self.assertEqual(body["etag"], self.current["etag"])
                self.assertEqual(body["bindings"][:-1], self.current["bindings"])
            return SimpleNamespace(stdout=json.dumps(body))

        with patch.object(iam.subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(iam.main(["--account", "deploy@example.com", "--apply"]), 0)

    def test_refuses_broader_role(self):
        response = SimpleNamespace(stdout=json.dumps({
            "includedPermissions": [*sorted(iam.PERMISSIONS), "dns.managedZones.delete"],
        }))
        with (
            patch.object(iam.subprocess, "run", return_value=response) as run,
            self.assertRaisesRegex(ValueError, "exactly"),
        ):
            iam.main(["--account", "deploy@example.com", "--apply"])
        self.assertEqual(run.call_count, 1)

    def test_ops_identity_cannot_apply(self):
        with (
            patch.object(iam.subprocess, "run") as run,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            iam.main(["--account", "tr-ops-local@example.com", "--apply"])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
