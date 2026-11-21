import importlib.util
import unittest
from pathlib import Path
from unittest import mock

import nyte_acme_iam as iam

spec = importlib.util.spec_from_file_location("reconcile_trusted_dns", Path(__file__).with_name("reconcile-enclave-dns.py"))
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)


class TrustedDNSTests(unittest.TestCase):
    def test_failed_mirror_proof_excludes_address_from_every_publication(self):
        fleet = [{"ip":"34.1.1.1"}, {"ip":"34.2.2.2"}]
        def probe(ip, digest, *, api_host, confidential_host):
            self.assertEqual(digest, "signed")
            self.assertEqual(api_host, confidential_host)
            return not (ip == "34.2.2.2" and api_host == "api.trusted.uptimerouter.com")
        with (mock.patch.object(dns, "API_HOST", "api.trustedrouter.com"),
              mock.patch.object(dns, "attest", side_effect=probe) as probes,
              mock.patch.object(dns, "reconcile_dns_record") as publish):
            dns.reconcile_trusted(fleet, ["signed"], apply=True)
        self.assertEqual(probes.call_count, 10)
        self.assertEqual(len({c.kwargs["api_host"] for c in probes.call_args_list}), 5)
        self.assertEqual(publish.call_count, 3)
        for call in publish.call_args_list:
            self.assertEqual(call.args[2], ["34.1.1.1"])
            self.assertTrue(call.args[1].startswith("api.trusted."))

    def test_no_qualified_instances_removes_only_trusted_records(self):
        with (mock.patch.object(dns, "API_HOST", "api.trustedrouter.com"),
              mock.patch.object(dns, "current_dns_ips", return_value=["34.1.1.1"]),
              mock.patch.object(dns, "_check_pinned_drains") as guard,
              mock.patch.object(dns.subprocess, "run") as run):
            dns.reconcile_trusted([], ["signed"], apply=True)
        self.assertEqual(guard.call_count, 3)
        for call in run.call_args_list:
            self.assertIn("delete", call.args[0])
            self.assertTrue(call.args[0][4].startswith("api.trusted."))

    def test_certificate_grant_is_additive_idempotent_and_only_five_records(self):
        existing = {"etag":"guard", "bindings":[iam.required_binding()]}
        updated, changed = iam.updated_policy(existing, trusted_api=True)
        self.assertTrue(changed)
        self.assertEqual(updated["etag"], "guard")
        self.assertEqual(updated["bindings"][0], existing["bindings"][0])
        condition = updated["bindings"][1]["condition"]["expression"]
        self.assertEqual(len(set(iam.TRUSTED_RECORDS)), 5)
        self.assertEqual(condition.count("/TXT'"), 5)
        for record in iam.TRUSTED_RECORDS:
            self.assertIn(f"/rrsets/{record}/TXT'", condition)
        self.assertFalse(iam.updated_policy(updated, trusted_api=True)[1])
