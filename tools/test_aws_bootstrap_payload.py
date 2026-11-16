from __future__ import annotations

import json
import unittest

from tools import aws_bootstrap_payload as payload


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.catalog = payload.catalog()
        self.token_name = self.catalog["_TR_INTERNAL_TOKEN_SECRET_SUFFIX"]
        self.lease_name = self.catalog["_SPEND_LEASE_ISSUER_CONFIG_SECRET_SUFFIX"]
        self.sa = json.dumps({"type": "service_account", "private_key": "synthetic-test-only"})
        self.values = {}
        for table in ("_PROVIDER_KEYS", "_DIRECT_PROVIDER_KEYS", "_PROMPT_KEYS"):
            self.values.update({name: "synthetic-test-only" for _, name in self.catalog[table]})
        for name in (self.token_name, self.lease_name, self.catalog["_CLOUDFLARE_API_TOKEN_SECRET_SUFFIX"],
                     self.catalog["_CLOUDFLARE_ZONE_ID_SECRET_SUFFIX"]):
            self.values[name] = "synthetic-test-only"
        self.values[self.lease_name] = '{"version":1}'

    def build(self, omitted=None):
        return payload.build(self.values, region="eu-west-3", service_account=self.sa, omitted=omitted or [])

    def test_every_parent_catalog_entry_is_carried_without_cloud_reads(self):
        result = self.build()
        for table in ("_PROVIDER_KEYS", "_PROMPT_KEYS"):
            for field, name in self.catalog[table]:
                self.assertEqual(result[field], self.values[name])
        for provider, name in self.catalog["_DIRECT_PROVIDER_KEYS"]:
            self.assertEqual(result["provider_api_keys"][provider], self.values[name])
        self.assertEqual(result["trustedrouter_base_url"], "https://trustedrouter.com")
        self.assertEqual(result["region"], "eu-west-3")
        self.assertEqual(result["gcp_service_account_key_json"], self.sa)
        self.assertEqual(result["spend_lease_issuer_config"], {"version": 1})
        self.assertNotIn("spend_lease_shadow", result)

    def test_partial_values_cannot_silently_disable_a_provider(self):
        name = self.catalog["_PROVIDER_KEYS"][0][1]
        del self.values[name]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.build()
        self.assertNotIn(self.catalog["_PROVIDER_KEYS"][0][0], self.build([name]))

    def test_unknown_and_contradictory_omissions_are_rejected(self):
        for omitted in (["wrong-name"], [self.token_name], [self.token_name, self.token_name]):
            with self.assertRaises(ValueError):
                self.build(omitted)
        self.values["unrelated-control-plane-secret"] = "do-not-copy"
        with self.assertRaises(ValueError):
            self.build()

    def test_token_cannot_be_omitted(self):
        del self.values[self.token_name]
        with self.assertRaisesRegex(ValueError, "cannot be omitted"):
            self.build([self.token_name])

    def test_malformed_configuration_is_not_published_as_an_error_string(self):
        for value in ('{"version":1,"version":2}', '{"version":NaN}', 'null', '[]', 'malformed'):
            self.values[self.lease_name] = value
            with self.assertRaises(ValueError):
                self.build()

    def test_service_account_must_be_unwrapped_json(self):
        self.sa = "base64-kms-ciphertext-is-not-plaintext-json"
        with self.assertRaises(ValueError):
            self.build()


if __name__ == "__main__":
    unittest.main()
