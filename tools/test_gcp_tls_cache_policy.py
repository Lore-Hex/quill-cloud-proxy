import json
import unittest
from pathlib import Path


class TLSCachePolicyTests(unittest.TestCase):
    def test_exact_tls_ring_custody_boundary(self):
        root = Path(__file__).resolve().parents[1]
        path = root / "infra/gcp/tls-cache/deny-direct-decrypt.json"
        policy = json.loads(path.read_text())
        self.assertGreater(len(policy["displayName"]), 0)
        self.assertLessEqual(len(policy["displayName"]), 63)
        self.assertEqual(len(policy["rules"]), 1)
        rule = policy["rules"][0]["denyRule"]
        self.assertEqual(rule["deniedPrincipals"], ["principalSet://goog/public:all"])
        self.assertEqual(rule["exceptionPrincipals"], [
            "principalSet://iam.googleapis.com/projects/44325983244/locations/global/"
            "workloadIdentityPools/trustedrouter-batch/*"
        ])
        self.assertCountEqual(rule["deniedPermissions"], [
            "cloudkms.googleapis.com/cryptoKeyVersions.useToEncrypt",
            "cloudkms.googleapis.com/cryptoKeyVersions.useToDecrypt",
        ])
        self.assertEqual(rule["denialCondition"]["expression"],
                         "resource.matchTagId('tagKeys/281483783688164', 'tagValues/281476950601434')")


if __name__ == "__main__":
    unittest.main()
