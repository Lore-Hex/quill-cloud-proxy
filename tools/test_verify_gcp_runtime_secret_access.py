from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify-gcp-runtime-secret-access.py")
SPEC = importlib.util.spec_from_file_location("runtime_secret_access", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeSecretAccessTests(unittest.TestCase):
    def test_policy_requires_secret_accessor_for_exact_member(self) -> None:
        policy = {
            "bindings": [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["serviceAccount:runtime@example.test"],
                }
            ]
        }

        self.assertTrue(
            MODULE.policy_grants_access(policy, "serviceAccount:runtime@example.test")
        )
        self.assertFalse(
            MODULE.policy_grants_access(policy, "serviceAccount:deploy@example.test")
        )

        policy["bindings"][0]["condition"] = {
            "expression": "request.time < timestamp('2026-01-01T00:00:00Z')"
        }
        self.assertFalse(
            MODULE.policy_grants_access(policy, "serviceAccount:runtime@example.test")
        )

    def test_missing_access_is_deduplicated_and_fail_closed(self) -> None:
        policies = {
            "allowed": {
                "bindings": [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["serviceAccount:runtime@example.test"],
                    }
                ]
            },
            "denied": {"bindings": []},
        }

        def fetch(secret: str) -> dict[str, object]:
            if secret == "unreadable":
                raise RuntimeError("permission denied")
            return policies[secret]

        missing, errors = MODULE.missing_secret_access(
            ["allowed", "denied", "denied", "unreadable"],
            "serviceAccount:runtime@example.test",
            fetch,
        )

        self.assertEqual(missing, ["denied"])
        self.assertEqual(errors, {"unreadable": "permission denied"})


if __name__ == "__main__":
    unittest.main()
