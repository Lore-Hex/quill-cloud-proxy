from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest import mock

SCRIPT = Path(__file__).with_name("verify-gcp-runtime-secret-access.py")
SPEC = importlib.util.spec_from_file_location("runtime_secret_access", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeSecretAccessTests(unittest.TestCase):
    def test_transient_policy_read_retries_then_parses(self) -> None:
        failure = CompletedProcess([], 1, "", "Connection reset by peer")
        success = CompletedProcess([], 0, '{"bindings": []}', "")
        with (
            mock.patch.object(
                MODULE.subprocess, "run", side_effect=[failure, success]
            ) as run,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            self.assertEqual(
                MODULE.gcloud_json(["secrets", "get-iam-policy", "test"]),
                {"bindings": []},
            )
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        sleep.assert_called_once_with(1)

    def test_transport_exhaustion_fails_closed(self) -> None:
        for failure in (
            CompletedProcess([], 1, "", "Connection reset by peer"),
            TimeoutExpired("gcloud", 30),
        ):
            with (
                self.subTest(failure=failure),
                mock.patch.object(
                    MODULE.subprocess, "run", side_effect=[failure] * 3
                ) as run,
                mock.patch.object(MODULE.time, "sleep") as sleep,
            ):
                with self.assertRaises(RuntimeError):
                    MODULE.gcloud_json(["projects", "get-iam-policy", "test"])
                self.assertEqual(run.call_count, 3)
                self.assertEqual(sleep.call_args_list, [mock.call(1), mock.call(2)])

    def test_policy_denials_and_invalid_json_are_not_retried(self) -> None:
        for result in (
            CompletedProcess([], 1, "", "PERMISSION_DENIED"),
            CompletedProcess([], 0, "invalid", ""),
        ):
            with (
                self.subTest(result=result),
                mock.patch.object(MODULE.subprocess, "run", return_value=result) as run,
                mock.patch.object(MODULE.time, "sleep") as sleep,
            ):
                with self.assertRaises(RuntimeError):
                    MODULE.gcloud_json(["projects", "get-iam-policy", "test"])
                run.assert_called_once()
                sleep.assert_not_called()

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
