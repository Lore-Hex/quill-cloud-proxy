"""Offline regression tests for current serving topology and pin-only updates."""

import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import aws_fargate_pins as pins

OLD, NEW = "ab" * 48, "cd" * 48
DIGEST = "sha256:" + "12" * 32
IMAGE = "registry/router@" + DIGEST
SURFACE = pins.SURFACES[0]


def fixture():
    service = {
        "status": "ACTIVE",
        "desiredCount": 1,
        "runningCount": 1,
        "pendingCount": 0,
        "taskDefinition": "td:1",
        "deployments": [
            {"status": "PRIMARY", "rolloutState": "COMPLETED", "taskDefinition": "td:1"}
        ],
        "deploymentConfiguration": {
            "minimumHealthyPercent": 100,
            "maximumPercent": 200,
            "deploymentCircuitBreaker": {"enable": True, "rollback": True},
        },
        "loadBalancers": [
            {
                "containerName": "trusted-router",
                "containerPort": 8080,
                "targetGroupArn": "tg",
            }
        ],
    }
    container = {
        "name": "trusted-router",
        "image": IMAGE,
        "environment": [
            {"name": pins.PIN_ENV, "value": OLD},
            {"name": "TR_RELEASE", "value": "1234567"},
        ],
    }
    task = {
        "taskArn": "task",
        "taskDefinitionArn": "td:1",
        "lastStatus": "RUNNING",
        "pinOverrides": [],
        "containers": [
            {
                "name": "trusted-router",
                "lastStatus": "RUNNING",
                "image": IMAGE,
                "imageDigest": DIGEST,
                "networkInterfaces": [{"privateIpv4Address": "10.0.0.1"}],
            }
        ],
    }
    target = {
        "Target": {"Id": "10.0.0.1", "Port": 8080},
        "TargetHealth": {"State": "healthy"},
    }
    return {
        "describe-services": {"services": [service], "failures": []},
        "describe-task-definition": {"containers": [container]},
        "list-tasks": {"taskArns": ["task"]},
        "describe-tasks": {"tasks": [task], "failures": []},
        "describe-target-health": {"TargetHealthDescriptions": [target]},
    }


class ServingEvidenceTests(unittest.TestCase):
    def check(self, responses):
        def read(region, *args):
            self.assertNotIn("apprunner", args)
            return copy.deepcopy(responses[args[1]])

        with mock.patch.object(pins, "aws_json", side_effect=read):
            return pins.serving_pin(*SURFACE)

    def test_healthy_running_tasks_and_targets(self):
        self.assertEqual(self.check(fixture())["pin"], OLD)

    def test_unreadable_missing_or_unhealthy_evidence_fails_closed(self):
        variants = []
        data = fixture()
        data["describe-services"]["failures"] = [{"reason": "MISSING"}]
        variants.append(data)
        for key, value in (
            ("desiredCount", 0),
            ("pendingCount", 1),
            ("runningCount", 0),
        ):
            data = fixture()
            data["describe-services"]["services"][0][key] = value
            variants.append(data)
        data = fixture()
        data["describe-services"]["services"][0]["deployments"][0]["rolloutState"] = (
            "IN_PROGRESS"
        )
        variants.append(data)
        data = fixture()
        data["describe-services"]["services"][0]["deploymentConfiguration"][
            "minimumHealthyPercent"
        ] = 0
        variants.append(data)
        for value in ([], [{"name": pins.PIN_ENV, "value": "malformed"}]):
            data = fixture()
            data["describe-task-definition"]["containers"][0]["environment"] = value
            variants.append(data)
        for key, value in (
            ("taskDefinitionArn", "td:old"),
            ("pinOverrides", [[{"name": pins.PIN_ENV, "value": NEW}]]),
        ):
            data = fixture()
            data["describe-tasks"]["tasks"][0][key] = value
            variants.append(data)
        data = fixture()
        data["describe-tasks"]["tasks"][0]["containers"][0]["imageDigest"] = "wrong"
        variants.append(data)
        data = fixture()
        data["list-tasks"]["taskArns"] = []
        variants.append(data)
        data = fixture()
        data["describe-target-health"]["TargetHealthDescriptions"][0]["TargetHealth"][
            "State"
        ] = "unhealthy"
        variants.append(data)
        data = fixture()
        data["describe-target-health"]["TargetHealthDescriptions"] *= 2
        variants.append(data)
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check(data)

    def test_service_change_during_evidence_collection_rejected(self):
        data = fixture()
        before = pins.service_snapshot
        count = 0

        def snapshot(*args):
            nonlocal count
            result = before(*args)
            count += 1
            if count == 2:
                result["taskDefinition"] = "td:2"
            return result

        with (
            mock.patch.object(
                pins,
                "aws_json",
                side_effect=lambda region, *args: copy.deepcopy(data[args[1]]),
            ),
            mock.patch.object(pins, "service_snapshot", side_effect=snapshot),
            self.assertRaisesRegex(ValueError, "changed"),
        ):
            pins.serving_pin(*SURFACE)

    def test_cli_errors_do_not_disclose_response_or_credentials(self):
        with (
            mock.patch.object(
                pins.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(
                    1, ["aws"], output="SECRET", stderr="SECRET"
                ),
            ),
            self.assertRaises(ValueError) as raised,
        ):
            pins.aws_json(SURFACE[0], "ecs", "describe-services")
        self.assertNotIn("SECRET", str(raised.exception))


class PinUpdateTests(unittest.TestCase):
    def payload(self):
        return {
            "taskDefinition": {
                "taskDefinitionArn": "td:1",
                "revision": 1,
                "family": "tr-cp-euw1",
                "taskRoleArn": "role",
                "executionRoleArn": "execution",
                "volumes": [{"name": "keep"}],
                "containerDefinitions": [
                    {
                        "name": "trusted-router",
                        "image": IMAGE,
                        "environment": [
                            {"name": pins.PIN_ENV, "value": OLD},
                            {"name": "OTHER", "value": "unchanged"},
                        ],
                        "secrets": [{"name": "KEY", "valueFrom": "secret-ref"}],
                    },
                    {"name": "sidecar", "image": "sidecar", "environment": []},
                ],
            },
            "tags": [{"key": "owner", "value": "keep"}],
        }

    def test_only_pin_and_readonly_fields_change_tags_and_secret_refs_preserved(self):
        payload = self.payload()
        before = copy.deepcopy(payload)
        result = pins.pin_task_definition(payload, OLD + "," + NEW)
        expected = copy.deepcopy(payload["taskDefinition"])
        del expected["taskDefinitionArn"], expected["revision"]
        expected["containerDefinitions"][0]["environment"][0]["value"] = OLD + "," + NEW
        expected["tags"] = payload["tags"]
        self.assertEqual(result, expected)
        self.assertEqual(payload, before)

    def test_missing_or_duplicate_pin_refuses_to_mutate(self):
        for entries in ([], [{"name": pins.PIN_ENV, "value": OLD}] * 2):
            payload = self.payload()
            payload["taskDefinition"]["containerDefinitions"][0]["environment"] = (
                entries
            )
            with self.assertRaises(ValueError):
                pins.pin_task_definition(payload, NEW)

    def test_failed_roll_restores_and_verifies_previous_definition(self):
        snapshot = {
            k: fixture()["describe-services"]["services"][0][k]
            for k in (
                "taskDefinition",
                "desiredCount",
                "loadBalancers",
                "deploymentConfiguration",
            )
        }
        evidence = {**snapshot, "pin": OLD, "release": "1234567", "digest": DIGEST}
        updates = []
        paths = []

        def aws(region, *args):
            if args[1] == "describe-task-definition":
                return self.payload()
            if args[1] == "register-task-definition":
                path = Path(args[3].removeprefix("file://"))
                paths.append(path)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertIn(
                    NEW,
                    json.loads(path.read_text())["containerDefinitions"][0][
                        "environment"
                    ][0]["value"],
                )
                return {"taskDefinition": {"taskDefinitionArn": "td:2"}}
            self.assertEqual(args[1], "update-service")
            updates.append(args[-1])
            return {}

        with (
            mock.patch.object(pins, "serving_pin", return_value=evidence),
            mock.patch.object(pins, "service_snapshot", return_value=snapshot),
            mock.patch.object(pins, "aws_json", side_effect=aws),
            mock.patch.object(
                pins, "wait_serving", side_effect=[ValueError("bad rollout"), None]
            ) as wait,
            self.assertRaisesRegex(ValueError, "restored and verified"),
        ):
            pins.repin(*SURFACE, OLD + "," + NEW, expected=evidence)
        self.assertEqual(updates, ["td:2", "td:1"])
        self.assertEqual(wait.call_args.args[-2:], ("td:1", OLD))
        self.assertTrue(all(not path.exists() for path in paths))

    def test_changed_preflight_refuses_update(self):
        with (
            mock.patch.object(pins, "serving_pin", return_value={"changed": True}),
            mock.patch.object(pins, "aws_json") as aws,
            self.assertRaisesRegex(ValueError, "changed"),
        ):
            pins.repin(*SURFACE, NEW, expected={})
        aws.assert_not_called()

    def test_waiter_success_is_not_proof_of_requested_revision(self):
        with (
            mock.patch.object(pins.subprocess, "run"),
            mock.patch.object(
                pins, "serving_pin", return_value={"taskDefinition": "old", "pin": OLD}
            ),
            self.assertRaisesRegex(ValueError, "did not adopt"),
        ):
            pins.wait_serving(*SURFACE, "new", NEW)


if __name__ == "__main__":
    unittest.main()
