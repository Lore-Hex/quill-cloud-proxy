"""Verify and update PCR0 pins on the two serving AWS Fargate control planes.

Topology and serving-evidence checks follow quill-router's
scripts/deploy/{aws_ecs_control_plane.sh,cloud_serving_release.py}. App Runner
is retired; an unreadable, rolling, or unhealthy ECS service is not evidence.
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import tempfile
import time

PIN_ENV = "TR_ATTESTATION_EXPECTED_PCR0"
SURFACES = (("eu-west-1", "tr-cp", "tr-cp-euw1"), ("eu-west-3", "tr-cp", "tr-cp-euw3"))
READONLY_FIELDS = (
    "taskDefinitionArn",
    "revision",
    "status",
    "requiresAttributes",
    "compatibilities",
    "registeredAt",
    "registeredBy",
    "deregisteredAt",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def pin_set(value: str) -> set[str]:
    pins = {pin.strip().lower() for pin in value.split(",")}
    require(
        bool(pins) and all(re.fullmatch(r"[0-9a-f]{96}", p) for p in pins),
        "missing or malformed PCR0 set",
    )
    return pins


def aws_json(region: str, *args: str) -> dict:
    try:
        result = subprocess.run(
            ["aws", *args, "--region", region, "--output", "json", "--no-cli-pager"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        payload = json.loads(result.stdout)
        require(isinstance(payload, dict), "unexpected AWS response shape")
        return payload
    except (OSError, subprocess.SubprocessError, ValueError):
        # Task definitions can contain secret values. Never include cloud
        # stdout/stderr or exception details in operator logs.
        raise ValueError(f"AWS {args[0]} {args[1]} failed in {region}") from None


def service_snapshot(region: str, cluster: str, service: str) -> dict:
    require((region, cluster, service) in SURFACES, "unconfigured AWS pin surface")
    payload = aws_json(
        region, "ecs", "describe-services", "--cluster", cluster, "--services", service
    )
    require(
        not payload.get("failures") and len(payload["services"]) == 1,
        "missing ECS service",
    )
    current = payload["services"][0]
    desired = current["desiredCount"]
    require(
        current["status"] == "ACTIVE"
        and 0 < desired <= 100
        and current["runningCount"] == desired
        and current["pendingCount"] == 0,
        "ECS service is not fully running",
    )
    deployments = current["deployments"]
    require(
        len(deployments) == 1
        and deployments[0]["status"] == "PRIMARY"
        and deployments[0]["rolloutState"] == "COMPLETED"
        and deployments[0]["taskDefinition"] == current["taskDefinition"],
        "ECS service has an incomplete deployment",
    )
    protection = current["deploymentConfiguration"]
    require(
        protection["minimumHealthyPercent"] == 100
        and protection["maximumPercent"] >= 200
        and protection["deploymentCircuitBreaker"]
        == {"enable": True, "rollback": True},
        "ECS deployment protections are not enabled",
    )
    return {
        k: current[k]
        for k in (
            "taskDefinition",
            "desiredCount",
            "loadBalancers",
            "deploymentConfiguration",
        )
    }


def serving_pin(region: str, cluster: str, service: str) -> dict:
    before = service_snapshot(region, cluster, service)
    definition = before["taskDefinition"]
    payload = aws_json(
        region,
        "ecs",
        "describe-task-definition",
        "--task-definition",
        definition,
        "--query",
        "{containers:taskDefinition.containerDefinitions[].{name:name,image:image,"
        "environment:environment[?name==`TR_ATTESTATION_EXPECTED_PCR0` || name==`TR_RELEASE`]}}",
    )
    containers = [c for c in payload["containers"] if c["name"] == "trusted-router"]
    require(len(containers) == 1, "missing trusted-router container")
    container = containers[0]
    pins = [e["value"] for e in container["environment"] if e["name"] == PIN_ENV]
    releases = [
        e["value"] for e in container["environment"] if e["name"] == "TR_RELEASE"
    ]
    require(len(pins) == 1, "missing or duplicated PCR0 pin")
    pin_set(pins[0])
    require(
        len(releases) == 1 and re.fullmatch(r"[0-9a-f]{7,40}", releases[0]) is not None,
        "missing or malformed control-plane release",
    )
    image = container["image"]
    require(
        re.fullmatch(r".+@sha256:[0-9a-f]{64}", image) is not None,
        "control-plane image is not digest pinned",
    )
    digest = image.split("@", 1)[1]
    arns = aws_json(
        region,
        "ecs",
        "list-tasks",
        "--cluster",
        cluster,
        "--service-name",
        service,
        "--desired-status",
        "RUNNING",
    )["taskArns"]
    require(
        len(set(arns)) == len(arns) == before["desiredCount"],
        "incomplete ECS task census",
    )
    payload = aws_json(
        region,
        "ecs",
        "describe-tasks",
        "--cluster",
        cluster,
        "--tasks",
        *arns,
        "--query",
        "{failures:failures,tasks:tasks[].{taskArn:taskArn,"
        "taskDefinitionArn:taskDefinitionArn,lastStatus:lastStatus,"
        "pinOverrides:overrides.containerOverrides[].environment[?name==`TR_ATTESTATION_EXPECTED_PCR0`],"
        "containers:containers[].{name:name,lastStatus:lastStatus,image:image,imageDigest:imageDigest,"
        "networkInterfaces:networkInterfaces}}}",
    )
    tasks = payload["tasks"]
    require(
        not payload.get("failures")
        and len(tasks) == len(arns)
        and {t["taskArn"] for t in tasks} == set(arns),
        "incomplete ECS task evidence",
    )
    addresses = set()
    for task in tasks:
        require(
            task["taskDefinitionArn"] == definition
            and task["lastStatus"] == "RUNNING"
            and not any(task.get("pinOverrides") or []),
            "mixed or overridden ECS tasks",
        )
        running = [c for c in task["containers"] if c["name"] == "trusted-router"]
        require(len(running) == 1, "missing running trusted-router container")
        current = running[0]
        require(
            current["lastStatus"] == "RUNNING"
            and current["image"] == image
            and current["imageDigest"] == digest,
            "running image differs from task definition",
        )
        require(len(current["networkInterfaces"]) == 1, "ambiguous ECS task address")
        addresses.add(current["networkInterfaces"][0]["privateIpv4Address"])
    require(len(addresses) == len(arns), "duplicate ECS task addresses")
    balancers = before["loadBalancers"]
    require(
        len(balancers) == 1 and balancers[0]["containerName"] == "trusted-router",
        "unexpected ECS load-balancer topology",
    )
    balancer = balancers[0]
    targets = aws_json(
        region,
        "elbv2",
        "describe-target-health",
        "--target-group-arn",
        balancer["targetGroupArn"],
    )["TargetHealthDescriptions"]
    require(
        len(targets) == len(addresses)
        and {t["Target"]["Id"] for t in targets} == addresses
        and all(
            t["TargetHealth"]["State"] == "healthy"
            and t["Target"]["Port"] == balancer["containerPort"]
            for t in targets
        ),
        "ECS targets are missing, extra, or unhealthy",
    )
    require(
        service_snapshot(region, cluster, service) == before,
        "ECS service changed during verification",
    )
    return {**before, "pin": pins[0], "release": releases[0], "digest": digest}


def pin_task_definition(payload: dict, pins: str) -> dict:
    pin_set(pins)
    definition = copy.deepcopy(payload["taskDefinition"])
    containers = [
        c for c in definition["containerDefinitions"] if c["name"] == "trusted-router"
    ]
    require(len(containers) == 1, "missing trusted-router container")
    entries = [e for e in containers[0].get("environment", []) if e["name"] == PIN_ENV]
    require(
        len(entries) == 1,
        "missing or duplicated PCR0 pin; refusing to add a new configuration",
    )
    pin_set(entries[0]["value"])
    entries[0]["value"] = pins
    for field in READONLY_FIELDS:
        definition.pop(field, None)
    # DescribeTaskDefinition can return []; ECS rejects registering empty tags.
    if payload.get("tags"):
        definition["tags"] = copy.deepcopy(payload["tags"])
    return definition


def wait_serving(
    region: str, cluster: str, service: str, definition: str, pins: str
) -> None:
    try:
        subprocess.run(
            [
                "aws",
                "ecs",
                "wait",
                "services-stable",
                "--region",
                region,
                "--cluster",
                cluster,
                "--services",
                service,
                "--no-cli-pager",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=660,
        )
        # ECS stability can precede removal of draining NLB targets. Require
        # complete serving evidence, with the same bounded settle window used
        # by the control-plane release procedure.
        deadline = time.monotonic() + 480
        while True:
            try:
                current = serving_pin(region, cluster, service)
                break
            except (ValueError, KeyError, TypeError):
                if time.monotonic() >= deadline:
                    raise ValueError(
                        f"ECS serving evidence did not settle in {region}"
                    ) from None
                time.sleep(15)
        require(
            current["taskDefinition"] == definition
            and pin_set(current["pin"]) == pin_set(pins),
            "ECS service did not adopt the requested pin revision",
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError(f"ECS stability wait failed in {region}") from None


def repin(
    region: str, cluster: str, service: str, pins: str, *, expected: dict
) -> None:
    before = serving_pin(region, cluster, service)
    require(
        before == expected, "ECS service changed since preflight; refusing to repin"
    )
    if pin_set(before["pin"]) == pin_set(pins):
        return
    payload = aws_json(
        region,
        "ecs",
        "describe-task-definition",
        "--task-definition",
        before["taskDefinition"],
        "--include",
        "TAGS",
    )
    definition = pin_task_definition(payload, pins)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        path = handle.name
        os.chmod(path, 0o600)
        json.dump(definition, handle)
    try:
        new_arn = aws_json(
            region,
            "ecs",
            "register-task-definition",
            "--cli-input-json",
            f"file://{path}",
        )["taskDefinition"]["taskDefinitionArn"]
    finally:
        os.unlink(path)
    require(
        service_snapshot(region, cluster, service)
        == {
            k: before[k]
            for k in (
                "taskDefinition",
                "desiredCount",
                "loadBalancers",
                "deploymentConfiguration",
            )
        },
        "ECS service changed before update; refusing to overwrite it",
    )
    try:
        aws_json(
            region,
            "ecs",
            "update-service",
            "--cluster",
            cluster,
            "--service",
            service,
            "--task-definition",
            new_arn,
        )
        wait_serving(region, cluster, service, new_arn, pins)
    except (ValueError, KeyError, TypeError):
        aws_json(
            region,
            "ecs",
            "update-service",
            "--cluster",
            cluster,
            "--service",
            service,
            "--task-definition",
            before["taskDefinition"],
        )
        wait_serving(region, cluster, service, before["taskDefinition"], before["pin"])
        raise ValueError(
            f"{service}: repin failed; previous task definition restored and verified"
        ) from None
    print(
        f"  {service}: healthy serving PCR0 set verified via {new_arn.rsplit('/', 1)[-1]}"
    )
