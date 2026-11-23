#!/usr/bin/env python3
"""Region-at-a-time AWS Nitro gateway rollout steps for rollout-aws-gateway.yml.

Each subcommand is one gate of docs/runbook-aws-enclave-release.md, made
non-interactive. None of them widens or narrows an admission set, writes a KMS
policy, or touches DNS: admission stays in tools/aws_eif_admission.py and
tools/capture-plane-measurements.py, KMS stays with its reviewed Terraform.

    fetch-release      download and authenticate the CI manifest for a source
    serving            record a region's serving ASG, numbered template and
                       the parent/pump digests and EIF its user data pins
    candidate-version  find the candidate template version this run created
    compare-template   prove the candidate differs from the serving template
                       only in the EIF identity (or by a reviewed diff)
    launch-candidate   start one standalone, non-serving candidate instance
    verify-instance    SSM-forward to an instance and run the exact-instance,
                       exact-PCR0, strict-bootstrap probe (and, optionally, a
                       negative control that must fail)
    refresh            refresh the ASG to an explicit numbered template, with
                       AWS automatic rollback, and wait for a terminal status
    census             every member on the template, healthy in the target
                       group, nothing extra, each one individually verified
    terminate-candidate  terminate only this run's candidate instances
    capture-narrow     narrow the record and runtime pins through one member
    wait-kms           wait for both recipient-only key policies to equal a set

AWS errors are printed by type, never with payloads: some AWS responses
contain secret values.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
import gzip
import hashlib
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "330422590279"
REGIONS = ("eu-west-3", "eu-west-1")  # rollout order: Paris, then Dublin
ASG = "quill-enclave-asg"
LT_NAME = "quill-enclave-lt"
CANDIDATE_PROJECT = "quill-release-candidate"
SERVING_PROJECT = "quill-enclave"
SHA = re.compile(r"[0-9a-f]{40}")
INSTANCE = re.compile(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})")
# The preferences of the 2026-11-17 production refreshes, which retained the
# full warmup, checkpoint, drain and bake periods. Do not shorten them here.
REFRESH_PREFERENCES = {
    "MinHealthyPercentage": 100,
    "MaxHealthyPercentage": 150,
    "InstanceWarmup": 300,
    "CheckpointPercentages": [50, 100],
    "CheckpointDelay": 900,
    "SkipMatching": False,
    "AutoRollback": True,
    "ScaleInProtectedInstances": "Wait",
    "StandbyInstances": "Wait",
    "BakeTime": 300,
}
EIF_KEY = re.compile(r"releases/([0-9a-f]{40})/([0-9a-f]{64})/enclave\.eif")
EIF_SIZE = re.compile(r'test "\$\(stat -c %s /opt/quill/enclave\.eif\.tmp\)" = "([0-9]+)"')
PARENT = re.compile(rf"{ACCOUNT}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/quill-parent@(sha256:[0-9a-f]{{64}})")
PUMP = re.compile(rf"{ACCOUNT}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/quill-parent-pump@(sha256:[0-9a-f]{{64}})")


class AwsError(RuntimeError):
    pass


class ForwardError(RuntimeError):
    """A transient SSM forward failure; verification retries it."""


def aws(region: str, *args: str, timeout: int = 120) -> Any:
    try:
        result = subprocess.run(
            ["aws", *args, "--region", region, "--output", "json", "--no-cli-pager"],
            check=True, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        # The error code is safe to show; the message body is not printed.
        code = re.search(r"\(([A-Za-z]+(?:Exception|Error|Denied|Fault)?)\)", exc.stderr or "")
        raise AwsError(f"aws {args[0]} {args[1]} failed in {region}: {code.group(1) if code else 'error'}") from None
    return json.loads(result.stdout) if result.stdout.strip() else {}


def require_region(region: str) -> str:
    if region not in REGIONS:
        raise SystemExit(f"unknown gateway region {region!r}")
    return region


# --------------------------------------------------------------------------
# pure helpers (unit-tested)
# --------------------------------------------------------------------------
def decode_user_data(encoded: str) -> str:
    raw = base64.b64decode(encoded, validate=True)
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8")


def eif_identity(user_data: str) -> dict[str, str]:
    keys = set(EIF_KEY.findall(user_data))
    sizes = set(EIF_SIZE.findall(user_data))
    parents = set(PARENT.findall(user_data))
    pumps = set(PUMP.findall(user_data))
    if len(keys) != 1 or len(sizes) != 1 or len(parents) != 1 or len(pumps) != 1:
        raise ValueError("user data must pin exactly one EIF, size, parent and pump image")
    (source, eif_sha), = keys
    return {"source": source, "eif_sha256": eif_sha, "eif_size": sizes.pop(),
            "parent_digest": parents.pop(), "pump_digest": pumps.pop()}


def normalized_template_diff(serving: dict[str, Any], candidate: dict[str, Any],
                             new_eif: dict[str, str]) -> str:
    """Unified diff between the serving template and the candidate after the
    serving template's EIF identity is rewritten to the new one.

    An empty diff means the candidate changes nothing but which signed EIF the
    host downloads. Anything else must be reviewed before it reaches a fleet.
    """
    serving = json.loads(json.dumps(serving))
    candidate = json.loads(json.dumps(candidate))
    old_ud = decode_user_data(serving.pop("UserData"))
    new_ud = decode_user_data(candidate.pop("UserData"))
    old = eif_identity(old_ud)
    if eif_identity(new_ud)["source"] != new_eif["source"]:
        raise ValueError("candidate template does not pin the requested EIF")
    rewritten = (old_ud.replace(old["source"], new_eif["source"])
                 .replace(old["eif_sha256"], new_eif["eif_sha256"])
                 .replace(f'= "{old["eif_size"]}"', f'= "{new_eif["eif_size"]}"'))
    left = json.dumps(serving, indent=1, sort_keys=True).splitlines() + rewritten.splitlines()
    right = json.dumps(candidate, indent=1, sort_keys=True).splitlines() + new_ud.splitlines()
    return "\n".join(difflib.unified_diff(left, right, "serving(eif-rewritten)", "candidate", lineterm=""))


def diff_digest(diff: str) -> str:
    return hashlib.sha256(diff.encode("utf-8")).hexdigest()


def template_gate(diff: str, accepted_digest: str) -> None:
    if not diff:
        return
    if accepted_digest and accepted_digest == diff_digest(diff):
        return
    raise SystemExit(
        "candidate template differs from the serving template beyond the EIF identity.\n"
        f"Review the diff above; to accept exactly it, re-dispatch with template_diff_sha256={diff_digest(diff)}"
    )


def candidate_name(source: str, run_id: str, region: str) -> str:
    if not SHA.fullmatch(source) or not re.fullmatch(r"[0-9]{1,20}", run_id):
        raise ValueError("invalid candidate identity")
    return f"{CANDIDATE_PROJECT}-{source[:12]}-{run_id}-{region}"


def numbered(version: Any) -> str:
    version = str(version)
    if not re.fullmatch(r"[1-9][0-9]*", version):
        raise ValueError(f"launch template version must be numbered, got {version!r}")
    return version


def census_problems(group: dict[str, Any], targets: list[dict[str, Any]], version: str) -> list[str]:
    problems = []
    members = group.get("Instances", [])
    desired = group.get("DesiredCapacity")
    if len(members) != desired:
        problems.append(f"{len(members)} members for desired capacity {desired}")
    for member in members:
        name = member.get("InstanceId")
        if str(member.get("LaunchTemplate", {}).get("Version")) != version:
            problems.append(f"{name} runs template {member.get('LaunchTemplate', {}).get('Version')}")
        if member.get("LifecycleState") != "InService" or member.get("HealthStatus") != "Healthy":
            problems.append(f"{name} is {member.get('LifecycleState')}/{member.get('HealthStatus')}")
    ids = {m.get("InstanceId") for m in members}
    seen = set()
    for target in targets:
        tid = target.get("Target", {}).get("Id")
        state = target.get("TargetHealth", {}).get("State")
        seen.add(tid)
        if tid not in ids:
            problems.append(f"target {tid} ({state}) is not an ASG member")
        elif state != "healthy":
            problems.append(f"target {tid} is {state}")
    for missing in sorted(ids - seen):
        problems.append(f"member {missing} is not registered")
    return problems


# --------------------------------------------------------------------------
# AWS-facing steps
# --------------------------------------------------------------------------
def group(region: str) -> dict[str, Any]:
    groups = aws(region, "autoscaling", "describe-auto-scaling-groups",
                 "--auto-scaling-group-names", ASG)["AutoScalingGroups"]
    if len(groups) != 1:
        raise SystemExit(f"{region}: expected exactly one {ASG}")
    return groups[0]


def template_data(region: str, lt_id: str, version: str) -> dict[str, Any]:
    versions = aws(region, "ec2", "describe-launch-template-versions", "--launch-template-id", lt_id,
                   "--versions", numbered(version))["LaunchTemplateVersions"]
    if len(versions) != 1:
        raise SystemExit(f"{region}: template {lt_id} version {version} not found")
    return versions[0]


def cmd_fetch_release(args: argparse.Namespace) -> None:
    if not SHA.fullmatch(args.source):
        raise SystemExit("--source must be a full commit id")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    found: dict[str, str] = {}
    for region in REGIONS:
        bucket = f"quill-enclave-eif-{region}-{ACCOUNT}"
        listing = aws(region, "s3api", "list-objects-v2", "--bucket", bucket,
                      "--prefix", f"releases/{args.source}/")
        keys = sorted(item["Key"] for item in listing.get("Contents", []))
        manifests = [k for k in keys if k.endswith("/manifest.json")]
        if len(manifests) != 1:
            raise SystemExit(
                f"{region}: expected exactly one published EIF for {args.source}, found {len(manifests)}. "
                "Dispatch publish-aws-eif.yml on main at that commit first.")
        found[region] = manifests[0]
    if len(set(found.values())) != 1:
        raise SystemExit("the two regional buckets disagree on the published EIF")
    key = found[REGIONS[0]]
    bucket = f"quill-enclave-eif-{REGIONS[0]}-{ACCOUNT}"
    for name in ("manifest.json", "manifest.json.bundle"):
        aws(REGIONS[0], "s3api", "get-object", "--bucket", bucket,
            "--key", key.rsplit("/", 1)[0] + "/" + name, str(out / name))
    verified = subprocess.run(
        [sys.executable, "-m", "tools.aws_eif_manifest", "verify", "--manifest", str(out / "manifest.json"),
         "--signature", str(out / "manifest.json.bundle"), "--expected-source", args.source],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=120).stdout
    record = json.loads(verified)
    summary = {"source": record["source_commit"], "eif_sha256": record["eif_sha256"],
               "eif_size": str(record["eif_size_bytes"]), "pcr0": record["measurements"]["PCR0"]}
    (out / "release.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))


def cmd_serving(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    current = group(region)
    spec = current.get("LaunchTemplate") or {}
    if current.get("MixedInstancesPolicy") or spec.get("LaunchTemplateName") != LT_NAME:
        raise SystemExit(f"{region}: {ASG} must use {LT_NAME} directly")
    version = numbered(spec.get("Version"))
    problems = census_problems(current, targets(region, current), version)
    if problems:
        raise SystemExit(f"{region}: serving fleet is mixed or unhealthy; refusing: {problems}")
    data = template_data(region, spec["LaunchTemplateId"], version)["LaunchTemplateData"]
    identity = eif_identity(decode_user_data(data["UserData"]))
    record = {"region": region, "launch_template_id": spec["LaunchTemplateId"], "version": version,
              "desired": current["DesiredCapacity"], "min": current["MinSize"],
              "subnets": sorted(s for s in current["VPCZoneIdentifier"].split(",") if s),
              "instances": sorted(m["InstanceId"] for m in current["Instances"]), **identity}
    Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


def targets(region: str, current: dict[str, Any]) -> list[dict[str, Any]]:
    arns = current.get("TargetGroupARNs") or []
    if len(arns) != 1:
        raise SystemExit(f"{region}: expected exactly one target group")
    return aws(region, "elbv2", "describe-target-health", "--target-group-arn", arns[0])["TargetHealthDescriptions"]


def cmd_candidate_version(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    log = Path(args.log).read_text()
    found = re.findall(r"candidate launch-template version ([1-9][0-9]*) created", log)
    if len(found) != 1:
        raise SystemExit("the template generator did not report exactly one candidate version")
    serving = json.loads(Path(args.serving).read_text())
    latest = aws(region, "ec2", "describe-launch-templates", "--launch-template-ids",
                 serving["launch_template_id"])["LaunchTemplates"][0]
    if str(latest["LatestVersionNumber"]) != found[0] or str(latest["DefaultVersionNumber"]) == found[0]:
        raise SystemExit(f"{region}: candidate version {found[0]} is not the latest non-default version")
    print(found[0])


def cmd_compare_template(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    serving = json.loads(Path(args.serving).read_text())
    release = json.loads(Path(args.release).read_text())
    old = template_data(region, serving["launch_template_id"], serving["version"])["LaunchTemplateData"]
    new = template_data(region, serving["launch_template_id"], args.version)["LaunchTemplateData"]
    diff = normalized_template_diff(old, new, release)
    if diff:
        print(diff)
    print(f"template diff sha256: {diff_digest(diff) if diff else 'none (EIF identity only)'}")
    template_gate(diff, args.accept_diff_sha256 or "")


def cmd_launch_candidate(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    serving = json.loads(Path(args.serving).read_text())
    name = candidate_name(args.source, args.run_id, region)
    existing = aws(region, "ec2", "describe-instances", "--filters",
                   f"Name=tag:Name,Values={name}", "Name=instance-state-name,Values=pending,running")
    if any(r["Instances"] for r in existing.get("Reservations", [])):
        raise SystemExit(f"{region}: a candidate named {name} is already running")
    tags = (f"ResourceType=instance,Tags=[{{Key=Project,Value={CANDIDATE_PROJECT}}},"
            f"{{Key=Name,Value={name}}},{{Key=ReleaseSource,Value={args.source}}}]")
    launched = aws(region, "ec2", "run-instances", "--count", "1",
                   "--launch-template", f"LaunchTemplateId={serving['launch_template_id']},Version={numbered(args.version)}",
                   "--subnet-id", serving["subnets"][0], "--tag-specifications", tags)["Instances"][0]
    instance = launched["InstanceId"]
    tag_map = {t["Key"]: t["Value"] for t in launched.get("Tags", [])}
    described = aws(region, "ec2", "describe-instances", "--instance-ids", instance)
    tag_map.update({t["Key"]: t["Value"] for r in described["Reservations"] for i in r["Instances"]
                    for t in i.get("Tags", [])})
    if tag_map.get("Project") != CANDIDATE_PROJECT or tag_map.get("Name") != name:
        aws(region, "ec2", "terminate-instances", "--instance-ids", instance)
        raise SystemExit(f"{region}: candidate {instance} did not carry isolation tags; terminated")
    print(instance)


@contextlib.contextmanager
def ssm_forward(region: str, instance: str) -> Iterator[int]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    params = json.dumps({"portNumber": ["8444"], "localPortNumber": [str(port)]})
    process = subprocess.Popen(
        ["aws", "ssm", "start-session", "--region", region, "--target", instance,
         "--document-name", "AWS-StartPortForwardingSession", "--parameters", params],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ForwardError(f"{region}: SSM session to {instance} ended")
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=2):
                break
            time.sleep(1)
        else:
            raise ForwardError(f"{region}: SSM forward to {instance} never opened")
        yield port
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)


def wait_ssm_online(region: str, instance: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = aws(region, "ssm", "describe-instance-information", "--filters",
                   f"Key=InstanceIds,Values={instance}").get("InstanceInformationList", [])
        if info and info[0].get("PingStatus") == "Online":
            return
        time.sleep(15)
    raise SystemExit(f"{region}: {instance} never registered with SSM")


def probe_instance(region: str, instance: str, args: argparse.Namespace) -> None:
    """Exact instance, exact CI PCR0, strict attested bootstrap, one socket."""
    release = json.loads(Path(args.release).read_text())
    probe = [sys.executable, "-m", "tools.aws_bootstrap_probe", "--manifest", args.manifest,
             "--signature", args.signature, "--expected-source", release["source"], "--instance", instance,
             "--policy", "strict", "--version", str(args.bundle_version)]
    deadline = time.monotonic() + args.boot_timeout
    last = "not attempted"
    while time.monotonic() < deadline:
        try:
            with ssm_forward(region, instance) as port:
                subprocess.run([*probe, "--port", str(port)], cwd=ROOT, check=True, timeout=120)
                if args.negative_control:
                    wrong = ("0" * 95) + "1" if release["pcr0"] != ("0" * 95) + "1" else ("0" * 95) + "2"
                    control = subprocess.run(
                        [sys.executable, str(ROOT / "tools" / "verify-attestation.py"), "--api-host",
                         "api-aws.trustedrouter.com", "--connect-ip", "127.0.0.1", "--port", str(port),
                         "--attested-cert-only", "--expected-pcr0", wrong],
                        cwd=ROOT, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if control.returncode == 0:
                        raise SystemExit(f"{region}: negative control PASSED against a wrong PCR0; verifier is not checking")
                    print(f"{region}: negative control failed as required (exit {control.returncode})")
            print(f"{region}: {instance} verified: exact instance, CI PCR0 {release['pcr0']}, strict bootstrap")
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ForwardError, AwsError) as exc:
            last = type(exc).__name__
            time.sleep(30)
    raise SystemExit(f"{region}: {instance} did not verify within {args.boot_timeout}s ({last})")


def cmd_verify_instance(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    if not INSTANCE.fullmatch(args.instance):
        raise SystemExit("invalid instance id")
    # Isolation before any probe: a candidate must not be a serving target.
    current = group(region)
    registered = {t.get("Target", {}).get("Id") for t in targets(region, current)}
    members = {m["InstanceId"] for m in current["Instances"]}
    if args.negative_control and (args.instance in registered or args.instance in members):
        raise SystemExit(f"{region}: candidate {args.instance} is in the serving ASG or target group")
    wait_ssm_online(region, args.instance, args.boot_timeout)
    probe_instance(region, args.instance, args)


def wait_refresh(region: str, refresh_id: str, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        refreshes = aws(region, "autoscaling", "describe-instance-refreshes", "--auto-scaling-group-name", ASG,
                        "--instance-refresh-ids", refresh_id)["InstanceRefreshes"]
        status = refreshes[0]["Status"]
        print(f"{region}: refresh {refresh_id} {status} {refreshes[0].get('PercentageComplete', 0)}%")
        if status in {"Successful", "Failed", "Cancelled", "RollbackSuccessful", "RollbackFailed"}:
            return status
        time.sleep(60)
    raise SystemExit(f"{region}: refresh {refresh_id} still running after {timeout}s")


def start_refresh(region: str, lt_id: str, version: str) -> str:
    in_progress = aws(region, "autoscaling", "describe-instance-refreshes", "--auto-scaling-group-name", ASG,
                      "--max-records", "5")["InstanceRefreshes"]
    if any(r["Status"] in {"Pending", "InProgress", "Cancelling", "RollbackInProgress", "Baking"} for r in in_progress):
        raise SystemExit(f"{region}: another instance refresh is active; refusing")
    desired = {"LaunchTemplate": {"LaunchTemplateId": lt_id, "Version": numbered(version)}}
    return aws(region, "autoscaling", "start-instance-refresh", "--auto-scaling-group-name", ASG,
               "--desired-configuration", json.dumps(desired),
               "--preferences", json.dumps(REFRESH_PREFERENCES))["InstanceRefreshId"]


def cmd_refresh(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    serving = json.loads(Path(args.serving).read_text())
    refresh_id = start_refresh(region, serving["launch_template_id"], args.version)
    # Recorded before waiting: the rollback may cancel only this refresh.
    Path(args.record).write_text(refresh_id + "\n")
    status = wait_refresh(region, refresh_id, args.timeout)
    if status != "Successful":
        raise SystemExit(f"{region}: refresh ended {status}; AWS automatic rollback restores template "
                         f"{serving['version']} when it can")


ACTIVE_REFRESH = {"Pending", "InProgress", "Cancelling", "RollbackInProgress", "Baking"}


def cancel_active_refresh(region: str, own_refresh: str, timeout: int) -> None:
    """Stop THIS run's refresh if it is still promoting the candidate (one
    that outlived the wait) and let it settle before the rollback refresh.
    Any other active refresh is not ours to touch: refuse instead."""
    deadline = time.monotonic() + timeout
    cancelled = False
    while True:
        refreshes = aws(region, "autoscaling", "describe-instance-refreshes", "--auto-scaling-group-name", ASG,
                        "--max-records", "5")["InstanceRefreshes"]
        active = [r for r in refreshes if r["Status"] in ACTIVE_REFRESH]
        if not active:
            return
        foreign = [r["InstanceRefreshId"] for r in active if r["InstanceRefreshId"] != own_refresh]
        if foreign:
            raise SystemExit(f"{region}: refresh {foreign} was not started by this run; not touching it")
        if not cancelled and any(r["Status"] in {"Pending", "InProgress", "Baking"} for r in active):
            aws(region, "autoscaling", "cancel-instance-refresh", "--auto-scaling-group-name", ASG)
            cancelled = True
            print(f"{region}: cancelled the active refresh before rolling back")
        if time.monotonic() > deadline:
            raise SystemExit(f"{region}: a refresh is still active; operator recovery required")
        time.sleep(30)


def cmd_rollback(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    serving = json.loads(Path(args.serving).read_text())
    record = Path(args.record)
    if not record.is_file():
        # This run never started a refresh: nothing of ours to undo.
        print(f"{region}: no refresh was started by this run; nothing to roll back")
        return
    cancel_active_refresh(region, record.read_text().strip(), 1800)
    current = group(region)
    if str(current["LaunchTemplate"]["Version"]) == serving["version"] and not census_problems(
            current, targets(region, current), serving["version"]):
        print(f"{region}: already on the recorded previous template {serving['version']}")
        return
    refresh_id = start_refresh(region, serving["launch_template_id"], serving["version"])
    status = wait_refresh(region, refresh_id, args.timeout)
    if status != "Successful":
        raise SystemExit(f"{region}: rollback refresh ended {status}; operator recovery required")
    print(f"{region}: rolled back to template {serving['version']}")


def cmd_census(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    version = numbered(args.version)
    current = group(region)
    if str(current["LaunchTemplate"]["Version"]) != version:
        raise SystemExit(f"{region}: ASG names template {current['LaunchTemplate']['Version']}, not {version}")
    problems = census_problems(current, targets(region, current), version)
    if problems:
        raise SystemExit(f"{region}: census failed: {problems}")
    for member in sorted(m["InstanceId"] for m in current["Instances"]):
        probe_instance(region, member, args)
    print(f"{region}: all {len(current['Instances'])} members on template {version}, healthy and verified")


def cmd_terminate_candidate(args: argparse.Namespace) -> None:
    region = require_region(args.region)
    name = candidate_name(args.source, args.run_id, region)
    described = aws(region, "ec2", "describe-instances", "--filters", f"Name=tag:Name,Values={name}",
                    f"Name=tag:Project,Values={CANDIDATE_PROJECT}",
                    "Name=instance-state-name,Values=pending,running,stopping,stopped")
    ids = [i["InstanceId"] for r in described.get("Reservations", []) for i in r["Instances"]]
    if ids:
        aws(region, "ec2", "terminate-instances", "--instance-ids", *ids)
    print(f"{region}: terminated {ids or 'nothing'}")


def cmd_capture_narrow(args: argparse.Namespace) -> None:
    """Narrow the record and runtime pins to the measurement every member now
    serves, captured through one verified member's SSM forward."""
    region = require_region(args.region)
    if not SHA.fullmatch(args.source) or re.fullmatch(r"[0-9a-f]{96}", args.expected_pcr0) is None:
        raise SystemExit("invalid source or PCR0")
    current = group(region)
    member = sorted(m["InstanceId"] for m in current["Instances"])[0]
    with ssm_forward(region, member) as port:
        subprocess.run([sys.executable, str(ROOT / "tools" / "capture-plane-measurements.py"), "--plane", "aws",
                        "--write", "--repin-aws-monitor", "--aws-forward-port", str(port),
                        "--source-commit", args.source], cwd=ROOT, check=True, timeout=2400)
    record = json.loads((ROOT / "trust-page" / "trust" / "aws-release.json").read_text())
    if record.get("pcr0") != args.expected_pcr0 or record.get("accepted_pcr0s") != [args.expected_pcr0]:
        raise SystemExit("captured record does not narrow to exactly the CI measurement")
    print(f"narrowed to {args.expected_pcr0} via {member}")


def cmd_rehearse_reads(args: argparse.Namespace) -> None:
    """The reads a rollout makes that recording and verifying the serving fleet
    do not: those of candidate-version, launch-candidate, verify-instance,
    refresh, rollback, terminate-candidate and the control plane repin. Each is
    issued against what is serving now and its result discarded; a refusal
    names the call. Nothing here writes."""
    region = require_region(args.region)
    serving = json.loads(Path(args.serving).read_text())
    member = serving["instances"][0]
    if not INSTANCE.fullmatch(member):
        raise SystemExit("invalid instance id")
    aws(region, "ec2", "describe-launch-templates", "--launch-template-ids", serving["launch_template_id"])
    aws(region, "ec2", "describe-instances", "--filters", f"Name=tag:Project,Values={CANDIDATE_PROJECT}",
        "Name=instance-state-name,Values=pending,running,stopping,stopped")
    aws(region, "ec2", "describe-instances", "--instance-ids", member)
    aws(region, "ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={member}")
    aws(region, "autoscaling", "describe-instance-refreshes", "--auto-scaling-group-name", ASG, "--max-records", "1")
    # The repin registers a copy of the serving task definition with its tags.
    # A task definition can hold values that must not reach a log: the reply
    # is parsed for one field and never printed.
    sys.path.insert(0, str(ROOT))
    from tools import aws_fargate_pins

    surfaces = [(cluster, service) for surface, cluster, service in aws_fargate_pins.SURFACES if surface == region]
    if len(surfaces) != 1:
        raise SystemExit(f"{region}: expected exactly one control plane service")
    (cluster, service), = surfaces
    services = aws(region, "ecs", "describe-services", "--cluster", cluster, "--services", service)["services"]
    if len(services) != 1:
        raise SystemExit(f"{region}: control plane service {service} not found")
    aws(region, "ecs", "describe-task-definition", "--task-definition", services[0]["taskDefinition"],
        "--include", "TAGS")
    print(f"{region}: the candidate, refresh and repin reads are allowed")


def cmd_wait_kms(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(ROOT))
    from tools import aws_kms_admission

    accepted = [p for p in args.accepted.split(",") if p]
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            aws_kms_admission.check_keys(accepted)
            print("both recipient-only key policies admit exactly: " + ",".join(sorted(accepted)))
            return
        except (ValueError, TypeError, subprocess.SubprocessError) as exc:
            if time.monotonic() >= deadline:
                raise SystemExit(f"KMS key policies still differ from the admission set ({type(exc).__name__})")
            print(f"waiting for the reviewed KMS Terraform apply ({type(exc).__name__})", file=sys.stderr)
            time.sleep(60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def region_cmd(name: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name)
        p.add_argument("--region", required=True, choices=REGIONS)
        return p

    p = sub.add_parser("fetch-release")
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    p = region_cmd("serving")
    p.add_argument("--out", required=True)
    p = region_cmd("candidate-version")
    p.add_argument("--serving", required=True)
    p.add_argument("--log", required=True)
    p = region_cmd("compare-template")
    p.add_argument("--serving", required=True)
    p.add_argument("--release", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--accept-diff-sha256", default="")
    p = region_cmd("launch-candidate")
    p.add_argument("--serving", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--run-id", required=True)
    for name in ("verify-instance", "census"):
        p = region_cmd(name)
        if name == "verify-instance":
            p.add_argument("--instance", required=True)
        else:
            p.add_argument("--version", required=True)
        p.add_argument("--release", required=True)
        p.add_argument("--manifest", required=True)
        p.add_argument("--signature", required=True)
        p.add_argument("--bundle-version", type=int, required=True)
        p.add_argument("--boot-timeout", type=int, default=1500)
        p.add_argument("--negative-control", action="store_true")
    for name in ("refresh", "rollback"):
        p = region_cmd(name)
        p.add_argument("--serving", required=True)
        if name == "refresh":
            p.add_argument("--version", required=True)
        p.add_argument("--record", required=True, help="file holding the refresh id this run started")
        # The 2026-11-17 refreshes took about 36 minutes; leave headroom so a
        # slow but healthy refresh is not cancelled and rolled back.
        p.add_argument("--timeout", type=int, default=5400)
    p = region_cmd("terminate-candidate")
    p.add_argument("--source", required=True)
    p.add_argument("--run-id", required=True)
    p = region_cmd("capture-narrow")
    p.add_argument("--source", required=True)
    p.add_argument("--expected-pcr0", required=True)
    p = region_cmd("rehearse-reads")
    p.add_argument("--serving", required=True)
    p = sub.add_parser("wait-kms")
    p.add_argument("--accepted", required=True)
    p.add_argument("--timeout", type=int, default=0)
    args = parser.parse_args()
    handler = globals()["cmd_" + args.command.replace("-", "_")]
    try:
        handler(args)
    except AwsError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
