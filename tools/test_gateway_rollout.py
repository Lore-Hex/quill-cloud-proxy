"""Guards for the AWS and Azure gateway rollout workflows and their helpers.

The workflows automate docs/runbook-aws-enclave-release.md and
docs/runbooks/azure-enclave.md. These tests pin the safety order those
runbooks require, so a later edit cannot quietly reorder a drain after a
deploy, refresh a fleet before its candidate verified, or give CI a KMS write.
"""
from __future__ import annotations

import ast
import base64
import gzip
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import aws_gateway_rollout as aws  # noqa: E402
from tools import azure_gateway_rollout as azure  # noqa: E402
from tools import gateway_trust_pr as trust_pr  # noqa: E402

AWS_WF = ROOT / ".github/workflows/rollout-aws-gateway.yml"
AZURE_WF = ROOT / ".github/workflows/rollout-azure-gateway.yml"
OLD_SRC, NEW_SRC = "a" * 40, "b" * 40
OLD_SHA, NEW_SHA = "c" * 64, "d" * 64
PARENT = "330422590279.dkr.ecr.eu-west-3.amazonaws.com/quill-parent@sha256:" + "1" * 64
PUMP = "330422590279.dkr.ecr.eu-west-3.amazonaws.com/quill-parent-pump@sha256:" + "2" * 64


def user_data(source: str, sha: str, size: str, extra: str = "") -> str:
    script = (
        "#!/bin/bash\n"
        f"docker pull {PARENT}\n"
        f"docker pull {PUMP}\n"
        f"aws s3api get-object --key releases/{source}/{sha}/enclave.eif /opt/quill/enclave.eif.tmp\n"
        f'test "$(stat -c %s /opt/quill/enclave.eif.tmp)" = "{size}"\n'
        f"printf '%s  %s\\n' '{sha}' /opt/quill/enclave.eif.tmp | sha256sum --check --strict\n"
        f"{extra}"
    )
    return base64.b64encode(gzip.compress(script.encode())).decode()


def template(ud: str, instance_type: str = "m5.xlarge") -> dict:
    return {"ImageId": "ami-07dcdf1066ae9dad3", "InstanceType": instance_type,
            "SecurityGroupIds": ["sg-1"], "UserData": ud}


NEW_EIF = {"source": NEW_SRC, "eif_sha256": NEW_SHA, "eif_size": "700"}


class AwsTemplateGateTests(unittest.TestCase):
    def test_only_the_eif_identity_changing_is_an_empty_diff(self):
        old = template(user_data(OLD_SRC, OLD_SHA, "600"))
        new = template(user_data(NEW_SRC, NEW_SHA, "700"))
        self.assertEqual(aws.normalized_template_diff(old, new, NEW_EIF), "")
        aws.template_gate("", "")

    def test_any_other_change_needs_the_exact_reviewed_digest(self):
        old = template(user_data(OLD_SRC, OLD_SHA, "600"))
        for new in (template(user_data(NEW_SRC, NEW_SHA, "700", "echo drift\n")),
                    template(user_data(NEW_SRC, NEW_SHA, "700"), instance_type="m5.2xlarge")):
            diff = aws.normalized_template_diff(old, new, NEW_EIF)
            self.assertTrue(diff)
            with self.assertRaises(SystemExit):
                aws.template_gate(diff, "")
            with self.assertRaises(SystemExit):
                aws.template_gate(diff, "0" * 64)
            aws.template_gate(diff, hashlib.sha256(diff.encode()).hexdigest())

    def test_candidate_must_pin_the_requested_eif(self):
        old = template(user_data(OLD_SRC, OLD_SHA, "600"))
        with self.assertRaises(ValueError):
            aws.normalized_template_diff(old, template(user_data(OLD_SRC, OLD_SHA, "600")), NEW_EIF)

    def test_user_data_must_pin_exactly_one_artifact_set(self):
        doubled = aws.decode_user_data(user_data(OLD_SRC, OLD_SHA, "600")) + f"releases/{NEW_SRC}/{NEW_SHA}/enclave.eif\n"
        with self.assertRaises(ValueError):
            aws.eif_identity(doubled)
        identity = aws.eif_identity(aws.decode_user_data(user_data(OLD_SRC, OLD_SHA, "600")))
        self.assertEqual(identity["parent_digest"], "sha256:" + "1" * 64)
        self.assertEqual(identity["pump_digest"], "sha256:" + "2" * 64)

    def test_templates_are_numbered_never_latest_or_default(self):
        for bad in ("$Latest", "$Default", "0", "", None):
            with self.assertRaises(ValueError):
                aws.numbered(bad)
        self.assertEqual(aws.numbered(55), "55")

    def test_refresh_keeps_full_capacity_rollback_and_a_complete_last_checkpoint(self):
        prefs = aws.REFRESH_PREFERENCES
        self.assertEqual(prefs["MinHealthyPercentage"], 100)
        self.assertTrue(prefs["AutoRollback"])
        self.assertEqual(prefs["CheckpointPercentages"][-1], 100)
        self.assertGreaterEqual(prefs["InstanceWarmup"], 300)
        self.assertGreaterEqual(prefs["CheckpointDelay"], 900)
        self.assertGreaterEqual(prefs["BakeTime"], 300)
        self.assertFalse(prefs["SkipMatching"])

    def test_candidate_identity_is_never_the_serving_project(self):
        name = aws.candidate_name(NEW_SRC, "123", "eu-west-3")
        self.assertTrue(name.startswith(aws.CANDIDATE_PROJECT))
        self.assertNotEqual(aws.CANDIDATE_PROJECT, aws.SERVING_PROJECT)
        with self.assertRaises(ValueError):
            aws.candidate_name("main", "123", "eu-west-3")

    def test_census_requires_every_member_on_the_template_and_healthy_targets(self):
        group = {"DesiredCapacity": 2, "Instances": [
            {"InstanceId": "i-1", "LaunchTemplate": {"Version": "56"}, "LifecycleState": "InService", "HealthStatus": "Healthy"},
            {"InstanceId": "i-2", "LaunchTemplate": {"Version": "56"}, "LifecycleState": "InService", "HealthStatus": "Healthy"},
        ]}
        healthy = [{"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}},
                   {"Target": {"Id": "i-2"}, "TargetHealth": {"State": "healthy"}}]
        self.assertEqual(aws.census_problems(group, healthy, "56"), [])
        self.assertTrue(aws.census_problems(group, healthy, "55"))
        self.assertTrue(aws.census_problems(group, healthy[:1], "56"))
        draining = healthy + [{"Target": {"Id": "i-old"}, "TargetHealth": {"State": "draining"}}]
        self.assertTrue(aws.census_problems(group, draining, "56"))
        short = dict(group, DesiredCapacity=3)
        self.assertTrue(aws.census_problems(short, healthy, "56"))

    def test_the_rollout_tool_has_no_kms_iam_or_dns_write(self):
        text = (ROOT / "tools/aws_gateway_rollout.py").read_text()
        for forbidden in ("put-key-policy", "create-grant", "put-role-policy", "change-resource-record-sets",
                          "modify-launch-template", "update-auto-scaling-group", "register-targets"):
            self.assertNotIn(forbidden, text)


GATE_LOG = """[12:00:00] verify ok
[12:00:01] MEASUREMENT NOT PUBLISHED: this region attests hostdata
[12:00:01]   {hd}
[12:00:01] which is not in the published set
[12:00:01]       --azure-region quill-enclave-uaenorth={bundle},{commit},sha256:{digest}
"""


class AzureHelperTests(unittest.TestCase):
    def test_publication_args_come_from_the_deploy_gate(self):
        log = GATE_LOG.format(hd="e" * 64, bundle="f" * 32, commit="a" * 40, digest="b" * 64)
        value, hostdata = azure.publication_args(log, "dubai")
        self.assertEqual(value, f"quill-enclave-uaenorth={'f' * 32},{'a' * 40},sha256:{'b' * 64}")
        self.assertEqual(hostdata, "e" * 64)
        with self.assertRaises(ValueError):
            azure.publication_args(log, "sydney")
        with self.assertRaises(ValueError):
            azure.publication_args("[12:00:00] verify ok\n", "dubai")

    def test_hostdata_is_the_sha256_of_the_decoded_policy(self):
        policy = b"package policy\n"
        self.assertEqual(azure.hostdata_from_policy(base64.b64encode(policy).decode()),
                         hashlib.sha256(policy).hexdigest())

    def test_regions_roll_dubai_then_sydney_and_each_peer_is_the_other(self):
        self.assertEqual(azure.ORDER, ("dubai", "sydney"))
        self.assertEqual(azure.peer("dubai"), "sydney")
        self.assertEqual(azure.peer("sydney"), "dubai")
        self.assertGreaterEqual(azure.DRAIN_SECONDS, 330)

    def test_the_azure_tool_never_changes_a_key_or_container_group(self):
        text = (ROOT / "tools/azure_gateway_rollout.py").read_text()
        for forbidden in ("set-attributes", "container\", \"delete", "container\", \"create", "deployment\", \"group"):
            self.assertNotIn(forbidden, text)


class TrustPrTests(unittest.TestCase):
    def test_porcelain_parsing_keeps_the_first_character(self):
        raw = " M trust-page/trust/aws-release.json\0?? trust-page/trust/eif/a/b/manifest.json\0"
        self.assertEqual(trust_pr.parse_porcelain_z(raw), ["trust-page/trust/aws-release.json",
                                                           "trust-page/trust/eif/a/b/manifest.json"])
        with self.assertRaises(SystemExit):
            trust_pr.parse_porcelain_z("R  new\0old\0")

    def test_a_plane_pr_changes_only_that_planes_trust_files(self):
        trust_pr.require_only_plane_changes("aws", ["trust-page/trust/aws-release.json",
                                                    "trust-page/trust/eif/x/y/manifest.json"])
        for plane, stray in (("aws", "trust-page/trust/azure-release.json"),
                             ("azure", "trust-page/trust/aws-release.json"),
                             ("aws", "tools/aws_gateway_rollout.py")):
            with self.assertRaises(SystemExit):
                trust_pr.require_only_plane_changes(plane, [stray])
        with self.assertRaises(SystemExit):
            trust_pr.require_only_plane_changes("azure", [])

    def test_checks_verdict(self):
        required = [{"__typename": "CheckRun", "name": n, "status": "COMPLETED", "conclusion": "SUCCESS"}
                    for n in trust_pr.REQUIRED_CHECKS]
        done = {"__typename": "CheckRun", "name": "other", "status": "COMPLETED", "conclusion": "SUCCESS"}
        self.assertEqual(trust_pr.checks_verdict([done]), "pending", "required contexts missing")
        done_all = required + [done]
        running = {"__typename": "CheckRun", "status": "IN_PROGRESS", "conclusion": ""}
        failed = {"__typename": "CheckRun", "status": "COMPLETED", "conclusion": "FAILURE"}
        self.assertEqual(trust_pr.checks_verdict([]), "pending")
        self.assertEqual(trust_pr.checks_verdict(done_all), "success")
        self.assertEqual(trust_pr.checks_verdict(done_all + [running]), "pending")
        self.assertEqual(trust_pr.checks_verdict([running, failed]), "failure")


def steps_of(job: dict) -> list[str]:
    return [step.get("name") or step.get("uses", "") for step in job["steps"]]


def index_of(names: list[str], fragment: str) -> int:
    matches = [i for i, name in enumerate(names) if fragment in name]
    assert len(matches) == 1, (fragment, matches)
    return matches[0]


class WorkflowGuardTests(unittest.TestCase):
    def load(self, path: Path) -> dict:
        workflow = yaml.safe_load(path.read_text())
        # PyYAML reads the bare `on:` key as boolean True.
        workflow["on"] = workflow.pop(True, workflow.get("on"))
        return workflow

    def common(self, workflow: dict, cloud: str, unreserved: frozenset[str] = frozenset()) -> None:
        # `unreserved` names the jobs of this one workflow that hold no
        # reservation because they replace nothing. The caller that passes a
        # name owns the test that pins what that job runs.
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertTrue(workflow["on"]["workflow_dispatch"]["inputs"]["release_sha"]["required"])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        jobs = workflow["jobs"]
        self.assertIn("refs/heads/main", jobs["preflight"]["if"])
        acquire = "\n".join(s.get("run", "") for s in jobs["admit-cloud"]["steps"])
        self.assertIn(f"cloud-rollout.py acquire --cloud {cloud}", acquire)
        final = jobs["finalize-cloud"]
        self.assertIn("always()", final["if"])
        release = "\n".join(s.get("run", "") for s in final["steps"])
        self.assertIn(f"cloud-rollout.py release --cloud {cloud}", release)
        self.assertEqual(set(final["needs"]), set(jobs) - {"preflight", "finalize-cloud"} - unreserved)
        for name, job in jobs.items():
            if name in {"preflight", "admit-cloud", "finalize-cloud"} | unreserved:
                continue
            self.assertIn("admit-cloud", job["needs"], name)
            self.assertEqual(job["env"]["TR_DEPLOY_MUTEX_CLOUD"] if "env" in job and "TR_DEPLOY_MUTEX_CLOUD" in job["env"] else cloud, cloud)
            self.assertLessEqual(job.get("timeout-minutes", 360), 355, name)
        text = path_text = yaml.safe_dump(workflow)
        for forbidden in ("bash -x", "set -x", "put-key-policy", "TR_CLOUD_BAKE_OVERRIDE", "--force", "--admin"):
            self.assertNotIn(forbidden, path_text, forbidden)
        del text

    def test_aws_workflow_order(self):
        workflow = self.load(AWS_WF)
        # test_aws_rehearsal_reserves_and_writes_nothing pins that job.
        self.common(workflow, "aws", unreserved=frozenset({"rehearse"}))
        jobs = workflow["jobs"]
        self.assertEqual(jobs["stage-admission"]["needs"], ["preflight", "admit-cloud"])
        self.assertIn("stage-admission", jobs["kms-widen"]["needs"])
        self.assertIn("kms-widen", jobs["widen-runtime"]["needs"])
        self.assertIn("widen-runtime", jobs["fleet"]["needs"])
        self.assertIn("fleet", jobs["narrow"]["needs"])
        names = steps_of(jobs["fleet"])
        last = -1
        for region in ("Paris", "Dublin"):
            order = [index_of(names, f"{region}: {step}") for step in (
                "record the serving fleet", "generate the numbered candidate template",
                "the candidate changes only", "launch one standalone candidate",
                "verify the candidate over SSM", "terminate the candidate",
                "refresh the ASG", "census", "fresh AWS session for rollback", "roll back")]
            self.assertEqual(order, sorted(order), region)
            self.assertGreater(order[0], last, "Paris completes before Dublin starts")
            last = order[-1]
        fleet_steps = {s.get("name"): s for s in jobs["fleet"]["steps"]}
        for region in ("Paris", "Dublin"):
            self.assertEqual(fleet_steps[f"{region}: terminate the candidate"]["if"], "always()")
            self.assertIn("--negative-control", fleet_steps[f"{region}: verify the candidate over SSM, with a negative control"]["run"])
            self.assertIn("CANDIDATE_TEMPLATE_ONLY=1", fleet_steps[f"{region}: generate the numbered candidate template only"]["run"])
        narrow = "\n".join(s.get("run", "") for s in jobs["narrow"]["steps"])
        self.assertIn("capture-narrow", narrow)
        self.assertIn("release-aws-enclave.sh --verify-only", narrow)
        role = workflow["env"]["AWS_ROLLOUT_ROLE_ARN"]
        self.assertEqual(role, "arn:aws:iam::330422590279:role/trustedrouter-github-gateway-rollout")

    def test_aws_bundle_version_must_be_stated(self):
        # A default goes stale the next time a bundle is sealed, and a stale
        # number is refused only at the candidate, after the reservation.
        declared = self.load(AWS_WF)["on"]["workflow_dispatch"]["inputs"]["bundle_version"]
        self.assertEqual(set(declared), {"description", "required", "type"})
        self.assertIs(declared["required"], True)
        self.assertEqual(declared["type"], "string")
        runbook = (ROOT / "docs/runbook-aws-enclave-release.md").read_text()
        dispatches = re.findall(r"gh workflow run rollout-aws-gateway\.yml[^~]*?bundle_version=(\S+)", runbook)
        self.assertEqual(dispatches, ["<version>", "<version>"])
        self.assertIn("curl -s https://api-aws.trustedrouter.com/health | jq .aws_bootstrap.bundle_version", runbook)

    def test_aws_rehearsal_reserves_and_writes_nothing(self):
        workflow = self.load(AWS_WF)
        jobs = workflow["jobs"]
        declared = workflow["on"]["workflow_dispatch"]["inputs"]["rehearse"]
        self.assertEqual(declared["type"], "boolean")
        self.assertIs(declared["default"], False)
        job = jobs["rehearse"]
        self.assertEqual(job["needs"], "preflight")
        self.assertEqual(job["if"], "${{ inputs.rehearse }}")
        # A rehearsal never becomes a rollout: the reservation, and with it
        # every job that stages, widens, refreshes or narrows, is for the
        # other value only.
        self.assertEqual(jobs["admit-cloud"]["if"], "${{ !inputs.rehearse }}")
        for name in ("stage-admission", "kms-widen", "widen-runtime", "fleet", "narrow"):
            self.assertIn("admit-cloud", jobs[name]["needs"])
            self.assertNotIn("if", jobs[name])
        self.assertEqual(jobs["finalize-cloud"]["if"], "${{ always() && needs.admit-cloud.result == 'success' }}")
        # The whole job is pinned, not searched for known-bad words: its
        # keys, its environment, its steps in order, and every line each
        # step runs. A step may carry nothing that lets it pass unverified.
        self.assertEqual(set(job), {"needs", "if", "runs-on", "timeout-minutes", "permissions", "env", "steps"})
        self.assertEqual(job["runs-on"], "ubuntu-latest")
        self.assertEqual(job["timeout-minutes"], 100)
        self.assertEqual(job["env"], {"BUNDLE_VERSION": "${{ inputs.bundle_version }}"})
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(set(workflow["env"]), {
            "RELEASE_SHA", "AWS_ROLLOUT_ROLE_ARN", "AWS_ROLLOUT_SESSION_SECONDS", "STRICT_BOOTSTRAP_SOURCE"})
        self.assertNotIn("secrets.", str(workflow["env"]))
        self.assertEqual(
            [s["uses"].split("@")[0].rsplit("/", 1)[-1] if "uses" in s else s["name"] for s in job["steps"]],
            ["checkout", "setup-uv", "Install locked attestation dependencies in isolation", "gcp-auth",
             "setup-gcloud", "aws-credentials", "cosign-install", "Rehearsal: tools and both cloud identities",
             "Rehearsal: a token without pull request write is refused the same request",
             "Rehearsal: the trust token may open a pull request (none is opened)",
             "Rehearsal: published set, runtime pins and live endpoint as they stand",
             "Rehearsal: Paris, every serving member verified over SSM",
             "Rehearsal: Dublin, every serving member verified over SSM",
             "Rehearsal: the template generator's lookups for this release, without --apply",
             "Rehearsal: the remaining reads of the candidate, refresh and repin steps"])
        # One step, and only that step, holds the trust token: it runs the
        # helper's probe and nothing else.
        # The step before it asks the same question with this job's own
        # token, which the job's permissions keep from opening pull requests.
        control = job["steps"].pop(8)
        self.assertEqual(control, {
            "name": "Rehearsal: a token without pull request write is refused the same request",
            "env": {"GH_TOKEN": "${{ github.token }}"},
            "run": "python3 tools/gateway_trust_pr.py probe-token --expect-refusal",
        })
        self.assertNotIn("pull-requests", job["permissions"])
        self.assertNotIn("pull-requests", workflow["permissions"])
        probe = job["steps"].pop(8)
        self.assertEqual(probe, {
            "name": "Rehearsal: the trust token may open a pull request (none is opened)",
            "env": {"GH_TOKEN": "${{ secrets.TRUST_PUSH_TOKEN }}"},
            "run": "python3 tools/gateway_trust_pr.py probe-token",
        })
        for step in job["steps"]:
            self.assertNotIn("secrets.", str(step))
            self.assertIn(set(step), ({"uses"}, {"uses", "with"}, {"name", "run"}), step)
        # The setup is the fleet job's own, step for step and value for
        # value, so the rehearsal runs with the tools, the identities and the
        # four-hour session a rollout will have.
        self.assertEqual(job["steps"][:7], jobs["fleet"]["steps"][:7])
        self.assertEqual(job["steps"][0]["with"], {"ref": "main", "fetch-depth": 0, "persist-credentials": False})
        self.assertEqual(job["steps"][5]["with"]["role-duration-seconds"], "${{ env.AWS_ROLLOUT_SESSION_SECONDS }}")
        self.assertEqual(job["steps"][7]["run"].splitlines(), [
            "set -euo pipefail",
            '[[ "$BUNDLE_VERSION" =~ ^[1-9][0-9]{0,5}$ ]] || { echo "::error::bundle_version must be a positive integer"; exit 1; }',
            "session-manager-plugin --version",
            "gcloud auth print-access-token > /dev/null",
            'python3 tools/aws_gateway_rollout.py fetch-release --source "$RELEASE_SHA" --out "$RUNNER_TEMP/release"',
        ])
        # The one step that waits: it stops at the first pass, and thirty
        # refusals a minute apart end it red. Nothing else runs in the loop.
        self.assertEqual(job["steps"][8]["run"].splitlines(), [
            "set -euo pipefail",
            "for attempt in $(seq 1 30); do",
            "  if bash tools/release-aws-enclave.sh --verify-only; then exit 0; fi",
            '  echo "The published-state check did not pass (attempt $attempt of 30). If a router deploy is moving the '
            'AWS control plane, it passes once that step ends; next attempt in 60 s."',
            "  sleep 60",
            "done",
            'echo "::error::the published-state check did not pass in 30 attempts, one minute apart"',
            "exit 1",
        ])
        for step, region in ((job["steps"][9], "eu-west-3"), (job["steps"][10], "eu-west-1")):
            serving, release = f'"$RUNNER_TEMP/serving-{region}.json"', f"$RUNNER_TEMP/serving-release-{region}"
            self.assertEqual(step["run"].splitlines(), [
                "set -euo pipefail",
                f"python3 tools/aws_gateway_rollout.py serving --region {region} --out {serving}",
                f'python3 tools/aws_gateway_rollout.py fetch-release --source "$(jq -r .source {serving})" \\',
                f'  --out "{release}"',
                f'python3 tools/aws_gateway_rollout.py census --region {region} --version "$(jq -r .version {serving})" \\',
                f'  --release "{release}/release.json" --manifest "{release}/manifest.json" \\',
                f'  --signature "{release}/manifest.json.bundle" --bundle-version "$BUNDLE_VERSION" --boot-timeout 300',
            ])
        # The generator runs as the fleet job runs it, one region after the
        # other, with one difference: no --apply.
        generator = job["steps"][11]["run"].splitlines()
        self.assertEqual(generator, [
            "set -euo pipefail",
            "for region in eu-west-3 eu-west-1; do",
            '  parent="$(python3 tools/aws_tls_parent.py --source "$RELEASE_SHA" --region "$region" --serving "$RUNNER_TEMP/serving-$region.json")"',
            '  AWS_REGION="$region" \\',
            '  AWS_EIF_MANIFEST="$RUNNER_TEMP/release/manifest.json" \\',
            '  AWS_EIF_SIGNATURE="$RUNNER_TEMP/release/manifest.json.bundle" \\',
            '  AWS_EIF_SOURCE_COMMIT="$RELEASE_SHA" \\',
            '  AWS_PARENT_IMAGE_DIGEST="$parent" \\',
            '  AWS_PARENT_PUMP_IMAGE_DIGEST="$(jq -r .pump_digest "$RUNNER_TEMP/serving-$region.json")" \\',
            "  CANDIDATE_TEMPLATE_ONLY=1 \\",
            "    bash tools/deploy-aws-nitro.sh --phase compute",
            "done",
        ])
        fleet_steps = {s.get("name"): s for s in jobs["fleet"]["steps"]}
        for city, region in (("Paris", "eu-west-3"), ("Dublin", "eu-west-1")):
            real = fleet_steps[f"{city}: generate the numbered candidate template only"]["run"].splitlines()
            call = real.index("  bash tools/deploy-aws-nitro.sh --apply --phase compute 2>&1 | tee "
                              f'"$RUNNER_TEMP/compute-{region}.log"')
            self.assertEqual(
                [line.strip().replace(region, "$region") for line in real[1:call]],
                [line.strip().replace('"$region"', "$region") for line in generator[2:10]], city)
        self.assertEqual(job["steps"][12]["run"].splitlines(), [
            "set -euo pipefail",
            "for region in eu-west-3 eu-west-1; do",
            '  python3 tools/aws_gateway_rollout.py rehearse-reads --region "$region" --serving "$RUNNER_TEMP/serving-$region.json"',
            "done",
            'echo "## AWS gateway rollout rehearsal: release \\`$RELEASE_SHA\\` authenticated; the published state, both '
            "serving fleets, the template generator's lookups and the candidate, refresh and repin reads all passed "
            "with the rollout role. The trust token may open a pull request and read its checks. Nothing reserved or "
            "written. Not covered: "
            "the key policy reads, the journal, the trust token's branch push and merge, and every write.\" "
            '>> "$GITHUB_STEP_SUMMARY"',
        ])

    def test_trust_token_probe_asks_without_opening_anything(self):
        # The probe's whole effect on GitHub is one refused request and reads.
        # It names a head that cannot exist, and treats any answer but the
        # refusal of that head as a failure.
        source = Path(trust_pr.__file__).read_text()
        function = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef) and node.name == "probe_token")
        body = ast.get_source_segment(source, function)
        commands = [[element.value for element in node.elts if isinstance(element, ast.Constant)]
                    for node in ast.walk(function) if isinstance(node, ast.List)
                    and node.elts and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "gh"]
        self.assertEqual(commands, [
            ["gh", "api", "-i", "-X", "POST", "-f", "title=permission probe", "-f", "-f", "base=main"],
            ["gh", "pr", "list", "--repo", "--state", "merged", "--limit", "1", "--json", "number"],
            ["gh", "run", "list", "--repo", "--workflow", "--limit", "1", "--json", "databaseId"],
        ])
        self.assertIn('head = "bot/no-such-branch-" + os.urandom(8).hex()', body)
        self.assertIn('"-f", f"head={head}"', body)
        self.assertIn('f"repos/{REPO}/pulls"', body)
        code = body.replace(ast.get_docstring(function, clean=False), "").replace("subprocess.run(", "")
        for forbidden in ("git", "push", '"merge"', "pr merge", "pr create", "open_and_merge", "run(", "update-branch"):
            self.assertNotIn(forbidden, code, forbidden)
        self.assertEqual(code.count("print("), 2)
        self.assertNotIn("stdout)", code.replace('(answer.stdout or "")', "").replace("json.loads(merged.stdout)", ""))
        self.assertNotIn("stderr", code)
        # Its one other helper only reads.
        view = ast.get_source_segment(source, next(
            node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "pr_state"))
        self.assertIn('run("gh", "pr", "view", str(number), "--repo", REPO, "--json",', view)

        refused_head = ('HTTP/2.0 422 Unprocessable Entity\r\n\r\n{"message":"Validation Failed","errors":'
                        '[{"resource":"PullRequest","field":"head","code":"invalid"}],"status":"422"}')
        forbidden = 'HTTP/2.0 403 Forbidden\r\n\r\n{"message":"Resource not accessible by integration"}'
        rollup = [{"__typename": "CheckRun", "name": name, "status": "COMPLETED", "conclusion": "SUCCESS"}
                  for name in trust_pr.REQUIRED_CHECKS]

        def github(api: str, *, merged: str = '[{"number": 7}]', listing: int = 0, view: dict | None = None,
                   view_code: int = 0, runs: int = 0):
            calls: list[list[str]] = []
            view = {"state": "MERGED", "statusCheckRollup": rollup} if view is None else view

            def fake(command, **kwargs):
                command = list(command)
                calls.append(command)
                if command[:2] == ["gh", "api"]:
                    self.assertEqual(kwargs.get("capture_output"), True)
                    return subprocess.CompletedProcess(command, 1, api, "")
                if command[:3] == ["gh", "pr", "list"]:
                    return subprocess.CompletedProcess(command, listing, merged, "")
                if command[:3] == ["gh", "pr", "view"]:
                    self.assertEqual(command[3], "7")
                    if view_code:
                        raise subprocess.CalledProcessError(view_code, command)
                    return subprocess.CompletedProcess(command, 0, json.dumps(view), "")
                self.assertEqual(command[:3], ["gh", "run", "list"])
                return subprocess.CompletedProcess(command, runs, "[]", "")
            return calls, fake

        def probe(expect_refusal: bool = False, **answers) -> list[list[str]]:
            calls, fake = github(**answers)
            original = trust_pr.subprocess.run
            trust_pr.subprocess.run = fake
            try:
                trust_pr.probe_token(expect_refusal)
            finally:
                trust_pr.subprocess.run = original
            return calls

        # A permitted token: the refusal of the head, then only reads.
        self.assertEqual([call[:3] for call in probe(api=refused_head)], [
            ["gh", "api", "-i"], ["gh", "pr", "list"], ["gh", "pr", "view"], ["gh", "run", "list"], ["gh", "run", "list"]])
        # Any other answer to the request fails and sends nothing further.
        for api in (forbidden, 'HTTP/2.0 404 Not Found\r\n\r\n{"message":"Not Found"}',
                    'HTTP/2.0 422 Unprocessable Entity\r\n\r\n{"errors":[{"field":"base","code":"invalid"}]}',
                    'HTTP/2.0 201 Created\r\n\r\n{"number":1}', ""):
            calls: list[list[str]] = []
            with self.assertRaises(SystemExit, msg=api[:40]):
                calls = probe(api=api)
            self.assertEqual(calls, [])
        # Permitted to open, but unable to read what open-and-merge reads.
        for answers, said in (
            ({"listing": 1}, ", ".join(trust_pr.REQUIRED_CHECKS)),
            ({"merged": "[]"}, ", ".join(trust_pr.REQUIRED_CHECKS)),
            ({"view_code": 1}, ", ".join(trust_pr.REQUIRED_CHECKS)),
            ({"view": {"state": "MERGED", "statusCheckRollup": rollup[:1]}}, trust_pr.REQUIRED_CHECKS[1]),
            ({"view": {"state": "MERGED", "statusCheckRollup": []}}, ", ".join(trust_pr.REQUIRED_CHECKS)),
            ({"view": {"state": "OPEN", "statusCheckRollup": rollup}}, "the pull request"),
            ({"runs": 1}, "Actions: read"),
        ):
            with self.assertRaises(SystemExit, msg=str(answers)) as refused:
                probe(api=refused_head, **answers)
            self.assertIn(said, str(refused.exception), answers)
        # The control: a token without the permission must be refused, and
        # the head's refusal there means the probe tells nothing.
        for api in (forbidden, 'HTTP/2.0 404 Not Found\r\n\r\n{"message":"Not Found"}'):
            self.assertEqual([call[:3] for call in probe(True, api=api)], [["gh", "api", "-i"]])
        for api in (refused_head, 'HTTP/2.0 201 Created\r\n\r\n{"number":1}', "",
                    'HTTP/2.0 500 Internal Server Error\r\n\r\n{}'):
            with self.assertRaises(SystemExit, msg=api[:40]):
                probe(True, api=api)

    def test_aws_rehearsal_commands_only_read(self):
        # Everything the rehearsal's four helper commands can reach, followed
        # through the helper's own call graph, reads or opens a port forward.
        source = Path(aws.__file__).read_text()
        functions = {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
        verb = re.compile(r'"(?:autoscaling|ec2|ecr|ecs|elbv2|iam|kms|s3api|ssm|sts)",\s*"([a-z0-9-]+)"')

        def reach(*roots: str) -> set[str]:
            seen: set[str] = set()
            pending = list(roots)
            while pending:
                name = pending.pop()
                if name in seen:
                    continue
                seen.add(name)
                pending += [node.id for node in ast.walk(functions[name])
                            if isinstance(node, ast.Name) and node.id in functions]
            return seen

        def verbs(names: set[str]) -> set[str]:
            return {found for name in names for found in verb.findall(ast.get_source_segment(source, functions[name]))}

        rehearsed = reach("cmd_fetch_release", "cmd_serving", "cmd_census", "cmd_rehearse_reads")
        self.assertEqual(verbs(rehearsed), {
            "describe-auto-scaling-groups", "describe-instance-information", "describe-instance-refreshes",
            "describe-instances", "describe-launch-template-versions", "describe-launch-templates",
            "describe-services", "describe-target-health", "describe-task-definition", "get-object",
            "list-objects-v2", "start-session"})
        # The scan is not blind: it sees the helper's writes, all of them in
        # commands a rehearsal never runs, and no other command has a read
        # that the rehearsal lacks.
        everything = verbs(set(functions))
        self.assertEqual(everything - verbs(rehearsed), {
            "run-instances", "terminate-instances", "start-instance-refresh", "cancel-instance-refresh"})
        self.assertFalse(rehearsed & {"cmd_launch_candidate", "cmd_refresh", "cmd_rollback", "cmd_terminate_candidate",
                                      "cmd_capture_narrow", "cmd_wait_kms", "start_refresh", "cancel_active_refresh"})
        # The reply of the task definition read is never printed.
        reads = ast.get_source_segment(source, functions["cmd_rehearse_reads"])
        self.assertEqual(reads.count("print("), 1)
        self.assertIn('print(f"{region}: the candidate, refresh and repin reads are allowed")', reads)
        # release-aws-enclave.sh --verify-only is one read-only check.
        script = (ROOT / "tools/release-aws-enclave.sh").read_text()
        self.assertIn("  --verify-only)\n    exec python3 tools/capture-plane-measurements.py --plane aws --check-published\n", script)
        capture = (ROOT / "tools/capture-plane-measurements.py").read_text()
        self.assertIn('parser.error("--check-published is read-only")', capture)

    def test_aws_template_generator_without_apply_writes_no_template(self):
        # The rehearsal runs deploy-aws-nitro.sh --phase compute without
        # --apply. That is only a rehearsal while the script starts in its
        # dry-run mode, takes no reservation there, and guards each write on
        # the path a candidate-only run takes.
        script = (ROOT / "tools/deploy-aws-nitro.sh").read_text()
        self.assertIn('\nDRY_RUN=1\nPHASE="all"\n', script)
        self.assertEqual(re.findall(r"DRY_RUN=0", script), ["DRY_RUN=0"])
        self.assertIn("    --apply) DRY_RUN=0; shift ;;\n", script)
        self.assertIn('if [ "$DRY_RUN" -eq 0 ]; then\n  source "${SCRIPT_DIR}/cloud-rollout-guard.sh"\n'
                      "  require_cloud_rollout aws\n", script)
        compute = script[script.index("\nphase_compute() {\n"):]
        stop = ('  if [ "$CANDIDATE_TEMPLATE_ONLY" -eq 1 ]; then\n'
                '    log "  candidate launch-template version ${lt_version} created; default, ASG, targets and DNS unchanged"\n'
                "    return 0\n  fi\n")
        candidate = compute[:compute.index(stop)]
        # The host's own boot script is text here, not calls this script makes.
        boot = candidate[candidate.index("  user_data=$(cat <<EOS\n"):candidate.index("\nEOS\n")]
        made = candidate.replace(boot, "")
        calls = re.findall(r"\baws ([a-z0-9]+) ([a-z0-9-]+)", made)
        self.assertEqual(sorted(calls), sorted([
            ("s3api", "head-object"), ("ec2", "describe-security-groups"), ("ec2", "describe-security-groups"),
            ("ec2", "describe-subnets"), ("iam", "get-instance-profile"), ("ec2", "describe-launch-templates"),
            ("autoscaling", "describe-auto-scaling-groups"), ("ec2", "create-launch-template"),
            ("ec2", "create-launch-template-version"), ("ec2", "modify-launch-template")]))
        # No call goes through the script's `run` wrapper on this path either.
        self.assertEqual(re.findall(r"(?m)^\s*(?:\S+=\$\()?run\s", made), [])
        writes = made[made.index('  local lt_version="DRY_RUN"\n'):]
        self.assertEqual(writes.count("aws ec2 "), 3)
        guarded = re.findall(r"(?m)^    if \[ \$DRY_RUN -eq 0 \]; then\n(.*?)^    fi\n", writes, flags=re.S)
        self.assertEqual(len(guarded), 2)
        self.assertEqual("".join(guarded).count("aws ec2 "), 3)
        self.assertIn("aws ec2 create-launch-template --region", guarded[0])
        self.assertIn("aws ec2 create-launch-template-version --region", guarded[1])
        self.assertIn("aws ec2 modify-launch-template --region", guarded[1])
        # The admission check a real run makes first is also for --apply only:
        # a rehearsed release is not staged yet.
        self.assertIn('  if [ "$DRY_RUN" -eq 0 ]; then\n'
                      '    (cd "$SCRIPT_DIR/.." && python3 -m tools.aws_eif_admission check-ready \\\n', candidate)
        # Image lookups happen before the generator and are reads.
        resolve = script[script.index("\nresolve_parent_image() {\n"):script.index("\nphase_compute() {\n")]
        self.assertEqual(set(re.findall(r"\baws ([a-z0-9]+) ([a-z0-9-]+)", resolve)), {("ecr", "describe-images")})

    def test_azure_workflow_drains_before_replacing_and_narrows_after_publishing(self):
        workflow = self.load(AZURE_WF)
        # test_azure_rehearsal_reserves_and_replaces_nothing pins that job.
        self.common(workflow, "azure", unreserved=frozenset({"rehearse"}))
        jobs = workflow["jobs"]
        for name in ("preflight", "dubai", "sydney"):
            self.assertEqual(jobs[name]["environment"], "azure-gateway-rollout")
        self.assertIn("dubai", jobs["sydney"]["needs"], "Sydney waits for Dubai")
        for region in ("Dubai", "Sydney"):
            names = steps_of(jobs[region.lower()])
            order = [index_of(names, f"{region}: {step}") for step in (
                "drain its Traffic Manager endpoint", "build, bind (widen), deploy and verify",
                "restore the previous key release policy", "read the publication gate", "publish its measurement",
                "narrow the key release policy", "re-enable its endpoint")]
            self.assertEqual(order, sorted(order), region)
            restore = next(s for s in jobs[region.lower()]["steps"] if s.get("name", "").startswith(f"{region}: restore"))
            self.assertEqual(restore["if"], f"${{{{ failure() && steps.deploy_{region.lower()}.outcome == 'failure' }}}}")
        text = AZURE_WF.read_text()
        self.assertNotIn("--apply all", text)
        self.assertIn("--apply preflight template policy bind deploy verify", text)
        self.assertNotIn("--apply preflight build", text)
        gate = next(s["run"] for s in jobs["preflight"]["steps"] if s.get("id") == "qualified")
        for required in ("stage-qualified-oci.yml", '.workflow_id == $id', '.head_branch == "main"',
                         '.conclusion == "success"', "--signer-workflow", "--deny-self-hosted-runners",
                         '--source-ref refs/heads/main --source-digest "$sha"', 'receipt "$receipt" "$RELEASE_SHA"',
                         '--image "quill-enclave-azure@$digest"', '[[ "$actual" == "$digest" ]]'):
            self.assertIn(required, gate)
        for region in ("dubai", "sydney"):
            drain = next(s["run"] for s in jobs[region]["steps"] if s.get("id") == "drain_" + region)
            self.assertLess(drain.index('azure_qualified_image.py prepare'), drain.index('azure_gateway_rollout.py drain'))
            self.assertEqual(jobs[region]["env"]["QUALIFIED_DIGEST"], "${{ needs.preflight.outputs.qualified_digest }}")
        self.assertIn("env -u GOOGLE_APPLICATION_CREDENTIALS", text)
        dubai_publish = next(s for s in jobs["dubai"]["steps"] if s.get("name", "").startswith("Dubai: publish"))
        sydney_publish = next(s for s in jobs["sydney"]["steps"] if s.get("name", "").startswith("Sydney: publish"))
        self.assertIn("--keep-accepted", dubai_publish["run"])
        self.assertNotIn("--keep-accepted", sydney_publish["run"])

    def test_azure_workflow_runs_the_deploy_script_through_bash(self):
        # The script is not executable in every release commit the workflow may
        # check out, and "./tools/x.sh" then stops with exit 126 after the
        # region is drained.
        text = AZURE_WF.read_text()
        calls = re.findall(r"(\S*)[ \t]+\./tools/deploy-azure-aci\.sh", text)
        self.assertGreaterEqual(len(calls), 10, calls)
        self.assertEqual(set(calls), {"bash"})

    def test_azure_rehearsal_reserves_and_replaces_nothing(self):
        workflow = self.load(AZURE_WF)
        jobs = workflow["jobs"]
        declared = workflow["on"]["workflow_dispatch"]["inputs"]["rehearse"]
        self.assertEqual(declared["type"], "boolean")
        self.assertIs(declared["default"], False)
        job = jobs["rehearse"]
        self.assertEqual(job["needs"], "preflight")
        self.assertEqual(job["if"], "${{ inputs.rehearse }}")
        self.assertEqual(job["environment"], "azure-gateway-rollout")
        # A rehearsal never becomes a rollout: the reservation, and with it
        # every job that replaces a region, is for the other value only.
        self.assertEqual(jobs["admit-cloud"]["if"], "${{ !inputs.rehearse }}")
        for name in ("dubai", "sydney"):
            self.assertIn("admit-cloud", jobs[name]["needs"])
            self.assertNotIn("if", jobs[name])
        self.assertEqual(jobs["finalize-cloud"]["if"], "${{ always() && needs.admit-cloud.result == 'success' }}")
        # The whole job is pinned, not searched for known-bad words: its
        # environment, its steps in order, and every line the last step runs.
        self.assertEqual(set(job["env"]), {"BUNDLE_VERSION", "QUALIFIED_DIGEST"})
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(
            [s["uses"].split("@")[0].rsplit("/", 1)[-1] if "uses" in s else s["name"] for s in job["steps"]],
            ["checkout", "checkout", "setup-uv", "Install locked attestation dependencies in isolation",
             "cosign-install", "The checked-out release is exactly the requested commit",
             "Rehearsal: Dubai's preflight, build, template and policy, then the key audit"])
        for step in job["steps"]:
            self.assertNotIn("TRUST_PUSH_TOKEN", str(step.get("with", "")) + str(step.get("env", "")))
            self.assertNotIn("if", step)
        installs = dict(jobs["dubai"]["steps"][3])
        self.assertEqual(job["steps"][3], installs)
        self.assertEqual(job["steps"][5]["run"], 'test "$(git -C src rev-parse HEAD)" = "$RELEASE_SHA"')
        rehearsal = job["steps"][6]
        self.assertEqual(set(rehearsal), {"name", "working-directory", "run"})
        self.assertEqual(rehearsal["working-directory"], "src")
        self.assertEqual(rehearsal["run"].splitlines(), [
            "set -euo pipefail",
            "bash ../trust/tools/azure-oidc-login.sh",
            "set -a",
            'eval "$(python3 ../trust/tools/azure_gateway_rollout.py env --region dubai)"',
            "set +a",
            'python3 ../trust/tools/azure_qualified_image.py prepare "$RUNNER_TEMP/aci-rehearsal" "$RELEASE_SHA" "$QUALIFIED_DIGEST"',
            'WORKDIR="$RUNNER_TEMP/aci-rehearsal" QUILL_AZURE_BUNDLE_VERSION="$BUNDLE_VERSION" \\',
            "  TR_CONTROL_PLANE_BASE_URL=https://trustedrouter.com \\",
            "  bash ./tools/deploy-azure-aci.sh --apply preflight template policy",
            'WORKDIR="$RUNNER_TEMP/aci-rehearsal" QUILL_AZURE_BUNDLE_VERSION="$BUNDLE_VERSION" \\',
            "  bash ./tools/deploy-azure-aci.sh audit",
            'echo "## Azure gateway rollout rehearsal: release \\`$RELEASE_SHA\\` built, rendered, measured and audited; '
            'nothing reserved or replaced." >> "$GITHUB_STEP_SUMMARY"',
        ])
        # The phases above are the ones deploy-azure-aci.sh runs without the
        # reservation; the guarded ones are named in its own dispatch.
        script = (ROOT / "tools/deploy-azure-aci.sh").read_text()
        guarded = re.search(r"^    ([a-z|-]+)\)\n      if \[ \"\$APPLY\" = \"1\" \]; then\n        source [^\n]*cloud-rollout-guard\.sh", script, flags=re.M)
        self.assertIsNotNone(guarded)
        self.assertEqual(set(guarded.group(1).split("|")), {"all", "bind", "deploy", "narrow", "narrow-live", "rollback"})
        self.assertFalse({"preflight", "build", "template", "policy", "audit"} & set(guarded.group(1).split("|")))
        # The peer check belongs to a rollout: a rehearsal may run while a region is drained.
        peer = next(s for s in jobs["preflight"]["steps"] if "peer-check" in s.get("run", ""))
        self.assertEqual(peer["if"], "${{ !inputs.rehearse }}")

    def test_azure_login_caches_a_token_for_every_resource_a_step_uses(self):
        # az exchanges the GitHub token per resource, lazily, and that token is
        # valid for minutes. A resource first used after the registry build and
        # missing here fails there, after the region is drained. The registry's
        # own audience is what `az acr repository show` and `az acr login` ask for.
        login = (ROOT / "tools/azure-oidc-login.sh").read_text()
        loop = re.search(r"^for resource in ([^;\n]+); do\n((?:  .*\n)+)done$", login, flags=re.M)
        self.assertIsNotNone(loop)
        self.assertEqual(loop.group(1).split(), ["https://management.core.windows.net/", "https://vault.azure.net",
                                                 "https://containerregistry.azure.net"])
        # The token itself is never written out: only its expiry is queried.
        self.assertEqual(loop.group(2).count("get-access-token"), 1)
        self.assertIn('get-access-token --resource "$resource" --query expiresOn --output tsv', loop.group(2))
        self.assertEqual(login.count("get-access-token"), 1)
        script = (ROOT / "tools/deploy-azure-aci.sh").read_text()
        self.assertIn("az_cli acr repository show", script)
        self.assertIn("az_rw acr login", script)

    def run_azure_login(self, failing: str = "") -> tuple[int, str, list[str]]:
        """Run tools/azure-oidc-login.sh against recording stand-ins for az and curl.

        Returns the exit status, the output, and one line per az call. An az
        call whose arguments contain `failing` exits 1.
        """
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp) / "calls"
            calls.write_text("")
            (Path(tmp) / "az").write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "$*" | sed -E \'s/--federated-token [^ ]+/--federated-token <t>/\' >> "$CALLS"\n'
                'if [ -n "$FAILING" ] && [[ "$*" == *"$FAILING"* ]]; then exit 1; fi\n'
                'if [[ "$*" == *get-access-token* ]]; then echo "2026-01-01 00:00:00.000000"; fi\n')
            (Path(tmp) / "curl").write_text("#!/usr/bin/env bash\ncat >/dev/null\necho '{\"value\": \"stand-in\"}'\n")
            for name in ("az", "curl"):
                (Path(tmp) / name).chmod(0o755)
            guid = "00000000-0000-0000-0000-000000000000"
            env = {"PATH": f"{tmp}:{os.environ['PATH']}", "CALLS": str(calls), "FAILING": failing,
                   "AZURE_CLIENT_ID": guid, "AZURE_TENANT_ID": guid, "AZURE_SUBSCRIPTION_ID": guid,
                   "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token?x=1",
                   "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request"}
            done = subprocess.run(["bash", str(ROOT / "tools/azure-oidc-login.sh")], env=env,
                                  capture_output=True, text=True, timeout=60, check=False)
            return done.returncode, done.stdout + done.stderr, calls.read_text().splitlines()

    def test_azure_login_starts_from_an_empty_cache_and_stops_on_any_refusal(self):
        status, output, calls = self.run_azure_login()
        self.assertEqual(status, 0, output)
        self.assertEqual([call.split(" --")[0] for call in calls], [
            "cloud set", "account clear", "login", "account set",
            "account get-access-token", "account get-access-token", "account get-access-token"])
        # Cleared before the login, so the login and every later request mint
        # new tokens instead of returning an earlier step's.
        self.assertLess(calls.index(next(c for c in calls if c.startswith("account clear"))),
                        calls.index(next(c for c in calls if c.startswith("login"))))
        self.assertEqual([call.split("--resource ")[1].split()[0] for call in calls if "get-access-token" in call],
                         ["https://management.core.windows.net/", "https://vault.azure.net",
                          "https://containerregistry.azure.net"])
        self.assertEqual(output.count("cached until 2026-01-01"), 3)
        self.assertNotIn("stand-in", output.replace("::add-mask::stand-in", ""))
        for failing in ("account clear", "login", "account set", "https://vault.azure.net",
                        "https://containerregistry.azure.net"):
            status, output, calls = self.run_azure_login(failing)
            self.assertEqual(status, 1, failing)
            self.assertIn("::error::azure-oidc-login:", output, failing)
            self.assertIn(failing, calls[-1], "nothing runs after the refused call")

    def test_only_the_azure_rollout_declares_its_identity_environment(self):
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            if path != AZURE_WF:
                self.assertNotIn("azure-gateway-rollout", path.read_text(), path.name)
        identity = (ROOT / "tools/azure-gateway-rollout-identity/main.tf").read_text()
        self.assertIn('"repo:Lore-Hex/quill-cloud-proxy:environment:azure-gateway-rollout"', identity)
        self.assertNotIn("ref:refs/heads/main", identity.split("github_subject =", 1)[1].splitlines()[0])
        for broad in ('"Owner"', '"Contributor"', '"User Access Administrator"', "Microsoft.Authorization/roleAssignments/write"):
            self.assertNotIn(broad, identity)

    def test_azure_role_text_has_no_angle_brackets(self):
        # Azure refuses a role definition whose name or description holds
        # "<" or ">" (RoleDefinitionCannotContainHtmlTags), and the refusal
        # only shows at apply time, after the other resources exist.
        identity = (ROOT / "tools/azure-gateway-rollout-identity/main.tf").read_text()
        texts = re.findall(r'^\s*(?:name|description)\s*=\s*"([^"\n]*)"', identity, flags=re.M)
        self.assertGreaterEqual(len(texts), 8, texts)
        for text in texts:
            self.assertNotRegex(text, "[<>]")


if __name__ == "__main__":
    unittest.main()
