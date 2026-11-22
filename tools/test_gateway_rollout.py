"""Guards for the AWS and Azure gateway rollout workflows and their helpers.

The workflows automate docs/runbook-aws-enclave-release.md and
docs/runbooks/azure-enclave.md. These tests pin the safety order those
runbooks require, so a later edit cannot quietly reorder a drain after a
deploy, refresh a fleet before its candidate verified, or give CI a KMS write.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import json
import re
import sys
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
        self.common(workflow, "aws")
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
        self.assertIn("--apply preflight build template policy bind deploy verify", text)
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
        self.assertNotIn("rehearse", self.load(AWS_WF)["jobs"])
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
        self.assertEqual(set(job["env"]), {"BUNDLE_VERSION"})
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
            'WORKDIR="$RUNNER_TEMP/aci-rehearsal" QUILL_AZURE_BUNDLE_VERSION="$BUNDLE_VERSION" \\',
            "  TR_CONTROL_PLANE_BASE_URL=https://trustedrouter.com \\",
            "  bash ./tools/deploy-azure-aci.sh --apply preflight build template policy",
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
        self.assertEqual(loop.group(1).split(), ["https://management.azure.com/", "https://vault.azure.net",
                                                 "https://containerregistry.azure.net"])
        # The token itself is never written out: only its expiry is queried.
        self.assertEqual(loop.group(2).count("get-access-token"), 1)
        self.assertIn('get-access-token --resource "$resource" --query expiresOn --output tsv', loop.group(2))
        self.assertEqual(login.count("get-access-token"), 1)
        script = (ROOT / "tools/deploy-azure-aci.sh").read_text()
        self.assertIn("az_cli acr repository show", script)
        self.assertIn("az_rw acr login", script)

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
