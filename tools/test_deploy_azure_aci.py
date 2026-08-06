#!/usr/bin/env python3
"""Regression tests for tools/deploy-azure-aci.sh.

Run directly (the repo convention for tool tests, see
tools/test_synthetic_gate_status.py):

    python3 tools/test_deploy_azure_aci.py

WHY THIS FILE EXISTS
--------------------
The deploy script's job is to make ONE failure impossible: creating a
confidential container group whose CCE policy hash is not what the SKR key's
release policy pins, which produces an enclave that boots, attests perfectly,
gets 403 from Key Vault and — under restartPolicy=Never — never comes back.

Every guard in that script is therefore load-bearing, and a guard nobody
executes is a comment. These tests execute them, against a stubbed `az` and
`docker` that model the responses that matter: what the key pins, whether the
group exists, what state a group is in when its containers have exited, and
what `acipolicygen` writes into the template.

Nothing here touches Azure. `az` and `docker` are Python stubs placed on PATH,
and every mutation they would perform is recorded to a log the tests assert on
— so "this run would have deleted production" is a testable claim.

Each test names the defect it pins. All eight were reproduced against the
script before the fix and fail again if the fix is reverted.
"""

from __future__ import annotations

import pathlib
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FOREIGN_AUTHORITY = "https://trquillsea.sasia.attest.azure.net"
SCRIPT = REPO_ROOT / "tools" / "deploy-azure-aci.sh"
SEALER = REPO_ROOT / "tools" / "azure-seal-bundle.py"

# ---------------------------------------------------------------------------
# the stubs
# ---------------------------------------------------------------------------
# State lives in $STUB_STATE as one file per fact, so a test can set up
# "the key pins X and the group runs Y" by writing two files. Every invocation
# is appended to az.log; everything that would CHANGE Azure is appended to
# mutations.log, which is what most assertions read.

AZ_STUB = r'''#!/usr/bin/env python3
import base64, json, os, sys

# A second region's MAA instance. Kept in sync with the module-level
# constant of the same name so tests can assert on it.
FOREIGN_AUTHORITY = "https://trquillsea.sasia.attest.azure.net"

state = os.environ["STUB_STATE"]


def read(name, default=""):
    try:
        with open(os.path.join(state, name)) as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return default


def write(name, value):
    with open(os.path.join(state, name), "w") as handle:
        handle.write(value)


def log(fname, line):
    with open(os.path.join(state, fname), "a") as handle:
        handle.write(line + "\n")


def flag(name):
    return os.path.exists(os.path.join(state, name))


argv = sys.argv[1:]
joined = " ".join(argv)
log("az.log", "ARGV: " + joined)


def arg(name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default


if argv[:2] == ["identity", "show"]:
    if arg("--query") == "clientId":
        print("11111111-2222-3333-4444-555555555555")
    else:
        print("/subscriptions/STUB/resourcegroups/%s/providers/Microsoft.ManagedIdentity"
              "/userAssignedIdentities/%s" % (arg("--resource-group"), arg("--name")))
    sys.exit(0)

if argv[:2] == ["acr", "build"]:
    log("mutations.log", "MUTATE-ACR-BUILD")
    sys.exit(0)

if argv[:2] == ["acr", "login"]:
    sys.exit(0)

if argv[:3] == ["acr", "repository", "show"]:
    print(read("image-digest", "sha256:" + "a" * 64))
    sys.exit(0)

if argv[:3] == ["keyvault", "key", "set-attributes"]:
    path = arg("--policy") or arg("--release-policy")
    with open(path) as handle:
        policy = json.load(handle)
    # Split by AUTHORITY. The stub used to flatten every clause into one set,
    # which modelled a world where regions share a pin list — they do not, and
    # the flattening hid the very bug these tests exist to catch.
    mine, theirs = [], []
    for clause in policy.get("anyOf", []):
        bucket = theirs if clause.get("authority") == FOREIGN_AUTHORITY else mine
        for claim in clause.get("allOf", []):
            if claim.get("claim") == "x-ms-sevsnpvm-hostdata":
                bucket.append(claim["equals"])
    write("bound-hostdata", "\n".join(mine))
    write("foreign-hostdata", "\n".join(theirs))
    log("mutations.log", "MUTATE-BIND-KEY :: pins=" + ",".join(mine))
    sys.exit(0)

if argv[:3] == ["keyvault", "key", "show"]:
    bound = read("bound-hostdata")
    foreign = read("foreign-hostdata")
    if not bound and not foreign:
        sys.exit(0)
    # The authority MUST match the one this deploy binds under. The real
    # multi-region carry-over preserves clauses belonging to OTHER authorities,
    # so a stub speaking as "stub.attest.azure.net" would be modelling a second
    # region that does not exist and its pins would accumulate forever.
    authority = "https://" + os.environ.get("MAA_ENDPOINT", "trquilluaen.uaen.attest.azure.net")
    clauses = [{"authority": authority,
                "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": pin}]}
               for pin in bound.splitlines()]
    # A SECOND region, if the test asked for one. Its clauses must survive every
    # write and must never be read as if they belonged to this region.
    for pin in read("foreign-hostdata").splitlines():
        if pin:
            clauses.append({"authority": FOREIGN_AUTHORITY,
                            "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": pin}]})
    document = {"version": "1.0.0", "anyOf": clauses}
    # Emitted as the CLI really emits it: a Python bytes repr, not base64.
    print(repr(json.dumps(document).encode()))
    sys.exit(0)

if argv[:2] == ["container", "show"]:
    if flag("show-fails"):
        print("ERROR: AADSTS700082: The refresh token has expired.", file=sys.stderr)
        sys.exit(1)
    exists = os.path.exists(os.path.join(state, "deployed-policy"))
    query = arg("--query")
    if query is None:
        if not exists:
            print("ERROR: (ResourceNotFound) The Resource "
                  "'Microsoft.ContainerInstance/containerGroups/%s' under resource group "
                  "'%s' was not found." % (arg("--name"), arg("--resource-group")),
                  file=sys.stderr)
            sys.exit(3)
        properties = {} if flag("show-omits-policy") else {"ccePolicy": read("deployed-policy")}
        json.dump({"name": arg("--name"),
                   "sku": "Confidential",
                   "confidentialComputeProperties": properties,
                   "instanceView": {"state": read("group-state", "Running")},
                   "ipAddress": {"ip": read("group-ip", "10.0.0.9"),
                                 "fqdn": read("group-fqdn", "stub.uaenorth.azurecontainer.io")}},
                  sys.stdout)
        print()
        sys.exit(0)
    if not exists:
        print("ERROR: (ResourceNotFound) The Resource "
              "'Microsoft.ContainerInstance/containerGroups/%s' under resource group "
              "'%s' was not found." % (arg("--name"), arg("--resource-group")),
              file=sys.stderr)
        sys.exit(3)
    if query == "confidentialComputeProperties.ccePolicy":
        print("" if flag("show-omits-policy") else read("deployed-policy"))
    elif query == "containers[0].instanceView.restartCount":
        print(read("group-restarts", "0"))
    elif query == "instanceView.state":
        print(read("group-state", "Running"))
    elif query == "ipAddress.ip":
        print(read("group-ip", "10.0.0.9"))
    elif query == "ipAddress.fqdn":
        print(read("group-fqdn", "stub.uaenorth.azurecontainer.io"))
    else:
        print("")
    sys.exit(0)

if argv[:2] == ["container", "delete"]:
    log("mutations.log", "MUTATE-DELETE-GROUP")
    try:
        os.remove(os.path.join(state, "deployed-policy"))
    except FileNotFoundError:
        pass
    sys.exit(0)

if argv[:3] == ["deployment", "group", "create"]:
    if flag("create-fails"):
        log("mutations.log", "CREATE-GROUP-FAILED")
        print("ERROR: (RegistryErrorResponse) An error response is received from the "
              "docker registry.", file=sys.stderr)
        sys.exit(1)
    with open(arg("--template-file")) as handle:
        document = json.load(handle)
    policy = document["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]
    log("mutations.log", "MUTATE-CREATE-GROUP :: ccePolicy=%r" % (policy,))
    write("deployed-policy", policy)
    write("deployment-name", arg("--name"))
    sys.exit(0)

if argv[:2] == ["container", "logs"]:
    print(read("container-logs", "quill-enclave: skr release: http 403 from key vault"))
    sys.exit(0)

print("stub az: unhandled %r" % (argv,), file=sys.stderr)
sys.exit(97)
'''

DOCKER_STUB = r'''#!/usr/bin/env python3
"""Stub `docker` standing in for `az confcom acipolicygen`.

Finds the host path bound at /work, rewrites template.json IN PLACE with a
base64 rego policy derived from the measured definition (so a changed container
group really does produce a changed hash), and prints a hash line the way
acipolicygen does.

STUB_POLICY_HASH_UPPER prints that hash uppercase; STUB_POLICY_HASH_OVERRIDE
prints a different hash entirely, which is the disagreement the cross-check
exists to catch.
"""
import base64, hashlib, json, os, sys

state = os.environ["STUB_STATE"]
argv = sys.argv[1:]
with open(os.path.join(state, "docker.log"), "a") as handle:
    handle.write("ARGV: " + " ".join(argv) + "\n")

mounts = {}
index = 0
while index < len(argv):
    if argv[index] == "-v":
        host, _, rest = argv[index + 1].partition(":")
        mounts[rest.split(":")[0]] = argv[index + 1]
        index += 2
    else:
        index += 1

# 9e16b0f pre-pulls the measured image into the host daemon, because confcom
# rides the mounted socket and its own pull is anonymous. A pull carries no
# -v, so without this the stub rejects it as "no /work mount". docker.log
# already records the invocation for assertions.
if argv and argv[0] == "pull":
    sys.exit(0)

work_spec = mounts.get("/work")
if not work_spec:
    print("stub docker: no /work mount", file=sys.stderr)
    sys.exit(1)
work = work_spec.split(":")[0]

template_path = os.path.join(work, "template.json")
with open(template_path) as handle:
    template = json.load(handle)

body = "package policy\n# " + json.dumps(template["resources"][0]["properties"], sort_keys=True)
template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] = (
    base64.b64encode(body.encode()).decode())
with open(template_path, "w") as handle:
    json.dump(template, handle, indent=2)
    handle.write("\n")

digest = os.environ.get("STUB_POLICY_HASH_OVERRIDE") or hashlib.sha256(body.encode()).hexdigest()
if os.environ.get("STUB_POLICY_HASH_UPPER"):
    digest = digest.upper()
print("Generating security policy for ARM template: %s" % template_path)
print("cce policy hash: %s" % digest)
'''


class DeployHarness(unittest.TestCase):
    """One stubbed Azure per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self.bin = root / "bin"
        self.bin.mkdir()
        for name, source in (("az", AZ_STUB), ("docker", DOCKER_STUB)):
            path = self.bin / name
            path.write_text(source)
            path.chmod(0o755)

        self.state = root / "state"
        self.state.mkdir()
        self.work = root / "work"
        self.work.mkdir()
        # phase_policy refuses to let docker create the operator's credential
        # directory, so give the fake HOME one.
        self.home = root / "home"
        (self.home / ".azure").mkdir(parents=True)

    # -- driving the script -------------------------------------------------

    def run_script(self, *args: str, **env_overrides: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            PATH=f"{self.bin}{os.pathsep}{env['PATH']}",
            HOME=str(self.home),
            STUB_STATE=str(self.state),
            WORKDIR=str(self.work),
            # One provider secret, so render_env_json has something to emit and
            # the enclave-side "at least one provider" rule is satisfied.
            QUILL_OPENROUTER_SECRET="quill-openrouter-key",
            # f610fd9 made an unpinned bundle FATAL under --apply, and this
            # harness never pinned one — so every --apply test died at the
            # pin guard before reaching the behaviour it actually names.
            # env_overrides is applied after this, so a test can still pass
            # QUILL_AZURE_BUNDLE_VERSION="" to exercise the refusal itself.
            QUILL_AZURE_BUNDLE_VERSION="stubbundleversion0123456789abcdef",
            VERIFY_TIMEOUT_SECONDS="1",
        )
        env.update(env_overrides)
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )

    # -- stubbed-Azure state ------------------------------------------------

    def state_file(self, name: str) -> Path:
        return self.state / name

    def read_state(self, name: str, default: str = "") -> str:
        path = self.state_file(name)
        return path.read_text().strip() if path.exists() else default

    def mutations(self) -> list[str]:
        path = self.state_file("mutations.log")
        return path.read_text().splitlines() if path.exists() else []

    def clear_mutations(self) -> None:
        self.state_file("mutations.log").write_text("")

    def bound_pins(self) -> list[str]:
        return [line for line in self.read_state("bound-hostdata").splitlines() if line]

    def template_cce_policy(self) -> str:
        document = json.loads((self.work / "template.json").read_text())
        return document["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]

    def healthy_deploy(self, **env_overrides: str) -> str:
        """Bring the stubbed Azure to a healthy post-deploy state.

        Returns the hostdata the key ends up pinning.
        """
        result = self.run_script(
            "--apply", "build", "template", "policy", "bind", "deploy", **env_overrides
        )
        self.assertEqual(result.returncode, 0, f"setup deploy failed:\n{result.stderr}")
        self.clear_mutations()
        pins = self.bound_pins()
        self.assertEqual(len(pins), 1, f"expected exactly one pin after a clean deploy, got {pins}")
        return pins[0]


class TestDeployGuardAuthenticatesTheTemplate(DeployHarness):
    """The guard must check the ARTIFACT, not a note left beside it.

    $WORKDIR/cce-policy-hash.txt and $WORKDIR/template.json are separate files
    that drift apart. Re-running `template` rewrites the template with an EMPTY
    ccePolicy — by design, so a stale policy can never be copied forward — and
    leaves the hash file at the previous run's real value. A guard that reads
    the hash file then compares the old hash to the key's old pin, PASSES, and
    deletes a healthy production group to replace it with one carrying no policy
    at all: hostdata cannot match, Key Vault answers 403, and restartPolicy
    Never means it does not come back.
    """

    def test_stale_hash_file_cannot_wave_through_a_policyless_template(self) -> None:
        self.healthy_deploy()
        live_policy_before = self.read_state("deployed-policy")

        # `template` on its own. The header calls dry-run safe; it still
        # rewrites the shared workdir, which is exactly how the two files
        # desynchronize in the field.
        self.assertEqual(self.run_script("template").returncode, 0)
        self.assertEqual(self.template_cce_policy(), "", "template should have been reset")
        self.assertTrue(
            (self.work / "cce-policy-hash.txt").read_text().strip(),
            "the hash file should still hold the previous run's real hash",
        )
        self.clear_mutations()

        result = self.run_script("--apply", "deploy")

        self.assertNotEqual(result.returncode, 0, "deploy must refuse a policyless template")
        self.assertIn("ccePolicy", result.stderr)
        self.assertIn("EMPTY", result.stderr)
        self.assertEqual(self.mutations(), [], "no Azure mutation may happen")
        self.assertEqual(
            self.read_state("deployed-policy"),
            live_policy_before,
            "the running container group must be untouched",
        )

    def test_phases_typed_out_of_order_cannot_deploy_an_unbound_workload(self) -> None:
        """`--apply deploy bind` runs deploy first; the key still pins the old
        measurement, and the guard has to notice from the template alone."""
        old_pin = self.healthy_deploy()
        result = self.run_script("--apply", "build", "template", "policy", ENCLAVE_CPU="4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.clear_mutations()

        result = self.run_script("--apply", "deploy", "bind", ENCLAVE_CPU="4")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REFUSING TO DEPLOY", result.stderr)
        self.assertIn(old_pin, result.stderr)
        self.assertEqual(self.mutations(), [])


class TestBindKeepsAWayBack(DeployHarness):
    """bind must widen the pin, not replace it.

    Replacing destroys the only record of what the RUNNING enclave is allowed to
    be, at the moment the deploy is most likely to fail: `deploy` has to delete
    the old group before creating the new one, so an ARM create that fails for
    an ordinary reason (ACR pull, capacity, quota) previously left no group and
    no way back — the old measurement being reconstructible only by reproducing
    the previous image bit for bit.
    """

    def test_a_failed_create_leaves_the_old_pin_accepted_and_rollback_possible(self) -> None:
        old_pin = self.healthy_deploy()
        self.state_file("create-fails").write_text("")

        result = self.run_script(
            "--apply", "build", "template", "policy", "bind", "deploy", ENCLAVE_CPU="4"
        )
        self.assertNotEqual(result.returncode, 0, "the ARM create was supposed to fail")

        pins = self.bound_pins()
        self.assertIn(
            old_pin,
            pins,
            "the outgoing measurement must still be accepted: anything that recycles the "
            "running enclave during the deploy window would otherwise be unrecoverable",
        )
        self.assertEqual(len(pins), 2, f"expected a {{old, new}} window, got {pins}")
        self.assertEqual(
            (self.work / "previous-hostdata.txt").read_text().strip(),
            old_pin,
            "bind must record the outgoing pin for rollback",
        )

        (self.state / "create-fails").unlink()
        rollback = self.run_script("--apply", "rollback")
        self.assertEqual(rollback.returncode, 0, rollback.stderr)
        self.assertEqual(self.bound_pins(), [old_pin], "rollback must restore the previous pin")

    def test_narrow_closes_the_window_and_repeated_binds_do_not_widen_it(self) -> None:
        old_pin = self.healthy_deploy()

        # Three binds without a narrow. The window must stay {old, current} —
        # a policy that accumulated every intermediate hash would leave the key
        # releasing to measurements nobody runs and nobody watches.
        for cpu in ("4", "6", "8"):
            result = self.run_script(
                "--apply", "build", "template", "policy", "bind", ENCLAVE_CPU=cpu
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            pins = self.bound_pins()
            self.assertEqual(len(pins), 2, f"window grew to {pins}")
            self.assertIn(old_pin, pins)

        result = self.run_script("--apply", "deploy", "narrow", ENCLAVE_CPU="8")
        self.assertEqual(result.returncode, 0, result.stderr)
        pins = self.bound_pins()
        self.assertEqual(len(pins), 1, f"narrow must close the window, got {pins}")
        self.assertNotIn(old_pin, pins)
        self.assertFalse((self.work / "previous-hostdata.txt").exists())


class TestGroupExistenceIsNotGuessed(DeployHarness):
    """"no such group" and "the CLI failed" are different facts.

    Collapsing both into an empty string makes an expired token look like a
    fresh region: the delete is skipped and the create becomes a PUT over a live
    confidential group, whose measured surface cannot change in place. bind has
    already re-pointed the key by then, so the result is the old group running
    on the old measurement while the key pins the new one — fine until the next
    cold start, then dead.
    """

    def test_a_failing_container_show_stops_the_deploy(self) -> None:
        self.healthy_deploy()
        result = self.run_script(
            "--apply", "build", "template", "policy", "bind", ENCLAVE_MEMORY_GB="8"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.clear_mutations()
        self.state_file("show-fails").write_text("")

        result = self.run_script("--apply", "deploy", ENCLAVE_MEMORY_GB="8")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not determine whether container group", result.stderr)
        self.assertEqual(
            self.mutations(),
            [],
            "an unreadable group must not be updated in place, nor blindly recreated",
        )

    def test_a_group_that_does_not_echo_its_policy_is_recreated_not_updated(self) -> None:
        self.healthy_deploy()
        self.state_file("show-omits-policy").write_text("")
        result = self.run_script(
            "--apply", "build", "template", "policy", "bind", ENCLAVE_MEMORY_GB="8"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.clear_mutations()

        result = self.run_script("--apply", "deploy", ENCLAVE_MEMORY_GB="8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MUTATE-DELETE-GROUP", self.mutations())
        self.assertTrue(any(line.startswith("MUTATE-CREATE-GROUP") for line in self.mutations()))

    def test_an_unchanged_definition_is_a_no_op(self) -> None:
        self.healthy_deploy()
        result = self.run_script("--apply", "template", "policy", "bind", "deploy")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("MUTATE-DELETE-GROUP", self.mutations())
        self.assertFalse(
            any(line.startswith("MUTATE-CREATE-GROUP") for line in self.mutations()),
            f"re-running an unchanged deploy must not recreate the group: {self.mutations()}",
        )


class TestVerifyReportsTheFailureItExistsFor(DeployHarness):
    """A 403 at boot must be diagnosed, not waited out.

    `Terminated` is a CONTAINER state; a container group whose containers have
    exited under restartPolicy=Never reports the GROUP state Succeeded. Handling
    only Failed|Terminated meant the Key Vault 403 — the exact failure this
    script exists to prevent — was the one path that spun the full
    VERIFY_TIMEOUT_SECONDS in silence and then died without dumping the log that
    says "http 403".
    """

    def test_a_group_that_exited_is_terminal_and_dumps_logs(self) -> None:
        for state in ("Succeeded", "Stopped", "Failed"):
            with self.subTest(state=state):
                self.healthy_deploy()
                self.state_file("group-state").write_text(state)
                self.state_file("container-logs").write_text(
                    "quill-enclave: FATAL skr release: http 403 from key vault"
                )

                result = self.run_script("--apply", "verify")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"container group state is '{state}'", result.stderr)
                self.assertIn("http 403", result.stderr, "the diagnostic log must be dumped")

    def test_a_timeout_also_dumps_logs(self) -> None:
        self.healthy_deploy()
        # A state the script does not treat as terminal, so it times out.
        self.state_file("group-state").write_text("Pending")
        self.state_file("container-logs").write_text("quill-enclave: still pulling image")

        result = self.run_script("--apply", "verify")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not reach Running", result.stderr)
        self.assertIn("still pulling image", result.stderr, "a timeout must dump logs too")


class TestPolicyHashCrossCheck(DeployHarness):
    """The confcom cross-check must compare values, not spellings.

    The scrape was case-INSENSITIVE and the comparison case-SENSITIVE, so an
    acipolicygen build that prints uppercase hex refused to bind for ever, on
    every deploy, over the same 256-bit number written two ways.
    """

    def test_an_uppercase_hash_from_acipolicygen_is_accepted(self) -> None:
        result = self.run_script(
            "--apply", "build", "template", "policy", STUB_POLICY_HASH_UPPER="1"
        )
        self.assertEqual(
            result.returncode, 0, f"uppercase hex must not block the deploy:\n{result.stderr}"
        )
        hashed = (self.work / "cce-policy-hash.txt").read_text().strip()
        self.assertEqual(hashed, hashed.lower())
        self.assertEqual(len(hashed), 64)

    def test_a_genuinely_different_hash_still_stops_the_deploy(self) -> None:
        """The case tolerance above must not have hollowed out the check.

        acipolicygen reports a hash that is NOT sha256 of the policy it wrote.
        One of the two is what the hardware will put in x-ms-sevsnpvm-hostdata,
        and binding the other guarantees a 403 at boot, so neither may be used.
        """
        self.clear_mutations()
        result = self.run_script(
            "--apply", "build", "template", "policy", STUB_POLICY_HASH_OVERRIDE="b" * 64
        )

        self.assertNotEqual(result.returncode, 0, "a disagreeing hash must stop the deploy")
        self.assertIn("Refusing to bind either", result.stderr)
        self.assertFalse(
            any("MUTATE-BIND-KEY" in line for line in self.mutations()),
            "nothing may be bound while the two hashes disagree",
        )

    def test_an_uppercase_disagreement_is_still_a_disagreement(self) -> None:
        """Lowercasing must normalise spelling, not swallow different values."""
        result = self.run_script(
            "--apply",
            "build",
            "template",
            "policy",
            STUB_POLICY_HASH_OVERRIDE="b" * 64,
            STUB_POLICY_HASH_UPPER="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to bind either", result.stderr)


class TestWorkdirIsLocked(DeployHarness):
    """Two runs sharing $WORKDIR silently swap workloads.

    $WORKDIR is derived from $CONTAINER_GROUP alone, so A and B share
    template.json and cce-policy-hash.txt. Interleaved, A ends up deploying B's
    template while the key pins B's hash — and the guard passes, because BOTH of
    its operands came from the clobbered files. Nothing downstream can detect
    it: the live group really is B's and the key really does pin B.
    """

    def test_a_second_run_refuses_to_share_the_workdir(self) -> None:
        self.healthy_deploy()
        lock = Path(str(self.work) + ".lock")
        lock.mkdir()
        # A pid that is certainly alive: this test process.
        (lock / "pid").write_text(str(os.getpid()))
        self.clear_mutations()

        result = self.run_script("--apply", "build", "template", "policy", "bind", "deploy")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already holds", result.stderr)
        self.assertEqual(self.mutations(), [], "the blocked run must not touch Azure")

    def test_a_stale_lock_is_reclaimed_and_released(self) -> None:
        lock = Path(str(self.work) + ".lock")
        lock.mkdir()
        # A pid that cannot be running: 0 is never a real user process here, and
        # the script treats an unreadable/absent holder as stale.
        (lock / "pid").write_text("999999")

        result = self.run_script("--apply", "build")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stale lock", result.stderr)
        self.assertFalse(lock.exists(), "the lock must be released when the run ends")


class TestBuildSurfacesDigestChurn(DeployHarness):
    """A moving image digest silently recreates production.

    IMAGE_TAG is minted from a fresh timestamp and `az acr build` runs
    unconditionally, so whether an unchanged source tree stays a no-op depends
    entirely on ACR producing a byte-identical manifest — and an OCI image
    config carries a `created` timestamp. If the digest moves, the template
    moves, the policy moves, and phase_deploy correctly deletes and recreates a
    healthy group for a source tree that did not change. That has to be visible,
    and avoidable.
    """

    def test_a_changed_digest_is_reported(self) -> None:
        self.run_script("--apply", "build")
        self.state_file("image-digest").write_text("sha256:" + "b" * 64)

        result = self.run_script("--apply", "build")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("image digest CHANGED", result.stderr)
        self.assertIn("REUSE_IMAGE=1", result.stderr)

    def test_reuse_image_skips_the_build(self) -> None:
        self.run_script("--apply", "build")
        self.clear_mutations()

        result = self.run_script("--apply", "build", REUSE_IMAGE="1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [], "REUSE_IMAGE must not rebuild")


class TestCredentialStoreIsNotWritable(DeployHarness):
    """The operator's Azure credential store is mounted into a container that
    also holds the host docker socket.

    On Linux ~/.azure/msal_token_cache.json is plaintext when no keyring backend
    is present. Read access is unavoidable (confcom pulls from a private ACR);
    write access buys nothing, and it is also how `az extension add` lands
    ROOT-OWNED files inside the operator's own config directory — after which
    their next host-side `az` fails with EACCES on its own config.
    """

    def test_the_azure_config_dir_is_mounted_read_only(self) -> None:
        result = self.run_script("--apply", "build", "template", "policy")
        self.assertEqual(result.returncode, 0, result.stderr)

        docker_log = (self.state / "docker.log").read_text()
        self.assertIn(f"{self.home}/.azure:", docker_log, "the credential store is still mounted")
        mounts = [
            token
            for token in docker_log.split()
            if token.startswith(f"{self.home}/.azure:")
        ]
        self.assertTrue(mounts, docker_log)
        for mount in mounts:
            self.assertTrue(
                mount.endswith(":ro"),
                f"{mount} must be read-only: this container also has the host docker socket",
            )
            self.assertNotIn(
                ":/root/.azure",
                mount,
                "binding it at AZURE_CONFIG_DIR is what makes `az extension add` write "
                "root-owned files into the operator's own config directory",
            )

    def test_the_container_gets_a_writable_config_dir_elsewhere(self) -> None:
        result = self.run_script("--apply", "build", "template", "policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        docker_log = (self.state / "docker.log").read_text()
        self.assertIn(
            "AZURE_CONFIG_DIR=/azure-config",
            docker_log,
            "az writes commandIndex.json/versionCheck.json/logs on nearly every "
            "invocation and would fail against a read-only config dir",
        )


class TestAzureImageTmpMode(unittest.TestCase):
    """/tmp in the Azure image must actually carry the mode the file claims.

    `COPY <dir> <dest>` copies the CONTENTS of <dir>, so `COPY /out/tmp /tmp`
    creates /tmp implicitly with the default 0755 and silently drops the
    preceding `chmod 1777` — the built layer really contained
    `drwxr-xr-x 0/0 tmp/`, which `docker save | tar -tv` shows. `--chmod` does
    not help either: it applies to the entries being copied, not to a
    destination the copy invents. Copying the PARENT makes tmp/ an entry that is
    itself copied, so its mode survives.

    The load-bearing part was always that /tmp EXISTS (cmd/enclave/main.go
    writes /tmp/gcp-sa.json with no MkdirAll and exits 1 if it cannot), and that
    part worked. What did not work was the documented mode — and a comment
    asserting a permission the image does not have is what the next change gets
    built on.
    """

    DOCKERFILE = REPO_ROOT / "enclave-go" / "Dockerfile.enclave.azure.multi"

    def test_tmp_is_copied_as_an_entry_not_as_contents(self) -> None:
        text = self.DOCKERFILE.read_text()
        self.assertIn(
            "chmod 1777 /out/rootfs/tmp",
            text,
            "the staging directory is what lets the mode reach the image",
        )
        self.assertIn(
            "COPY --from=builder /out/rootfs/ /",
            text,
            "copying the PARENT makes tmp/ a copied entry, so its mode survives",
        )
        self.assertNotIn(
            "COPY --from=builder /out/tmp /tmp",
            text,
            "this form copies the CONTENTS of /out/tmp and drops the chmod: the layer "
            "ends up with drwxr-xr-x, not the 1777 the comment claims",
        )

    def test_the_runtime_stage_still_creates_tmp(self) -> None:
        """The actual boot requirement, independent of the mode."""
        text = self.DOCKERFILE.read_text()
        runtime = text.split("FROM scratch", 1)[1]
        self.assertIn(
            "/out/rootfs/",
            runtime,
            "without this the scratch image has no /tmp and the Azure boot path dies with "
            '"write GCP SA key tmpfs failed: no such file or directory"',
        )


class TestSecretNameListsDoNotDrift(unittest.TestCase):
    """The deploy script's QUILL_*_SECRET list must match the sealer's table.

    The sealer's mirror of secrets.go is pinned by a Go test. The SHELL's list
    had no such check: a provider added to secrets.go and the sealer but not
    here leaves CI green and ships a deploy with that provider silently
    unconfigured.
    """

    def test_render_env_json_names_every_binding(self) -> None:
        sealer_output = subprocess.run(
            [sys.executable, str(SEALER), "--print-bindings"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        bindings = json.loads(sealer_output)
        # The deploy configures the PRIMARY spelling of each binding; the legacy
        # aliases exist only so an old container-group env still boots.
        primary = sorted(binding["envs"][0] for binding in bindings)

        script = SCRIPT.read_text()
        # The list render_env_json iterates, i.e. what actually reaches the
        # container group's measured env.
        start = script.index("for name in (")
        end = script.index("):", start)
        rendered = sorted(
            token.strip().strip('",')
            for token in script[start:end].replace("for name in (", "").split(",")
            if token.strip().strip('",').startswith("QUILL_")
        )

        self.assertEqual(
            rendered,
            primary,
            "tools/deploy-azure-aci.sh and tools/azure-seal-bundle.py disagree about which "
            "secrets this deploy configures; a name in one and not the other ships a "
            "provider the enclave never sees",
        )

    def test_every_rendered_name_has_a_default(self) -> None:
        script = SCRIPT.read_text()
        start = script.index("for name in (")
        end = script.index("):", start)
        rendered = {
            token.strip().strip('",')
            for token in script[start:end].split(",")
            if token.strip().strip('",').startswith("QUILL_")
        }
        defaults = {
            line.split("=", 1)[0]
            for line in script.splitlines()
            if line.startswith("QUILL_") and "=" in line
        }
        self.assertEqual(
            rendered - defaults,
            set(),
            "a name rendered into the container env with no default above is always empty, "
            "so the provider is silently unconfigured",
        )


class TestUnpinnedBundleIsRefused(DeployHarness):
    """f610fd9 shipped this guard with no test at all.

    SKR gates WHO may open the bundle, never WHICH bundle — so a deploy that
    follows the mutable "current" version can be silently substituted or
    rolled back underneath a measurement that still verifies. The refusal is
    the only thing closing that hole, which makes an untested refusal a
    security control nobody knows is working.
    """

    def test_apply_without_a_pin_is_fatal_and_mutates_nothing(self) -> None:
        result = self.run_script(
            "--apply", "build", "template", "policy", "bind", "deploy",
            QUILL_AZURE_BUNDLE_VERSION="",
        )
        self.assertNotEqual(result.returncode, 0, "an unpinned --apply must not proceed")
        self.assertIn("FATAL", result.stderr)
        self.assertIn("QUILL_AZURE_BUNDLE_VERSION", result.stderr)
        # The point is not just the exit code: refusing AFTER mutating Azure
        # would leave exactly the half-applied state the guard exists to avoid.
        self.assertEqual(self.mutations(), [], "a refused deploy must touch nothing")

    def test_dry_run_without_a_pin_only_warns(self) -> None:
        """A dry run cannot substitute anything, so it must stay reviewable."""
        result = self.run_script(
            "build", "template", "policy", QUILL_AZURE_BUNDLE_VERSION="",
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])

    def test_the_escape_hatch_works_and_is_explicit(self) -> None:
        result = self.run_script(
            "--apply", "build", "template",
            QUILL_AZURE_BUNDLE_VERSION="", ALLOW_UNPINNED_BUNDLE="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])

    def test_the_pin_reaches_the_MEASURED_env(self) -> None:
        """A pin the CCE policy does not measure is decoration: the container
        could be started with a different bundle version and still attest."""
        import json as _json
        result = self.run_script("print-env", QUILL_AZURE_BUNDLE_VERSION="pinnedbundle0123456789abcdef0123")
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        env = _json.loads(result.stdout)
        self.assertEqual(env.get("QUILL_AZURE_BUNDLE_VERSION"), "pinnedbundle0123456789abcdef0123")


class TestPolicyPullIsDryRunSafe(DeployHarness):
    """9e16b0f's pre-pull ran bare, so it fired on a DRY RUN too.

    On a dry run the digest is the synthetic sha256:DRYRUN000... that no
    registry has, so every dry run died at "cannot pull". That contradicts the
    script's own require_tool contract - a dry run must produce a reviewable
    template on a laptop with neither az nor docker - and made the SAFE command
    the failing one.
    """

    def test_dry_run_does_not_pull(self) -> None:
        result = self.run_script("build", "template", "policy")
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertIn("DRY-RUN", result.stderr)
        self.assertNotIn("cannot pull", result.stderr)

    def test_apply_does_pull_before_confcom(self) -> None:
        """The pull must still happen for real, and BEFORE the policy gen -
        confcom's own pull rides the socket anonymously and 401s against ACR."""
        result = self.run_script("--apply", "build", "template", "policy")
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        log = (self.state / "docker.log").read_text() if (self.state / "docker.log").exists() else ""
        pull_at = log.find("pull")
        gen_at = log.find("acipolicygen")
        self.assertNotEqual(pull_at, -1, f"no docker pull recorded; log={log[:400]}")
        if gen_at != -1:
            self.assertLess(pull_at, gen_at, "the pull must precede confcom's policy generation")



class TestReleasePolicyIsMultiRegionSafe(unittest.TestCase):
    """One SKR key serves every Azure region; each region attests against its OWN
    MAA instance. Rendering the policy from one deploy's values alone drops the
    other region's clause, and that region's next COLD START takes a Key Vault
    403 and never returns — an outage in a region nobody touched, caused by
    deploying its neighbour.

    So a deploy owns the clauses naming its own authority and must carry every
    other authority's clause through untouched. That also makes the two deploys
    order-independent, which matters because nothing locks between them.
    """

    UAEN = "https://trquilluaen.uaen.attest.azure.net"
    SEA = "https://trquillsea.sasia.attest.azure.net"

    def _render(self, maa, hostdata, existing):
        """Run the script's embedded policy renderer against a given prior policy."""
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            prior = os.path.join(tmp, "prior.json")
            with open(prior, "w") as fh:
                json.dump(existing, fh) if existing is not None else fh.write("")
            src = _extract_release_policy_python()
            subprocess.run(
                [sys.executable, "-c", src, out, maa, prior, *hostdata],
                check=True, capture_output=True, text=True,
            )
            with open(out) as fh:
                return json.load(fh)

    def _authorities(self, policy):
        return sorted({c["authority"] for c in policy["anyOf"]})

    def _hostdata_for(self, policy, authority):
        out = []
        for c in policy["anyOf"]:
            if c["authority"] != authority:
                continue
            for claim in c["allOf"]:
                if claim["claim"] == "x-ms-sevsnpvm-hostdata":
                    out.append(claim["equals"])
        return sorted(out)

    def test_first_region_writes_its_own_clause(self) -> None:
        pol = self._render(self.UAEN.removeprefix("https://"), ["aa" * 32], None)
        self.assertEqual(self._authorities(pol), [self.UAEN])
        self.assertEqual(self._hostdata_for(pol, self.UAEN), ["aa" * 32])

    def test_second_region_does_not_drop_the_first(self) -> None:
        first = self._render(self.UAEN.removeprefix("https://"), ["aa" * 32], None)
        both = self._render(self.SEA.removeprefix("https://"), ["bb" * 32], first)
        self.assertEqual(self._authorities(both), sorted([self.SEA, self.UAEN]))
        self.assertEqual(self._hostdata_for(both, self.UAEN), ["aa" * 32],
                         "deploying southeastasia must not disturb uaenorth's clause")
        self.assertEqual(self._hostdata_for(both, self.SEA), ["bb" * 32])

    def test_redeploying_a_region_replaces_only_its_own_clauses(self) -> None:
        first = self._render(self.UAEN.removeprefix("https://"), ["aa" * 32], None)
        both = self._render(self.SEA.removeprefix("https://"), ["bb" * 32], first)
        # uaenorth rolls to a new measurement, spanning old+new during the window
        rolled = self._render(self.UAEN.removeprefix("https://"), ["aa" * 32, "cc" * 32], both)
        self.assertEqual(self._hostdata_for(rolled, self.UAEN), sorted(["aa" * 32, "cc" * 32]))
        self.assertEqual(self._hostdata_for(rolled, self.SEA), ["bb" * 32],
                         "rolling uaenorth must leave southeastasia untouched")

    def test_deploy_order_does_not_matter(self) -> None:
        a = self._render(self.SEA.removeprefix("https://"), ["bb" * 32],
                         self._render(self.UAEN.removeprefix("https://"), ["aa" * 32], None))
        b = self._render(self.UAEN.removeprefix("https://"), ["aa" * 32],
                         self._render(self.SEA.removeprefix("https://"), ["bb" * 32], None))
        self.assertEqual(self._authorities(a), self._authorities(b))
        for auth in self._authorities(a):
            self.assertEqual(self._hostdata_for(a, auth), self._hostdata_for(b, auth))

    def test_an_unreadable_prior_policy_is_REFUSED(self) -> None:
        """Semantics deliberately inverted after this bit in production.

        This originally asserted that a corrupt prior policy should not block a
        deploy. That is wrong: if the key HAS a policy we cannot read, rendering
        from this deploy's values alone silently revokes every other region.
        "Unreadable" and "absent" are different facts and only absent is safe.
        The decoder therefore fails, and the shell refuses.
        """
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "raw")
            with open(raw, "w") as fh:
                fh.write("{ this is not json")
            r = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("azure_decode_release_policy.py")), raw],
                capture_output=True, text=True,
            )
        self.assertNotEqual(r.returncode, 0,
                            "an unreadable policy must fail, never look like an absent one")
        self.assertEqual(r.stdout, "")

    def test_pinning_nothing_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(
                [sys.executable, "-c", _extract_release_policy_python(),
                 os.path.join(tmp, "o.json"), "x.attest.azure.net", os.path.join(tmp, "none.json")],
                capture_output=True, text=True,
            )
        self.assertNotEqual(r.returncode, 0, "a policy pinning no hostdata must be refused")


def _extract_release_policy_python() -> str:
    """Pull the python heredoc out of write_release_policy so the test exercises
    the SHIPPING renderer rather than a copy that can drift from it."""
    src = pathlib.Path(__file__).with_name("deploy-azure-aci.sh").read_text()
    start = src.index("write_release_policy() {")
    body = src[start:src.index("\nPY\n", start)]
    return body[body.index("<<'PY'\n") + len("<<'PY'\n"):]


class TestReleasePolicyDecoder(unittest.TestCase):
    """`az keyvault key show --query releasePolicy.encodedPolicy -o tsv` returns a
    PYTHON BYTES REPR, not base64, despite the field name. `base64 -d` on it
    yields nothing — and an empty result was indistinguishable from "this key has
    no policy", so the multi-region carry-over would have concluded there was
    nothing to preserve and silently revoked every other region's access to the
    bootstrap key. Those regions keep serving until their next cold start, then
    never come back.

    "Could not read it" and "there is nothing there" are different facts and only
    the second is safe to act on, so the decoder reports failure rather than
    emitting empty.
    """

    DECODER = Path(__file__).with_name("azure_decode_release_policy.py")
    POLICY = {
        "version": "1.0.0",
        "anyOf": [{
            "authority": "https://trquilluaen.uaen.attest.azure.net",
            "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": "aa" * 32}],
        }],
    }

    def _run(self, raw):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "raw")
            with open(f, "w") as fh:
                fh.write(raw)
            return subprocess.run([sys.executable, str(self.DECODER), f],
                                  capture_output=True, text=True)

    def test_decodes_the_python_bytes_repr_the_cli_actually_returns(self) -> None:
        raw = repr(json.dumps(self.POLICY).encode())
        r = self._run(raw)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), self.POLICY)

    def test_decodes_real_base64_too(self) -> None:
        raw = base64.b64encode(json.dumps(self.POLICY).encode()).decode()
        r = self._run(raw)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), self.POLICY)

    def test_decodes_plain_json(self) -> None:
        r = self._run(json.dumps(self.POLICY))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), self.POLICY)

    def test_garbage_FAILS_rather_than_emitting_empty(self) -> None:
        """The whole point: an unreadable policy must not look like an absent one."""
        for raw in ("!!!not-a-policy!!!", "b'not json'", '{"version":"1.0.0"}'):
            with self.subTest(raw=raw):
                r = self._run(raw)
                self.assertNotEqual(r.returncode, 0,
                                    f"{raw!r} must fail, not silently yield nothing")
                self.assertEqual(r.stdout, "")

    def test_empty_input_fails(self) -> None:
        self.assertNotEqual(self._run("").returncode, 0)
        self.assertNotEqual(self._run("None").returncode, 0)


class TestBoundHostdataIsScopedToThisRegion(DeployHarness):
    """The release policy is SHARED across regions; reads of it must not be.

    One key, one `anyOf` clause per region. Reading hostdata across every
    clause was correct when there was one region and silently wrong at two: it
    makes `bind` compute its baseline from the other region's measurement, so
    bringing up region two widens region two's clause to also accept region
    one's workload — and `rollback` in region two then restores region one's
    hashes into region two's clause, a state no deploy of region two can reach
    or undo.
    """

    def test_bind_does_not_absorb_another_regions_measurement(self) -> None:
        foreign = "f" * 64
        self.state_file("foreign-hostdata").write_text(foreign)

        mine = self.healthy_deploy()

        self.assertNotIn(
            foreign,
            self.bound_pins(),
            "this region's clause absorbed another region's measurement",
        )
        self.assertIn(mine, self.bound_pins())

    def test_the_other_regions_clause_survives_the_write(self) -> None:
        """Scoping the READ must not turn into dropping the other clause.

        Losing it is worse than absorbing it: the other region keeps serving
        and fails its next COLD START, which is the quietest way to lose a
        region.
        """
        foreign = "f" * 64
        self.state_file("foreign-hostdata").write_text(foreign)
        self.healthy_deploy()

        written = json.loads((self.work / "release-policy.json").read_text())
        authorities = {clause["authority"] for clause in written["anyOf"]}
        self.assertIn(FOREIGN_AUTHORITY, authorities, "the other region's clause was dropped")


class TestAuditSeesWhatDashboardsCannot(DeployHarness):
    """`audit` asks the two questions about a region that is already up.

    Both describe a fleet that is serving, green, and wrong about what happens
    NEXT — which is why nothing else reports them.
    """

    def test_a_clean_region_audits_clean(self) -> None:
        self.healthy_deploy()
        result = self.run_script("audit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("audit clean", result.stderr)

    def test_an_open_bind_window_is_a_failure(self) -> None:
        """A deploy that died at `verify` leaves {old, new} pinned forever.

        The retired measurement keeps the right to unseal every current
        provider credential. UAE North was in exactly this state when `audit`
        was written, from a deploy weeks earlier.
        """
        live = self.healthy_deploy()
        retired = "1" * 64
        self.state_file("bound-hostdata").write_text(f"{live}\n{retired}")

        result = self.run_script("audit")

        self.assertNotEqual(result.returncode, 0, "an open bind window audited clean")
        self.assertIn("bind window is still OPEN", result.stderr)
        self.assertIn(retired, result.stderr)

    def test_a_running_workload_that_lost_its_authorization_is_a_failure(self) -> None:
        """It is serving only because it holds its secrets in MEMORY.

        It dies at its next cold start — an ACI host maintenance event, at no
        time of anyone's choosing. Nothing between now and then reports it.
        """
        self.healthy_deploy()
        self.state_file("bound-hostdata").write_text("2" * 64)

        result = self.run_script("audit")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOT in this authority", result.stderr)
        self.assertIn("cold start", result.stderr)

    def test_audit_never_mutates(self) -> None:
        """It runs against production to answer a question, so it must be inert
        even when it finds problems."""
        live = self.healthy_deploy()
        self.state_file("bound-hostdata").write_text(f"{live}\n{'1' * 64}")
        self.clear_mutations()

        self.run_script("--apply", "audit")

        self.assertEqual(self.mutations(), [], "audit mutated Azure")

    def test_a_region_with_no_group_yet_is_not_a_failure(self) -> None:
        """Before a region's first deploy there is nothing to check, and
        `audit` must not become a thing operators learn to ignore."""
        # The key already exists, carrying the first region's clause.
        self.state_file("foreign-hostdata").write_text("f" * 64)
        result = self.run_script("audit")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_audit_ignores_the_other_regions_clauses(self) -> None:
        """Otherwise every region audits dirty as soon as a second exists."""
        self.state_file("foreign-hostdata").write_text("f" * 64)
        self.healthy_deploy()
        result = self.run_script("audit")
        self.assertEqual(result.returncode, 0, result.stderr)


class TestNarrowLive(DeployHarness):
    """Closing a window whose deploy workdir is long gone.

    `narrow` narrows to what THIS workspace built, which is unavailable in the
    situation that actually leaves windows open: a deploy that failed weeks
    ago, on another machine, into a temp directory. `audit` could then see the
    window and offer no way to close it, which is how it stays open.
    """

    def _verifier(self, *, succeeds: bool) -> str:
        path = self.bin / "stub-verify"
        path.write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$@" >> "$STUB_STATE/verify.log"\n'
            f"exit {0 if succeeds else 1}\n"
        )
        path.chmod(0o755)
        return str(path)

    def test_narrows_to_the_live_workload(self) -> None:
        live = self.healthy_deploy()
        self.state_file("bound-hostdata").write_text(f"{live}\n{'1' * 64}")

        result = self.run_script(
            "--apply", "narrow-live", VERIFY_ATTESTATION_CMD=self._verifier(succeeds=True)
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bound_pins(), [live])

    def test_refuses_when_the_live_enclave_does_not_attest(self) -> None:
        """Narrowing to an UNVERIFIED measurement is strictly worse than the
        open window it replaces: it revokes every other measurement while
        blessing one nobody has checked."""
        live = self.healthy_deploy()
        retired = "1" * 64
        self.state_file("bound-hostdata").write_text(f"{live}\n{retired}")
        self.clear_mutations()

        result = self.run_script(
            "--apply", "narrow-live", VERIFY_ATTESTATION_CMD=self._verifier(succeeds=False)
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did NOT attest", result.stderr)
        self.assertEqual(
            sorted(self.bound_pins()),
            sorted([live, retired]),
            "the pin was changed despite a failed attestation",
        )

    def test_verifies_against_this_regions_authority(self) -> None:
        """*.attest.azure.net is a namespace every Azure tenant can join, not
        an authority. A verifier called without the issuer pin proves nothing.
        """
        self.healthy_deploy()
        verifier = self._verifier(succeeds=True)
        self.run_script("--apply", "narrow-live", VERIFY_ATTESTATION_CMD=verifier)

        recorded = self.read_state("verify.log")
        self.assertIn("--expected-maa-issuer", recorded)
        self.assertIn("https://" + os.environ.get(
            "MAA_ENDPOINT", "trquilluaen.uaen.attest.azure.net"), recorded)

    def test_dry_run_does_not_narrow(self) -> None:
        live = self.healthy_deploy()
        retired = "1" * 64
        self.state_file("bound-hostdata").write_text(f"{live}\n{retired}")
        self.clear_mutations()

        result = self.run_script("narrow-live", VERIFY_ATTESTATION_CMD=self._verifier(succeeds=True))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [])

    def test_refuses_when_nothing_is_running(self) -> None:
        result = self.run_script(
            "--apply", "narrow-live", VERIFY_ATTESTATION_CMD=self._verifier(succeeds=True)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nothing live to narrow to", result.stderr)


class TestBundlePinGuardFiresWhereItApplies(DeployHarness):
    """A guard that fires where it does not apply gets routed around where it does.

    The only way past the unpinned-bundle refusal is ALLOW_UNPINNED_BUNDLE=1.
    While it fired on every --apply, an operator repairing a release policy at
    2am had to set that variable — and carried the habit into the one phase
    where it silently un-pins the secret set of a real deploy.
    """

    def test_deploy_still_refuses_an_unpinned_bundle(self) -> None:
        self.healthy_deploy()
        result = self.run_script("--apply", "deploy", QUILL_AZURE_BUNDLE_VERSION="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("QUILL_AZURE_BUNDLE_VERSION is unset", result.stderr)

    def test_build_still_refuses_an_unpinned_bundle(self) -> None:
        """The version is baked into the measured container at build time."""
        result = self.run_script("--apply", "build", QUILL_AZURE_BUNDLE_VERSION="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("QUILL_AZURE_BUNDLE_VERSION is unset", result.stderr)

    def test_repair_phases_do_not_demand_a_bundle_version(self) -> None:
        """narrow, narrow-live and rollback never read the bundle and cannot
        pin anything, so there is nothing for the operator to supply."""
        live = self.healthy_deploy()
        self.state_file("bound-hostdata").write_text(f"{live}\n{'1' * 64}")
        verifier = self.bin / "stub-verify-ok"
        verifier.write_text("#!/usr/bin/env bash\nexit 0\n")
        verifier.chmod(0o755)

        result = self.run_script(
            "--apply", "narrow-live",
            QUILL_AZURE_BUNDLE_VERSION="",
            VERIFY_ATTESTATION_CMD=str(verifier),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bound_pins(), [live])

    def test_audit_does_not_demand_a_bundle_version(self) -> None:
        self.healthy_deploy()
        result = self.run_script("--apply", "audit", QUILL_AZURE_BUNDLE_VERSION="")
        self.assertEqual(result.returncode, 0, result.stderr)


class TestRestartPolicyIsTheAvailabilityBudget(DeployHarness):
    """`Never` made every one-off fault permanent.

    A panic, an OOM, a transient upstream stall — anything that exits the
    process once — left the group in `Succeeded` forever, serving nothing,
    until a human noticed. Four nines is 52 minutes a YEAR; one un-restarted
    crash spends the entire budget before anyone has read the page.
    """

    def test_the_group_restarts_on_failure_by_default(self) -> None:
        self.healthy_deploy()
        template = json.loads((self.work / "template.json").read_text())
        self.assertEqual(
            template["resources"][0]["properties"]["restartPolicy"],
            "OnFailure",
            "a fault that exits the process once would be a permanent outage",
        )

    def test_never_is_still_reachable_for_debugging(self) -> None:
        """A region being actively debugged wants one clear failure, not a loop."""
        self.healthy_deploy(RESTART_POLICY="Never")
        template = json.loads((self.work / "template.json").read_text())
        self.assertEqual(template["resources"][0]["properties"]["restartPolicy"], "Never")

    def test_restart_policy_is_measured(self) -> None:
        """It is part of the container definition, so it changes HOST_DATA.

        If it were not measured, an operator could flip a deployed group's
        restart behaviour without the key noticing — and the measurement would
        stop describing the workload.
        """
        def measure(policy: str) -> str:
            result = self.run_script("--apply", "build", "template", "policy", RESTART_POLICY=policy)
            self.assertEqual(result.returncode, 0, result.stderr)
            return (self.work / "cce-policy-hash.txt").read_text().strip()

        self.assertNotEqual(
            measure("Never"), measure("OnFailure"),
            "restartPolicy did not change the measurement",
        )


class TestACrashLoopFailsFast(DeployHarness):
    """Under OnFailure a failing workload never settles on `Succeeded`.

    So the state check that catches a Key Vault 403 cannot see it — the group
    reports `Running` while restarting forever, and the deploy spins its whole
    timeout before dying with a generic message. That is the cost the old
    `Never` was buying, and it has to be paid here instead of by making every
    real fault permanent.
    """

    def test_a_climbing_restart_count_ends_the_wait(self) -> None:
        self.healthy_deploy()
        self.state_file("group-restarts").write_text("5")
        self.state_file("container-logs").write_text(
            "quill-enclave: skr release: http 403 from key vault"
        )

        result = self.run_script("--apply", "verify", VERIFY_TIMEOUT_SECONDS="60")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("crash-looping", result.stderr)
        self.assertIn("not starting slowly", result.stderr)
        self.assertIn("403", result.stderr, "the deciding log line must be shown")

    def test_one_restart_during_a_cold_start_is_tolerated(self) -> None:
        """A single restart while coming up is normal; failing on it would make
        the deploy flaky, and a flaky gate gets bypassed."""
        self.healthy_deploy()
        self.state_file("group-restarts").write_text("1")
        verifier = self.bin / "stub-verify-ok"
        verifier.write_text("#!/usr/bin/env bash\nexit 0\n")
        verifier.chmod(0o755)

        result = self.run_script(
            "--apply", "verify", VERIFY_ATTESTATION_CMD=str(verifier)
        )

        self.assertNotIn("crash-looping", result.stderr)


class TestDnsIsAPreconditionNotAnAssumption(DeployHarness):
    """A DNS fault used to be reported as an enclave fault.

    Every gcloud call in the DNS block can fail — expired credentials being the
    common one — and the error scrolled past while the deploy carried on
    waiting for /attestation on a hostname resolving nowhere. Ten minutes later
    it died saying the enclave never served, and printed the enclave's log,
    which was healthy. This cost a real debugging cycle on the southeastasia
    bring-up.
    """

    def _gcloud(self, *, succeeds: bool = True) -> None:
        """The DNS writer. Real gcloud on PATH is unauthenticated in CI, which
        made every one of these tests die at the wrong step."""
        stub = self.bin / "gcloud"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            + ("exit 0\n" if succeeds
               else "echo 'ERROR: You do not currently have an active account selected.' >&2\nexit 1\n")
        )
        stub.chmod(0o755)

    def _resolver(self, address: str) -> Path:
        stub = self.bin / "dig"
        stub.write_text(f"#!/usr/bin/env bash\necho '{address}'\n")
        stub.chmod(0o755)
        return stub

    def test_a_record_pointing_elsewhere_stops_the_wait(self) -> None:
        self.healthy_deploy()
        self._gcloud()
        self._resolver("203.0.113.7")  # not the group's 10.0.0.9

        result = self.run_script("--apply", "verify", VERIFY_TIMEOUT_SECONDS="120")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolves to 203.0.113.7", result.stderr)
        self.assertIn("NOT an enclave fault", result.stderr)

    def test_a_failed_dns_write_says_the_deploy_is_half_finished(self) -> None:
        """Under `set -e` this was a bare gcloud error and an exit code.

        In the middle of `all`, AFTER the group was created and the policy
        bound, but BEFORE verify and narrow. The operator sees an auth error
        and has no way to know Azure was already changed.
        """
        self.healthy_deploy()
        self._gcloud(succeeds=False)

        result = self.run_script("--apply", "verify")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HALF-FINISHED", result.stderr)
        self.assertIn("--apply verify narrow", result.stderr)

    def test_a_correct_record_does_not_stop_the_wait(self) -> None:
        self.healthy_deploy()
        self._gcloud()
        self._resolver("10.0.0.9")
        verifier = self.bin / "stub-verify-ok"
        verifier.write_text("#!/usr/bin/env bash\nexit 0\n")
        verifier.chmod(0o755)

        result = self.run_script("--apply", "verify", VERIFY_ATTESTATION_CMD=str(verifier))

        self.assertNotIn("NOT an enclave fault", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
