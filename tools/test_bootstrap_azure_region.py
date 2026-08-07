#!/usr/bin/env python3
"""Regression tests for tools/bootstrap-azure-region.sh.

Run directly (repo convention for tool tests):

    python3 tools/test_bootstrap_azure_region.py

WHY THIS FILE EXISTS
--------------------
This script hands a new region's identity the right to release the wrapping key
that unseals every provider credential the fleet holds. It runs rarely, by
hand, under time pressure, in a region that does not work yet — which is
exactly the situation in which nobody notices that it did something subtly
wrong.

Two of its failure modes are silent and expensive:

  RECREATING AN EXISTING IDENTITY mints a fresh principalId. The old one's four
  role assignments still exist, pointing at a principal the container group no
  longer runs as. Every check reports green: the identity exists, the grants
  exist, the deploy succeeds. The running enclave is untouched because it holds
  its secrets in memory. The region dies at its next COLD START, with a Key
  Vault 403, possibly weeks later.

  DECLARING SUCCESS BEFORE RBAC PROPAGATES sends the operator into a deploy
  that 403s, and a propagation 403 is byte-identical to a HOST_DATA-mismatch
  403. One is fixed by waiting, the other by a re-bind. Guessing wrong costs a
  full deploy cycle in each direction.

Nothing here touches Azure. `az` is a Python stub on PATH; every call is logged
and every mutating call is logged separately, so "this run would have granted
production access" is a testable claim.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "tools" / "bootstrap-azure-region.sh"

# ---------------------------------------------------------------------------
# the az stub
# ---------------------------------------------------------------------------
# State is one file per fact in $STUB_STATE, so a test sets up "the identity
# already exists and its grants have not propagated" by writing two files.
#
# az.log       every invocation
# mutations.log everything that would CHANGE Azure

AZ_STUB = r'''#!/usr/bin/env python3
import os, sys

state = os.environ["STUB_STATE"]
argv = sys.argv[1:]


def read(name, default=""):
    try:
        with open(os.path.join(state, name)) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        return default


def log(name, line):
    with open(os.path.join(state, name), "a") as fh:
        fh.write(line + "\n")


log("az.log", " ".join(argv))
group = argv[:2]


def out(value):
    sys.stdout.write(value + "\n")
    sys.exit(0)


if group == ["account", "show"]:
    out("SUBSCRIPTION-ID")

if group == ["group", "show"]:
    sys.exit(0 if read("group_exists", "1") == "1" else 1)

if group == ["keyvault", "show"]:
    sys.exit(0 if read("vault_exists", "1") == "1" else 1)

if group == ["acr", "show"]:
    sys.exit(0 if read("acr_exists", "1") == "1" else 1)

if group == ["keyvault", "key"] and argv[2] == "show":
    # Two distinct uses: the shared-prerequisite existence check, and the
    # propagation proof (which asks for the release policy).
    if "--query" in argv:
        if read("policy_readable", "1") != "1":
            sys.exit(1)
        out("POLICY")
    sys.exit(0 if read("key_exists", "1") == "1" else 1)

if group == ["identity", "show"]:
    if read("identity_exists", "0") != "1":
        sys.exit(1)
    out(read("principal_id", "EXISTING-PRINCIPAL"))

if group == ["identity", "create"]:
    log("mutations.log", "identity create " + " ".join(argv))
    with open(os.path.join(state, "identity_exists"), "w") as fh:
        fh.write("1")
    with open(os.path.join(state, "principal_id"), "w") as fh:
        fh.write("NEW-PRINCIPAL")
    sys.exit(0)

if group == ["role", "assignment"] and argv[2] == "create":
    if read("grant_create_fails", "0") == "1":
        sys.exit(1)
    log("mutations.log", "role assignment create " + " ".join(argv))
    sys.exit(0)

if group == ["role", "assignment"] and argv[2] == "list":
    out(read("existing_grant_id", ""))

sys.exit(0)
'''


def run(*, apply: bool, **facts) -> tuple[int, str, list[str], list[str]]:
    """Run the script against a stubbed az. Returns (rc, output, calls, mutations)."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "state"
        state.mkdir()
        binaries = Path(tmp) / "bin"
        binaries.mkdir()
        for name, value in facts.items():
            (state / name).write_text(str(value))

        stub = binaries / "az"
        stub.write_text(AZ_STUB)
        stub.chmod(0o755)

        env = dict(os.environ)
        env.update(
            PATH=f"{binaries}:{env['PATH']}",
            STUB_STATE=str(state),
            LOCATION="southeastasia",
            RESOURCE_GROUP="TR-TEE-SEA",
            PROPAGATION_TIMEOUT="0",
        )
        argv = ["bash", str(SCRIPT)] + (["--apply"] if apply else [])
        proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120)

        def lines(name: str) -> list[str]:
            path = state / name
            return path.read_text().splitlines() if path.exists() else []

        return proc.returncode, proc.stdout + proc.stderr, lines("az.log"), lines("mutations.log")


class TestDryRunIsInert(unittest.TestCase):
    def test_dry_run_mutates_nothing(self):
        """A dry run must not create the identity or any grant.

        This script's whole justification is that grants are deliberate. A dry
        run that quietly granted would make that claim false, and the operator
        would have no reason to look.
        """
        rc, out, _calls, mutations = run(apply=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual(mutations, [], f"dry run mutated Azure: {mutations}")
        self.assertIn("DRY RUN", out)

    def test_dry_run_names_every_grant_it_would_make(self):
        """The plan must be readable, or "dry run first" is not real review."""
        _rc, out, _calls, _mut = run(apply=False)
        for role in (
            "Key Vault Crypto Service Release User",
            "Key Vault Crypto Officer",
            "Key Vault Secrets User",
            "AcrPull",
        ):
            self.assertIn(role, out)


class TestIdentityIsReusedNeverRecreated(unittest.TestCase):
    def test_existing_identity_is_not_recreated(self):
        """Recreating mints a new principalId and orphans all four grants.

        The damage is invisible until the region cold-starts, because a running
        enclave holds its unsealed secrets in memory. This is the single most
        expensive mistake this script could make.
        """
        rc, out, _calls, mutations = run(apply=True, identity_exists="1")
        self.assertEqual(rc, 0, out)
        creates = [m for m in mutations if m.startswith("identity create")]
        self.assertEqual(creates, [], "an existing identity was RECREATED — grants are now orphaned")
        self.assertIn("already exists", out)

    def test_absent_identity_is_created(self):
        rc, out, _calls, mutations = run(apply=True, identity_exists="0")
        self.assertEqual(rc, 0, out)
        self.assertTrue(
            any(m.startswith("identity create") for m in mutations),
            "identity was missing and was not created",
        )


class TestGrants(unittest.TestCase):
    def test_all_four_grants_at_the_right_scopes(self):
        """Each grant unblocks a different point in the boot.

        Release User releases the key, Crypto Officer re-binds the policy,
        Secrets User reads the bundle, AcrPull pulls the image. Dropping any
        one produces a 403 at a different moment, so a partial grant reads as a
        different bug than it is.
        """
        rc, out, _calls, mutations = run(apply=True)
        self.assertEqual(rc, 0, out)
        grants = [m for m in mutations if m.startswith("role assignment create")]
        self.assertEqual(len(grants), 4, f"expected 4 grants, got: {grants}")

        vault_scoped = [g for g in grants if "vaults/trquillkv" in g]
        acr_scoped = [g for g in grants if "registries/trquillacr" in g]
        self.assertEqual(len(vault_scoped), 3, f"vault grants: {vault_scoped}")
        self.assertEqual(len(acr_scoped), 1, f"acr grants: {acr_scoped}")

    def test_grants_target_the_principal_id_not_the_name(self):
        """A just-created identity has not replicated to AAD.

        Resolving it by name goes through Graph and fails intermittently, which
        looks like a permissions problem and is not one.
        """
        rc, _out, _calls, mutations = run(apply=True, identity_exists="0")
        self.assertEqual(rc, 0)
        for grant in (m for m in mutations if m.startswith("role assignment create")):
            self.assertIn("--assignee-object-id", grant)
            self.assertIn("NEW-PRINCIPAL", grant)

    def test_already_granted_is_not_an_error(self):
        """Re-running after a partial failure must converge, not refuse."""
        rc, out, _calls, _mut = run(
            apply=True, grant_create_fails="1", existing_grant_id="/some/assignment/id"
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("already granted", out)

    def test_ungrantable_and_absent_is_fatal(self):
        """The dangerous case: the grant could not be made and is not present.

        Continuing here would hand the operator a "ready for a deploy" message
        for a region that cannot read the key — sending them to debug the
        deploy for a fault that is one step upstream of it.
        """
        rc, out, _calls, _mut = run(apply=True, grant_create_fails="1", existing_grant_id="")
        self.assertNotEqual(rc, 0, "script declared success without the grant")
        self.assertIn("User Access Administrator", out)


class TestPrerequisitesAreCheckedNotAssumed(unittest.TestCase):
    def test_missing_resource_group_is_fatal(self):
        """The script grants access; it does not decide where a region lives.

        Creating the group here would let a typo in LOCATION silently stand up
        a region in the wrong jurisdiction — which for a confidential-compute
        product is a compliance fact, not an inconvenience.
        """
        rc, out, _calls, mutations = run(apply=True, group_exists="0")
        self.assertNotEqual(rc, 0)
        self.assertEqual(mutations, [], "mutated Azure despite a missing resource group")
        self.assertIn("does not exist", out)

    def test_missing_wrapping_key_is_fatal(self):
        """Without the key there is nothing to release, and the deploy's
        first act — widening the release policy — has no target."""
        rc, out, _calls, mutations = run(apply=True, key_exists="0")
        self.assertNotEqual(rc, 0)
        self.assertEqual(mutations, [])
        self.assertIn("wrapping key", out)

    def test_missing_registry_is_fatal(self):
        rc, out, _calls, mutations = run(apply=True, acr_exists="0")
        self.assertNotEqual(rc, 0)
        self.assertEqual(mutations, [])


class TestPropagationIsProvenNotAssumed(unittest.TestCase):
    def test_unreadable_key_blocks_the_ready_message(self):
        """If the grants have not propagated, saying "ready" is the whole bug.

        The operator deploys, gets a 403, and cannot tell it from a HOST_DATA
        mismatch. With PROPAGATION_TIMEOUT=0 this asserts the loop is a real
        gate rather than a decorative retry.
        """
        rc, out, _calls, _mut = run(apply=True, policy_readable="0")
        self.assertNotEqual(rc, 0, "declared the region ready without proving access")
        self.assertIn("did not propagate", out)
        self.assertNotIn("ready for a deploy", out)

    def test_readable_key_yields_the_ready_message(self):
        rc, out, _calls, _mut = run(apply=True)
        self.assertEqual(rc, 0, out)
        self.assertIn("grants are live", out)
        self.assertIn("ready for a deploy", out)

    def test_ready_message_warns_about_the_other_regions_policy_clauses(self):
        """The deploy widens a SHARED key's release policy.

        If it drops the other regions' clauses they keep serving and fail their
        next cold start — the quietest possible way to lose a region, so the
        operator must be told to check for it before they walk away.
        """
        _rc, out, _calls, _mut = run(apply=True)
        self.assertIn("cold start", out.lower())


class TestRequiredInputs(unittest.TestCase):
    def test_location_is_required(self):
        env = dict(os.environ, LOCATION="", RESOURCE_GROUP="TR-TEE-SEA")
        proc = subprocess.run(
            ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("LOCATION is required", proc.stdout + proc.stderr)

    def test_resource_group_is_required(self):
        env = dict(os.environ, LOCATION="southeastasia", RESOURCE_GROUP="")
        proc = subprocess.run(
            ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("RESOURCE_GROUP is required", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
