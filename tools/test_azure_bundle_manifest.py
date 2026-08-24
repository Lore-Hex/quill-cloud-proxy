"""The Azure deploy may not name a secret the sealed bundle cannot serve.

deploy-azure-aci.sh names a QUILL_*_SECRET for every provider; the sealed
bootstrap bundle holds a value for each of those names. They move on different
clocks — a provider PR edits the deploy script in one commit, the bundle only
changes when someone re-seals — and when the deploy names a secret the pinned
immutable bundle never held, the enclave dies at bootstrap with "no entry ...
in the bundle" AFTER a full attestation round trip. That is the shape that took
Dubai down on 2026-08-24 (stepfun + 18 more) and the Foundry crash the day
before; NVIDIA NIM was one rebase from being the next.

This converts that boot-time fatal into a merge-time CI failure: the check
reads the checked-in bundle manifest (the shadow of the immutable Key Vault
secret) and the deploy script, and fails if the deploy demands a name the
bundle does not carry. It reuses azure-seal-bundle.py's own parse helpers so
the guard and the sealer cannot disagree about what "demanded" means.

If this fails: a provider was given a non-empty QUILL_*_SECRET default in the
deploy without its key being sealed. Either seal a new bundle (which
regenerates tools/azure-bundle.manifest and prints a new bundle version to
pin) or default the secret empty to leave that provider dark on Azure. Do NOT
hand-add the name to the manifest — the manifest tracks what is actually
sealed, and a name with no value behind it re-arms the exact crash.

Run: python3 tools/test_azure_bundle_manifest.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"
SEALER_PATH = TOOLS / "azure-seal-bundle.py"
MANIFEST_PATH = TOOLS / "azure-bundle.manifest"
DEPLOY_PATH = TOOLS / "deploy-azure-aci.sh"


def _load_sealer():
    # The module file name has hyphens, so it cannot be imported by name; load
    # it from its path. Loading it (rather than re-implementing the parse here)
    # is the point — the test exercises the same deploy_demanded_names /
    # read_manifest_names the sealer's own --check-deploy-manifest uses.
    spec = importlib.util.spec_from_file_location("azure_seal_bundle", SEALER_PATH)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the sealer defines frozen dataclasses, and
    # dataclasses resolves field types through sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sealer = _load_sealer()


class TestDeployNamesOnlyProvisionedSecrets(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        self.deploy_text = DEPLOY_PATH.read_text(encoding="utf-8")
        self.provisioned = sealer.read_manifest_names(self.manifest_text)
        self.demanded = sealer.deploy_demanded_names(self.deploy_text)

    def test_manifest_and_deploy_both_parse_nonempty(self) -> None:
        # A guard that silently matches nothing passes for the wrong reason; if
        # either shape changes out from under the regex, fail loudly here.
        self.assertTrue(
            self.provisioned,
            "azure-bundle.manifest parsed no provisioned names",
        )
        self.assertTrue(
            self.demanded,
            "deploy-azure-aci.sh parsed no demanded QUILL_*_SECRET names",
        )

    def test_manifest_declares_a_bundle_version(self) -> None:
        version = sealer.read_manifest_version(self.manifest_text)
        self.assertRegex(
            version,
            r"^[0-9a-f]{32}$",
            "manifest must declare '# bundle-version: <32-hex>' — the immutable "
            "Key Vault secret version it mirrors",
        )

    def test_every_deployed_secret_is_provisioned(self) -> None:
        unserved = sorted(
            name for name in self.demanded.values() if name not in self.provisioned
        )
        self.assertEqual(
            unserved,
            [],
            "deploy-azure-aci.sh names {n} secret(s) absent from the sealed bundle "
            "manifest: {names}. An enclave built from this deploy dies at bootstrap "
            'with "no entry ... in the bundle". Seal a new bundle to provision them, '
            'or default each empty (QUILL_X_SECRET="${{QUILL_X_SECRET:-}}") to leave '
            "the provider dark on Azure.".format(n=len(unserved), names=unserved),
        )

    def test_checker_entrypoint_agrees_with_this_test(self) -> None:
        # The sealer's --check-deploy-manifest is what CI actually runs; prove it
        # returns success on the same tree this test passes on, so the two cannot
        # diverge into a green test beside a red gate or vice versa.
        self.assertEqual(sealer.check_deploy_against_manifest(), 0)


class TestDeployParseIsHonest(unittest.TestCase):
    """The parse must distinguish a named secret from a deliberately dark one."""

    def test_empty_default_is_not_demanded(self) -> None:
        sample = 'QUILL_STEPFUN_SECRET="${QUILL_STEPFUN_SECRET:-}"\n'
        self.assertEqual(sealer.deploy_demanded_names(sample), {})

    def test_nonempty_default_is_demanded_under_its_name(self) -> None:
        sample = 'QUILL_STEPFUN_SECRET="${QUILL_STEPFUN_SECRET:-trustedrouter-stepfun-api-key}"\n'
        self.assertEqual(
            sealer.deploy_demanded_names(sample),
            {"QUILL_STEPFUN_SECRET": "trustedrouter-stepfun-api-key"},
        )

    def test_a_reintroduced_unprovisioned_default_would_fail(self) -> None:
        # Regression fixture for the Dubai crash: re-adding a non-empty default
        # for a secret the manifest lacks must be caught. Simulate by asking the
        # parse+diff directly rather than mutating the real deploy file.
        provisioned = sealer.read_manifest_names(MANIFEST_PATH.read_text())
        reintroduced = 'QUILL_GHOST_SECRET="${QUILL_GHOST_SECRET:-trustedrouter-ghost-api-key}"\n'
        demanded = sealer.deploy_demanded_names(reintroduced)
        unserved = [n for n in demanded.values() if n not in provisioned]
        self.assertEqual(unserved, ["trustedrouter-ghost-api-key"])


if __name__ == "__main__":
    unittest.main()
