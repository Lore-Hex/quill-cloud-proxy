"""Guard the gitleaks secret scan: pinned binary, fail-closed, redacted, narrow allowlists."""
from pathlib import Path
import re
import tomllib
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/secret-scan.yml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def _steps():
    return _workflow()["jobs"]["gitleaks"]["steps"]


def _step(name_prefix):
    return next(step for step in _steps() if step.get("name", "").startswith(name_prefix))


class SecretScanWorkflowTest(unittest.TestCase):
    def test_runs_on_every_pr_and_push_to_main_with_read_only_token(self):
        workflow = _workflow()
        triggers = workflow[True]  # YAML 1.1 parses the GitHub `on` key as True.
        self.assertEqual(
            triggers,
            {
                "pull_request": {"branches": ["main"]},
                "push": {"branches": ["main"]},
                "workflow_dispatch": {},
            },
        )
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), {"gitleaks"})
        job = workflow["jobs"]["gitleaks"]
        self.assertNotIn("permissions", job)
        self.assertNotIn("if", job)  # PRs from forks are scanned too.
        self.assertNotIn("secrets.", WORKFLOW.read_text())

    def test_fails_closed(self):
        job = _workflow()["jobs"]["gitleaks"]
        self.assertNotIn("continue-on-error", job)
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
            if "run" in step:
                self.assertTrue(step["run"].lstrip().startswith("set -euo pipefail"), step.get("name"))

    def test_checkout_is_sha_pinned_with_full_history_and_no_credentials(self):
        checkout = _steps()[0]
        self.assertRegex(checkout["uses"], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertEqual(checkout["with"], {"fetch-depth": 0, "persist-credentials": False})
        # Only the checkout is an action; gitleaks itself is a verified binary.
        self.assertEqual([step["uses"] for step in _steps() if "uses" in step], [checkout["uses"]])

    def test_gitleaks_binary_is_version_pinned_and_checksum_verified(self):
        env = _workflow()["env"]
        self.assertRegex(env["GITLEAKS_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(env["GITLEAKS_SHA256"], r"^[0-9a-f]{64}$")
        run = _step("Install gitleaks")["run"]
        self.assertIn("https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}", run)
        self.assertIn('echo "${GITLEAKS_SHA256}  ${tarball}" | sha256sum -c -', run)
        self.assertIn('grep -qxF "${GITLEAKS_SHA256}  ${tarball}" "$checksums"', run)
        # Verification happens before the archive is unpacked or run.
        self.assertLess(run.index("sha256sum -c"), run.index("tar -xzf"))
        self.assertLess(run.index("tar -xzf"), run.index("./gitleaks version"))

    def test_scan_is_redacted_and_limited_to_the_added_commits(self):
        step = _step("Scan added commits")
        self.assertEqual(
            step["env"],
            {
                "EVENT": "${{ github.event_name }}",
                "PR_BASE": "${{ github.event.pull_request.base.sha }}",
                "PR_HEAD": "${{ github.event.pull_request.head.sha }}",
                "PUSH_BEFORE": "${{ github.event.before }}",
                "PUSH_AFTER": "${{ github.event.after }}",
            },
        )
        run = step["run"]
        self.assertNotIn("${{", run)  # Event data reaches the shell only through env.
        self.assertIn('range="${PR_BASE}..${PR_HEAD}"', run)
        self.assertIn('range="${PUSH_BEFORE}..${PUSH_AFTER}"', run)
        command = re.search(r"gitleaks git .*?\.$", run, re.S)
        self.assertIsNotNone(command)
        flags = command.group(0).split()
        for flag in ("--redact", "--exit-code", "--config", '--log-opts="--diff-merges=first-parent', '$range"'):
            self.assertIn(flag, flags)
        self.assertEqual(flags[flags.index("--exit-code") + 1], "1")
        self.assertEqual(flags[flags.index("--config") + 1], ".gitleaks.toml")
        self.assertFalse(any(flag.startswith("--redact=") for flag in flags))  # Full redaction only.
        # Both ends must resolve before the scan, and the count is its own command.
        self.assertIn('git rev-parse --verify --quiet "${end}^{commit}"', run)
        self.assertIn('count=$(git rev-list --count "$range")', run)

    def test_allowlists_extend_the_default_rules_and_stay_rule_scoped(self):
        config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
        self.assertEqual(config["extend"], {"useDefault": True})
        self.assertNotIn("rules", config)  # No default rule is replaced or weakened.
        self.assertNotIn("allowlist", config)  # The legacy unscoped form.
        self.assertTrue(config["allowlists"])
        for allowlist in config["allowlists"]:
            with self.subTest(allowlist=allowlist["description"][:60]):
                self.assertTrue(allowlist["targetRules"])
                self.assertTrue(allowlist["paths"])
                self.assertLessEqual(
                    set(allowlist),
                    {"description", "targetRules", "paths", "condition", "regexTarget", "regexes"},
                )
                if "regexes" in allowlist:
                    # A value pattern only ever narrows a path entry, never stands alone.
                    self.assertEqual(allowlist["condition"], "AND")
                for path in allowlist["paths"]:
                    self.assertTrue(path.startswith("^"), path)
                    re.compile(path)


if __name__ == "__main__":
    unittest.main()
