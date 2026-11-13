"""Lore-Hex runs no third-party GitHub Actions.

Every `uses:` in .github/workflows and .github/actions must be one of:
  * a GitHub-owned action (actions/*, github/*) pinned by full commit SHA with
    a `# vX.Y.Z` comment;
  * this repository's own composite action, pinned by full commit SHA:
    Lore-Hex/quill-cloud-proxy/.github/actions/<name>@<sha>;
  * a local reusable workflow, or, only in actions-selftest.yml, a local
    action (./.github/actions/<name>) that tests the pull request's own tree.
The repository's Actions setting (allowed_actions=selected, GitHub-owned plus
Lore-Hex/*) enforces the same boundary on GitHub's side.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OWN_ACTIONS = "Lore-Hex/quill-cloud-proxy/.github/actions/"
GITHUB_OWNED = re.compile(r"(actions|github)/[A-Za-z0-9._-]+(/[A-Za-z0-9._/-]+)?@[0-9a-f]{40}")
OWN = re.compile(re.escape(OWN_ACTIONS) + r"([a-z0-9-]+)@[0-9a-f]{40}")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<value>[^#\n]*?)\s*(?:#\s*(?P<comment>.*))?$")


def _files(root: Path) -> list[Path]:
    return sorted([*(root / ".github/workflows").glob("*.y*ml"), *(root / ".github/actions").glob("*/action.y*ml")])


def _uses_lines(path: Path) -> list[tuple[int, str, str | None]]:
    found = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        match = USES_LINE.match(line)
        if match and not line.lstrip().startswith("#"):
            found.append((number, match["value"].strip().strip("'\""), match["comment"]))
    return found


def violations(root: Path = ROOT) -> list[str]:
    problems = []
    for path in _files(root):
        relative = path.relative_to(root).as_posix()
        for number, value, comment in _uses_lines(path):
            where = f"{relative}:{number}: {value}"
            if value.startswith("./.github/workflows/") and relative.startswith(".github/workflows/"):
                continue
            if value.startswith("./.github/actions/") and relative == ".github/workflows/actions-selftest.yml":
                if not (root / value / "action.yml").is_file():
                    problems.append(f"{where}: no such local action")
                continue
            if GITHUB_OWNED.fullmatch(value):
                if not (comment and re.fullmatch(r"v\d+\.\d+\.\d+", comment.strip())):
                    problems.append(f"{where}: a GitHub-owned action needs a '# vX.Y.Z' comment")
                continue
            own = OWN.fullmatch(value)
            if own:
                if not (root / ".github/actions" / own[1] / "action.yml").is_file():
                    problems.append(f"{where}: no .github/actions/{own[1]}/action.yml in this repository")
                continue
            problems.append(f"{where}: not a SHA-pinned GitHub-owned or Lore-Hex action")
    return problems


class WorkflowActionPolicyTest(unittest.TestCase):
    def test_every_action_is_github_owned_or_our_own_and_pinned_by_sha(self) -> None:
        self.assertEqual(violations(), [])

    def test_the_workflows_use_one_pin_for_the_repository_actions(self) -> None:
        pins = {
            value.rsplit("@", 1)[1]
            for path in (ROOT / ".github/workflows").glob("*.y*ml")
            for _, value, _ in _uses_lines(path)
            if value.startswith(OWN_ACTIONS)
        }
        self.assertEqual(len(pins), 1, pins)

    def test_composite_actions_name_no_other_action(self) -> None:
        for path in (ROOT / ".github/actions").glob("*/action.y*ml"):
            action = yaml.safe_load(path.read_text())
            self.assertEqual(action["runs"]["using"], "composite", path)
            self.assertTrue(all("uses" not in step for step in action["runs"]["steps"]), path)

    def test_the_policy_rejects_what_it_should(self) -> None:
        sha = "0123456789abcdef0123456789abcdef01234567"
        for uses, accepted in (
            ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1", True),
            (f"{OWN_ACTIONS}setup-uv@{sha} # main", True),
            ("actions/checkout@v7", False),
            ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", False),
            ("sigstore/cosign-installer@v3", False),
            (f"aws-actions/configure-aws-credentials@{sha} # v6.0.0", False),
            (f"{OWN_ACTIONS}setup-uv@main", False),
            (f"{OWN_ACTIONS}no-such-action@{sha} # main", False),
            (f"Lore-Hex/quill-router/.github/actions/setup-uv@{sha} # main", False),
            ("google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@" + sha, False),
            ("./.github/actions/setup-uv", False),
            ("docker://alpine:3", False),
        ):
            with self.subTest(uses=uses), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".github/workflows").mkdir(parents=True)
                (root / ".github/actions/setup-uv").mkdir(parents=True)
                (root / ".github/actions/setup-uv/action.yml").write_text("runs: {using: composite, steps: []}\n")
                (root / ".github/workflows/x.yml").write_text(f"jobs:\n  j:\n    steps:\n      - uses: {uses}\n")
                self.assertEqual(violations(root) == [], accepted)

    def test_reusable_workflow_calls_are_local(self) -> None:
        for path in (ROOT / ".github/workflows").glob("*.y*ml"):
            workflow = yaml.safe_load(path.read_text())
            for name, job in workflow.get("jobs", {}).items():
                if "uses" in job:
                    with self.subTest(workflow=path.name, job=name):
                        self.assertTrue(job["uses"].startswith("./.github/workflows/"), job["uses"])


if __name__ == "__main__":
    unittest.main()
