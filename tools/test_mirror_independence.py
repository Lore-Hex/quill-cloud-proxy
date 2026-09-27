"""The trust mirrors must not share a failure domain.

Three surfaces serving the same records only buys independence if they share no
hosting provider, no DNS provider, and no registrar. Each of those is a single
thing that can take down — or take over — every surface depending on it.

This is the classic invariant that is true the day it is written and quietly
false a year later, when one name gets moved to whatever provider was convenient
for an unrelated reason. Nothing about that change looks like it touches trust,
which is why it needs a test rather than a comment.

Run: python3 tools/test_mirror_independence.py
"""

from __future__ import annotations

import json
import subprocess
import unittest
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MIRRORS = REPO_ROOT / "trust-page" / "mirrors.json"
TRUST_DIR = REPO_ROOT / "trust-page"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Columns that must be pairwise disjoint across live mirrors.
FAILURE_DOMAINS = ("hosting_provider", "dns_provider", "registrar")


def _config() -> dict:
    return json.loads(MIRRORS.read_text())


class MirrorIndependence(unittest.TestCase):
    def test_live_mirrors_share_no_failure_domain(self) -> None:
        mirrors = _config()["mirrors"]
        self.assertGreaterEqual(len(mirrors), 2, "independence needs at least two mirrors")
        for column in FAILURE_DOMAINS:
            values = [m[column] for m in mirrors if m[column] != "none-of-ours"]
            duplicates = [v for v, n in Counter(values).items() if n > 1]
            self.assertEqual(
                duplicates,
                [],
                f"mirrors share {column}={duplicates}. Two surfaces behind the same "
                f"{column.replace('_', ' ')} fail together, so this is one mirror "
                "wearing two names, not two mirrors.",
            )

    def test_every_record_is_listed_and_exists(self) -> None:
        config = _config()
        for record in config["records"]:
            self.assertTrue(
                (TRUST_DIR / record).is_file(),
                f"mirrors.json lists {record} but it is not in trust-page/",
            )

    def test_all_three_planes_are_covered(self) -> None:
        records = " ".join(_config()["records"])
        for plane in ("gcp", "aws", "azure"):
            self.assertIn(
                f"{plane}-release.json",
                records,
                f"no record listed for the {plane} plane; a plane with no published "
                "record cannot be checked independently, which is the requirement.",
            )

    def test_planned_mirrors_are_not_counted_as_live(self) -> None:
        # A planned mirror is a gap, not a mitigation. Counting it would let the
        # independence assertion pass on infrastructure that does not exist.
        config = _config()
        live_urls = {m["url"] for m in config["mirrors"]}
        for planned in config.get("planned", []):
            self.assertNotIn(
                planned["url"],
                live_urls,
                f"{planned['name']} is listed as both planned and live. If it is "
                "actually serving, move it into 'mirrors' so its failure domains "
                "are checked against the others.",
            )

    def test_s3_publication_precedes_freshness(self) -> None:
        publisher = (WORKFLOWS / "publish-trust-s3.yml").read_text()
        freshness = (WORKFLOWS / "verify-trust-freshness.yml").read_text()
        script = (REPO_ROOT / "tools" / "publish-trust-s3.sh").read_text()

        self.assertIn('workflows: ["Publish trust page"]', publisher)
        self.assertIn("bash tools/publish-trust-s3.sh", publisher)
        self.assertIn("AWS_TRUST_PUBLISH_ROLE_ARN", publisher)
        self.assertIn("https://trust.quill.lorehex.co", publisher)
        self.assertIn("gh workflow run verify-trust-freshness.yml --ref main", publisher)
        self.assertNotIn("\n  workflow_run:\n", freshness)
        self.assertNotIn("\n  push:\n", freshness)
        self.assertIn('s3://${bucket}/', script)
        self.assertIn("--delete", script)

    def test_publish_trust_s3_yml_is_the_only_writer_of_the_s3_mirror(self) -> None:
        # aws s3 sync skips a same-size file whose local copy is older than the
        # S3 copy, so a sync from an older checkout, or one racing another
        # writer, can upload a file's root copy and skip its trust/ copy. Only
        # publish-trust-s3.yml writes the mirror: one run at a time, from a
        # checkout of main. Nothing here is executed; the files are read, and
        # workflows are parsed as YAML.
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.split("\0")
        workflows = {
            name: yaml.safe_load((REPO_ROOT / name).read_text())
            for name in tracked
            if name.startswith(".github/") and name.endswith((".yml", ".yaml"))
        }
        scripts = {
            name: (REPO_ROOT / name).read_text(errors="replace")
            for name in tracked
            if (name == "Makefile" or name.endswith((".sh", ".py")))
            and not Path(name).name.startswith("test_")
        }

        # One script holds the S3 commands. Comment lines, including those in a
        # workflow step's shell, run nothing.
        self.assertEqual(
            sorted(
                [name for name, text in scripts.items() if "aws s3" in _code(text)]
                + [
                    name
                    for name, doc in workflows.items()
                    if any("aws s3" in _code(value) for _, value in _strings(doc))
                ]
            ),
            ["tools/publish-trust-s3.sh"],
        )
        # One workflow step runs it. A workflow's path filters name it without
        # running it, and no script names it outside a comment.
        runs = [
            (name, path)
            for name, doc in workflows.items()
            for path, value in _strings(doc)
            if "publish-trust-s3.sh" in _code(value) and "paths" not in path
        ]
        self.assertEqual(len(runs), 1, runs)
        self.assertEqual(runs[0][0], ".github/workflows/publish-trust-s3.yml")
        self.assertEqual(runs[0][1][-1], "run")
        self.assertEqual(
            [name for name, text in scripts.items() if "publish-trust-s3.sh" in _code(text)],
            [],
        )
        # That workflow runs one at a time, from main.
        publisher = workflows[".github/workflows/publish-trust-s3.yml"]
        self.assertEqual(
            publisher.get("concurrency"),
            {"group": "trust-s3-deployment", "cancel-in-progress": False},
        )
        (job,) = publisher["jobs"].values()
        self.assertEqual(
            [
                step.get("with", {}).get("ref")
                for step in job["steps"]
                if str(step.get("uses", "")).startswith("actions/checkout")
            ],
            ["main"],
        )
        # It refuses a tree whose two copies of a file differ, before syncing.
        script = [
            line.strip()
            for line in scripts["tools/publish-trust-s3.sh"].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        sync_line = next((i for i, line in enumerate(script) if line.startswith("aws s3 sync")), None)
        self.assertIsNotNone(sync_line)
        for checker in ("check-trust-copies.py", "check-trust-signatures.py"):
            check_line = next((i for i, line in enumerate(script) if checker in line), None)
            self.assertIsNotNone(check_line, f"tools/publish-trust-s3.sh does not run {checker}")
            self.assertLess(check_line, sync_line)
        # Both workflows install cosign before the step that needs it, and Pages
        # checks the signatures before it uploads anything.
        self.assertLess(
            _step(publisher, "sigstore/cosign-installer"), _step(publisher, "bash tools/publish-trust-s3.sh")
        )
        pages = workflows[".github/workflows/publish-trust-page.yml"]
        self.assertLess(
            _step(pages, "sigstore/cosign-installer"),
            _step(pages, "python3 tools/check-trust-signatures.py trust-page"),
        )
        self.assertLess(
            _step(pages, "python3 tools/check-trust-signatures.py trust-page"),
            _step(pages, "actions/upload-pages-artifact"),
        )
        # Those steps always run. The cosign version the trust workflows install
        # is checked in tools/test_check_trust_signatures.py.
        for workflow, command in (
            (publisher, "sigstore/cosign-installer"),
            (publisher, "bash tools/publish-trust-s3.sh"),
            (pages, "sigstore/cosign-installer"),
            (pages, "python3 tools/check-trust-signatures.py trust-page"),
        ):
            (job,) = workflow["jobs"].values()
            step = job["steps"][_step(workflow, command)]
            self.assertNotIn("if", step, command)
            self.assertFalse(step.get("continue-on-error"), command)


def _step(workflow: dict, command: str) -> int:
    """The index of the single job's first step that uses or runs command."""
    (job,) = workflow["jobs"].values()
    for index, step in enumerate(job["steps"]):
        if str(step.get("uses", "")).startswith(command) or command in _code(step.get("run", "")):
            return index
    raise AssertionError(f"no step uses or runs {command}")


def _code(text: str) -> str:
    """text without its comment lines."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _strings(node: object, path: tuple = ()) -> list[tuple[tuple, str]]:
    """Each string in a parsed YAML document, with the keys and indexes leading to it."""
    if isinstance(node, str):
        return [(path, node)]
    if isinstance(node, dict):
        return [item for key, value in node.items() for item in _strings(value, (*path, str(key)))]
    if isinstance(node, list):
        return [item for index, value in enumerate(node) for item in _strings(value, (*path, index))]
    return []


if __name__ == "__main__":
    unittest.main()
