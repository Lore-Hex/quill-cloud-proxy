#!/usr/bin/env python3
"""Offline tests for gateway release trains (tools/superseded_rollout.py)."""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("superseded_rollout", ROOT / "tools/superseded_rollout.py")
train = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = train
SPEC.loader.exec_module(train)

WORKFLOW = ROOT / ".github/workflows/deploy-enclave-gcp.yml"
A, B, C = "a" * 40, "b" * 40, "c" * 40


def run(run_id, number, sha, status="pending", conclusion=None, event="push", branch="main"):
    return {"id": run_id, "run_number": number, "head_sha": sha, "status": status,
            "conclusion": conclusion, "event": event, "head_branch": branch}


class FakeGitHub:
    """Commit graph A -> B -> C on main unless told otherwise."""

    def __init__(self, runs, ci=None, order=(A, B, C), main=C, fail=None):
        self.listing, self.ci_states = runs, ci or {}
        self.order, self.main, self.fail = list(order), main, fail
        self.calls = []

    def runs(self, workflow):
        self.calls.append(("runs", workflow))
        if self.fail == "runs":
            raise train.Unknown("listing failed")
        return self.listing

    def compare(self, base, head):
        self.calls.append(("compare", base, head))
        if self.fail == "compare":
            raise train.Unknown("compare failed")
        head = self.main if head == "main" else head
        if base not in self.order or head not in self.order:
            return "diverged"
        i, j = self.order.index(base), self.order.index(head)
        return "identical" if i == j else ("ahead" if j > i else "behind")

    def ci(self, sha):
        self.calls.append(("ci", sha))
        states = self.ci_states.get(sha, ("completed", "success"))
        if isinstance(states, list):
            return states.pop(0) if len(states) > 1 else states[0]
        return states


def decide(github, sha=A, event="push", run_id=10, **kwargs):
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    return train.decide(github, "deploy-enclave-gcp.yml", run_id, sha, event,
                        sleep=sleep, monotonic=lambda: clock[0], **kwargs)


class TrainTests(unittest.TestCase):
    def test_older_run_skips_for_newer_queued_green_descendant(self):
        github = FakeGitHub([run(12, 3, C), run(11, 2, B), run(10, 1, A, "in_progress")])
        decision = decide(github)
        self.assertFalse(decision.proceed)
        self.assertIn("queued run 12", decision.reason)  # newest successor is named

    def test_newest_run_proceeds_and_carries_the_train(self):
        github = FakeGitHub([run(12, 3, C, "in_progress"), run(11, 2, B, "completed", "success"),
                             run(10, 1, A, "completed", "success")])
        self.assertTrue(decide(github, sha=C, run_id=12).proceed)

    def test_manual_dispatch_never_skips(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress", event="workflow_dispatch")])
        decision = decide(github, event="workflow_dispatch")
        self.assertTrue(decision.proceed)
        self.assertEqual(github.calls, [])

    def test_queued_dispatch_is_not_a_successor(self):
        github = FakeGitHub([run(12, 3, C, event="workflow_dispatch"), run(10, 1, A, "in_progress")])
        self.assertTrue(decide(github).proceed)

    def test_red_successor_is_not_yielded_to(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")], ci={C: ("completed", "failure")})
        self.assertTrue(decide(github).proceed)

    def test_falls_back_to_an_older_green_successor_when_the_newest_is_red(self):
        github = FakeGitHub([run(12, 3, C), run(11, 2, B), run(10, 1, A, "in_progress")],
                            ci={C: ("completed", "failure")})
        decision = decide(github)
        self.assertFalse(decision.proceed)
        self.assertIn("queued run 11", decision.reason)

    def test_successor_ci_still_running_is_awaited_then_used(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")],
                            ci={C: [("in_progress", None), ("completed", "success")]})
        self.assertFalse(decide(github).proceed)

    def test_successor_ci_that_never_finishes_means_proceed(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")], ci={C: ("in_progress", None)})
        self.assertTrue(decide(github, ci_wait=120).proceed)

    def test_successor_without_any_ci_run_means_proceed(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")], ci={C: None})
        self.assertTrue(decide(github, ci_wait=60).proceed)

    def test_non_descendant_newer_run_is_not_a_successor(self):
        # A newer run for an ancestor of this commit (still on main) would not
        # ship this commit, so it cannot carry the train.
        github = FakeGitHub([run(12, 3, B), run(10, 1, A, "in_progress")], order=(B, A, C))
        self.assertTrue(decide(github).proceed)
        diverged = FakeGitHub([run(12, 3, "d" * 40), run(10, 1, A, "in_progress")])
        self.assertTrue(decide(diverged).proceed)

    def test_successor_no_longer_on_main_is_not_used(self):
        github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")], main=B)
        self.assertTrue(decide(github).proceed)

    def test_newer_delivered_descendant_prevents_a_rollback(self):
        github = FakeGitHub([run(12, 3, C, "completed", "success", event="workflow_dispatch"),
                             run(10, 1, A, "in_progress")])
        decision = decide(github)
        self.assertFalse(decision.proceed)
        self.assertIn("roll the gateway back", decision.reason)

    def test_failed_or_cancelled_newer_runs_are_not_successors(self):
        github = FakeGitHub([run(12, 3, C, "completed", "failure"), run(11, 2, B, "completed", "cancelled"),
                             run(10, 1, A, "in_progress")])
        self.assertTrue(decide(github).proceed)

    def test_older_runs_and_same_commit_reruns_are_ignored(self):
        github = FakeGitHub([run(10, 5, A, "in_progress"), run(9, 4, A), run(8, 3, B)], order=(B, A, C))
        self.assertTrue(decide(github).proceed)

    def test_other_branches_are_ignored(self):
        github = FakeGitHub([run(12, 3, C, branch="feature"), run(10, 1, A, "in_progress")])
        self.assertTrue(decide(github).proceed)

    def test_unreadable_evidence_means_proceed(self):
        for fail in ("runs", "compare"):
            with self.subTest(fail=fail):
                github = FakeGitHub([run(12, 3, C), run(10, 1, A, "in_progress")], fail=fail)
                self.assertTrue(decide(github).proceed)

    def test_own_run_missing_from_listing_means_proceed(self):
        github = FakeGitHub([run(12, 3, C)])
        self.assertTrue(decide(github).proceed)


def glob_regex(pattern):
    """GitHub Actions path filter semantics for the patterns this repo uses."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + "$")


def bot_committed_paths():
    """Every path a workflow's own bot commits stage with `git add`."""
    paths = set()
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text()
        if "[bot]" not in text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("git add"):
                for token in line.split()[2:]:
                    token = token.strip("'\"")
                    if token in {"--", "||", "true"} or token.startswith("-"):
                        continue
                    paths.add(token)
    return paths


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW.read_text())
        self.jobs = self.workflow["jobs"]
        # PyYAML reads the bare `on:` key as boolean True.
        self.on = self.workflow.get("on", self.workflow.get(True))

    def test_bot_commits_never_trigger_a_gateway_rollout(self):
        triggers = [glob_regex(p) for p in self.on["push"]["paths"]]
        staged = bot_committed_paths()
        self.assertTrue(staged)
        for path in staged:
            with self.subTest(path=path):
                self.assertTrue(path.startswith("trust-page/"), path)
                # A staged directory or glob covers files beneath it.
                for sample in (path, path.rstrip("/") + "/x.json", path.replace("**", "a/b").replace("*", "x")):
                    self.assertFalse(any(t.match(sample) for t in triggers), sample)
        self.assertFalse(any(p.startswith("trust-page") for p in self.on["push"]["paths"]))

    def test_glob_helper_matches_real_triggers(self):
        triggers = [glob_regex(p) for p in self.on["push"]["paths"]]
        for path in ("enclave-go/main.go", "enclave-go/a/b.go", "tools/deploy-gcp-mig.sh",
                     ".github/workflows/deploy-enclave-gcp.yml"):
            self.assertTrue(any(t.match(path) for t in triggers), path)

    def test_train_decides_before_any_trust_or_production_mutation(self):
        decide = self.jobs["train"]
        self.assertEqual(decide["needs"], "gate-on-ci")
        self.assertEqual(decide["outputs"]["proceed"], "${{ steps.train.outputs.proceed }}")
        script = decide["steps"][-1]["run"]
        for flag in ("tools/superseded_rollout.py", "--run-id", "--sha", "--event"):
            self.assertIn(flag, script)
        build = self.jobs["build-and-release"]
        self.assertIn("train", build["needs"])
        self.assertEqual(build["if"], "${{ needs.train.outputs.proceed == 'true' }}")
        # Everything that commits, grants, reserves or rolls depends on the build.
        for name in ("verify-transition-trust-page", "grant-batch-image-access", "admit-cloud", "rollout",
                     "finalize-trust-artifacts"):
            needs = self.jobs[name]["needs"]
            self.assertIn("build-and-release", [needs] if isinstance(needs, str) else needs, name)
            self.assertNotIn("always()", str(self.jobs[name].get("if", "")), name)
        # The lease release still runs only for a run that actually reserved.
        self.assertIn("needs.admit-cloud.result == 'success'", self.jobs["finalize-cloud"]["if"])

    def test_queue_retains_every_pending_release(self):
        concurrency = self.workflow["concurrency"]
        self.assertEqual(concurrency["queue"], "max")
        self.assertFalse(concurrency["cancel-in-progress"])

    def test_train_script_changes_are_deploy_inputs(self):
        self.assertIn("tools/superseded_rollout.py", self.on["push"]["paths"])


if __name__ == "__main__":
    unittest.main()
