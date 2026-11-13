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


ROLLED = {"train": "success", "build-and-release": "success", "rollout": "success"}
SKIPPED = {"train": "success", "build-and-release": "skipped", "rollout": "skipped"}


class FakeGitHub:
    """Commit graph A -> B -> C on main unless told otherwise.

    `runs` may be a list of listings, returned in turn (the last repeats), to
    model the run list changing between passes. `jobs` maps run id to job
    conclusions; a completed run without an entry is a failed rollout.
    """

    def __init__(self, runs, ci=None, order=(A, B, C), main=C, fail=None, jobs=None):
        self.listings = runs if runs and isinstance(runs[0], list) else [runs]
        self.ci_states = ci or {}
        self.order, self.main, self.fail = list(order), main, fail
        self.job_map = jobs or {}
        self.calls = []
        self.reruns = []

    def runs(self, workflow):
        self.calls.append(("runs", workflow))
        if self.fail == "runs":
            raise train.Unknown("listing failed")
        if self.fail == "keyerror":
            raise KeyError("workflow_runs")
        return self.listings.pop(0) if len(self.listings) > 1 else self.listings[0]

    def jobs(self, run_id):
        self.calls.append(("jobs", run_id))
        if self.fail == "typeerror":
            raise TypeError("'NoneType' object is not subscriptable")
        return self.job_map.get(run_id, {"rollout": "failure"})

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

    def rerun(self, run_id):
        self.reruns.append(run_id)


def decide(github, sha=A, event="push", run_id=10, clock=None, **kwargs):
    clock = clock if clock is not None else [0.0]

    def sleep(seconds):
        clock[0] += seconds

    return train.decide(github, "deploy-enclave-gcp.yml", run_id, sha, event,
                        sleep=sleep, monotonic=lambda: clock[0], **kwargs)


def rescue(github, sha=C, run_id=12, event="push", proceed="true", rollout="failure"):
    return train.rescue(github, "deploy-enclave-gcp.yml", run_id, sha, event, proceed, rollout)


class TrainTests(unittest.TestCase):
    def test_older_run_skips_for_newer_queued_green_descendant(self):
        github = FakeGitHub([run(12, 3, C), run(11, 2, B), run(10, 1, A, "in_progress")])
        decision = decide(github)
        self.assertFalse(decision.proceed)
        self.assertIn("queued run 12", decision.reason)  # newest successor is named

    def test_newest_run_proceeds_and_carries_the_train(self):
        github = FakeGitHub([run(12, 3, C, "in_progress"), run(11, 2, B, "completed", "success"),
                             run(10, 1, A, "completed", "success")], jobs={11: SKIPPED, 10: SKIPPED})
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

    def test_all_ci_waiting_shares_one_deadline(self):
        # Review probe S2: two successors with pending CI used to wait 30 min each.
        d = "d" * 40
        clock = [0.0]
        github = FakeGitHub([run(13, 4, d), run(12, 3, C), run(10, 1, A, "in_progress")],
                            ci={d: ("in_progress", None), C: ("in_progress", None)},
                            order=(A, B, C, d), main=d)
        decision = decide(github, clock=clock, ci_wait=1800)
        self.assertTrue(decision.proceed)
        self.assertLessEqual(clock[0], 1800)

    def test_run_list_is_reread_after_waiting_for_ci(self):
        # Review probe S3: a successor cancelled during the wait was still yielded to.
        github = FakeGitHub([[run(12, 3, C), run(10, 1, A, "in_progress")],
                             [run(12, 3, C, "completed", "cancelled"), run(10, 1, A, "in_progress")]],
                            ci={C: [("in_progress", None), ("completed", "success")]})
        self.assertTrue(decide(github).proceed)
        self.assertEqual(sum(1 for call in github.calls if call[0] == "runs"), 2)

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

    def test_newer_rolled_out_descendant_prevents_a_rollback(self):
        github = FakeGitHub([run(12, 3, C, "completed", "success", event="workflow_dispatch"),
                             run(10, 1, A, "in_progress")], jobs={12: ROLLED})
        decision = decide(github)
        self.assertFalse(decision.proceed)
        self.assertIn("roll the gateway back", decision.reason)

    def test_rolled_out_but_failed_later_is_still_a_rollback_risk(self):
        github = FakeGitHub([run(12, 3, C, "completed", "failure"), run(10, 1, A, "in_progress")],
                            jobs={12: {**ROLLED, "finalize-trust-artifacts": "failure"}})
        self.assertFalse(decide(github).proceed)

    def test_train_skipped_newer_run_is_not_delivered(self):
        # Review probe S1: a skipped run concludes success but shipped nothing.
        github = FakeGitHub([run(12, 3, C, "completed", "failure"), run(11, 2, B, "completed", "success"),
                             run(10, 1, A, "in_progress")], jobs={11: SKIPPED, 12: {"rollout": "failure"}})
        decision = decide(github)
        self.assertTrue(decision.proceed, decision.reason)

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

    def test_unreadable_or_unexpected_evidence_means_proceed(self):
        for fail in ("runs", "compare", "keyerror", "typeerror"):
            with self.subTest(fail=fail):
                github = FakeGitHub([run(12, 3, C, "completed", "success"), run(10, 1, A, "in_progress")],
                                    fail=fail)
                self.assertTrue(decide(github).proceed)

    def test_own_run_missing_from_listing_means_proceed(self):
        github = FakeGitHub([run(12, 3, C)])
        self.assertTrue(decide(github).proceed)


class RescueTests(unittest.TestCase):
    """The run others skipped for re-runs the newest of them if it did not roll out."""

    def listing(self):
        runs = [run(12, 3, C, "in_progress"), run(11, 2, B, "completed", "success"),
                run(10, 1, A, "completed", "success"), run(9, 0, "e" * 40, "completed", "success")]
        return runs

    def github(self, jobs=None, **kwargs):
        return FakeGitHub(self.listing(), order=("e" * 40, A, B, C),
                          jobs=jobs or {11: SKIPPED, 10: SKIPPED, 9: ROLLED}, **kwargs)

    def test_successor_failing_anywhere_before_rollout_reruns_the_newest_skipped_run(self):
        # Build, trust publication, Batch grant and admission failures all leave
        # rollout skipped; a canary failure fails it; cancellation cancels it.
        for result in ("skipped", "failure", "cancelled", ""):
            with self.subTest(rollout=result):
                github = self.github()
                self.assertIn("re-ran run 11", rescue(github, rollout=result))
                self.assertEqual(github.reruns, [11])

    def test_rolled_out_run_rescues_nothing(self):
        github = self.github()
        rescue(github, rollout="success")
        self.assertEqual(github.reruns, [])

    def test_a_run_that_was_itself_skipped_rescues_nothing(self):
        github = self.github()
        rescue(github, proceed="false", rollout="skipped")
        self.assertEqual(github.reruns, [])

    def test_dispatch_rescues_nothing(self):
        github = self.github()
        rescue(github, event="workflow_dispatch")
        self.assertEqual(github.reruns, [])

    def test_stops_at_the_last_rollout(self):
        github = self.github(jobs={11: ROLLED, 10: SKIPPED, 9: ROLLED})
        self.assertIn("rolled out", rescue(github))
        self.assertEqual(github.reruns, [])

    def test_failed_older_runs_are_passed_over_for_an_older_skipped_one(self):
        github = self.github(jobs={11: {"train": "success", "build-and-release": "failure"}, 10: SKIPPED, 9: ROLLED})
        github.listings[0][1]["conclusion"] = "failure"
        self.assertIn("re-ran run 10", rescue(github))
        self.assertEqual(github.reruns, [10])

    def test_older_run_already_queued_again_is_left_to_decide(self):
        github = self.github()
        github.listings[0][1]["status"] = "queued"
        self.assertIn("queued or running", rescue(github))
        self.assertEqual(github.reruns, [])

    def test_skipped_run_that_is_not_an_ancestor_is_ignored(self):
        # Run 11 is older but built a commit newer than this run's (still on
        # main): re-running it would not ship what skipped for this run.
        f = "f" * 40
        github = FakeGitHub([run(12, 3, C, "in_progress"), run(11, 2, f, "completed", "success"),
                             run(10, 1, A, "completed", "success")], order=(A, C, f), main=f,
                            jobs={11: SKIPPED, 10: SKIPPED})
        self.assertIn("re-ran run 10", rescue(github))

    def test_the_rerun_then_deploys_its_own_commit(self):
        # After the rescue, run 11 decides again: run 12 failed, so it proceeds.
        github = FakeGitHub([run(12, 3, C, "completed", "failure"), run(11, 2, B, "queued"),
                             run(10, 1, A, "completed", "success")], jobs={12: {"rollout": "failure"}, 10: SKIPPED})
        self.assertTrue(decide(github, sha=B, run_id=11).proceed)


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

    def test_train_job_can_only_read(self):
        self.assertEqual(self.jobs["train"]["permissions"], {"actions": "read", "contents": "read"})
        self.assertIn("superseded_rollout.py decide", self.jobs["train"]["steps"][-1]["run"])

    def test_rescue_job_runs_after_any_outcome_of_a_push(self):
        rescue_job = self.jobs["rescue-skipped"]
        self.assertEqual(rescue_job["needs"], ["train", "rollout"])
        self.assertIn("always()", rescue_job["if"])
        self.assertIn("github.event_name == 'push'", rescue_job["if"])
        self.assertEqual(rescue_job["permissions"], {"actions": "write", "contents": "read"})
        script = rescue_job["steps"][-1]["run"]
        for arg in ("superseded_rollout.py rescue", '--train-proceed "${{ needs.train.outputs.proceed }}"',
                    '--rollout-result "${{ needs.rollout.result }}"', "--run-id", "--sha", "--event"):
            self.assertIn(arg, script)

    def test_queue_retains_every_pending_release(self):
        concurrency = self.workflow["concurrency"]
        self.assertEqual(concurrency["queue"], "max")
        self.assertFalse(concurrency["cancel-in-progress"])

    def test_train_script_changes_are_deploy_inputs(self):
        self.assertIn("tools/superseded_rollout.py", self.on["push"]["paths"])


if __name__ == "__main__":
    unittest.main()
