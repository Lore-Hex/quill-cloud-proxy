#!/usr/bin/env python3
"""Gateway release trains: skip a rollout a newer queued run will carry, and
make sure a skipped commit still ships if that newer run does not.

deploy-enclave-gcp.yml queues every main push in one concurrency group, and
each rollout holds the shared gcp lease for about two and a half hours.

`decide` (the `train` job, before anything is built or published) skips this
run when either
  * a newer push run of the same workflow is queued for a strict descendant
    of this commit that is still on main, and that commit's ci.yml run is
    green, so the newer run ships this commit too; or
  * a newer run for a descendant still on main has already rolled out, in
    any attempt: its `rollout` job succeeded, or it promoted us-central1
    back into canonical DNS before failing later (a partial rollout still
    serves the newer commit), so deploying this commit would roll it back.
A train-skipped run concludes success but never counts as rolled out. Every
pass re-reads the run list, all waiting for CI shares one deadline, and any
failed read, malformed answer or unexpected error means "proceed", which is
the behavior before trains existed. Only push runs ever skip; a manual
dispatch deploys exactly what was asked.

`rescue` (the `rescue-skipped` job, run on pushes unless the run was
cancelled) closes the gap a skip leaves: if this run did not skip and
promoted no region (it failed at CI, build, trust publication, admission or
its first canary), it re-runs the newest older run that yielded to this very
run (each skip logs `train-yielded-to-run=<id>`) since the last rollout of
any run, dispatches included. That re-run decides again, finds this run did
not roll out, and deploys its own commit, which includes every older commit
that yielded to this run. A cancelled run rescues nothing, so one cancel
stops the chain.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any, NamedTuple

LIVE = frozenset({"queued", "pending", "waiting", "requested", "in_progress"})
# The first promotion in a rollout: us-central1 re-enters canonical DNS on the
# new image. Once it succeeds the newer commit serves, even if a later region
# fails. tools/test_superseded_rollout.py pins this step name to the workflow.
PRIMARY_PROMOTION_STEP = "Restore us-central1 canonical drain state"
YIELD_MARKER = "train-yielded-to-run="


class Unknown(RuntimeError):
    """Evidence could not be read; never skip on it."""


class GitHub:
    def __init__(self, repo: str) -> None:
        self.repo = repo

    def api(self, path: str, method: str = "GET") -> Any:
        try:
            result = subprocess.run(  # noqa: S603 - fixed CLI, repository-scoped call
                ["gh", "api", "-X", method, "-H", "Accept: application/vnd.github+json", path],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Unknown(f"{path}: {type(exc).__name__}") from exc
        if result.returncode != 0:
            raise Unknown(f"{path}: gh exit {result.returncode}")
        if method != "GET":
            return None
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise Unknown(f"{path}: invalid JSON") from exc

    def runs(self, workflow: str) -> list[dict[str, Any]]:
        body = self.api(f"repos/{self.repo}/actions/workflows/{workflow}/runs?branch=main&per_page=50")
        runs = body.get("workflow_runs") if isinstance(body, dict) else None
        if not isinstance(runs, list):
            raise Unknown("workflow run listing is malformed")
        return runs

    def jobs(self, run_id: int) -> list[dict[str, Any]]:
        """Every job of every attempt (the API's default is the latest attempt only)."""
        jobs: list[dict[str, Any]] = []
        page = 1
        while True:
            body = self.api(f"repos/{self.repo}/actions/runs/{run_id}/jobs?filter=all&per_page=100&page={page}")
            batch = body.get("jobs") if isinstance(body, dict) else None
            total = body.get("total_count") if isinstance(body, dict) else None
            if not isinstance(batch, list) or not isinstance(total, int):
                raise Unknown(f"jobs of run {run_id} are malformed")
            jobs.extend(job for job in batch if isinstance(job, dict))
            if not batch or len(jobs) >= total:
                return jobs
            page += 1

    def job_log(self, job_id: int) -> str:
        try:
            result = subprocess.run(  # noqa: S603 - fixed CLI, repository-scoped read
                ["gh", "api", f"repos/{self.repo}/actions/jobs/{job_id}/logs"],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Unknown(f"log of job {job_id}: {type(exc).__name__}") from exc
        if result.returncode != 0:
            raise Unknown(f"log of job {job_id}: gh exit {result.returncode}")
        return result.stdout

    def compare(self, base: str, head: str) -> str:
        body = self.api(f"repos/{self.repo}/compare/{base}...{head}")
        status = body.get("status") if isinstance(body, dict) else None
        if status not in {"ahead", "behind", "identical", "diverged"}:
            raise Unknown(f"compare {base}...{head} is malformed")
        return status

    def ci(self, sha: str) -> tuple[str, str | None] | None:
        body = self.api(f"repos/{self.repo}/actions/workflows/ci.yml/runs?head_sha={sha}&per_page=5")
        runs = body.get("workflow_runs") if isinstance(body, dict) else None
        if not isinstance(runs, list):
            raise Unknown("CI run listing is malformed")
        if not runs:
            return None
        newest = max(runs, key=lambda r: (str(r.get("created_at") or ""), int(r.get("id") or 0)))
        return str(newest.get("status")), newest.get("conclusion")

    def rerun(self, run_id: int) -> None:
        self.api(f"repos/{self.repo}/actions/runs/{run_id}/rerun", method="POST")


class Decision(NamedTuple):
    proceed: bool
    reason: str
    yielded_to: int | None = None


def rolled_out(github: Any, run_id: int) -> bool:
    """Whether any attempt of a run put its commit into service.

    True if a `rollout` job succeeded, or promoted us-central1 back into
    canonical DNS on the new image before something later failed.
    """
    for job in github.jobs(run_id):
        if job.get("name") != "rollout":
            continue
        if job.get("conclusion") == "success":
            return True
        for step in job.get("steps") or []:
            if (isinstance(step, dict) and step.get("name") == PRIMARY_PROMOTION_STEP
                    and step.get("conclusion") == "success"):
                return True
    return False


def latest_attempt(jobs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    attempt = max((int(job.get("run_attempt") or 1) for job in jobs), default=1)
    return {str(job.get("name")): job for job in jobs if int(job.get("run_attempt") or 1) == attempt}


def yielded_to(github: Any, run_id: int) -> int | None:
    """The run this run's latest attempt skipped in favor of, if it skipped."""
    jobs = latest_attempt(github.jobs(run_id))
    train, build = jobs.get("train"), jobs.get("build-and-release")
    if not train or train.get("conclusion") != "success" or not build or build.get("conclusion") != "skipped":
        return None
    for line in github.job_log(train["id"]).splitlines():
        if YIELD_MARKER in line:
            value = line.split(YIELD_MARKER, 1)[1].strip()
            if value.isdigit():
                return int(value)
    return None


def descendant_on_main(github: Any, base: str, head: str) -> bool:
    return github.compare(base, head) == "ahead" and github.compare(head, "main") in {"ahead", "identical"}


def newer_runs(runs: list[dict[str, Any]], run_id: int, sha: str) -> list[dict[str, Any]]:
    mine = next((r for r in runs if isinstance(r, dict) and r.get("id") == run_id), None)
    if mine is None or not isinstance(mine.get("run_number"), int):
        raise Unknown(f"run {run_id} is not in the newest 50 runs")
    return sorted(
        (r for r in runs
         if isinstance(r, dict) and r.get("id") != run_id
         and isinstance(r.get("run_number"), int) and r["run_number"] > mine["run_number"]
         and r.get("head_branch") == "main" and isinstance(r.get("head_sha"), str)
         and r["head_sha"] != sha),
        key=lambda r: r["run_number"], reverse=True)


def decide(github: Any, workflow: str, run_id: int, sha: str, event: str,
           ci_wait: int = 1800, sleep: Callable[[float], None] = time.sleep,
           monotonic: Callable[[], float] = time.monotonic) -> Decision:
    if event != "push":
        return Decision(True, f"{event} run deploys exactly {sha}; trains apply to pushes only")
    deadline = monotonic() + ci_wait
    try:
        while True:
            waiting_for = None
            for run in newer_runs(github.runs(workflow), run_id, sha):
                head = run["head_sha"]
                completed = run.get("status") == "completed"
                queued = run.get("event") == "push" and run.get("status") in LIVE
                if not (completed or queued) or not descendant_on_main(github, sha, head):
                    continue
                if completed:
                    if rolled_out(github, run["id"]):
                        return Decision(False, f"run {run['id']} already rolled out descendant {head}; "
                                               f"deploying {sha} would roll the gateway back")
                    continue
                state = github.ci(head)
                if state is not None and state[0] == "completed":
                    if state[1] == "success":
                        return Decision(False, f"queued run {run['id']} for descendant {head} (green CI) "
                                               f"deploys {sha} in the same train", run["id"])
                    print(f"superseded_rollout: run {run['id']} for {head} is not a successor (CI {state[1]})")
                    continue
                waiting_for = waiting_for or run
            if waiting_for is None:
                return Decision(True, f"no newer green run is queued for a descendant of {sha}")
            remaining = deadline - monotonic()
            if remaining <= 0:
                return Decision(True, f"CI for queued run {waiting_for['id']} did not finish in time; deploying {sha}")
            sleep(min(30, remaining))
    except Exception as exc:  # noqa: BLE001 - any doubt means deploy this commit, as before trains
        return Decision(True, f"successor evidence unclear ({type(exc).__name__}: {exc}); deploying {sha}")


def rescue(github: Any, workflow: str, run_id: int, sha: str, event: str,
           train_proceed: str, rollout_result: str) -> str:
    """Re-run the newest older run that yielded to this one, if this one shipped nothing."""
    if event != "push":
        return "not a push run; nothing skipped in its favor"
    if train_proceed == "false":
        return "this run was itself skipped; the run it yielded to is responsible"
    if rollout_result == "success":
        return "this run rolled out; every commit that skipped for it shipped"
    if rollout_result == "cancelled":
        return "this run was cancelled; a cancel stops the train, nothing is re-run"
    if rolled_out(github, run_id):
        return "this run promoted at least one region; the commits that yielded to it are serving"
    runs = github.runs(workflow)
    mine = next((r for r in runs if isinstance(r, dict) and r.get("id") == run_id), None)
    if mine is None or not isinstance(mine.get("run_number"), int):
        raise Unknown(f"run {run_id} is not in the newest 50 runs")
    older = sorted(
        (r for r in runs
         if isinstance(r, dict) and isinstance(r.get("run_number"), int)
         and r["run_number"] < mine["run_number"] and r.get("head_branch") == "main"
         and isinstance(r.get("head_sha"), str)),
        key=lambda r: r["run_number"], reverse=True)
    for run in older:
        push = run.get("event") == "push"
        if run.get("status") != "completed":
            # Queued or running again (a re-run): it decides for its own commit.
            if push and github.compare(run["head_sha"], sha) in {"ahead", "identical"}:
                return f"run {run['id']} is queued or running and will decide for {run['head_sha']}"
            continue
        # Any run that put its commit into service, dispatches included, ends
        # the walk: everything older is already contained in what serves.
        if rolled_out(github, run["id"]):
            return f"run {run['id']} rolled out; nothing older is waiting"
        if (push and run.get("conclusion") == "success"
                and yielded_to(github, run["id"]) == run_id
                and github.compare(run["head_sha"], sha) in {"ahead", "identical"}
                and github.compare(run["head_sha"], "main") in {"ahead", "identical"}):
            github.rerun(run["id"])
            return f"re-ran run {run['id']} ({run['head_sha']}), which yielded to this run"
    return "no older run yielded to this run"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("decide", "rescue"))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--workflow", default="deploy-enclave-gcp.yml")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--ci-wait", type=int, default=1800)
    parser.add_argument("--train-proceed", default="")
    parser.add_argument("--rollout-result", default="")
    args = parser.parse_args()
    github = GitHub(args.repo)
    if args.command == "rescue":
        try:
            print("rescue: " + rescue(github, args.workflow, args.run_id, args.sha, args.event,
                                      args.train_proceed, args.rollout_result))
        except Exception as exc:  # noqa: BLE001 - fail loudly; a skipped commit may be waiting
            print(f"rescue failed ({type(exc).__name__}: {exc}); re-run the newest train-skipped run by hand",
                  file=sys.stderr)
            return 1
        return 0
    decision = decide(github, args.workflow, args.run_id, args.sha, args.event, args.ci_wait)
    print(("proceed: " if decision.proceed else "superseded: ") + decision.reason)
    if decision.yielded_to is not None:
        # Read back by the yielded-to run's rescue: only it may re-run this one.
        print(f"{YIELD_MARKER}{decision.yielded_to}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"proceed={'true' if decision.proceed else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
