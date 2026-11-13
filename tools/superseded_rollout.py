#!/usr/bin/env python3
"""Decide whether this gateway rollout is superseded by a newer one (a release train).

deploy-enclave-gcp.yml queues every main push in one concurrency group, and
each rollout holds the shared gcp lease for about two and a half hours. When
a run reaches the head of that queue it checks, before building or touching
the trust page, whether a newer push run of the same workflow is already
queued behind it for a descendant commit that is still on main and has green
CI. If so, this run skips: the newer run deploys this commit too, so the
whole queue ships in one rollout. It also skips when a newer run for a
descendant commit has already completed successfully, which would otherwise
roll the gateway back.

Only push runs ever skip; a manual dispatch deploys exactly what was asked.
Any read failure or unclear evidence means "proceed", which is today's
behavior. Skipping never cancels another run and never touches the lease.

Writes proceed=true|false to $GITHUB_OUTPUT when set; always exits 0 on a
decision so a skip is a green, rollout-free run.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

LIVE = frozenset({"queued", "pending", "waiting", "requested", "in_progress"})


class Unknown(RuntimeError):
    """Evidence could not be read; never skip on it."""


class GitHub:
    def __init__(self, repo: str) -> None:
        self.repo = repo

    def api(self, path: str) -> Any:
        try:
            result = subprocess.run(  # noqa: S603 - fixed CLI, repository-scoped read
                ["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Unknown(f"{path}: {type(exc).__name__}") from exc
        if result.returncode != 0:
            raise Unknown(f"{path}: gh exit {result.returncode}")
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


@dataclass
class Decision:
    proceed: bool
    reason: str


def decide(github: Any, workflow: str, run_id: int, sha: str, event: str,
           ci_wait: int = 1800, sleep: Callable[[float], None] = time.sleep,
           monotonic: Callable[[], float] = time.monotonic) -> Decision:
    if event != "push":
        return Decision(True, f"{event} run deploys exactly {sha}; trains apply to pushes only")
    try:
        runs = github.runs(workflow)
        mine = next((r for r in runs if r.get("id") == run_id), None)
        if mine is None:
            raise Unknown(f"run {run_id} is not in the newest 50 runs of {workflow}")
        newer = sorted(
            (r for r in runs
             if isinstance(r, dict) and r.get("id") != run_id
             and isinstance(r.get("run_number"), int) and r["run_number"] > mine["run_number"]
             and r.get("head_branch") == "main" and r.get("head_sha") != sha),
            key=lambda r: r["run_number"], reverse=True)
        for run in newer:
            head = run.get("head_sha")
            if not isinstance(head, str):
                continue
            delivered = run.get("status") == "completed" and run.get("conclusion") == "success"
            queued = run.get("event") == "push" and run.get("status") in LIVE
            if not (delivered or queued):
                continue
            if github.compare(sha, head) != "ahead":
                continue  # not a strict descendant of this commit
            if github.compare(head, "main") not in {"ahead", "identical"}:
                continue  # no longer on main
            if delivered:
                return Decision(False, f"run {run['id']} already delivered descendant {head}; "
                                       f"deploying {sha} would roll the gateway back")
            verdict = wait_for_ci(github, head, ci_wait, sleep, monotonic)
            if verdict == "success":
                return Decision(False, f"queued run {run['id']} for descendant {head} (green CI) "
                                       f"deploys {sha} in the same train")
            print(f"superseded_rollout: run {run['id']} for {head} is not a successor (CI {verdict})")
    except Unknown as exc:
        return Decision(True, f"successor evidence unavailable ({exc}); deploying {sha}")
    return Decision(True, f"no newer green run is queued for a descendant of {sha}")


def wait_for_ci(github: Any, sha: str, ci_wait: int, sleep: Callable[[float], None],
                monotonic: Callable[[], float]) -> str:
    deadline = monotonic() + ci_wait
    while True:
        state = github.ci(sha)
        if state is not None and state[0] == "completed":
            return "success" if state[1] == "success" else str(state[1])
        if monotonic() >= deadline:
            return "pending"
        sleep(min(30, max(0, deadline - monotonic())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--workflow", default="deploy-enclave-gcp.yml")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--ci-wait", type=int, default=1800)
    args = parser.parse_args()
    decision = decide(GitHub(args.repo), args.workflow, args.run_id, args.sha, args.event, args.ci_wait)
    print(("proceed: " if decision.proceed else "superseded: ") + decision.reason)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"proceed={'true' if decision.proceed else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
