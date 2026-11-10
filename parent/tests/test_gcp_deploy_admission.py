"""The GCP deploy's admission wait outlasts a run of control-plane rollouts.

Both repositories' deploys reserve the gcp lease through the one reviewed
coordinator (tools/cloud-rollout.py fetches it at the commit pinned in
tools/cloud-rollout-source.json). A quill-router rollout holds the lease for
67-72 minutes, and router pushes land back to back, so a gateway deploy whose
admission gives up after an hour loses the freed lease to the next router run
and fails without a rollout. The wait is the coordinator's cap, four hours,
which is also what the router waits for the mirror case (a gateway rollout
holds the lease about 2 h 20 min); the job must not time out before the wait
does. The lease TTL clock starts at acquisition, and its holder is the rollout
job (no job timeout, so GitHub's default) and the short finalizers after it:
the TTL is the coordinator's maximum and outlasts that default.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
COORDINATOR_PIN = REPO_ROOT / "tools" / "cloud-rollout-source.json"

# MAX_ADMISSION_WAIT_SECONDS of scripts/deploy/cloud_rollout.py in quill-router at
# the pinned commit (raised from two hours in quill-router #1481, 2026-10-02).
PINNED_COORDINATOR_CAP_SECONDS = 4 * 3600
# The coordinator's maximum lease TTL (`60 <= ttl <= 43_200`), and GitHub's
# default job timeout, which bounds the rollout job that holds the lease.
PINNED_COORDINATOR_MAX_TTL_SECONDS = 12 * 3600
GITHUB_DEFAULT_JOB_TIMEOUT_MINUTES = 360


def _admit_cloud_job() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("\n  admit-cloud:\n")
    return workflow[start : workflow.index("\n  rollout:\n", start)]


def _setting(job: str, pattern: str) -> int:
    matches = re.findall(pattern, job)
    assert len(matches) == 1, (pattern, matches)
    return int(matches[0])


def test_the_admission_wait_is_the_pinned_coordinators_cap() -> None:
    job = _admit_cloud_job()
    wait = _setting(job, r'TR_DEPLOY_WAIT_SECONDS: "(\d+)"')
    timeout_minutes = _setting(job, r"timeout-minutes: (\d+)")
    ttl = _setting(job, r'TR_DEPLOY_MUTEX_TTL_SECONDS: "(\d+)"')
    assert wait == PINNED_COORDINATOR_CAP_SECONDS
    assert timeout_minutes * 60 > wait
    assert ttl == PINNED_COORDINATOR_MAX_TTL_SECONDS
    assert ttl > GITHUB_DEFAULT_JOB_TIMEOUT_MINUTES * 60
    assert 'fence="$(python3 tools/cloud-rollout.py acquire --cloud gcp)"' in job


def test_the_coordinator_pin_names_the_commit_whose_cap_the_wait_assumes() -> None:
    pin = json.loads(COORDINATOR_PIN.read_text())
    assert set(pin) == {"commit", "sha256"}
    assert re.fullmatch(r"[a-f0-9]{40}", pin["commit"])
    assert re.fullmatch(r"[a-f0-9]{64}", pin["sha256"])
    # quill-router 200f758ec (2026-10-03): the first coordinator with the four
    # hour cap and the deleted-owner-run recovery rule; the content digest is
    # the file's sha256 at that commit, which tools/cloud-rollout.py re-checks
    # before every use.
    assert pin["commit"] == "200f758ec8c82cba6e77d1b261d1229e7d873c7c"
    assert pin["sha256"] == "63579c677b28ad05e81461f43f2535231007e102a3980d77b636783860e2c7b9"
