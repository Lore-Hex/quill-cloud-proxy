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
# the pinned commit (raised from two hours in quill-router #1481, 2026-10-02;
# unchanged by FIFO admission, #2557, by schema v3, #2568, and by the holdback
# lease-over check, #2573).
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
    # quill-router 90dfc68a (2026-11-13, #2573 merged): a grant that leases the
    # protected cloud first reads that cloud's release evidence, and refuses
    # when it is readable and differs or is invalid. That sits on top of
    # schema v3 component leases with the read-only `lanes` command
    # tools/gate_hold.py reads (#2568) and FIFO admission (#2557). It keeps
    # the four hour cap and 12 h maximum TTL that the wait and TTL above
    # assume (MAX_ADMISSION_WAIT_SECONDS = 4 * 3600 and 60 <= ttl <= 43_200 at
    # that commit). The new read runs only inside a grant, so in this workflow
    # only the admit-cloud job above can reach it: the rollout job and its
    # finalizer run `assert`, `lanes` and `release`, which never do. The
    # content digest is the file's sha256 at that commit, which
    # tools/cloud-rollout.py re-checks before every use.
    assert pin["commit"] == "90dfc68ac587ef39b9baa449d8b7dd9405ecd627"
    assert pin["sha256"] == "85037e7f5176e599ffc44213e19824ba2595acc416a6cc89624b79dfd3a18f94"
