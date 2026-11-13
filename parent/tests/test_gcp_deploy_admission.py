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
# unchanged by FIFO admission, #2557, by schema v3, #2568, by the holdback
# lease-over check, #2573, and by the control-plane probe's limiter fix, #2581).
PINNED_COORDINATOR_CAP_SECONDS = 4 * 3600
# The coordinator's maximum lease TTL (`60 <= ttl <= 43_200`), and GitHub's
# default job timeout, which bounds the rollout job that holds the lease.
PINNED_COORDINATOR_MAX_TTL_SECONDS = 12 * 3600
GITHUB_DEFAULT_JOB_TIMEOUT_MINUTES = 360

# One admission attempt of the pinned coordinator, from its own limits. A
# journal command is cut off at 45 s. A fetch makes three HTTP attempts, each
# taken at its 15 s socket timeout, and sleeps at most 5 s after each of the
# first two (1 s and 2 s, or a Retry-After it honours only up to 5 s).
PINNED_JOURNAL_COMMAND_SECONDS = 45
PINNED_FETCH_SECONDS = 3 * 15 + 2 * 5
PINNED_ADMISSION_ATTEMPT_SECONDS = (
    # The journal read: the generation, then the object at that generation.
    2 * PINNED_JOURNAL_COMMAND_SECONDS
    # A grant that leases the protected cloud reads that cloud's release
    # evidence twice before protection moves (quill-router #2573).
    + 2 * PINNED_FETCH_SECONDS
    # Then it probes the other two clouds for a new holdback, four fetches each.
    + 2 * 4 * PINNED_FETCH_SECONDS
    # The journal write.
    + PINNED_JOURNAL_COMMAND_SECONDS
)
# The job's checkout, authentication and gcloud steps have no limits of their own.
RUNNER_SETUP_SECONDS = 300
BOOTSTRAP = REPO_ROOT / "tools" / "cloud-rollout.py"


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


def test_the_job_outlasts_the_wait_and_one_last_admission_attempt() -> None:
    """The last attempt starts as the wait ends, and may be the one granted.

    A job that ended inside that attempt could be killed with the journal
    write in flight: a lease may land that no rollout holds, and no job
    releases it, because finalize-cloud runs only after this job succeeds. So
    the job limit covers what runs before the wait, the wait, and one whole
    attempt. A lost compare-and-swap repeats an attempt; the limit covers one.
    """
    job = _admit_cloud_job()
    wait = _setting(job, r'TR_DEPLOY_WAIT_SECONDS: "(\d+)"')
    timeout_minutes = _setting(job, r"timeout-minutes: (\d+)")
    # Before the wait starts, the bootstrap fetches the coordinator, and the
    # coordinator checks the journal bucket with one command.
    bootstrap_fetch = _setting(BOOTSTRAP.read_text(), r"timeout=(\d+)")
    before_the_wait = RUNNER_SETUP_SECONDS + bootstrap_fetch + PINNED_JOURNAL_COMMAND_SECONDS
    assert PINNED_ADMISSION_ATTEMPT_SECONDS == 685
    assert timeout_minutes * 60 >= before_the_wait + wait + PINNED_ADMISSION_ATTEMPT_SECONDS
    assert timeout_minutes <= GITHUB_DEFAULT_JOB_TIMEOUT_MINUTES


def test_the_coordinator_pin_names_the_commit_whose_cap_the_wait_assumes() -> None:
    pin = json.loads(COORDINATOR_PIN.read_text())
    assert set(pin) == {"commit", "sha256"}
    assert re.fullmatch(r"[a-f0-9]{40}", pin["commit"])
    assert re.fullmatch(r"[a-f0-9]{64}", pin["sha256"])
    # quill-router 06134e53, the head of #2581 (draft). RE-PIN BEFORE MERGE:
    # this must name #2581's merge commit on quill-router main, and the digest
    # must be recomputed there (it stays the same unless cloud_rollout.py
    # changes again before that merge).
    #
    # #2581: the v3 release probe of a control-plane lease passes the
    # application's own source limiter 429, matched byte for byte, so outside
    # traffic that spends the shared unauthenticated bucket can no longer hold
    # a finished control-plane lease. fetch converts a Retry-After only when it
    # is one to nine ASCII digits, so a decimal past Python's 4300 digit limit
    # or superscript digits give up as the HTTP error instead of refusing a
    # grant. That sits on top of the holdback lease-over check (#2573), schema
    # v3 component leases with the read-only `lanes` command tools/gate_hold.py
    # reads (#2568) and FIFO admission (#2557). It keeps the four hour cap and
    # 12 h maximum TTL that the wait and TTL above assume
    # (MAX_ADMISSION_WAIT_SECONDS = 4 * 3600 and 60 <= ttl <= 43_200 at that
    # commit), and a fetch still sleeps at most 5 s between attempts, so the
    # admission attempt above is unchanged. The holdback read (#2573) runs
    # only inside a grant, so in this workflow only the admit-cloud job above
    # can reach it: the rollout job and its finalizer run `assert`, `lanes`
    # and `release`, which never do. The probe change runs only in `release`
    # and `recover` of a v3 control-plane lease, which this workflow never
    # holds: it reserves as the gateway, and under the v2 journal production
    # runs today `release` probes the whole cloud. The content digest is the
    # file's sha256 at that commit, which tools/cloud-rollout.py re-checks
    # before every use.
    assert pin["commit"] == "06134e534ea9a535c6d0b978a3250e2b76228d63"
    assert pin["sha256"] == "21e5ccf9853be7658b3b0838f4df60acca6ab381082bc784277af9d7de3b5e14"
