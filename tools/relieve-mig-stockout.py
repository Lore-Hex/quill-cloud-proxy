#!/usr/bin/env python3
"""Move a regional enclave MIG's VMs out of ONE zone that has no capacity.

Why this exists (2026-09-20). The enclave groups roll with the SUBSTITUTE
replacement method: every outdated VM gets its replacement created FIRST, and
Google creates that replacement "in the same zone as the outdated machines, even
if the zone doesn't have resources" (their words, under Limitations of
regional-mig-set-target-distribution-shape). us-central1-c ran out of
c3-standard-4 TDX capacity; the replacement for the VM in that zone sat in
CREATING with ZONE_RESOURCE_POOL_EXHAUSTED, the rollout's 15-minute "wait until
stable" step timed out, and every deploy of a healthy build was rolled back.
A distribution shape of BALANCED does not change that for an update. What does,
again in Google's words: "delete the outdated VMs from the constrained zone,
then increase the group size by the number of the deleted VMs. The group creates
instances ... in zones where capacity is available."

This tool does that in the opposite, safer order, so the group never serves from
fewer VMs than its target: it ADDS the replacements first, proves that each of
them ATTESTS (RUNNING is not serving: a Confidential Space workload cannot mint
its attestation token for minutes after boot), and only then removes the VMs in
the dead zone.

It keeps NO local state and it never CHOOSES a VM to delete. It deletes only
the VMs in the zone the operator named, or the one VM the operator named, and
only straight after ONE fresh pass in which every VM that would remain answered
GET /attestation, asked for by name. (An earlier version cleaned up after itself
by deleting "the newest" VMs. Review broke that three ways: a failed lookup made
an original VM look newest, the newest VM was sometimes the one keeping two VMs
attesting, and a VM that attested early had stopped by the time of the delete. A later round found the
same mistake in two more places: a VM that was already being DELETED still
answered and was counted among the VMs that would remain, and so did a VM that
had begun STOPPING after the group was listed.)
If anything goes wrong before the deletion, the group is left ENLARGED, which is
safe -- it serves from more VMs than it needs -- and the run says what to do:

  relieve    size == target: start (shape EVEN -> BALANCED, resize up by the
             number of VMs in the zone). size == target + that number: resume,
             which is how a cancelled run or a dead runner is recovered. Then
             wait for `target` VMs RUNNING outside the zone, prove in one pass
             that ALL the VMs outside it attest, delete the zone's VMs by name
             (Compute lowers the size by the number deleted), verify.
             With --prepare-only it stops before the deletion and prints
             "ready": the workflow drains the region from DNS at that point,
             then runs `relieve` again, which resumes, proves attestation
             afresh, and deletes.
  remove-vm  delete ONE named VM from an enlarged group, after proving in one
             pass that at least `target` of the others attest. For the VM a
             failed run added. Never a bare resize: Compute would choose.

It must run with no rollout in flight; the workflow that calls it shares the
deploy's concurrency group.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

PROJECT = "quill-cloud-proxy"
ATTEST_HOST = "api.trustedrouter.com"
STOCKOUT = "ZONE_RESOURCE_POOL_EXHAUSTED"
TOLERANT_SHAPES = {"BALANCED", "ANY", "ANY_SINGLE_ZONE"}

Runner = Callable[[list[str]], str]
Probe = Callable[[str], bool]


class Refused(Exception):
    """A precondition does not hold. Nothing was changed."""


class Failed(Exception):
    """Something went wrong after a change was made."""


def gcloud(args: list[str]) -> str:
    completed = subprocess.run(
        ["gcloud", "--project", PROJECT, *args], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise Failed(f"gcloud {' '.join(args[:6])} ...: {completed.stderr.strip()[:400]}")
    return completed.stdout


def attests(ip: str) -> bool:
    """Does the VM at this address answer GET /attestation with 200?"""
    completed = subprocess.run(
        [
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8",
            "--resolve", f"{ATTEST_HOST}:443:{ip}",
            f"https://{ATTEST_HOST}/attestation?nonce={secrets.token_hex(8)}",
        ],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    return completed.returncode == 0 and completed.stdout.strip() == "200"


def log(message: str) -> None:
    print(f"[relieve-mig-stockout] {message}", file=sys.stderr, flush=True)


class Group:
    def __init__(self, mig: str, region: str, run: Runner = gcloud) -> None:
        self.mig, self.region, self.run = mig, region, run

    def _managed(self, *args: str) -> list[str]:
        return ["compute", "instance-groups", "managed", *args, self.mig, f"--region={self.region}"]

    def describe(self) -> dict[str, Any]:
        return json.loads(self.run([*self._managed("describe"), "--format=json"]))

    def instances(self) -> list[dict[str, Any]]:
        # The regional managed-instances list is one complete answer; it is not
        # the aggregated instances list, which can return a partial result.
        rows = json.loads(self.run([*self._managed("list-instances"), "--format=json"]) or "[]")
        out = []
        for row in rows:
            url = row["instance"]
            errors = ((row.get("lastAttempt") or {}).get("errors") or {}).get("errors") or []
            out.append(
                {
                    "name": url.rsplit("/", 1)[-1],
                    "zone": url.split("/zones/", 1)[1].split("/", 1)[0],
                    "status": row.get("instanceStatus", ""),
                    "action": row.get("currentAction", ""),
                    "errors": [error.get("code", "") for error in errors],
                }
            )
        return out

    def vm(self, name: str, zone: str) -> dict[str, str] | None:
        """One VM, asked for BY NAME in its zone. None if it cannot be looked up,
        for whatever reason: the caller treats that as "not proven", never as a
        fact about the VM."""
        try:
            raw = self.run(["compute", "instances", "describe", name, f"--zone={zone}", "--format=json"])
        except Failed:
            return None
        instance = json.loads(raw)
        interfaces = instance.get("networkInterfaces") or [{}]
        access = (interfaces[0].get("accessConfigs") or [{}])[0]
        return {"ip": access.get("natIP", ""), "status": instance.get("status", "")}

    def set_tolerant_shape(self) -> None:
        self.run(
            [
                *self._managed("update"),
                "--instance-redistribution-type=none",
                "--target-distribution-shape=balanced",
            ]
        )

    def resize(self, size: int) -> None:
        self.run([*self._managed("resize"), f"--size={size}"])

    def delete(self, names: list[str]) -> None:
        self.run([*self._managed("delete-instances"), f"--instances={','.join(names)}"])

    def wait_until_stable(self, seconds: int) -> None:
        self.run([*self._managed("wait-until"), "--stable", f"--timeout={seconds}"])


def _zones(group: dict[str, Any]) -> list[str]:
    return [z["zone"].rsplit("/", 1)[-1] for z in group.get("distributionPolicy", {}).get("zones", [])]


def _running(instance: dict[str, Any]) -> bool:
    return instance["status"] == "RUNNING" and instance["action"] in ("NONE", "VERIFYING")


def relieve(
    group: Group,
    zone: str,
    target: int,
    *,
    probe: Probe = attests,
    prepare_only: bool = False,
    wait_seconds: int = 600,
    attest_seconds: int = 900,
    stable_seconds: int = 900,
    poll_seconds: int = 15,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    described, vms = group.describe(), group.instances()
    size = int(described["targetSize"])
    if zone not in _zones(described):
        raise Refused(f"{zone} is not one of the group's zones {_zones(described)}")
    if described.get("autoscaler") or (described.get("status") or {}).get("autoscaler"):
        raise Refused("the group is autoscaled; a fixed size is assumed")
    dead = sorted(i["name"] for i in vms if i["zone"] == zone)
    if not dead:
        if size == target:
            log(f"no VM of this group is in {zone}: nothing to relieve")
            return "nothing"
        raise Refused(f"no VM is in {zone} but the size reads {size}, not {target}; not guessing")

    if size == target:
        if not (described.get("status") or {}).get("isStable"):
            raise Refused("the group is not stable: a rollout or another operation is in flight")
        if len(vms) != target or not all(i["status"] == "RUNNING" and i["action"] == "NONE" for i in vms):
            raise Refused(f"expected {target} RUNNING idle VMs, found {vms}")
        _ensure_tolerant_shape(group, described)
        log(f"adding {len(dead)} VM(s): size {target} -> {target + len(dead)}; {dead} keep serving")
        group.resize(target + len(dead))
    elif size == target + len(dead):
        log(f"size already reads {size}: resuming a run that stopped before it finished")
        _ensure_tolerant_shape(group, described)
    else:
        raise Refused(f"size reads {size}; expected {target} (start) or {target + len(dead)} (resume)")

    # A failure from here to the deletion leaves the group ENLARGED and touches
    # nothing else. That state is safe, and running this again resumes from it.
    _await_running_outside(group, zone, dead, target, wait_seconds, poll_seconds, sleep)
    _await_one_pass_in_which_all_attest(group, zone, target, probe, attest_seconds, poll_seconds, sleep)
    if prepare_only:
        log(f"ready: {dead} can be deleted once {zone}'s region is drained; nothing was deleted")
        return "ready"

    # Immediately after that pass. From here on the replacements ARE the group.
    log(f"deleting {dead} in {zone}: size returns to {target}")
    group.delete(dead)
    group.wait_until_stable(stable_seconds)
    after, size = group.instances(), int(group.describe()["targetSize"])
    left = [i["name"] for i in after if i["zone"] == zone]
    if size != target or left or len(after) != target or not all(_running(i) for i in after):
        raise Failed(f"unexpected end state: size={size} in_zone={left} instances={after}")
    log(f"done: {[(i['name'], i['zone']) for i in after]}")
    return "relieved"


def _ensure_tolerant_shape(group: Group, described: dict[str, Any]) -> None:
    shape = described.get("distributionPolicy", {}).get("targetShape", "EVEN")
    if shape in TOLERANT_SHAPES:
        return
    log(f"distribution shape {shape} -> BALANCED (redistribution off); this moves no VM")
    group.set_tolerant_shape()
    shape = group.describe().get("distributionPolicy", {}).get("targetShape", "")
    if shape not in TOLERANT_SHAPES:
        raise Refused(f"the shape still reads {shape!r}; under EVEN an added VM returns to the dead zone")


def _await_running_outside(
    group: Group, zone: str, dead: list[str], target: int, wait_seconds: int, poll_seconds: int,
    sleep: Callable[[float], None],
) -> list[dict[str, Any]]:  # fmt: skip
    stuck_polls: dict[str, int] = {}
    for _ in range(max(1, wait_seconds // poll_seconds)):
        vms = group.instances()
        in_zone = sorted(i["name"] for i in vms if i["zone"] == zone)
        if in_zone != dead:
            raise Failed(f"{zone} now holds {in_zone}, not {dead}: the group placed a VM there again")
        for instance in vms:
            if any(code.startswith(STOCKOUT) for code in instance["errors"]):
                stuck_polls[instance["name"]] = stuck_polls.get(instance["name"], 0) + 1
                if stuck_polls[instance["name"]] >= 3:
                    raise Failed(f"{instance['name']} in {instance['zone']} has no capacity either")
        outside = [i for i in vms if i["zone"] != zone and _running(i)]
        if len(outside) >= target:
            return outside
        sleep(poll_seconds)
    raise Failed(f"{target} VM(s) were not RUNNING outside {zone} after {wait_seconds}s")


def _attesting_now(group: Group, vms: list[dict[str, Any]], probe: Probe) -> list[str]:
    """ONE pass: the names of the VMs that answer GET /attestation right now.

    Each is asked for BY NAME in its zone. A VM that cannot be looked up, has no
    address, or does not answer simply is not in the result; nothing is inferred
    from a failure, and nothing is remembered from an earlier pass.

    An answer alone is not enough. A guest keeps answering while it shuts down,
    and Compute reports a deletion as done before the VM is gone, so a VM that
    an interrupted run deleted can answer now and not exist a minute from now.
    So the readings that say a VM is STAYING are all taken after EVERY VM has
    answered, not one VM at a time (a VM that was read early could begin to
    stop while the next one was still being asked): first the group is listed
    again and must show the VM RUNNING with nothing pending (not DELETING,
    RECREATING, ...), and last of all the VM's own status, by name, must be
    RUNNING. The two disagree for a while in both directions, which is why both
    are read: the listing lags a VM that stops, the VM's status lags a deletion.
    What is left is the second or two these readings take, and the delete call.
    """
    answered = []
    for instance in vms:
        described = group.vm(instance["name"], instance["zone"])
        if described and described["ip"] and probe(described["ip"]):
            answered.append(instance)
    settled = {i["name"] for i in group.instances() if _running(i)}
    return [
        i["name"] for i in answered
        if i["name"] in settled and (group.vm(i["name"], i["zone"]) or {}).get("status") == "RUNNING"
    ]  # fmt: skip


def _await_one_pass_in_which_all_attest(
    group: Group, zone: str, target: int, probe: Probe, attest_seconds: int, poll_seconds: int,
    sleep: Callable[[float], None],
) -> None:  # fmt: skip
    missing: list[str] = []
    for _ in range(max(1, attest_seconds // poll_seconds)):
        survivors = [i for i in group.instances() if i["zone"] != zone]
        attesting = _attesting_now(group, survivors, probe)
        missing = sorted({i["name"] for i in survivors} - set(attesting))
        if len(survivors) >= target and not missing:
            log(f"every VM that will remain attests: {sorted(attesting)}")
            return
        sleep(poll_seconds)
    raise Failed(
        f"{missing or 'too few VMs outside the zone'} did not attest within {attest_seconds}s. Nothing was "
        "deleted; the group is enlarged, which is safe. Run this again to resume, or remove-vm the extra VM."
    )


def remove_vm(group: Group, name: str, target: int, *, probe: Probe = attests, stable_seconds: int = 900) -> str:
    """Delete ONE operator-named VM from an enlarged group, if `target` others attest right now."""
    vms, size = group.instances(), int(group.describe()["targetSize"])
    named = [i for i in vms if i["name"] == name]
    if not named:
        raise Refused(f"{name} is not a VM of this group: {sorted(i['name'] for i in vms)}")
    if named[0]["action"] == "DELETING":
        raise Refused(f"{name} is already being deleted; the size was lowered when that was asked for")
    if size <= target:
        raise Refused(f"size reads {size}: removing a VM would leave fewer than {target}")
    others = [i for i in vms if i["name"] != name]
    attesting = _attesting_now(group, others, probe)
    if len(attesting) < target:
        raise Refused(f"only {sorted(attesting)} attest without {name}; {target} are needed. Nothing was deleted")
    log(f"{sorted(attesting)} attest; deleting {name}: size {size} -> {size - 1}")
    group.delete([name])
    group.wait_until_stable(stable_seconds)
    after, now = group.instances(), int(group.describe()["targetSize"])
    if now != size - 1 or name in {i["name"] for i in after} or len(after) != now:
        raise Failed(f"unexpected end state: size={now} instances={after}")
    return "removed"


def main(argv: list[str] | None = None, make_group: Callable[[str, str], Group] = Group) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("relieve", "remove-vm"))
    parser.add_argument("mig")
    parser.add_argument("region")
    parser.add_argument("what", help="relieve: the zone with no capacity. remove-vm: the VM's name")
    parser.add_argument("--target-size", type=int, required=True, help="the size the group is meant to have")
    parser.add_argument("--prepare-only", action="store_true", help="relieve: stop before the deletion")
    args = parser.parse_args(argv)
    if args.prepare_only and args.command != "relieve":
        parser.error("--prepare-only belongs to relieve")
    if args.command == "relieve" and not args.what.startswith(args.region + "-"):
        parser.error(f"{args.what} is not a zone of {args.region}")
    if args.target_size < 1:
        parser.error("--target-size must be at least 1")

    group = make_group(args.mig, args.region)
    try:
        if args.command == "relieve":
            outcome = relieve(group, args.what, args.target_size, prepare_only=args.prepare_only)
        else:
            outcome = remove_vm(group, args.what, args.target_size)
        print(outcome)  # the ONLY line on stdout: nothing | ready | relieved | removed
        return 0
    except Refused as refusal:
        log(f"REFUSED, nothing changed: {refusal}")
        return 2
    except Failed as failure:
        log(f"FAILED: {failure}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
