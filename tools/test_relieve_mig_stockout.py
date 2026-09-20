#!/usr/bin/env python3
"""Tests for tools/relieve-mig-stockout.py against a simulated managed instance group.

The simulator models the Compute behavior the tool depends on, as observed in
production on 2026-09-20: `delete-instances` lowers the target size by the number
of VMs deleted, `resize` creates VMs from nothing, a VM is pinned to the zone it
was scheduled in, a zone with no capacity leaves a VM in CREATING with
ZONE_RESOURCE_POOL_EXHAUSTED, a VM is RUNNING for minutes before it ATTESTS, and
a deletion is reported done BEFORE the VM is gone: it stays listed as DELETING,
and keeps answering, for a while. After EVERY mutating call it checks the
property the tool exists to keep: the group never has fewer ATTESTING VMs than
its target, not counting a VM that is on its way out. RUNNING does not count:
the first version of this simulator counted it, and review showed a sequence
that deleted the old VM while its replacement could not attest yet. A deletion
used to be instantaneous here, too; that hid a run that counted a VM which was
already being deleted among the VMs that would remain. And a VM that is shutting
down keeps ANSWERING here, while the group's listing still calls it RUNNING: only
its own status, asked for by name, says STOPPING.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("relieve", ROOT / "tools" / "relieve-mig-stockout.py")
assert _spec and _spec.loader
relieve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relieve)

ZONE_URL = "https://www.googleapis.com/compute/v1/projects/quill-cloud-proxy/zones/"
DEAD = "us-central1-c"


class FakeGroup:
    """A regional MIG of two VMs, one of them in the zone that has no capacity."""

    def __init__(self, *, shape: str = "EVEN", stable: bool = True, places_in: str = "us-central1-f",
                 polls_until_running: int = 2, polls_until_attesting: int = 4, stuck: bool = False,
                 autoscaled: bool = False, dead_zone_recovers: bool = False, deletion_takes: int = 3) -> None:
        self.shape, self.stable, self.autoscaled = shape, stable, autoscaled
        self.places_in, self.polls_until_running = places_in, polls_until_running
        self.polls_until_attesting, self.stuck, self.dead_zone_recovers = polls_until_attesting, stuck, dead_zone_recovers
        self.size, self.clock, self.polls, self.deletion_takes = 2, 100, 0, deletion_takes
        self.wait_until_times_out = False
        self.stops_after_lookups: dict[str, int] = {}  # name -> by-name lookups it survives before STOPPING
        self.lookups: dict[str, int] = {}
        self.describe_fails_on: dict[str, set[int]] = {}  # name -> which of its by-name lookups error (0 = the first)
        self.someone_deletes_after_lookups: dict[str, int] = {}  # name -> lookups after which SOMEONE ELSE deletes it
        self.stops_while_asking: dict[str, str] = {}  # name -> the OTHER VM during whose GET /attestation it begins to stop
        self.vms = {
            "mig-us-aaaa": self._vm("us-central1-b", running=True, created=10),
            "mig-us-cccc": self._vm(DEAD, running=True, created=90),  # the NEWER original, on purpose
        }
        self.calls: list[str] = []
        self.fewest_attesting = 2
        self.loses_attestation: dict[str, int] = {}  # name -> tick from which it no longer attests
        self.describe_fails_for = ""
        self.ticks = 0

    @staticmethod
    def _vm(zone: str, *, running: bool, created: int) -> dict:
        return {"zone": zone, "status": "RUNNING" if running else "", "action": "NONE" if running else "CREATING",
                "errors": [], "age": 99 if running else 0, "created": created}

    # -- what the tool calls ------------------------------------------------
    def __call__(self, args: list[str]) -> str:
        if args[:3] == ["compute", "instances", "describe"]:
            self._tick()  # time passes while the tool waits for attestation, too
            name = args[3]
            vm = self.vms.get(name)
            if name == self.describe_fails_for or self.lookups.get(name, 0) in self.describe_fails_on.get(name, ()):
                self.lookups[name] = self.lookups.get(name, 0) + 1
                raise relieve.Failed("503 backend error")  # transient, and says nothing about the VM
            if vm is None:
                raise relieve.Failed("instance not found")  # what gcloud() raises for a VM that does not exist
            if name in self.stops_after_lookups and self.lookups.get(name, 0) >= self.stops_after_lookups[name]:
                vm["stopping"] = True
            if vm["action"] != "DELETING" and self.lookups.get(name, 0) >= self.someone_deletes_after_lookups.get(name, 10**9):
                # Its own status still reads RUNNING for a while, and it still answers.
                vm.update(action="DELETING", gone_in=self.deletion_takes)
                self.size -= 1
            self.lookups[name] = self.lookups.get(name, 0) + 1
            status = "STOPPING" if vm.get("stopping") else vm["status"] or "PROVISIONING"
            return json.dumps({"status": status, "networkInterfaces": [{"accessConfigs": [{"natIP": f"ip-of-{name}"}]}]})
        verb = args[3]
        if verb == "describe":
            return json.dumps(self._describe())
        if verb == "list-instances":
            self.polls += 1
            self._tick()
            return json.dumps(self._list())
        self.calls.append(" ".join(a for a in args[3:] if not a.startswith("--region")))
        if verb == "update":
            assert "--instance-redistribution-type=none" in args and "--target-distribution-shape=balanced" in args
            self.shape = "BALANCED"
        elif verb == "resize":
            self._resize(int(next(a for a in args if a.startswith("--size=")).split("=")[1]))
        elif verb == "delete-instances":
            names = next(a for a in args if a.startswith("--instances=")).split("=")[1].split(",")
            for name in names:
                # KeyError = the tool named a VM that does not exist. The VM is
                # NOT gone yet: it is listed as DELETING and it still answers.
                self.vms[name].update(action="DELETING", gone_in=self.deletion_takes)
            self.size -= len(names)  # what Compute does, at once
            self._shrink_to_size()
        elif verb == "wait-until":
            if self.wait_until_times_out:
                raise relieve.Failed("wait-until: timed out")  # and the deletion is still pending
            while any(vm["action"] == "DELETING" for vm in self.vms.values()):
                self._tick()
            self.stable = True
        else:
            raise AssertionError(f"unexpected gcloud call: {args}")
        self.fewest_attesting = min(self.fewest_attesting, sum(1 for n in self._staying() if self._attesting_by_name(n)))
        return ""

    def _staying(self) -> list[str]:
        # A VM that is being deleted or is shutting down still ANSWERS (probe
        # says yes), and is not a VM the group will be serving from.
        return [name for name, vm in self.vms.items() if vm["action"] != "DELETING" and not vm.get("stopping")]

    def probe(self, ip: str) -> bool:
        asked = ip.removeprefix("ip-of-")
        for name, while_asking in self.stops_while_asking.items():
            if while_asking == asked and name in self.vms:
                self.vms[name]["stopping"] = True
        return self._attesting_by_name(asked)

    def _attesting_by_name(self, name: str) -> bool:
        vm = self.vms.get(name)
        lost = name in self.loses_attestation and self.ticks >= self.loses_attestation[name]
        return bool(vm) and self._attesting(vm) and not lost

    # -- the model ------------------------------------------------------------
    def _attesting(self, vm: dict) -> bool:
        return vm["status"] == "RUNNING" and vm["age"] >= self.polls_until_attesting

    def _describe(self) -> dict:
        return {
            "targetSize": self.size,
            "status": {"isStable": self.stable},
            "autoscaler": "https://example/autoscaler" if self.autoscaled else None,
            "distributionPolicy": {
                "targetShape": self.shape,
                "zones": [{"zone": ZONE_URL + z} for z in ("us-central1-b", DEAD, "us-central1-f")],
            },
        }

    def _list(self) -> list[dict]:
        return [
            {
                "instance": f"{ZONE_URL}{vm['zone']}/instances/{name}",
                "instanceStatus": vm["status"],
                "currentAction": vm["action"],
                "lastAttempt": {"errors": {"errors": [{"code": code} for code in vm["errors"]]}},
            }
            for name, vm in self.vms.items()
        ]

    def _resize(self, size: int) -> None:
        self.size = size
        while len(self._staying()) < size:
            self.clock += 1
            # Under EVEN the new VM goes back to the zone the group is thinnest in.
            zone = DEAD if self.shape == "EVEN" else self.places_in
            self.vms[f"mig-us-new{self.clock}"] = self._vm(zone, running=False, created=self.clock)
        self._shrink_to_size()

    def _shrink_to_size(self) -> None:
        # Compute removes VMs of ITS choosing to reach a smaller size. The
        # hostile choice: an attesting VM goes first.
        while len(self._staying()) > self.size:
            attesting = [n for n in self._staying() if self._attesting_by_name(n)]
            del self.vms[(attesting or self._staying())[0]]

    def _tick(self) -> None:
        self.ticks += 1
        for name in [n for n, vm in self.vms.items() if vm["action"] == "DELETING"]:
            self.vms[name]["gone_in"] -= 1
            if self.vms[name]["gone_in"] <= 0:
                del self.vms[name]
        for vm in self.vms.values():
            vm["age"] += 1
            if vm["action"] != "CREATING":
                continue
            if self.stuck or (vm["zone"] == DEAD and not self.dead_zone_recovers):
                vm["errors"] = ["ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS"]
            elif vm["age"] >= self.polls_until_running:
                vm.update(status="RUNNING", action="NONE")

    def mutations(self) -> list[str]:
        return [c.split()[0] for c in self.calls]


class RelieveMigStockoutTests(unittest.TestCase):
    def group(self, fake: FakeGroup):
        return relieve.Group("quill-enclave-mig-us", "us-central1", run=fake)

    def relieve(self, fake: FakeGroup, zone: str = DEAD, **kwargs):
        kwargs.setdefault("probe", fake.probe)
        return relieve.relieve(self.group(fake), zone, 2, poll_seconds=1, sleep=lambda _: None, **kwargs)

    def assert_nothing_was_deleted(self, fake: FakeGroup) -> None:
        self.assertEqual([c for c in fake.calls if c.startswith("delete-instances")], [])
        self.assertTrue({"mig-us-aaaa", "mig-us-cccc"} <= set(fake.vms), "an ORIGINAL VM is gone")
        self.assertEqual(fake.fewest_attesting, 2, "the group dropped below two ATTESTING VMs at some point")

    def test_the_vm_leaves_the_dead_zone_and_two_vms_attest_throughout(self) -> None:
        fake = FakeGroup()
        self.assertEqual(self.relieve(fake), "relieved")
        # Shape first: under EVEN the added VM returns to the dead zone.
        self.assertEqual(fake.mutations(), ["update", "resize", "delete-instances", "wait-until"])
        self.assertEqual(fake.calls[2], "delete-instances quill-enclave-mig-us --instances=mig-us-cccc")
        self.assertEqual(fake.size, 2)
        self.assertEqual(sorted(vm["zone"] for vm in fake.vms.values()), ["us-central1-b", "us-central1-f"])
        self.assertEqual(fake.fewest_attesting, 2)
        self.assertEqual(self.relieve(fake), "nothing", "a second run must find nothing to do")

    def test_a_running_replacement_that_cannot_attest_is_not_a_replacement(self) -> None:
        # RUNNING within two polls, never attesting: exactly what a listing-based
        # gate waved through. Nothing is deleted; the group stays enlarged.
        fake = FakeGroup(polls_until_attesting=10_000)
        fake.vms["mig-us-aaaa"]["age"] = fake.vms["mig-us-cccc"]["age"] = 20_000  # the originals do attest
        with self.assertRaises(relieve.Failed) as raised:
            self.relieve(fake, attest_seconds=6)
        self.assertIn("Nothing was deleted", str(raised.exception))
        self.assert_nothing_was_deleted(fake)
        self.assertEqual((fake.size, len(fake.vms)), (3, 3))

    def test_attestation_is_never_remembered_from_an_earlier_pass(self) -> None:
        # The original outside the zone attests, then restarts (TDX host
        # maintenance does this) and is RUNNING again without attesting, and only
        # THEN does the replacement come up. Remembering the early success would
        # delete the VM in the zone and leave one attesting VM.
        fake = FakeGroup(polls_until_attesting=8)
        fake.vms["mig-us-aaaa"]["age"] = fake.vms["mig-us-cccc"]["age"] = 20_000
        fake.loses_attestation = {"mig-us-aaaa": 6}  # from the sixth tick on, for good
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=40)
        self.assert_nothing_was_deleted(fake)

    def test_a_lookup_that_fails_proves_nothing_and_deletes_nothing(self) -> None:
        fake = FakeGroup()
        fake.describe_fails_for = "mig-us-aaaa"  # every lookup of the surviving original errors
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=12)
        self.assert_nothing_was_deleted(fake)

    def test_a_vm_that_begins_to_stop_while_the_next_one_is_asked_is_not_one_that_will_remain(self) -> None:
        # Review's sequence: A answers and reads RUNNING; while the replacement
        # is being asked, A begins STOPPING. It still answers and the group still
        # lists it RUNNING/NONE. Reading each VM's status straight after its own
        # answer kept A. Every status is read after EVERY answer.
        fake = FakeGroup(polls_until_attesting=0)
        fake.stops_while_asking = {"mig-us-aaaa": "mig-us-new101"}
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=12)
        self.assertTrue(fake.vms["mig-us-aaaa"]["stopping"] and fake.probe("ip-of-mig-us-aaaa"))
        self.assert_nothing_was_deleted(fake)

        enlarged = FakeGroup(shape="BALANCED", polls_until_attesting=0)
        enlarged("compute instance-groups managed resize quill-enclave-mig-us --size=3".split())
        for _ in range(6):
            enlarged("compute instance-groups managed list-instances quill-enclave-mig-us".split())
        enlarged.stops_while_asking = {"mig-us-aaaa": "mig-us-cccc"}
        calls = list(enlarged.calls)
        with self.assertRaises(relieve.Refused):
            relieve.remove_vm(self.group(enlarged), "mig-us-new101", 2, probe=enlarged.probe)
        self.assertEqual(enlarged.calls, calls)

    def test_a_lookup_that_fails_after_the_answer_proves_nothing_either(self) -> None:
        fake = FakeGroup()
        fake.vms["mig-us-aaaa"]["age"] = fake.vms["mig-us-cccc"]["age"] = 20_000
        fake.describe_fails_on = {"mig-us-aaaa": set(range(1, 10_000))}  # its address is learned, it answers, and then it cannot be asked
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=12)
        self.assert_nothing_was_deleted(fake)

    def test_a_vm_that_was_never_asked_is_not_counted_because_a_later_lookup_worked(self) -> None:
        # The replacement never attests. Its first lookup errors, so there is no
        # address to ask; its next lookup says RUNNING. RUNNING is not an answer.
        fake = FakeGroup(polls_until_attesting=10_000)
        fake.vms["mig-us-aaaa"]["age"] = fake.vms["mig-us-cccc"]["age"] = 20_000
        fake.describe_fails_on = {"mig-us-new101": {0}}
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=12)
        self.assertIn("mig-us-new101", fake.vms)
        self.assert_nothing_was_deleted(fake)

    def test_a_group_an_operator_already_made_tolerant_keeps_its_shape(self) -> None:
        fake = FakeGroup(shape="ANY")  # us-east4 in production
        self.relieve(fake)
        self.assertNotIn("update", fake.mutations())
        self.assertEqual(fake.shape, "ANY")

    def test_preconditions_refuse_without_touching_the_group(self) -> None:
        not_running = FakeGroup()
        not_running.vms["mig-us-aaaa"].update(status="STOPPING", action="RECREATING")
        odd_size = FakeGroup()
        odd_size.size = 5
        for label, fake in {"a rollout is in flight": FakeGroup(stable=False), "autoscaled": FakeGroup(autoscaled=True),
                            "a VM is not running": not_running, "a size that is neither start nor resume": odd_size}.items():
            with self.subTest(label):
                with self.assertRaises(relieve.Refused):
                    self.relieve(fake)
                self.assertEqual(fake.calls, [])
        fake = FakeGroup()
        with self.assertRaises(relieve.Refused):
            self.relieve(fake, zone="us-east4-a")
        self.assertEqual(self.relieve(fake, zone="us-central1-f"), "nothing")
        self.assertEqual(fake.calls, [])

    def test_every_way_the_replacement_can_fail_deletes_nothing(self) -> None:
        cases = {
            "the group places it in the dead zone again": FakeGroup(places_in=DEAD),
            "it lands in the dead zone and even starts there": FakeGroup(places_in=DEAD, dead_zone_recovers=True),
            "the other zone has no capacity either": FakeGroup(stuck=True),
            "it never starts running": FakeGroup(polls_until_running=10_000),
        }
        for label, fake in cases.items():
            with self.subTest(label):
                with self.assertRaises(relieve.Failed) as raised:
                    self.relieve(fake, wait_seconds=8)
                if "dead zone" in label:
                    # Recognized for what it is, at once: not waited out as "slow
                    # to start", which ends the same way minutes later.
                    self.assertIn("placed a VM there again", str(raised.exception))
                    self.assertLessEqual(fake.polls, 3)
                self.assert_nothing_was_deleted(fake)

    def test_a_stocked_out_replacement_is_given_up_on_quickly(self) -> None:
        fake = FakeGroup(stuck=True)
        with self.assertRaises(relieve.Failed) as raised:
            self.relieve(fake, wait_seconds=3600)
        self.assertIn("no capacity either", str(raised.exception))
        self.assertLessEqual(fake.polls, 8, "it kept polling a VM that had already reported a stockout")

    def test_a_run_that_died_after_the_resize_is_resumed_by_running_it_again(self) -> None:
        # No state file to lose: the second run reads size == target + 1 and
        # carries on. (A cancelled workflow or a dead runner leaves exactly this.)
        fake = FakeGroup()

        def dies(_: float) -> None:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            relieve.relieve(self.group(fake), DEAD, 2, probe=fake.probe, poll_seconds=1, sleep=dies)
        self.assertEqual((fake.size, len(fake.vms)), (3, 3))
        self.assertEqual(self.relieve(fake), "relieved")
        self.assertEqual(fake.mutations().count("resize"), 1, "the resumed run enlarged the group a second time")
        self.assertEqual((fake.size, fake.fewest_attesting), (2, 2))
        self.assertNotIn(DEAD, [vm["zone"] for vm in fake.vms.values()])

    def test_prepare_only_stops_before_the_deletion_and_the_next_run_finishes(self) -> None:
        # The workflow drains the region from DNS between the two runs, so that
        # no client is still being sent to the VM when it is deleted.
        fake = FakeGroup()
        self.assertEqual(self.relieve(fake, prepare_only=True), "ready")
        self.assert_nothing_was_deleted(fake)
        self.assertEqual((fake.size, len(fake.vms), fake.mutations()), (3, 3, ["update", "resize"]))
        self.assertEqual(self.relieve(fake, prepare_only=True), "ready", "asking twice must change nothing")
        self.assertEqual(fake.mutations(), ["update", "resize"])
        self.assertEqual(self.relieve(fake), "relieved")
        self.assertEqual(fake.mutations(), ["update", "resize", "delete-instances", "wait-until"])
        self.assertEqual((fake.size, fake.fewest_attesting), (2, 2))

    def test_remove_vm_deletes_only_the_named_vm_and_only_if_two_others_attest(self) -> None:
        def enlarged(**kwargs) -> tuple[FakeGroup, str]:
            fake = FakeGroup(shape="BALANCED", **kwargs)
            fake("compute instance-groups managed resize quill-enclave-mig-us --size=3".split())
            for _ in range(6):
                fake("compute instance-groups managed list-instances quill-enclave-mig-us".split())
            return fake, next(n for n in fake.vms if n.startswith("mig-us-new"))

        fake, added = enlarged()
        self.assertEqual(relieve.remove_vm(self.group(fake), added, 2, probe=fake.probe), "removed")
        self.assertEqual((fake.size, sorted(fake.vms)), (2, ["mig-us-aaaa", "mig-us-cccc"]))
        self.assertEqual(fake.fewest_attesting, 2)
        # It waits for the group to settle: the workflow's finalizer clears the
        # DNS drain only for a group that is stable.
        self.assertEqual(fake.mutations()[-2:], ["delete-instances", "wait-until"])

        # The same request when it would cost an attesting VM is refused.
        cases = {}
        fake, added = enlarged()
        fake.loses_attestation = {"mig-us-aaaa": 0}
        cases["an original cannot attest: the added VM is what keeps two"] = (fake, added)
        fake, added = enlarged()
        fake.describe_fails_for = "mig-us-cccc"
        cases["an original cannot be looked up: unknown is not proven"] = (fake, added)
        fake, _ = enlarged()
        cases["a name that is not in the group"] = (fake, "mig-us-zzzz")
        cases["the group is not enlarged"] = (FakeGroup(), "mig-us-cccc")
        # A rollout's SURGE: three attesting VMs while the size still reads 2.
        # Two others do attest, and deleting one would still lower the size to 1.
        surging = FakeGroup()
        surging.vms["mig-us-surge"] = FakeGroup._vm("us-central1-f", running=True, created=95)
        cases["a surge VM during a rollout: the size is not enlarged"] = (surging, "mig-us-surge")
        for label, (fake, name) in cases.items():
            with self.subTest(label):
                calls = list(fake.calls)
                with self.assertRaises(relieve.Refused):
                    relieve.remove_vm(self.group(fake), name, 2, probe=fake.probe)
                self.assertEqual(fake.calls, calls)

    def test_a_vm_that_is_already_being_deleted_is_not_one_that_will_remain(self) -> None:
        # Review's sequence. BOTH originals sit in the dead zone; C and D were
        # added (size 4); original A has stopped attesting. `remove-vm C` is
        # right: B and D attest. Its run dies while C is still DELETING, and C
        # still answers. `remove-vm D` must not count C: with D gone as well,
        # only B would be left attesting.
        fake = FakeGroup(shape="BALANCED", deletion_takes=10_000)
        fake.vms["mig-us-aaaa"]["zone"] = DEAD
        fake("compute instance-groups managed resize quill-enclave-mig-us --size=4".split())
        for _ in range(6):
            fake("compute instance-groups managed list-instances quill-enclave-mig-us".split())
        c, d = sorted(n for n in fake.vms if n.startswith("mig-us-new"))
        fake.loses_attestation = {"mig-us-aaaa": 0}
        fake.wait_until_times_out = True
        with self.assertRaises(relieve.Failed):  # the deletion was accepted; the run then died waiting
            relieve.remove_vm(self.group(fake), c, 2, probe=fake.probe)
        self.assertEqual((fake.size, fake.vms[c]["action"], fake.probe(f"ip-of-{c}")), (3, "DELETING", True))
        calls = list(fake.calls)
        with self.assertRaises(relieve.Refused) as raised:
            relieve.remove_vm(self.group(fake), d, 2, probe=fake.probe)
        self.assertIn("only ['mig-us-cccc'] attest", str(raised.exception))
        # Asking for C again is refused too: the size already went down for it.
        with self.assertRaises(relieve.Refused) as raised:
            relieve.remove_vm(self.group(fake), c, 2, probe=fake.probe)
        self.assertIn("already being deleted", str(raised.exception))
        self.assertEqual(fake.calls, calls)
        self.assertEqual(fake.fewest_attesting, 2)

    def test_a_vm_that_is_shutting_down_still_answers_and_is_not_one_that_will_remain(self) -> None:
        # The listing says RUNNING/NONE and GET /attestation says 200, because a
        # guest keeps serving while it shuts down. Only the VM's own status
        # knows, and only a status read AFTER the answer proves anything: in the
        # second case the VM is still RUNNING at the first lookup.
        for label, lookups_survived in {"already STOPPING when it is looked up": 0,
                                        "begins STOPPING between the lookup and the answer": 1}.items():
            with self.subTest(label):
                fake = FakeGroup()
                fake.vms["mig-us-aaaa"]["age"] = fake.vms["mig-us-cccc"]["age"] = 20_000
                fake.stops_after_lookups = {"mig-us-aaaa": lookups_survived}
                with self.assertRaises(relieve.Failed):
                    self.relieve(fake, attest_seconds=12)
                self.assertTrue(fake.probe("ip-of-mig-us-aaaa"), "the simulated VM must still ANSWER while it stops")
                self.assert_nothing_was_deleted(fake)

                enlarged = FakeGroup(shape="BALANCED")
                enlarged("compute instance-groups managed resize quill-enclave-mig-us --size=3".split())
                for _ in range(6):
                    enlarged("compute instance-groups managed list-instances quill-enclave-mig-us".split())
                added = next(n for n in enlarged.vms if n.startswith("mig-us-new"))
                enlarged.stops_after_lookups = {"mig-us-aaaa": lookups_survived}
                calls = list(enlarged.calls)
                with self.assertRaises(relieve.Refused):
                    relieve.remove_vm(self.group(enlarged), added, 2, probe=enlarged.probe)
                self.assertEqual(enlarged.calls, calls)

    def test_a_deletion_someone_asks_for_while_the_vms_are_being_asked_is_seen(self) -> None:
        # A person with gcloud deletes the original outside the zone in the
        # middle of the pass. It was RUNNING/NONE when the group was listed, it
        # answers, and its own status still reads RUNNING after it answered.
        # Only a listing taken AFTER the answers shows the deletion.
        fake = FakeGroup(deletion_takes=10_000, polls_until_attesting=0)  # the replacement attests at once
        # The deletion lands as the VM is first looked up, after the listing the
        # pass started from, in the very pass in which every VM answers.
        fake.someone_deletes_after_lookups = {"mig-us-aaaa": 0}
        with self.assertRaises(relieve.Failed):
            self.relieve(fake, attest_seconds=12)
        self.assertEqual(fake.vms["mig-us-aaaa"]["action"], "DELETING")
        self.assertEqual([c for c in fake.calls if c.startswith("delete-instances")], [], "it deleted the VM in the zone too")
        self.assertIn("mig-us-cccc", fake.vms)

    def test_both_vms_in_the_dead_zone_are_replaced_before_either_is_deleted(self) -> None:
        fake = FakeGroup()
        fake.vms["mig-us-aaaa"]["zone"] = DEAD
        self.assertEqual(self.relieve(fake), "relieved")
        self.assertEqual(fake.mutations(), ["update", "resize", "delete-instances", "wait-until"])
        self.assertEqual(fake.calls[1], "resize quill-enclave-mig-us --size=4")
        self.assertEqual(fake.calls[2], "delete-instances quill-enclave-mig-us --instances=mig-us-aaaa,mig-us-cccc")
        self.assertEqual((fake.size, fake.fewest_attesting), (2, 2))
        self.assertEqual(sorted(vm["zone"] for vm in fake.vms.values()), ["us-central1-f", "us-central1-f"])

    def test_the_command_line_refuses_a_zone_of_another_region(self) -> None:
        with self.assertRaises(SystemExit):
            relieve.main(["relieve", "quill-enclave-mig-us", "us-central1", "us-east4-a", "--target-size", "2"])
        with self.assertRaises(SystemExit):
            relieve.main(["relieve", "quill-enclave-mig-us", "us-central1", DEAD])  # the size is never assumed
        with self.assertRaises(SystemExit):
            relieve.main(["remove-vm", "quill-enclave-mig-us", "us-central1", "mig-us-cccc", "--target-size", "2",
                          "--prepare-only"])

    def test_the_outcome_is_the_only_thing_on_stdout(self) -> None:
        # The workflow reads it to decide whether there is anything to drain for.
        import contextlib
        import io

        fake = FakeGroup()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = relieve.main(["relieve", "quill-enclave-mig-us", "us-central1", "us-central1-f", "--target-size", "2",
                                 "--prepare-only"], make_group=lambda mig, region: relieve.Group(mig, region, run=fake))
        self.assertEqual((code, out.getvalue()), (0, "nothing\n"))
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
