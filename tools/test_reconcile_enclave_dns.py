#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).with_name("reconcile-enclave-dns.py")
SPEC = importlib.util.spec_from_file_location("reconcile_enclave_dns", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reconciler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconciler)


class GcloudReadTests(unittest.TestCase):
    def test_transient_failure_is_retried_and_then_parsed(self) -> None:
        failed = mock.Mock(returncode=1, stdout="", stderr="UNAVAILABLE")
        succeeded = mock.Mock(returncode=0, stdout='[{"name": "ok"}]', stderr="")
        with (
            mock.patch.object(
                reconciler.subprocess,
                "run",
                side_effect=[failed, succeeded],
            ) as run,
            mock.patch.object(reconciler.time, "sleep") as sleep,
        ):
            result = reconciler.gcloud_json(["dns", "record-sets", "list"])

        self.assertEqual(result, [{"name": "ok"}])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            reconciler.GCLOUD_TIMEOUT_SECONDS,
        )
        sleep.assert_called_once_with(0.5)

    def test_persistent_failure_surfaces_the_last_gcloud_error(self) -> None:
        failed = mock.Mock(returncode=1, stdout="", stderr="backend unavailable")
        with (
            mock.patch.object(
                reconciler.subprocess,
                "run",
                return_value=failed,
            ),
            mock.patch.object(reconciler.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, "backend unavailable"),
        ):
            reconciler.gcloud_json(["dns", "record-sets", "list"])


class ConfidentialDNSPolicyTests(unittest.TestCase):
    def test_only_policy_qualified_instances_published(self) -> None:
        fleet = [{"ip": "34.1.1.1"}, {"ip": "34.2.2.2"}]
        with (
            mock.patch.object(reconciler, "API_HOST", "api.trustedrouter.com"),
            mock.patch.object(reconciler, "attest", side_effect=lambda ip, *_args, **_kwargs: ip == "34.2.2.2") as attest,
            mock.patch.object(reconciler, "reconcile_dns_record") as publish,
        ):
            reconciler.reconcile_confidential(fleet, "sha256:release", apply=True)
        self.assertEqual(publish.call_count, 2)
        for call in publish.call_args_list:
            self.assertEqual(call.args[2], ["34.2.2.2"])
        for call in attest.call_args_list:
            self.assertEqual(call.kwargs["confidential_host"], call.kwargs["api_host"])
            self.assertIn(call.kwargs["api_host"], reconciler.CONFIDENTIAL_HOSTS)
        self.assertEqual(attest.call_count, 8)

    def test_candidate_without_one_mirror_certificate_is_not_published(self) -> None:
        with (
            mock.patch.object(reconciler, "API_HOST", "api.trustedrouter.com"),
            mock.patch.object(reconciler, "attest", side_effect=lambda *_args, **kw: kw["api_host"] != "api.confidential.allyrouter.com"),
            mock.patch.object(reconciler, "reconcile_dns_record") as publish,
            mock.patch.object(reconciler, "current_dns_ips", return_value=[]),
        ):
            reconciler.reconcile_confidential([{"ip": "34.1.1.1"}], "sha256:release", apply=True)
        publish.assert_not_called()

    def test_challenge_delegation_does_not_publish_inference_addresses(self) -> None:
        with (
            mock.patch.object(reconciler, "API_HOST", "api.trustedrouter.com"),
            mock.patch.object(reconciler, "current_dns_record", return_value=None),
            mock.patch.object(reconciler.subprocess, "run") as run,
        ):
            reconciler.provision_confidential_challenge_delegation(apply=True)
        command = run.call_args.args[0]
        self.assertIn("CNAME", command)
        self.assertIn("_acme-challenge.api.confidential.quillrouter.com.", command)
        self.assertIn("_acme-challenge.api-confidential-quillrouter.trustedrouter.com.", command)

    def test_confidential_dns_failures_do_not_skip_ordinary_updates(self) -> None:
        fleet = [{"ip": "34.1.1.1", "name": "one", "region": "us-central1"},
                 {"ip": "34.1.1.2", "name": "two", "region": "us-east4"}]
        for operation in ("provision_confidential_challenge_delegation", "reconcile_confidential"):
            with (
                self.subTest(operation=operation),
                mock.patch.object(sys, "argv", [str(SCRIPT), "--apply"]),
                mock.patch.object(reconciler, "provision_confidential_challenge_delegation"),
                mock.patch.object(reconciler, "reconcile_confidential"),
                mock.patch.object(reconciler, operation, side_effect=subprocess.TimeoutExpired("gcloud", 10)),
                mock.patch.object(reconciler, "trust_digests", return_value=["sha256:release"]),
                mock.patch.object(reconciler, "discover_instances", return_value=fleet),
                mock.patch.object(reconciler, "attest_fleet_with_release_fallback", return_value=([(item, True) for item in fleet], ["sha256:release"])),
                mock.patch.object(reconciler, "persistent_drains", return_value={}),
                mock.patch.object(reconciler, "EXCLUDE_CANONICAL_REGIONS", set()),
                mock.patch.object(reconciler, "reconcile_dns_record") as publish,
                mock.patch.object(reconciler, "PUBLISH_REGIONAL", False),
            ):
                self.assertEqual(reconciler._main_unlocked(), 1)
                publish.assert_any_call(reconciler.DNS_ZONE, reconciler.RECORD,
                                        ["34.1.1.1", "34.1.1.2"], apply=True, label="canonical")

    def test_zero_qualified_instances_removes_unsafe_records(self) -> None:
        with (
            mock.patch.object(reconciler, "API_HOST", "api.trustedrouter.com"),
            mock.patch.object(reconciler, "current_dns_ips", return_value=["34.1.1.1"]),
            mock.patch.object(reconciler.subprocess, "run") as run,
        ):
            reconciler.reconcile_confidential([], "sha256:release", apply=False)
            run.assert_not_called()
            reconciler.reconcile_confidential([], "sha256:release", apply=True)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertIn("delete", call.args[0])
            self.assertTrue(call.kwargs["check"])

    def test_verifier_gets_policy_probe_flag(self) -> None:
        with mock.patch.object(reconciler.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(reconciler.attest("34.1.1.1", "sha256:release", confidential_host="api.confidential.trustedrouter.com"))
        self.assertIn("--require-confidential-host", run.call_args.args[0])


class GcpEnclaveInventoryTests(unittest.TestCase):
    def test_discovery_excludes_regions_absent_from_rollout_inventory(self) -> None:
        rows = [
            {
                "name": "active",
                "zone": "projects/p/zones/us-central1-a",
                "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}]}],
            },
            {
                "name": "retired",
                "zone": "projects/p/zones/southamerica-east1-a",
                "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.2"}]}],
            },
        ]
        with mock.patch.object(reconciler, "gcloud_json", return_value=rows):
            fleet = reconciler.discover_instances()

        self.assertEqual([instance["name"] for instance in fleet], ["active"])
        self.assertNotIn("southamerica-east1", reconciler.GCP_ENCLAVE_REGIONS)

    def pending_regions(self, contents: str | None) -> frozenset[str]:
        serving = frozenset({"us-central1", "europe-west4", "us-east4"})
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "gcp-enclave-migs-pending.txt"
            if contents is not None:
                path.write_text(contents, encoding="utf-8")
            with mock.patch.object(reconciler, "GCP_ENCLAVE_PENDING_INVENTORY", path):
                return reconciler.gcp_enclave_pending_regions(serving)

    def test_pending_inventory_is_parsed_like_the_main_one(self) -> None:
        self.assertEqual(
            self.pending_regions("us-west1:quill-enclave-mig-uswest1\n"),
            frozenset({"us-west1"}),
        )
        # After promotion the file stays in place, empty.
        self.assertEqual(self.pending_regions(""), frozenset())
        for contents, message in (
            ("us-west1\n", "invalid GCP enclave inventory entry"),
            ("# bootstrapping\n", "invalid GCP enclave inventory entry"),
            ("us-west1:a\nus-west1:b\n", "must contain unique regions"),
        ):
            with self.subTest(contents=contents):
                with self.assertRaisesRegex(ValueError, message):
                    self.pending_regions(contents)

    def test_region_cannot_be_both_serving_and_pending(self) -> None:
        with self.assertRaisesRegex(
            ValueError, r"both serving and pending: \['us-east4'\]"
        ):
            self.pending_regions(
                "us-west1:quill-enclave-mig-uswest1\n"
                "us-east4:quill-enclave-mig-useast4\n"
            )

    def test_absent_pending_inventory_means_no_pending_regions(self) -> None:
        # An image or checkout from before the file existed.
        self.assertEqual(self.pending_regions(None), frozenset())
        with mock.patch.object(reconciler, "GCP_ENCLAVE_PENDING_REGIONS", frozenset()):
            self.assertEqual(
                reconciler.known_enclave_regions(), reconciler.GCP_ENCLAVE_REGIONS
            )
            self.assertEqual(
                reconciler.canonical_excluded_regions(),
                reconciler.EXCLUDE_CANONICAL_REGIONS,
            )

    def test_repository_inventories_load(self) -> None:
        self.assertTrue(reconciler.GCP_ENCLAVE_REGIONS)
        self.assertFalse(
            reconciler.GCP_ENCLAVE_REGIONS & reconciler.GCP_ENCLAVE_PENDING_REGIONS
        )


def _instance(name: str, zone: str, ip: str) -> dict:
    return {
        "name": name,
        "zone": f"projects/p/zones/{zone}",
        "networkInterfaces": [{"accessConfigs": [{"natIP": ip}]}],
    }


# Captured from the reconciler as it was before pending regions existed
# (origin/main at cf22daf), driven by PendingRegionTests.reconcile() below.
WITHOUT_PENDING_LOG = """\
reconcile: ignoring west in non-inventory region us-west1
reconcile: ignoring retired in non-inventory region southamerica-east1
reconcile: 2 running enclave instances; accepting digest(s) sha256:release…
  [ok ] us-central1    203.0.113.1     central
  [ok ] us-east4       203.0.113.2     east
reconcile: 2 healthy across 2 regions ['us-central1', 'us-east4']
reconcile: canonical api.trustedrouter.com. [] -> ['203.0.113.1', '203.0.113.2']
reconcile: APPLIED canonical api.trustedrouter.com.
reconcile: compatibility mirror api.quillrouter.com. [] -> ['203.0.113.1', '203.0.113.2']
reconcile: APPLIED compatibility mirror api.quillrouter.com.
  [regional ok ] us-central1    203.0.113.1     api-us-central1.quillrouter.com
  [regional ok ] us-east4       203.0.113.2     api-us-east4.quillrouter.com
  regional api-us-central1.quillrouter.com. [] -> ['203.0.113.1']
  regional api-us-central1.quillrouter.com. APPLIED
  regional api-us-east4.quillrouter.com. [] -> ['203.0.113.2']
  regional api-us-east4.quillrouter.com. APPLIED
"""

class PendingRegionTests(unittest.TestCase):
    """A region being bootstrapped: a regional record like any region's, and
    never canonical traffic. Drives the real _main_unlocked(); only gcloud
    reads, attestation and DNS writes are faked."""

    CENTRAL, EAST, WEST, RETIRED = (
        "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
    )
    ROWS = [
        _instance("central", "us-central1-a", CENTRAL),
        _instance("east", "us-east4-b", EAST),
        _instance("west", "us-west1-a", WEST),
        _instance("retired", "southamerica-east1-a", RETIRED),
    ]
    SERVING = frozenset({"us-central1", "europe-west4", "us-east4"})
    PENDING = frozenset({"us-west1"})
    WEST_RECORD = "api-us-west1.quillrouter.com."

    def reconcile(
        self,
        *,
        pending: frozenset[str],
        serving: frozenset[str] = SERVING,
        env_excluded: frozenset[str] = frozenset(),
        drains: dict[str, str] | None = None,
        cold_cnames: tuple[str, ...] = (),
        allow_promotion: frozenset[str] = frozenset(),
        unhealthy: tuple[str, ...] = (),
    ) -> SimpleNamespace:
        def gcloud_json(args: list[str]) -> list[dict]:
            if args[:3] == ["compute", "instances", "list"]:
                return self.ROWS
            self.assertEqual(args[:3], ["dns", "record-sets", "list"])
            record = args[args.index("--name") + 1]
            record_type = args[args.index("--type") + 1]
            if record_type == "CNAME" and record in cold_cnames:
                return [{"name": record, "type": "CNAME", "ttl": 300,
                         "rrdatas": ["api.quillrouter.com."]}]
            return []

        writes: dict[str, list[str]] = {}
        constants = {
            "GCP_ENCLAVE_REGIONS": serving,
            "GCP_ENCLAVE_PENDING_REGIONS": pending,
            # Empty is what an unset QUILL_EXCLUDE_CANONICAL_REGIONS parses to.
            "EXCLUDE_CANONICAL_REGIONS": set(env_excluded),
            "ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS": set(allow_promotion),
            "DNS_ZONE": "trustedrouter-com",
            "RECORD": "api.trustedrouter.com.",
            "CANONICAL_MIRRORS": [("quillrouter-com", "api.quillrouter.com.")],
            "PUBLISH_REGIONAL": True,
            "REGIONAL_ZONE": "quillrouter-com",
            "REGIONAL_SUFFIX": "quillrouter.com",
            "MIN_HEALTHY": 2,
            "MIN_HEALTHY_REGIONAL": 1,
        }
        fakes = {
            "gcloud_json": gcloud_json,
            "trust_digests": lambda: ["sha256:release"],
            "attest": lambda ip, digest, *args, **kwargs: ip not in unhealthy,
            # Consulted when an instance fails attestation; the real one runs gcloud.
            "recent_release_digests": lambda: [],
            "persistent_drains": lambda: dict(drains or {}),
            "provision_confidential_challenge_delegation": lambda **kwargs: None,
            "set_dns_ips": lambda zone, record, ips: writes.__setitem__(record, list(ips)),
        }
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", [str(SCRIPT), "--apply"]))
            # Everything that would shell out is faked above. Anything that
            # still tries is a hole in this harness, not something to run.
            stack.enter_context(mock.patch.object(
                reconciler.subprocess, "run",
                side_effect=AssertionError("the reconcile harness must not run a subprocess"),
            ))
            for name, value in constants.items():
                stack.enter_context(mock.patch.object(reconciler, name, value))
            for name, fake in fakes.items():
                stack.enter_context(mock.patch.object(reconciler, name, side_effect=fake))
            confidential = stack.enter_context(
                mock.patch.object(reconciler, "reconcile_confidential")
            )
            log = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                code: object = reconciler._main_unlocked()
            except SystemExit as exc:
                code = exc.code
        return SimpleNamespace(
            code=code,
            writes=writes,
            log=log.getvalue(),
            confidential=[
                instance["ip"] for call in confidential.call_args_list
                for instance in call.args[0]
            ],
        )

    def test_pending_vm_gets_its_regional_record_and_never_canonical(self) -> None:
        # env_excluded is empty: nothing but the pending inventory keeps it out.
        result = self.reconcile(pending=self.PENDING)

        self.assertEqual(result.code, 0, result.log)
        self.assertEqual(result.writes["api.trustedrouter.com."], [self.CENTRAL, self.EAST])
        self.assertEqual(result.writes["api.quillrouter.com."], [self.CENTRAL, self.EAST])
        self.assertEqual(result.confidential, [self.CENTRAL, self.EAST])
        self.assertEqual(result.writes[self.WEST_RECORD], [self.WEST])
        self.assertEqual(
            result.log.count(
                "reconcile: pending regions get regional DNS only, never canonical: us-west1\n"
            ),
            1,
        )
        self.assertIn("reconcile: excluding from canonical us-west1\n", result.log)
        # A region in neither inventory is still ignored everywhere.
        self.assertIn(
            "reconcile: ignoring retired in non-inventory region southamerica-east1\n",
            result.log,
        )
        self.assertNotIn(self.RETIRED, [ip for ips in result.writes.values() for ip in ips])
        self.assertNotIn("api-southamerica-east1.quillrouter.com.", result.writes)

    def test_the_same_vm_is_canonical_once_its_region_is_serving(self) -> None:
        # Positive control: nothing else about this VM keeps it out of canonical.
        result = self.reconcile(pending=frozenset(), serving=self.SERVING | self.PENDING)

        self.assertEqual(result.code, 0, result.log)
        self.assertEqual(
            result.writes["api.trustedrouter.com."], [self.CENTRAL, self.EAST, self.WEST]
        )
        self.assertEqual(result.confidential, [self.CENTRAL, self.EAST, self.WEST])
        self.assertNotIn("pending regions", result.log)

    def test_pending_vm_cannot_hold_up_the_canonical_floor(self) -> None:
        result = self.reconcile(pending=self.PENDING, unhealthy=(self.EAST,))

        self.assertIn("only 1 healthy (< MIN_HEALTHY=2)", str(result.code))
        self.assertEqual(result.writes, {})
        # Positive control: as a serving region its VM would count.
        counted = self.reconcile(
            pending=frozenset(), serving=self.SERVING | self.PENDING, unhealthy=(self.EAST,)
        )
        self.assertEqual(counted.code, 0, counted.log)
        self.assertEqual(counted.writes["api.trustedrouter.com."], [self.CENTRAL, self.WEST])

    def test_pending_region_obeys_the_cold_cname_hold_and_its_override(self) -> None:
        held = self.reconcile(
            pending=self.PENDING,
            drains={"us-west1": "rollout:33807667585"},
            cold_cnames=(self.WEST_RECORD,),
        )
        self.assertEqual(held.code, 0, held.log)
        self.assertNotIn(self.WEST_RECORD, held.writes)
        self.assertIn(
            f"regional {self.WEST_RECORD}: rollout drain holds cold CNAME", held.log
        )

        promoted = self.reconcile(
            pending=self.PENDING,
            drains={"us-west1": "rollout:33807667585"},
            cold_cnames=(self.WEST_RECORD,),
            allow_promotion=frozenset({"us-west1"}),
        )
        self.assertEqual(promoted.writes[self.WEST_RECORD], [self.WEST])
        for result in (held, promoted):
            self.assertEqual(
                result.writes["api.trustedrouter.com."], [self.CENTRAL, self.EAST]
            )

    def test_regional_sni_is_probed_for_a_pending_region_and_no_unknown_one(self) -> None:
        healthy = [
            {"name": "west", "region": "us-west1", "ip": self.WEST},
            {"name": "retired", "region": "southamerica-east1", "ip": self.RETIRED},
        ]
        with (
            mock.patch.object(reconciler, "GCP_ENCLAVE_REGIONS", self.SERVING),
            mock.patch.object(reconciler, "GCP_ENCLAVE_PENDING_REGIONS", self.PENDING),
            mock.patch.object(reconciler, "REGIONAL_SUFFIX", "quillrouter.com"),
            mock.patch.object(reconciler, "attest", return_value=True) as attest,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            by_region = reconciler.attest_regional_instances(healthy, "sha256:release")

        self.assertEqual(by_region, {"us-west1": [self.WEST]})
        attest.assert_called_once_with(
            self.WEST, "sha256:release", "api-us-west1.quillrouter.com"
        )

    def test_without_a_pending_inventory_nothing_changes(self) -> None:
        # The complete log and every DNS write of the reconciler as it was
        # before pending regions existed, for this fleet. us-west1 is then just
        # another region in neither inventory.
        result = self.reconcile(pending=frozenset())

        self.assertEqual(result.code, 0)
        self.assertEqual(result.writes, {
            "api.trustedrouter.com.": [self.CENTRAL, self.EAST],
            "api.quillrouter.com.": [self.CENTRAL, self.EAST],
            "api-us-central1.quillrouter.com.": [self.CENTRAL],
            "api-us-east4.quillrouter.com.": [self.EAST],
        })
        self.assertEqual(result.log, WITHOUT_PENDING_LOG)


class ReconcileLeaseTests(unittest.TestCase):
    def test_first_execution_acquires_atomic_object(self) -> None:
        with (
            mock.patch.object(reconciler, "RECONCILE_LOCK_BUCKET", "lock-bucket"),
            mock.patch.object(
                reconciler,
                "_storage_access_token",
                return_value="token",
            ),
            mock.patch.object(
                reconciler,
                "_read_reconcile_lock",
                return_value=None,
            ),
            mock.patch.object(
                reconciler,
                "_write_reconcile_lock",
                return_value=7,
            ) as write,
            mock.patch.dict(
                reconciler.os.environ,
                {"CLOUD_RUN_EXECUTION": "execution-one"},
            ),
        ):
            lease = reconciler.acquire_reconcile_lease(now=100.0)

        self.assertEqual(
            lease,
            reconciler.ReconcileLease(
                owner="execution-one",
                generation=7,
                acquired_at=100.0,
            ),
        )
        payload = write.call_args.args[1]
        self.assertEqual(payload["owner"], "execution-one")
        self.assertEqual(payload["state"], "running")
        self.assertEqual(payload["expires_at"], 340.0)
        self.assertEqual(write.call_args.kwargs["if_generation_match"], 0)

    def test_active_owner_makes_concurrent_execution_exit_cleanly(self) -> None:
        active = {
            "owner": "execution-one",
            "state": "running",
            "expires_at": 200.0,
        }
        with (
            mock.patch.object(reconciler, "RECONCILE_LOCK_BUCKET", "lock-bucket"),
            mock.patch.object(
                reconciler,
                "_storage_access_token",
                return_value="token",
            ),
            mock.patch.object(
                reconciler,
                "_read_reconcile_lock",
                return_value=(active, 4),
            ),
            mock.patch.object(reconciler, "_delete_reconcile_lock") as delete,
            mock.patch.object(reconciler, "_write_reconcile_lock") as write,
        ):
            lease = reconciler.acquire_reconcile_lease(now=100.0)

        self.assertIsNone(lease)
        delete.assert_not_called()
        write.assert_not_called()

    def test_expired_owner_is_replaced_with_generation_preconditions(self) -> None:
        expired = {
            "owner": "dead-execution",
            "state": "running",
            "expires_at": 99.0,
        }
        with (
            mock.patch.object(reconciler, "RECONCILE_LOCK_BUCKET", "lock-bucket"),
            mock.patch.object(
                reconciler,
                "_storage_access_token",
                return_value="token",
            ),
            mock.patch.object(
                reconciler,
                "_read_reconcile_lock",
                return_value=(expired, 4),
            ),
            mock.patch.object(
                reconciler,
                "_delete_reconcile_lock",
                return_value=True,
            ) as delete,
            mock.patch.object(
                reconciler,
                "_write_reconcile_lock",
                return_value=8,
            ),
            mock.patch.dict(
                reconciler.os.environ,
                {"CLOUD_RUN_EXECUTION": "execution-two"},
            ),
        ):
            lease = reconciler.acquire_reconcile_lease(now=100.0)

        self.assertIsNotNone(lease)
        self.assertEqual(lease.owner, "execution-two")
        self.assertEqual(lease.generation, 8)
        delete.assert_called_once_with("token", 4)

    def test_successful_completion_preserves_minimum_start_interval(self) -> None:
        lease = reconciler.ReconcileLease(
            owner="execution-one",
            generation=7,
            acquired_at=100.0,
        )
        with (
            mock.patch.object(reconciler, "RECONCILE_LOCK_BUCKET", "lock-bucket"),
            mock.patch.object(
                reconciler,
                "_storage_access_token",
                return_value="token",
            ),
            mock.patch.object(reconciler.time, "time", return_value=120.0),
            mock.patch.object(
                reconciler,
                "_write_reconcile_lock",
                return_value=8,
            ) as write,
        ):
            reconciler.finish_reconcile_lease(lease, succeeded=True)

        payload = write.call_args.args[1]
        self.assertEqual(payload["state"], "cooldown")
        self.assertEqual(payload["expires_at"], 190.0)
        self.assertEqual(write.call_args.kwargs["if_generation_match"], 7)

    def test_lost_ownership_cannot_release_another_execution(self) -> None:
        lease = reconciler.ReconcileLease(
            owner="execution-one",
            generation=7,
            acquired_at=100.0,
        )
        with (
            mock.patch.object(reconciler, "RECONCILE_LOCK_BUCKET", "lock-bucket"),
            mock.patch.object(
                reconciler,
                "_storage_access_token",
                return_value="token",
            ),
            mock.patch.object(reconciler.time, "time", return_value=120.0),
            mock.patch.object(
                reconciler,
                "_write_reconcile_lock",
                return_value=None,
            ),
            self.assertRaisesRegex(RuntimeError, "ownership changed"),
        ):
            reconciler.finish_reconcile_lease(lease, succeeded=True)


class AttestationProbeTests(unittest.TestCase):
    def test_dns_membership_uses_one_fresh_nonce_sample(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            reconciler.subprocess,
            "run",
            return_value=completed,
        ) as run:
            self.assertTrue(
                reconciler.attest("203.0.113.10", "sha256:" + "1" * 64)
            )

        command = run.call_args.args[0]
        samples_index = command.index("--samples")
        self.assertEqual(
            command[samples_index + 1],
            str(reconciler.ATTESTATION_SAMPLES),
        )
        self.assertEqual(reconciler.ATTESTATION_SAMPLES, 1)
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            reconciler.ATTESTATION_TIMEOUT_SECONDS,
        )

    def test_attestation_timeout_fails_closed_for_only_that_instance(self) -> None:
        with mock.patch.object(
            reconciler.subprocess,
            "run",
            side_effect=reconciler.subprocess.TimeoutExpired("uv", 30),
        ):
            self.assertFalse(
                reconciler.attest("203.0.113.10", "sha256:" + "1" * 64)
            )


class PersistentDrainTests(unittest.TestCase):
    def test_drain_payload_round_trips_deterministically(self) -> None:
        encoded = reconciler.encode_drain_rrdatas(
            {
                "us-east4": "operator",
                "europe-west4": "rollout:33807667585",
                "us-central1": "rollout:33807667585",
            }
        )

        self.assertEqual(
            encoded,
            [
                '"v2;europe-west4=rollout:33807667585;'
                'us-central1=rollout:33807667585;us-east4=operator"'
            ],
        )
        self.assertEqual(
            reconciler.parse_drain_rrdatas(encoded),
            {
                "us-east4": "operator",
                "europe-west4": "rollout:33807667585",
                "us-central1": "rollout:33807667585",
            },
        )

    def test_recorded_legacy_payload_is_read_as_operator_drains(self) -> None:
        fixture = (
            Path(__file__).with_name("testdata") / "drain-rrdatas-v1.txt"
        ).read_text(encoding="utf-8").strip()

        self.assertEqual(
            reconciler.parse_drain_rrdatas([fixture]),
            {"southamerica-east1": "operator", "us-east4": "operator"},
        )

    def test_recorded_mixed_operator_and_rollout_payload(self) -> None:
        fixture = (
            Path(__file__).with_name("testdata") / "drain-rrdatas-v2.txt"
        ).read_text(encoding="utf-8").strip()

        drains = reconciler.parse_drain_rrdatas([fixture])

        self.assertEqual(drains["europe-west4"], "operator")
        self.assertEqual(drains["us-central1"], "rollout:33807667585")
        self.assertEqual(drains["southamerica-east1"], "rollout:33800000001")
        self.assertEqual(drains["us-east4"], "operator")

    def test_empty_versioned_payload_means_no_drains(self) -> None:
        self.assertEqual(reconciler.parse_drain_rrdatas(['"v1"']), {})
        self.assertEqual(reconciler.parse_drain_rrdatas(['"v2"']), {})

    def test_malformed_drain_payload_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported payload"):
            reconciler.parse_drain_rrdatas(['"us-central1"'])
        with self.assertRaisesRegex(RuntimeError, "invalid region"):
            reconciler.parse_drain_rrdatas(['"v1;US_CENTRAL1"'])
        with self.assertRaisesRegex(RuntimeError, "invalid drain origin"):
            reconciler.parse_drain_rrdatas(['"v2;us-central1=human"'])
        with self.assertRaisesRegex(RuntimeError, "invalid drain entry"):
            reconciler.parse_drain_rrdatas(
                ['"v2;us-central1=operator;us-central1=rollout:33807667585"']
            )
        with self.assertRaisesRegex(RuntimeError, "exactly one TXT"):
            reconciler.parse_drain_rrdatas(['"v1;us-central1"', '"v1;us-east4"'])

    def test_set_drain_preserves_other_regions(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "persistent_drains",
                return_value={"europe-west4": "operator"},
            ),
            mock.patch.object(reconciler, "set_dns_txt") as set_dns_txt,
        ):
            regions = reconciler.update_persistent_drain(
                "us-central1",
                enabled=True,
            )

        self.assertEqual(
            regions,
            {"europe-west4": "operator", "us-central1": "operator"},
        )
        set_dns_txt.assert_called_once_with(
            reconciler.DNS_ZONE,
            reconciler.DRAIN_RECORD,
            ['"v2;europe-west4=operator;us-central1=operator"'],
        )

    def test_rollout_set_does_not_overwrite_operator_origin(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "persistent_drains",
                return_value={"us-central1": "operator"},
            ),
            mock.patch.object(reconciler, "set_dns_txt") as set_dns_txt,
        ):
            drains = reconciler.update_persistent_drain(
                "us-central1",
                enabled=True,
                origin="rollout:33807667585",
            )

        self.assertEqual(drains, {"us-central1": "operator"})
        set_dns_txt.assert_called_once_with(
            reconciler.DNS_ZONE,
            reconciler.DRAIN_RECORD,
            ['"v2;us-central1=operator"'],
        )

    def test_clear_drain_keeps_marker_with_empty_version(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "persistent_drains",
                return_value={"us-central1": "rollout:33807667585"},
            ),
            mock.patch.object(reconciler, "set_dns_txt") as set_dns_txt,
        ):
            regions = reconciler.update_persistent_drain(
                "us-central1",
                enabled=False,
            )

        self.assertEqual(regions, {})
        set_dns_txt.assert_called_once_with(
            reconciler.DNS_ZONE,
            reconciler.DRAIN_RECORD,
            ['"v2"'],
        )

    def test_list_prints_origins_and_regions_only_preserves_legacy_output(
        self,
    ) -> None:
        drains = {
            "us-central1": "rollout:33807667585",
            "europe-west4": "operator",
        }
        with (
            mock.patch.object(reconciler, "persistent_drains", return_value=drains),
            mock.patch.object(
                sys,
                "argv",
                [str(SCRIPT), "--list-drain-regions"],
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(reconciler._main_unlocked(), 0)
        self.assertEqual(
            output.getvalue(),
            "europe-west4\toperator\nus-central1\trollout:33807667585\n",
        )

        with (
            mock.patch.object(reconciler, "persistent_drains", return_value=drains),
            mock.patch.object(
                sys,
                "argv",
                [str(SCRIPT), "--list-drain-regions", "--regions-only"],
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(reconciler._main_unlocked(), 0)
        self.assertEqual(output.getvalue(), "europe-west4\nus-central1\n")

    def test_rollout_cli_records_the_github_run_id(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "update_persistent_drain",
                return_value={"us-central1": "rollout:33807667585"},
            ) as update,
            mock.patch.object(
                sys,
                "argv",
                [
                    str(SCRIPT),
                    "--set-drain-region",
                    "us-central1",
                    "--drain-origin",
                    "rollout",
                    "--github-run-id",
                    "33807667585",
                ],
            ),
        ):
            self.assertEqual(reconciler._main_unlocked(), 0)

        update.assert_called_once_with(
            "us-central1",
            enabled=True,
            origin="rollout:33807667585",
        )


class TrustDigestTests(unittest.TestCase):
    def test_reads_single_digest(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"sha256:" + b"1" * 64
        with mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response):
            self.assertEqual(reconciler.trust_digests(), ["sha256:" + "1" * 64])

    def test_reads_deduplicated_rollout_digest_set(self) -> None:
        old = "sha256:" + "1" * 64
        new = "sha256:" + "2" * 64
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = f"{old},{new},{old}\n".encode()
        with mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response):
            self.assertEqual(reconciler.trust_digests(), [old, new])

    def test_rejects_malformed_rollout_digest_set(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"sha256:not-a-digest"
        with (
            mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(SystemExit, "trust digest set looks wrong"),
        ):
            reconciler.trust_digests()


class ReleaseDigestFallbackTests(unittest.TestCase):
    def test_recent_release_lookup_retries_transient_failure(self) -> None:
        digest = "sha256:" + "a" * 64
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="unavailable")
        succeeded = subprocess.CompletedProcess([], 0, stdout=digest + "\n", stderr="")
        with (
            mock.patch.object(
                reconciler.subprocess,
                "run",
                side_effect=[failed, succeeded],
            ) as run,
            mock.patch.object(reconciler.time, "sleep") as sleep,
        ):
            self.assertEqual(reconciler.recent_release_digests(), [digest])

        self.assertEqual(run.call_count, 2)
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[1:5], ["artifacts", "docker", "images", "list"])
        self.assertIn("--include-tags", command)
        sleep.assert_called_once_with(0.5)

    def test_stable_fleet_never_reads_artifact_registry(self) -> None:
        fleet = [
            {"name": "one", "zone": "us-central1-a", "region": "us-central1", "ip": "1"},
            {"name": "two", "zone": "us-east4-a", "region": "us-east4", "ip": "2"},
        ]
        trusted = ["sha256:" + "1" * 64]
        with (
            mock.patch.object(reconciler, "attest", return_value=True) as attest,
            mock.patch.object(reconciler, "recent_release_digests") as recent,
        ):
            results, allowed = reconciler.attest_fleet_with_release_fallback(fleet, trusted)

        self.assertTrue(all(ok for _instance, ok in results))
        self.assertEqual(allowed, trusted)
        self.assertEqual(attest.call_count, 2)
        recent.assert_not_called()

    def test_only_failed_instances_retry_with_recent_release_digest(self) -> None:
        fleet = [
            {"name": "old", "zone": "us-central1-a", "region": "us-central1", "ip": "1"},
            {"name": "new", "zone": "us-east4-a", "region": "us-east4", "ip": "2"},
        ]
        trusted = "sha256:" + "1" * 64
        recent = "sha256:" + "2" * 64

        def verify(ip: str, digests: str, _api_host: str = reconciler.API_HOST) -> bool:
            if ip == "1":
                return True
            return recent in digests

        with (
            mock.patch.object(reconciler, "attest", side_effect=verify) as attest,
            mock.patch.object(
                reconciler,
                "recent_release_digests",
                return_value=[recent],
            ) as lookup,
        ):
            results, allowed = reconciler.attest_fleet_with_release_fallback(fleet, [trusted])

        self.assertTrue(all(ok for _instance, ok in results))
        self.assertEqual(allowed, [trusted, recent])
        self.assertEqual(attest.call_count, 3)
        self.assertEqual(attest.call_args_list[-1].args[:2], ("2", f"{trusted},{recent}"))
        lookup.assert_called_once_with()


class CanonicalMirrorTests(unittest.TestCase):
    def test_defaults_are_symmetric_for_both_public_api_names(self) -> None:
        self.assertEqual(
            reconciler.default_canonical_mirrors("api.trustedrouter.com"),
            "quillrouter-com:api.quillrouter.com.",
        )
        self.assertEqual(
            reconciler.default_canonical_mirrors("api.quillrouter.com"),
            "trustedrouter-com:api.trustedrouter.com.",
        )
        self.assertEqual(
            reconciler.default_canonical_mirrors("api-us-east4.quillrouter.com"),
            "",
        )

    def test_parses_canonical_mirrors(self) -> None:
        self.assertEqual(
            reconciler.parse_canonical_mirrors(
                "quillrouter-com:api.quillrouter.com,backup-zone:api.backup.test."
            ),
            [
                ("quillrouter-com", "api.quillrouter.com."),
                ("backup-zone", "api.backup.test."),
            ],
        )

    def test_rejects_malformed_canonical_mirror(self) -> None:
        with self.assertRaisesRegex(ValueError, "zone:record"):
            reconciler.parse_canonical_mirrors("api.quillrouter.com")

    def test_apply_reconciles_mirror_to_exact_canonical_set(self) -> None:
        healthy = ["203.0.113.10", "203.0.113.11"]
        with (
            mock.patch.object(
                reconciler,
                "current_dns_ips",
                return_value=["198.51.100.7"],
            ),
            mock.patch.object(reconciler, "set_dns_ips") as set_dns_ips,
        ):
            reconciler.reconcile_dns_record(
                "quillrouter-com",
                "api.quillrouter.com.",
                healthy,
                apply=True,
                label="compatibility mirror",
            )

        set_dns_ips.assert_called_once_with(
            "quillrouter-com",
            "api.quillrouter.com.",
            healthy,
        )

    def test_dry_run_never_mutates_mirror(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "current_dns_ips",
                return_value=["198.51.100.7"],
            ),
            mock.patch.object(reconciler, "set_dns_ips") as set_dns_ips,
        ):
            reconciler.reconcile_dns_record(
                "quillrouter-com",
                "api.quillrouter.com.",
                ["203.0.113.10"],
                apply=False,
                label="compatibility mirror",
            )

        set_dns_ips.assert_not_called()


class RegionalDnsPromotionTests(unittest.TestCase):
    def test_cname_to_a_uses_one_cloud_dns_transaction(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        cname = {
            "name": "api-us-east4.quillrouter.com.",
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }

        with mock.patch.object(
            reconciler.subprocess,
            "run",
            return_value=completed,
        ) as run:
            reconciler.replace_cname_with_ips(
                "quillrouter-com",
                "api-us-east4.quillrouter.com.",
                cname,
                ["203.0.113.10", "203.0.113.11"],
            )

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            [command[4] for command in commands],
            ["start", "remove", "add", "execute"],
        )
        self.assertIn("CNAME", commands[1])
        self.assertIn("api.quillrouter.com.", commands[1])
        self.assertIn("A", commands[2])
        self.assertIn("203.0.113.10", commands[2])
        self.assertIn("203.0.113.11", commands[2])
        transaction_files = {
            command[command.index("--transaction-file") + 1]
            for command in commands
        }
        self.assertEqual(len(transaction_files), 1)

    def test_set_dns_ips_promotes_existing_cname_without_separate_delete(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "replace_cname_with_ips") as replace,
            mock.patch.object(reconciler, "current_dns_ips") as current_ips,
        ):
            reconciler.set_dns_ips(
                "quillrouter-com",
                "api-us-east4.quillrouter.com.",
                ["203.0.113.10"],
            )

        replace.assert_called_once()
        current_ips.assert_not_called()

    def test_rollout_drain_holds_cold_cname_before_direct_canary(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "current_dns_ips") as current_ips,
            mock.patch.object(reconciler, "set_dns_ips") as set_ips,
        ):
            reconciler.reconcile_regional(
                {"us-east4": ["203.0.113.10"]},
                True,
                drained_regions={"us-east4"},
            )

        current_ips.assert_not_called()
        set_ips.assert_not_called()

    def test_direct_canary_override_allows_drained_cname_promotion(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS",
                {"us-east4"},
            ),
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "current_dns_ips", return_value=[]),
            mock.patch.object(reconciler, "set_dns_ips") as set_ips,
        ):
            reconciler.reconcile_regional(
                {"us-east4": ["203.0.113.10"]},
                True,
                drained_regions={"us-east4"},
            )

        set_ips.assert_called_once_with(
            reconciler.REGIONAL_ZONE,
            "api-us-east4.quillrouter.com.",
            ["203.0.113.10"],
        )

    def test_retired_region_is_never_reconciled(self) -> None:
        with (
            mock.patch.object(reconciler, "current_dns_record") as current_record,
            mock.patch.object(reconciler, "current_dns_ips") as current_ips,
            mock.patch.object(reconciler, "set_dns_ips") as set_ips,
        ):
            reconciler.reconcile_regional(
                {"southamerica-east1": ["35.247.235.153", "34.95.210.115"]},
                True,
            )

        current_record.assert_not_called()
        current_ips.assert_not_called()
        set_ips.assert_not_called()


if __name__ == "__main__":
    unittest.main()
