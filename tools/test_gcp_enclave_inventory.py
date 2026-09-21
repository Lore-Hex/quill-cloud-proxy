#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import gcp_enclave_inventory as inventory
from gcp_enclave_inventory import ABSENT, MAIN, PENDING, InventoryError, Mig

TOOL = Path(__file__).with_name("gcp_enclave_inventory.py")

US = Mig("us-central1", "quill-enclave-mig-us")
EU = Mig("europe-west4", "quill-enclave-mig-eu")
EAST = Mig("us-east4", "quill-enclave-mig-useast4")
WEST = Mig("us-west1", "quill-enclave-mig-uswest1")
SERVING = (US, EU, EAST)


def lines(*migs: Mig) -> str:
    return "".join(f"{mig}\n" for mig in migs)


class CompareTests(unittest.TestCase):
    def test_pending_mig_may_be_absent(self) -> None:
        comparison = inventory.compare(SERVING, (WEST,), SERVING)

        self.assertEqual(comparison.problems, ())
        self.assertEqual(
            comparison.rows,
            ((US, MAIN), (EU, MAIN), (EAST, MAIN), (WEST, ABSENT)),
        )

    def test_absence_is_forgiven_only_in_the_pending_inventory(self) -> None:
        # Positive control for the test above: the same production, with the
        # same MIG listed as a serving region, is refused.
        comparison = inventory.compare((*SERVING, WEST), (), SERVING)

        self.assertEqual(
            comparison.problems,
            (f"main inventory MIG {WEST} does not exist in production",),
        )

    def test_pending_mig_that_exists_is_reported_as_pending(self) -> None:
        comparison = inventory.compare(SERVING, (WEST,), (*SERVING, WEST))

        self.assertEqual(comparison.problems, ())
        self.assertEqual(comparison.rows[-1], (WEST, PENDING))

    def test_unknown_production_mig_fails(self) -> None:
        stray = Mig("southamerica-east1", "quill-enclave-mig-sa")

        comparison = inventory.compare(SERVING, (WEST,), (*SERVING, stray))
        self.assertEqual(
            comparison.problems,
            (f"production MIG {stray} is in neither inventory",),
        )
        # Positive control: naming it in the pending inventory is what clears it.
        self.assertEqual(
            inventory.compare(SERVING, (WEST, stray), (*SERVING, stray)).problems,
            (),
        )

    def test_missing_main_inventory_mig_fails(self) -> None:
        comparison = inventory.compare(SERVING, (WEST,), (US, EU))

        self.assertEqual(
            comparison.problems,
            (f"main inventory MIG {EAST} does not exist in production",),
        )

    def test_empty_production_listing_is_not_an_empty_fleet(self) -> None:
        # A listing that failed quietly looks like this. Every serving MIG is
        # reported missing; nothing reads as "only pending regions are absent".
        comparison = inventory.compare(SERVING, (WEST,), ())

        self.assertEqual(len(comparison.problems), len(SERVING))

    def test_a_mig_is_its_region_and_its_name(self) -> None:
        misplaced = Mig("us-west1", "quill-enclave-mig-us")

        comparison = inventory.compare(SERVING, (), (misplaced, EU, EAST))
        self.assertEqual(
            comparison.problems,
            (
                f"production MIG {misplaced} is in neither inventory",
                f"main inventory MIG {US} does not exist in production",
            ),
        )

    def test_inventories_that_cannot_be_trusted_are_refused(self) -> None:
        for main, pending, message in (
            ((), (WEST,), "lists no MIG"),
            (SERVING, (EAST,), "region us-east4 is listed twice"),
            (SERVING, (Mig("us-west1", EAST.name),), "MIG quill-enclave-mig-useast4 is listed twice"),
            ((US, US), (), "region us-central1 is listed twice"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(InventoryError, message):
                    inventory.compare(main, pending, SERVING)

    def test_mig_for_region_reads_both_inventories(self) -> None:
        self.assertEqual(inventory.mig_for_region(SERVING, (WEST,), "us-east4"), EAST)
        self.assertEqual(inventory.mig_for_region(SERVING, (WEST,), "us-west1"), WEST)
        self.assertIsNone(inventory.mig_for_region(SERVING, (WEST,), "asia-east1"))


class ParseTests(unittest.TestCase):
    def test_parses_bare_region_mig_lines(self) -> None:
        self.assertEqual(inventory.parse_migs(lines(US, WEST), "fixture"), (US, WEST))
        self.assertEqual(inventory.parse_migs("", "fixture"), ())

    def test_rejects_anything_the_other_parsers_would_not_skip(self) -> None:
        for text in (
            "# a comment\n",
            "\n",
            "us-west1\n",
            "us-west1:\n",
            ":quill-enclave-mig-uswest1\n",
            "us-west1:quill-enclave-mig-uswest1:extra\n",
            "us-west1: quill-enclave-mig-uswest1\n",
            "US-WEST1:quill-enclave-mig-uswest1\n",
            # Outside the listing filter, so production could never confirm it.
            "us-west1:quill-gateway-mig-uswest1\n",
            "us-west1:quill-enclave-mig-\n",
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(InventoryError, r"fixture:1: expected"):
                    inventory.parse_migs(text, "fixture")

    def test_repository_inventories_are_valid(self) -> None:
        main = inventory.parse_migs(
            inventory.MAIN_INVENTORY.read_text(encoding="utf-8"), "main"
        )
        pending = inventory.parse_migs(
            inventory.PENDING_INVENTORY.read_text(encoding="utf-8"), "pending"
        )
        inventory.validate_inventories(main, pending)
        self.assertTrue(main)


class CommandLineTests(unittest.TestCase):
    def run_tool(
        self,
        *arguments: str,
        production: str | None = lines(EU, US, EAST),
        main: str = lines(*SERVING),
        pending: str | None = lines(WEST),
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            (temp / "main.txt").write_text(main, encoding="utf-8")
            if pending is not None:
                (temp / "pending.txt").write_text(pending, encoding="utf-8")
            if production is not None:
                (temp / "actual.txt").write_text(production, encoding="utf-8")
            command = [
                sys.executable, str(TOOL),
                "--inventory", str(temp / "main.txt"),
                "--pending-inventory", str(temp / "pending.txt"),
                *arguments,
            ]
            if arguments[0] != "mig-for-region":
                command += ["--actual-file", str(temp / "actual.txt")]
            return subprocess.run(
                command, capture_output=True, text=True, timeout=10, check=False
            )

    def test_check_passes_while_the_pending_mig_is_absent(self) -> None:
        completed = self.run_tool("check")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"pending and not created yet {WEST}", completed.stdout)

    def test_check_fails_closed(self) -> None:
        for production, message in (
            (
                lines(EU, US, EAST, Mig("asia-east1", "quill-enclave-mig-asia")),
                "production MIG asia-east1:quill-enclave-mig-asia is in neither inventory",
            ),
            (
                lines(EU, US),
                f"main inventory MIG {EAST} does not exist in production",
            ),
            ("", f"main inventory MIG {US} does not exist in production"),
        ):
            with self.subTest(message=message):
                completed = self.run_tool("check", production=production)
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertIn(
                    "configured GCP enclave MIG inventory does not match production",
                    completed.stderr,
                )
                self.assertIn(message, completed.stderr)

    def test_list_existing_leaves_out_a_pending_mig_until_it_exists(self) -> None:
        absent = self.run_tool("list-existing")
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertEqual(
            absent.stdout.splitlines(),
            [f"{US}:main", f"{EU}:main", f"{EAST}:main"],
        )

        present = self.run_tool("list-existing", production=lines(EU, US, EAST, WEST))
        self.assertEqual(present.returncode, 0, present.stderr)
        self.assertEqual(
            present.stdout.splitlines(),
            [f"{US}:main", f"{EU}:main", f"{EAST}:main", f"{WEST}:pending"],
        )

    def test_list_all_marks_the_pending_mig_that_does_not_exist(self) -> None:
        completed = self.run_tool("list-all")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [f"{US}:main", f"{EU}:main", f"{EAST}:main", f"{WEST}:absent"],
        )

    def test_listings_print_nothing_when_production_disagrees(self) -> None:
        # Their output feeds `while read` loops: a partial list would silently
        # narrow what a rollout gate looks at.
        for command in ("list-existing", "list-all"):
            for production in ("", lines(EU, US), None):
                with self.subTest(command=command, production=production):
                    completed = self.run_tool(command, production=production)
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stdout, "")
                    self.assertNotEqual(completed.stderr, "")

    def test_a_missing_pending_inventory_is_not_an_empty_one(self) -> None:
        self.assertEqual(self.run_tool("check", pending="").returncode, 0)

        completed = self.run_tool("check", pending=None)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("cannot read", completed.stderr)

    def test_malformed_files_fail_with_their_line(self) -> None:
        completed = self.run_tool("check", pending="# bootstrapping\n" + lines(WEST))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("pending.txt:1: expected", completed.stderr)

        completed = self.run_tool("check", production="us-central1\n")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("actual.txt:1: expected", completed.stderr)

    def test_mig_for_region(self) -> None:
        for region, expected in (("us-east4", EAST), ("us-west1", WEST)):
            completed = self.run_tool("mig-for-region", region)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, f"{expected.name}\n")

        completed = self.run_tool("mig-for-region", "asia-east1")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn("no enclave group is listed for asia-east1", completed.stderr)


if __name__ == "__main__":
    unittest.main()
