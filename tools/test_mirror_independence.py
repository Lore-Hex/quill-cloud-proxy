"""The trust mirrors must not share a failure domain.

Three surfaces serving the same records only buys independence if they share no
hosting provider, no DNS provider, and no registrar. Each of those is a single
thing that can take down — or take over — every surface depending on it.

This is the classic invariant that is true the day it is written and quietly
false a year later, when one name gets moved to whatever provider was convenient
for an unrelated reason. Nothing about that change looks like it touches trust,
which is why it needs a test rather than a comment.

Run: python3 tools/test_mirror_independence.py
"""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MIRRORS = REPO_ROOT / "trust-page" / "mirrors.json"
TRUST_DIR = REPO_ROOT / "trust-page"

# Columns that must be pairwise disjoint across live mirrors.
FAILURE_DOMAINS = ("hosting_provider", "dns_provider", "registrar")


def _config() -> dict:
    return json.loads(MIRRORS.read_text())


class MirrorIndependence(unittest.TestCase):
    def test_live_mirrors_share_no_failure_domain(self) -> None:
        mirrors = _config()["mirrors"]
        self.assertGreaterEqual(len(mirrors), 2, "independence needs at least two mirrors")
        for column in FAILURE_DOMAINS:
            values = [m[column] for m in mirrors if m[column] != "none-of-ours"]
            duplicates = [v for v, n in Counter(values).items() if n > 1]
            self.assertEqual(
                duplicates,
                [],
                f"mirrors share {column}={duplicates}. Two surfaces behind the same "
                f"{column.replace('_', ' ')} fail together, so this is one mirror "
                "wearing two names, not two mirrors.",
            )

    def test_every_record_is_listed_and_exists(self) -> None:
        config = _config()
        for record in config["records"]:
            self.assertTrue(
                (TRUST_DIR / record).is_file(),
                f"mirrors.json lists {record} but it is not in trust-page/",
            )

    def test_all_three_planes_are_covered(self) -> None:
        records = " ".join(_config()["records"])
        for plane in ("gcp", "aws", "azure"):
            self.assertIn(
                f"{plane}-release.json",
                records,
                f"no record listed for the {plane} plane; a plane with no published "
                "record cannot be checked independently, which is the requirement.",
            )

    def test_planned_mirrors_are_not_counted_as_live(self) -> None:
        # A planned mirror is a gap, not a mitigation. Counting it would let the
        # independence assertion pass on infrastructure that does not exist.
        config = _config()
        live_urls = {m["url"] for m in config["mirrors"]}
        for planned in config.get("planned", []):
            self.assertNotIn(
                planned["url"],
                live_urls,
                f"{planned['name']} is listed as both planned and live. If it is "
                "actually serving, move it into 'mirrors' so its failure domains "
                "are checked against the others.",
            )


if __name__ == "__main__":
    unittest.main()
