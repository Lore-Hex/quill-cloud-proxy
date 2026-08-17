#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("write-trust-artifacts.py")
SPEC = importlib.util.spec_from_file_location("write_trust_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)

OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64
OLD_REF = "example/image:old"
NEW_REF = "example/image:new"


class TrustArtifactTests(unittest.TestCase):
    def test_current_release_accepts_only_target_digest(self) -> None:
        release = trust.release_payload("abc123", NEW_REF, NEW)

        self.assertEqual(release["image_digest"], NEW)
        self.assertEqual(release["accepted_image_digests"], [NEW])
        self.assertEqual(release["accepted_image_references"], [NEW_REF])
        self.assertEqual(release["release_state"], "current")

    def test_rolling_release_preserves_old_and_new_digests(self) -> None:
        release = trust.release_payload(
            "abc123",
            NEW_REF,
            NEW,
            [f"{OLD},{NEW}", OLD],
            [f"{OLD_REF},{NEW_REF}", OLD_REF],
        )

        self.assertEqual(release["image_digest"], NEW)
        self.assertEqual(release["accepted_image_digests"], [OLD, NEW])
        self.assertEqual(release["accepted_image_references"], [OLD_REF, NEW_REF])
        self.assertEqual(release["release_state"], "rolling")

    def test_rejects_malformed_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid OCI image digest"):
            trust.release_payload("abc123", NEW_REF, "sha256:not-a-digest")

    def test_data_policy_carries_the_client_telemetry_claim(self) -> None:
        """The SDK telemetry disclosure is a machine claim next to the prompt ones.

        Verifiers read data_policy to know what the platform promises about
        data; the client-observed reliability channel is content-free by
        construction (closed enums, bounded patterns, extra="forbid" on the
        server), so the release record says so and points at the contract.
        """
        release = trust.release_payload("abc123", NEW_REF, NEW, [], [])
        policy = release["data_policy"]
        self.assertIs(policy["prompt_output_storage"], False)
        self.assertIs(policy["control_plane_prompt_access"], False)
        self.assertIs(policy["client_telemetry_content_free"], True)
        self.assertEqual(
            policy["client_telemetry_disclosure"],
            "https://trustedrouter.com/docs/telemetry",
        )

    def test_artifacts_publish_machine_readable_accepted_set(self) -> None:
        release = trust.release_payload(
            "abc123",
            NEW_REF,
            NEW,
            [OLD],
            [OLD_REF],
        )
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            trust.write_artifacts(out, release)

            self.assertEqual(
                (out / "image-digest-gcp.txt").read_text(encoding="utf-8"),
                f"{NEW}\n",
            )
            self.assertEqual(
                (out / "accepted-image-digests-gcp.txt").read_text(
                    encoding="utf-8"
                ),
                f"{OLD},{NEW}\n",
            )
            stored = json.loads((out / "gcp-release.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["accepted_image_digests"], [OLD, NEW])
            self.assertEqual(
                stored["accepted_image_references"], [OLD_REF, NEW_REF]
            )
            self.assertEqual(
                (out / "image-reference-gcp.txt").read_text(encoding="utf-8"),
                f"{NEW_REF}\n",
            )
            self.assertEqual(
                (out / "accepted-image-references-gcp.txt").read_text(
                    encoding="utf-8"
                ),
                f"{OLD_REF},{NEW_REF}\n",
            )
            self.assertEqual(stored["release_state"], "rolling")
            page = (out / "index.html").read_text(encoding="utf-8")
            self.assertEqual(
                page.count(
                    '<link rel="canonical" href="https://trustedrouter.com/trust">'
                ),
                1,
            )
            self.assertNotIn(
                '<link rel="canonical" href="https://trust.trustedrouter.com/">',
                page,
            )
            self.assertIn("Accepted measured digests", page)
            self.assertIn("Accepted image references", page)
            self.assertIn("During a rolling release", page)
            self.assertIn(
                '<a href="https://trustedrouter.com/api/reference">API docs</a>',
                page,
            )
            self.assertNotIn(f'<a href="{release["api_base_url"]}">API</a>', page)
            self.assertIn("User-provided models", page)
            self.assertIn("leave the attested boundary", page)
            self.assertIn("not covered by TrustedRouter's zero-data-retention promise", page)
            self.assertIn("not yet served from the AWS region", page)


if __name__ == "__main__":
    unittest.main()
