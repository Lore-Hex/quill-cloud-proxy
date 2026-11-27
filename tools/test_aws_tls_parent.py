import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import aws_tls_parent as parent


class ParentTransitionTests(unittest.TestCase):
    tree = "a" * 40
    image = "sha256:" + "b" * 64
    paris = "sha256:" + "c" * 64
    dublin = "sha256:" + "d" * 64

    def setUp(self):
        self.plan = {"parent_tree": self.tree, "image": self.image,
                     "from": {"eu-west-3": self.paris, "eu-west-1": self.dublin}}

    def choose(self, region, seen, **changes):
        return parent.select(self.plan | changes, self.tree,
                             {"region": region, "parent_digest": seen}, region)

    def test_only_exact_regional_transitions_including_already_updated(self):
        for region, old in self.plan["from"].items():
            for seen in (old, self.image):
                self.assertEqual(self.choose(region, seen), self.image)
        for region, seen in [("eu-west-1", self.paris), ("eu-west-3", self.dublin),
                             ("us-east-1", self.image)]:
            with self.assertRaises(ValueError):
                self.choose(region, seen)
        with self.assertRaises(ValueError):
            parent.select(self.plan, self.tree, {"region": "eu-west-3", "parent_digest": self.image}, "eu-west-1")

    def test_refuses_source_drift_tags_and_incomplete_policy(self):
        for changes in [{"parent_tree": "1"*40}, {"image": "latest"}, {"from": {"eu-west-3": self.paris}},
                        {"from": {"eu-west-3": self.paris, "eu-west-1": "bad"}}, {"extra": True}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.choose("eu-west-3", self.paris, **changes)

    def test_stale_release_or_unpinned_release(self):
        with patch.object(parent.subprocess, "check_output", side_effect=[b"old", b"new"]):
            with self.assertRaisesRegex(ValueError, "differs from current"):
                parent.checked_image("1"*40, {}, "eu-west-1")
        with patch.object(parent.subprocess, "check_output") as git:
            with self.assertRaises(ValueError):
                parent.checked_image("main", {}, "eu-west-1")
            git.assert_not_called()

    def test_registry_manifest_identity_cardinality_and_namespace(self):
        good = {"registryId": "330422590279", "repositoryName": "quill-parent", "imageDigest": self.image,
                "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}
        for entries, ok in [([good], True), ([], False), ([good, good], False),
                            ([good | {"registryId": "wrong"}], False), ([good | {"imageDigest": self.paris}], False),
                            ([good | {"repositoryName": "quill-pump"}], False),
                            ([good | {"imageManifestMediaType": "application/vnd.oci.image.index.v1+json"}], False)]:
            with patch.object(parent.subprocess, "check_output", return_value=json.dumps({"imageDetails": entries})) as call:
                if ok:
                    parent.verify_registry("eu-west-3", self.image)
                else:
                    with self.assertRaises(ValueError):
                        parent.verify_registry("eu-west-3", self.image)
                args = call.call_args.args[0]
                self.assertEqual(args, [
                    "aws", "ecr", "describe-images", "--region", "eu-west-3", "--registry-id", "330422590279",
                    "--repository-name", "quill-parent", "--image-ids", f"imageDigest={self.image}",
                    "--output", "json", "--no-cli-pager",
                ])

    def test_workflow_uses_parent_guard_without_changing_pump_or_diff_guard(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/rollout-aws-gateway.yml"
        workflow = path.read_text()
        self.assertEqual(workflow.count("python3 tools/aws_tls_parent.py"), 4)
        self.assertEqual(workflow.count('AWS_PARENT_IMAGE_DIGEST="$parent"'), 3)
        self.assertEqual(workflow.count('AWS_PARENT_PUMP_IMAGE_DIGEST="$(jq -r .pump_digest'), 3)
        self.assertEqual(workflow.count('--accept-diff-sha256 "$ACCEPT_DIFF"'), 2)
