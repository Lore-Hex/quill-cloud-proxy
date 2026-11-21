import datetime as dt
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import ci_static_maple as build


class StaticBuildTests(unittest.TestCase):
    def test_only_a_recent_successful_main_push_can_supply_the_receipt(self):
        now = dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc)
        repo, key = "org/gateway", "maple-static-test"
        r = dict(id=123, head_sha="abc", head_repository={"full_name": repo}, event="push",
                 status="completed", conclusion="success", head_branch="main", path=".github/workflows/ci.yml")
        a = dict(workflow_run={"id":123, "head_sha":"abc"}, name=key, expired=False,
                 created_at=(now - dt.timedelta(minutes=5)).isoformat())
        def proof(artifact, run):
            return build.verified_run([artifact], [run], repo, key, now)
        self.assertEqual(proof(a, r), 123)
        for bad in ({"event":"pull_request"}, {"head_branch":"feature"}, {"conclusion":"failure"},
                    {"status":"in_progress"}, {"path":"other.yml"}, {"head_repository":{"full_name":"fork/gateway"}},
                    {"head_sha":"def"}, {"id":124}):
            with self.subTest(bad=bad):
                self.assertFalse(proof(a, r | bad))
        for bad in ({"name":"different"}, {"expired":True}, {"created_at":(now-dt.timedelta(days=1)).isoformat()}):
            self.assertFalse(proof(a | bad, r))

    def test_api_failure_builds(self):
        with patch.object(subprocess, "check_output", side_effect=subprocess.TimeoutExpired("gh", 12)):
            self.assertFalse(build.find_receipt("org/gateway", "example"))

    def test_key_tracks_the_actual_context_not_the_commit_or_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
            def commit():
                git("add", "-A")
                git("-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "fixture")
            git("init", "-q")
            module = root / "enclave-go"
            (module / "maple-transport").mkdir(parents=True)
            for path in ["maple-transport/Cargo.lock", build.DF, ".dockerignore"]:
                (module / path).write_text("original")
            (root / ".gitignore").write_text("ctx.tar\ntarget/\n")
            commit()
            tar = root / "ctx.tar"
            key = build.context(root, tar)
            (module / "maple-transport/target").mkdir()
            (module / "maple-transport/target/test").write_text("not an input")
            (root / "docs.md").write_text("unrelated")
            commit()
            self.assertEqual(key, build.context(root, tar))
            with tarfile.open(tar) as data:
                self.assertIn("maple-transport/Cargo.lock", data.getnames())
                self.assertNotIn("maple-transport/target/test", data.getnames())
            for path in ["maple-transport/Cargo.lock", build.DF, ".dockerignore", build.DF+".dockerignore"]:
                (module / path).write_text("changed")
                commit()
                changed = build.context(root, tar)
                self.assertNotEqual(key, changed, path)
                key = changed
