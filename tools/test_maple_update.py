#!/usr/bin/env python3
import json
import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import maple_policy as policy
import maple_update as update


class TransportTests(unittest.TestCase):
    def test_exact_archive_and_rejected_members(self):
        for extra in (None, "../image.eif", "/tmp/escape", "script.sh", "image.eif"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "input.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    for name in update.FILES:
                        bundle.writestr(name, b"fixture")
                    if extra:
                        bundle.writestr(extra, b"not allowed")
                if extra:
                    with self.assertRaises(policy.Refused):
                        update.unpack(archive, root / "extracted")
                else:
                    update.unpack(archive, root / "extracted")
                    self.assertEqual(
                        sorted(p.name for p in (root / "extracted").iterdir()),
                        sorted(update.FILES),
                    )

    def test_archive_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "input.zip", "w") as bundle:
                for name in update.FILES:
                    item = zipfile.ZipInfo(name)
                    item.external_attr = (
                        (stat.S_IFLNK if name == "image.eif" else stat.S_IFREG) | 0o644
                    ) << 16
                    bundle.writestr(item, b"/tmp/escape")
            with self.assertRaises(policy.Refused):
                update.unpack(root / "input.zip", root / "extracted")

    def test_pin_checks_require_matching_positive_and_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = {"check": "front_enclave_attestation", "ok": True, "pcr0": "a" * 96}
            negative = {"check": "changed_pin_rejected", "ok": True}
            (root / "valid-pin.json").write_text(json.dumps(good))
            (root / "wrong-pin.json").write_text(json.dumps(negative))
            update.validate_pin_checks(root, "a" * 96)
            with self.assertRaises(policy.Refused):
                update.validate_pin_checks(root, "b" * 96)
            (root / "wrong-pin.json").write_text(json.dumps(dict(negative, ok=False)))
            with self.assertRaises(policy.Refused):
                update.validate_pin_checks(root, "a" * 96)

    def test_publication_refuses_non_main_or_other_repository(self):
        for ref, repo in (
            ("refs/heads/untrusted", update.REPOSITORY),
            ("refs/heads/main", "other/repo"),
        ):
            with (
                self.subTest(ref=ref, repo=repo),
                patch.dict(os.environ, GITHUB_REF=ref, GITHUB_REPOSITORY=repo),
                self.assertRaises(policy.Refused),
            ):
                update.publish({}, {}, Path("missing"), Path("missing"))

    def test_review_build_can_never_publish(self):
        with patch.dict(
            os.environ,
            GITHUB_REF="refs/heads/main",
            GITHUB_REPOSITORY=update.REPOSITORY,
        ):
            for candidate, evidence in (
                ({"status": "review_required"}, {"review_only": False}),
                ({"status": "automatic"}, {"review_only": True}),
                ({"status": "automatic"}, {}),
            ):
                with (
                    self.subTest(candidate=candidate, evidence=evidence),
                    self.assertRaises(policy.Refused),
                ):
                    update.publish(
                        candidate, evidence, Path("missing"), Path("missing")
                    )

    def test_merge_requires_exact_head_and_all_eleven_ci_jobs(self):
        for conclusion, sha, count, last_job in (
            ("failure", "a" * 40, 11, "success"),
            ("success", "b" * 40, 11, "success"),
            ("success", "a" * 40, 10, "success"),
            ("success", "a" * 40, 11, "skipped"),
            ("success", "a" * 40, 11, "success"),
        ):
            calls = []

            def fake(
                *args,
                calls=calls,
                sha=sha,
                conclusion=conclusion,
                count=count,
                last_job=last_job,
            ):
                calls.append(args)
                if args[:2] == ("run", "list"):
                    return json.dumps(
                        [
                            {
                                "databaseId": 123,
                                "headSha": sha,
                                "status": "completed",
                                "conclusion": conclusion,
                            }
                        ]
                    ).encode()
                if args[:2] == ("run", "view"):
                    return json.dumps(
                        {
                            "jobs": [{"conclusion": "success"}] * (count - 1)
                            + [{"conclusion": last_job}]
                        }
                    ).encode()
                return b""

            valid = (
                conclusion == "success"
                and sha == "a" * 40
                and count == 11
                and last_job == "success"
            )
            with (
                self.subTest(
                    conclusion=conclusion, sha=sha, count=count, last_job=last_job
                ),
                patch.object(update, "gh", fake),
            ):
                if valid:
                    update.merge_after_ci("https://github.com/example/pull/1", "a" * 40)
                else:
                    with self.assertRaises(policy.Refused):
                        update.merge_after_ci(
                            "https://github.com/example/pull/1", "a" * 40
                        )
            merges = [args for args in calls if args[:2] == ("pr", "merge")]
            self.assertEqual(len(merges), int(valid))
            if valid:
                self.assertIn("--match-head-commit", merges[0])
                self.assertNotIn("--admin", merges[0])

    def test_sandbox_script_checks_actual_directory_and_strips_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries, vendor = root / "bin", root / "vendor"
            binaries.mkdir()
            (vendor / "scripts/ci").mkdir(parents=True)
            source = "a" * 40
            marker = root / "probe"
            marker.write_text("/build\n")
            scripts = {
                "git": f'#!/bin/sh\ncase "$*" in *rev-parse*) echo {source};; esac\n',
                "uname": '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo aarch64;; esac\n',
                "nix": (
                    '#!/bin/sh\ncase "$*" in\n'
                    '"--version") echo "nix (Determinate Nix 3.23.3) 2.35.3";;\n'
                    '"config show sandbox"|"config show sandbox-fallback") '
                    'test "$3" = sandbox && echo true || echo false;;\n'
                    '"config show substituters") echo https://cache.nixos.org;;\n'
                    f'build*) printf "%s\\n" "$*" > "{root / "expression"}"; echo "{marker}";;\n'
                    "*) exit 1;; esac\n"
                ),
            }
            for name, text in scripts.items():
                path = binaries / name
                path.write_text(text)
                path.chmod(0o755)
            (vendor / "scripts/ci/build_opensecret_eif.sh").write_text(
                '#!/bin/bash\nset -eu\ntest -z "${GH_TOKEN:-}"\n'
                'test -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"\n'
                'test -z "${GOOGLE_APPLICATION_CREDENTIALS:-}"\n'
                'test -z "${GITHUB_OUTPUT:-}"\ntest "$1" = prod\n'
            )
            env = {
                **os.environ,
                "PATH": str(binaries) + ":/usr/bin:/bin",
                "GH_TOKEN": "must-not-leak",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "must-not-leak",
                "GOOGLE_APPLICATION_CREDENTIALS": "must-not-leak",
                "GITHUB_OUTPUT": "must-not-leak",
            }
            script = Path(__file__).with_name("reproduce-maple.sh")
            subprocess.run(
                ["bash", str(script), str(vendor), source, str(root / "output")],
                env=env,
                check=True,
                capture_output=True,
            )
            self.assertIn("pwd > $out", (root / "expression").read_text())
            marker.write_text("/outside-sandbox\n")
            result = subprocess.run(
                ["bash", str(script), str(vendor), source, str(root / "output")],
                env=env,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
