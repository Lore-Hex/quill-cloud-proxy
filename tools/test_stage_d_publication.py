#!/usr/bin/env python3
"""Exercise the actual publication steps offline, without signing or publishing."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY = "gcp/stage-d-accepted.json"
STAGE_D_FILES = (
    POLICY,
    f"trust/{POLICY}",
    f"{POLICY}.bundle",
    f"trust/{POLICY}.bundle",
)


def workflow_step(workflow: str, name: str) -> str:
    # Keep this entry point stdlib-only, like the other Stage D gate tests.
    text = (ROOT / ".github/workflows" / workflow).read_text()
    step = text.split(f"      - name: {name}\n", 1)[1]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    script = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        script.append(line[10:])
    return "\n".join(script) + "\n"


class StageDPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "trust-page", self.root / "trust-page")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "GITHUB_RUN_ID": "offline",
            "GITHUB_REPOSITORY": "Lore-Hex/quill-cloud-proxy",
            "GITHUB_REF": "refs/heads/main",
        }

    def stub(self, name: str, script: str) -> None:
        path = self.bin / name
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + textwrap.dedent(script)
        )
        path.chmod(0o755)

    def run_step(self, workflow: str, name: str) -> subprocess.CompletedProcess[str]:
        script = workflow_step(workflow, name)
        # Isolate the existing live check's fixed temporary response filename.
        script = script.replace("/tmp/body", str(self.root / "body"))
        return subprocess.run(
            ["bash", "-c", script],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def assert_passed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sign_once_copies_exact_document_and_bundle_and_stages_mirror(self) -> None:
        self.stub(
            "cosign",
            r"""
            printf '%s\n' "$*" >> cosign.log
            command="$1"
            shift
            bundle=""
            while [ "$#" -gt 1 ]; do
              if [ "$1" = --bundle ]; then bundle="$2"; shift 2; else shift; fi
            done
            if [ "$command" = sign-blob ]; then
              printf 'detached bundle for %s\r\n' "$1" > "$bundle"
            fi
        """,
        )
        canonical = self.root / "trust-page" / POLICY
        original = canonical.read_bytes()
        # Both first publication and replacement of a stale mirror must work.
        for stale in (False, True):
            with self.subTest(stale=stale):
                for name in (POLICY, f"{POLICY}.bundle"):
                    mirror = self.root / "trust-page/trust" / name
                    if stale:
                        mirror.write_bytes(b"stale\r\n")
                    else:
                        mirror.unlink(missing_ok=True)
                (self.root / "cosign.log").write_text("")
                self.assert_passed(
                    self.run_step(
                        "publish-trust-gcp.yml",
                        "Sign the GCP Confidential Space record",
                    )
                )
                self.assertEqual(canonical.read_bytes(), original)
                for name in (POLICY, f"{POLICY}.bundle"):
                    self.assertEqual(
                        (self.root / "trust-page" / name).read_bytes(),
                        (self.root / "trust-page/trust" / name).read_bytes(),
                    )
                policy_signs = [
                    line
                    for line in (self.root / "cosign.log").read_text().splitlines()
                    if "stage-d-accepted" in line
                ]
                self.assertEqual(len(policy_signs), 1)
                self.assertIn("sign-blob --new-bundle-format", policy_signs[0])
                self.assert_passed(
                    self.run_step(
                        "publish-trust-gcp.yml",
                        "Verify each signature under THIS workflow's identity",
                    )
                )

        # Run only the staging portion in an empty scratch repo: no commits/pushes.
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        staging = workflow_step("publish-trust-gcp.yml", "Commit bundles").split(
            "if git diff --cached --quiet; then",
            1,
        )[0]
        subprocess.run(["bash", "-c", staging], cwd=self.root, check=True)
        staged = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only"],
            cwd=self.root,
            text=True,
        ).splitlines()
        for name in (f"trust/{POLICY}", f"{POLICY}.bundle", f"trust/{POLICY}.bundle"):
            self.assertIn(f"trust-page/{name}", staged)

    def test_static_validation_requires_both_files_and_exact_bytes(self) -> None:
        workflow = "publish-trust-page.yml"
        step = "Validate AWS and Azure trust records"
        self.assert_passed(self.run_step(workflow, step))
        for name in STAGE_D_FILES:
            path = self.root / "trust-page" / name
            original = path.read_bytes()
            for mutation in ("missing", "different_bytes"):
                with self.subTest(name=name, mutation=mutation):
                    if mutation == "missing":
                        path.unlink()
                    else:
                        # A text comparison normalizes CRLF, but detached signatures
                        # bind those bytes too. The one-line bundle has no newline.
                        path.write_bytes(
                            original.replace(b"\n", b"\r\n")
                            if b"\n" in original
                            else original + b"\n"
                        )
                    result = self.run_step(workflow, step)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(
                        "must both exist" if mutation == "missing" else "disagree",
                        result.stderr,
                    )
                    path.write_bytes(original)

    def prepare_live_stubs(self) -> None:
        shutil.copytree(self.root / "trust-page", self.root / "served")
        self.stub("sleep", "exit 0\n")
        self.stub(
            "curl",
            r"""
            output=""
            url=""
            while [ "$#" -gt 0 ]; do
              case "$1" in
                -o) output="$2"; shift 2 ;;
                -w) shift 2 ;;
                https://*) url="$1"; shift ;;
                *) shift ;;
              esac
            done
            file="${url#https://trust.trustedrouter.com/}"
            file="${file%%\?*}"
            printf '%s\n' "$file" >> curl.log
            if [ "${BAD_HTTP_PATH:-}" = "$file" ]; then
              printf '%s' "$BAD_HTTP_CODE"
            elif [ -f "served/$file" ]; then
              cp "served/$file" "$output"
              printf 200
            else
              printf 404
            fi
        """,
        )

    def test_live_validation_fetches_all_four_urls(self) -> None:
        self.prepare_live_stubs()
        self.assert_passed(
            self.run_step(
                "publish-trust-page.yml",
                "Verify every plane's record and bundle actually published",
            )
        )
        fetched = (self.root / "curl.log").read_text().splitlines()
        for name in STAGE_D_FILES:
            self.assertIn(name, fetched)

    def test_live_validation_rejects_non_200_and_different_bytes_at_either_path(
        self,
    ) -> None:
        self.prepare_live_stubs()
        for name in STAGE_D_FILES:
            path = self.root / "served" / name
            original = path.read_bytes()
            for failure in ("404", "302", "503", "different_bytes"):
                with self.subTest(name=name, failure=failure):
                    if failure == "different_bytes":
                        path.write_bytes(original + b"\n")
                    else:
                        self.env.update(BAD_HTTP_PATH=name, BAD_HTTP_CODE=failure)
                    result = self.run_step(
                        "publish-trust-page.yml",
                        "Verify every plane's record and bundle actually published",
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(
                        f"https://trust.trustedrouter.com/{name}", result.stdout
                    )
                    self.assertIn(
                        "differs from the repo copy"
                        if failure == "different_bytes"
                        else f"HTTP {failure}",
                        result.stdout,
                    )
                    self.env.pop("BAD_HTTP_PATH", None)
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
