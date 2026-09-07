#!/usr/bin/env python3
"""Exercise the actual publication steps offline, without signing or publishing."""

from __future__ import annotations

import json
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
    # Steps with an id put their name on the following line.
    step = text.split(f"name: {name}\n", 1)[1]
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
        return self.run_script(workflow_step(workflow, name))

    def run_script(self, script: str) -> subprocess.CompletedProcess[str]:
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

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.root, text=True, stderr=subprocess.STDOUT
        ).strip()

    def prepare_release(self, kind: str, missing_mirror: bool) -> None:
        (self.root / "tools").mkdir(exist_ok=True)
        for name in ("write-stage-d-policy.py", "write-trust-artifacts.py"):
            shutil.copy2(ROOT / "tools" / name, self.root / "tools" / name)
        canonical = self.root / "trust-page" / POLICY
        # The fixed transition is the finalizer's immediate predecessor.
        shutil.copy2(ROOT / "tools/testdata/stage-d-accepted.json", canonical)
        mirror = self.root / "trust-page/trust" / POLICY
        if missing_mirror:
            shutil.rmtree(mirror.parent, ignore_errors=True)
        else:
            mirror.parent.mkdir(parents=True, exist_ok=True)
            mirror.write_bytes(canonical.read_bytes())
        self.git("init", "-q")
        self.git("config", "user.name", "Offline publication test")
        self.git("config", "user.email", "offline@example.invalid")
        self.git("add", "trust-page")
        self.git("commit", "-qm", "baseline", "--allow-empty")
        self.env.update(
            GITHUB_RUN_NUMBER="601" if kind == "transitional" else "600",
            GITHUB_OUTPUT=str(self.root / "output"),
            SHA="0123456",
            DIGEST="sha256:" + "a" * 64,
            IMAGE_DIGEST="sha256:" + "a" * 64,
            IMAGE_REF="example.invalid/enclave:gcp-release-0123456",
            TR_TRUST_PUSH_DEPLOY_KEY="",
        )
        # Run real local Git, but never contact a remote from these workflow steps.
        self.env["REAL_GIT"] = shutil.which("git")
        self.stub("git", 'case "$1" in pull|push) exit 0 ;; esac\nexec "$REAL_GIT" "$@"\n')
        self.stub("cosign", 'echo "deploy must not sign" >&2; exit 99\n')

    def release_script(self, kind: str) -> str:
        workflow = "deploy-enclave-gcp.yml"
        if kind == "final":
            return workflow_step(
                workflow, "Publish only the fully rolled-out digest in source artifacts"
            )
        script = workflow_step(workflow, "Build verified transitional Stage D accepted set")
        # Exercise the actual document-writing tail with recorded discovery
        # inputs; the preceding curl/cosign/gcloud discovery is outside this test.
        start = script.index("python3 tools/write-stage-d-policy.py \\\n")
        (self.root / "running-digests.txt").write_text("sha256:" + "b" * 64 + "\n")
        return (
            "set -euo pipefail\n"
            "previous_args=(--accepted-policy trust-page/gcp/stage-d-accepted.json)\n"
            "running_digests=running-digests.txt\n"
            + script[start:]
            + workflow_step(workflow, "Write transitional trust-page artifacts")
            + workflow_step(workflow, "Commit trust artifacts back to main")
        )

    def check_release_commit(self, kind: str) -> None:
        for missing_mirror in (False, True):
            with self.subTest(kind=kind, missing_mirror=missing_mirror):
                self.prepare_release(kind, missing_mirror)
                bundles = {
                    p.relative_to(self.root): p.read_bytes()
                    for p in (self.root / "trust-page").rglob("*.bundle")
                }
                self.assert_passed(self.run_script(self.release_script(kind)))
                canonical = (self.root / "trust-page" / POLICY).read_bytes()
                self.assertEqual(json.loads(canonical)["kind"], kind)
                self.assertEqual(
                    (self.root / "trust-page/trust" / POLICY).read_bytes(), canonical
                )
                changed = self.git("diff", "--name-only", "HEAD^", "HEAD").splitlines()
                for name in (POLICY, f"trust/{POLICY}"):
                    self.assertIn(f"trust-page/{name}", changed)
                    committed = subprocess.check_output(
                        ["git", "show", f"HEAD:trust-page/{name}"], cwd=self.root
                    )
                    self.assertEqual(committed, canonical)
                self.assertEqual(
                    {p.relative_to(self.root): p.read_bytes()
                     for p in (self.root / "trust-page").rglob("*.bundle")},
                    bundles,
                )
                self.assert_passed(self.run_step(
                    "publish-trust-page.yml", "Validate AWS and Azure trust records"
                ))

    def test_transitional_release_commits_document_and_mirror_together(self) -> None:
        self.check_release_commit("transitional")

    def test_final_release_commits_document_and_mirror_together(self) -> None:
        self.check_release_commit("final")

    def test_release_refuses_a_copy_that_differs(self) -> None:
        for kind in ("transitional", "final"):
            with self.subTest(kind=kind):
                self.prepare_release(kind, missing_mirror=False)
                before = self.git("rev-parse", "HEAD")
                self.env["REAL_CP"] = shutil.which("cp")
                self.stub("cp", '"$REAL_CP" "$@"\nprintf "corrupt\\n" >> "$2"\n')
                result = self.run_script(self.release_script(kind))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.git("rev-parse", "HEAD"), before)

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

    def test_static_validation_requires_documents_and_exact_bytes(self) -> None:
        workflow = "publish-trust-page.yml"
        step = "Validate AWS and Azure trust records"
        self.assert_passed(self.run_step(workflow, step))
        for name in STAGE_D_FILES:
            path = self.root / "trust-page" / name
            original = path.read_bytes()
            for mutation in ("missing", "different_bytes"):
                if mutation == "missing" and name.endswith(".bundle"):
                    continue
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

    def test_bundle_lag_allows_missing_or_identically_stale_bundles(self) -> None:
        # New documents with the previous signature pair are the ordinary
        # release commit. Mirror absence also occurs on first publication.
        canonical = self.root / "trust-page" / POLICY
        canonical.write_bytes(canonical.read_bytes() + b"\n")
        (self.root / "trust-page/trust" / POLICY).write_bytes(canonical.read_bytes())
        bundles = [self.root / "trust-page" / name for name in STAGE_D_FILES[2:]]
        originals = [path.read_bytes() for path in bundles]
        self.prepare_live_stubs()
        for missing in ((), (0,), (1,), (0, 1)):
            with self.subTest(missing=missing):
                for i, (path, original) in enumerate(zip(bundles, originals)):
                    served = self.root / "served" / path.relative_to(self.root / "trust-page")
                    for target in (path, served):
                        if i in missing:
                            target.unlink(missing_ok=True)
                        else:
                            target.write_bytes(original)
                self.assert_passed(self.run_step(
                    "publish-trust-page.yml", "Validate AWS and Azure trust records"
                ))
                (self.root / "curl.log").write_text("")
                live = self.run_step(
                    "publish-trust-page.yml",
                    "Verify every plane's record and bundle actually published",
                )
                if missing:
                    # Relaxing the static assertion does not waive live coverage.
                    self.assertNotEqual(live.returncode, 0, live.stdout + live.stderr)
                    self.assertIn("not published (HTTP 404)", live.stdout)
                else:
                    self.assert_passed(live)
                fetched = (self.root / "curl.log").read_text().splitlines()
                for name in STAGE_D_FILES:
                    self.assertIn(name, fetched)

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
