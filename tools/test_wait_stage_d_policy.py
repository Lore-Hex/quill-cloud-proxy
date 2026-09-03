from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "wait-stage-d-policy.sh"
FIXTURE = ROOT / "tools" / "testdata" / "stage-d-accepted.json"


class WaitStageDPolicyTests(unittest.TestCase):
    def run_wait(self, *, served: bytes, cosign_ok: bool = True) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            served_file = temp / "served.json"
            served_file.write_bytes(served)
            curl = bin_dir / "curl"
            curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    output=""
                    while [ "$#" -gt 0 ]; do
                      if [ "$1" = "-o" ]; then output="$2"; shift 2; else shift; fi
                    done
                    if [[ "$output" == *.bundle ]]; then
                      printf '%s' '{"bundle":"recorded"}' > "$output"
                    else
                      cp "$SERVED_POLICY" "$output"
                    fi
                    """
                ),
                encoding="utf-8",
            )
            cosign = bin_dir / "cosign"
            cosign.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" > \"$COSIGN_LOG\"\n"
                f"exit {0 if cosign_ok else 1}\n",
                encoding="utf-8",
            )
            for path in (curl, cosign):
                path.chmod(path.stat().st_mode | stat.S_IXUSR)
            log = temp / "cosign.log"
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "SERVED_POLICY": str(served_file),
                "COSIGN_LOG": str(log),
                "TR_STAGE_D_POLICY_VERIFY_ATTEMPTS": "1",
                "TR_STAGE_D_POLICY_VERIFY_SLEEP_SECONDS": "0",
                "TR_TRUST_PAGE_BASE_URL": "https://trust.invalid",
            }
            result = subprocess.run(
                ["bash", str(SCRIPT), str(FIXTURE)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            result.cosign_log = log.read_text(encoding="utf-8") if log.exists() else ""  # type: ignore[attr-defined]
            return result

    def test_accepts_exact_bytes_and_exact_identity_signature(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes())
        self.assertEqual(result.returncode, 0, result.stderr)
        log = result.cosign_log  # type: ignore[attr-defined]
        self.assertIn("--certificate-identity https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-trust-gcp.yml@refs/heads/main", log)
        self.assertIn("--certificate-oidc-issuer https://token.actions.githubusercontent.com", log)

    def test_rejects_different_bytes_even_with_valid_signature(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes() + b"\n")
        self.assertEqual(result.returncode, 1)

    def test_rejects_wrong_identity_bundle(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes(), cosign_ok=False)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
