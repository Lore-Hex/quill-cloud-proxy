from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "wait-trust-page-set.sh"


class WaitTrustPageSetTests(unittest.TestCase):
    def _run(
        self,
        *,
        digest: str,
        reference: str,
        live_digest: str,
        live_reference: str,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            curl = tmp / "curl"
            curl.write_text(
                "#!/usr/bin/env bash\n"
                "url=\"${@: -1}\"\n"
                "case \"$url\" in\n"
                f"  *accepted-image-digests*) printf '%s' {live_digest!r} ;;\n"
                f"  *accepted-image-references*) printf '%s' {live_reference!r} ;;\n"
                "  *) exit 22 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
            env = {
                **os.environ,
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "TR_TRUST_VERIFY_ATTEMPTS": "1",
                "TR_TRUST_VERIFY_SLEEP_SECONDS": "0",
                "TR_TRUST_PAGE_BASE_URL": "https://trust.invalid/trust",
            }
            return subprocess.run(
                [str(SCRIPT), digest, reference],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_accepts_only_an_exact_digest_and_reference_set(self) -> None:
        result = self._run(
            digest="sha256:old,sha256:new",
            reference="image:old,image:new",
            live_digest="sha256:old,sha256:new",
            live_reference="image:old,image:new",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exact expected image set", result.stdout)

    def test_rejects_a_partial_or_superseded_public_set(self) -> None:
        result = self._run(
            digest="sha256:old,sha256:new",
            reference="image:old,image:new",
            live_digest="sha256:new",
            live_reference="image:new",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("did not converge", result.stderr)


if __name__ == "__main__":
    unittest.main()
