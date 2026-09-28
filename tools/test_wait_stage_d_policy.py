from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest

from test_check_trust_signatures import CERTIFICATE, CERTIFICATE_DER


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "wait-stage-d-policy.sh"
FIXTURE = ROOT / "tools" / "testdata" / "stage-d-accepted.json"
MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
# What the GCP signer writes for the Stage D policy: a protobuf bundle holding
# its signing certificate (a throwaway one here, which openssl parses).
SIGNED = {"mediaType": MEDIA_TYPE, "verificationMaterial": {"certificate": {"rawBytes": CERTIFICATE_DER}}}


class WaitStageDPolicyTests(unittest.TestCase):
    def run_wait(
        self, *, served: bytes, bundle: dict | None = SIGNED, cosign_ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            served_file = temp / "served.json"
            served_file.write_bytes(served)
            served_bundle = temp / "served.json.bundle"
            if bundle is not None:
                served_bundle.write_text(json.dumps(bundle), encoding="utf-8")
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
                      # No bundle served: succeed without writing the file, as
                      # curl -f does for a 304.
                      [ ! -f "$SERVED_BUNDLE" ] || cp "$SERVED_BUNDLE" "$output"
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
                "printf '%s\\n' \"$*\" >> \"$COSIGN_LOG\"\n"
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
                "SERVED_BUNDLE": str(served_bundle),
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
        self.assertIn("verify-blob --new-bundle-format", log)
        self.assertIn("--certificate-identity https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-trust-gcp.yml@refs/heads/main", log)
        self.assertIn("--certificate-oidc-issuer https://token.actions.githubusercontent.com", log)

    def test_rejects_different_bytes_even_with_valid_signature(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes() + b"\n")
        self.assertEqual(result.returncode, 1)

    def test_rejects_wrong_identity_bundle(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes(), cosign_ok=False)
        self.assertEqual(result.returncode, 1)

    def test_refuses_a_bundle_without_a_certificate_without_asking_cosign(self) -> None:
        # The same bundle with a public key where the certificate was; the
        # fake cosign would accept it.
        keyed = {"mediaType": MEDIA_TYPE, "verificationMaterial": {"publicKey": {"hint": "a key"}}}
        result = self.run_wait(served=FIXTURE.read_bytes(), bundle=keyed)
        self.assertEqual(result.returncode, 1)
        self.assertIn("stage-d-accepted.json.bundle carries no signing certificate", result.stderr)
        self.assertEqual(result.cosign_log, "")  # type: ignore[attr-defined]

    def test_refuses_a_policy_served_without_its_bundle(self) -> None:
        result = self.run_wait(served=FIXTURE.read_bytes(), bundle=None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("stage-d-accepted.json has no bundle beside it", result.stderr)
        self.assertEqual(result.cosign_log, "")  # type: ignore[attr-defined]

    def test_refuses_a_legacy_bundle_without_asking_cosign(self) -> None:
        # cosign up to 2.6.4 skips the identity check for some legacy bundles
        # (GHSA-fx35-mq7g-6g98); the Stage D policy's signer writes protobuf.
        legacy = {"base64Signature": "c2ln", "cert": CERTIFICATE, "rekorBundle": {}}
        result = self.run_wait(served=FIXTURE.read_bytes(), bundle=legacy)
        self.assertEqual(result.returncode, 1)
        self.assertIn("stage-d-accepted.json.bundle is not a protobuf bundle", result.stderr)
        self.assertEqual(result.cosign_log, "")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
