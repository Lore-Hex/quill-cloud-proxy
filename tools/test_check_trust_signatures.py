#!/usr/bin/env python3
"""tools/check-trust-signatures.py with a fake cosign, and against the repository.

The fake cosign accepts a bundle only if it records the document's current
sha256 and the expected plane identity, and only if --new-bundle-format is
passed exactly for new-format bundles. It records every call, so the tests
also check which identity each document was verified under. No real cosign,
network or cloud CLI is used.

Run: python3 tools/test_check_trust_signatures.py
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

SCRIPT = Path(__file__).with_name("check-trust-signatures.py")
SPEC = importlib.util.spec_from_file_location("check_trust_signatures", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

REPO = SCRIPT.parent.parent
PUBLISHER = SCRIPT.with_name("publish-trust-s3.sh")
# Written out here rather than read from the checker, so a change to the
# pinned identity or issuer fails the positive control.
IDENTITY = (
    "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/"
    "publish-trust-{plane}.yml@refs/heads/main"
)
# A throwaway self-signed certificate and public key: test material that signs
# nothing, so the checker's `openssl x509` parse has real input.
CERTIFICATE_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBozCCAUmgAwIBAgIUeaC2wIdrZLC1as9lQoRi1gixThYwCgYIKoZIzj0EAwIw
JjEkMCIGA1UEAwwbY2hlY2stdHJ1c3Qtc2lnbmF0dXJlcyB0ZXN0MCAXDTI2MDky
NzExMjUxMVoYDzIxMjYwOTAzMTEyNTExWjAmMSQwIgYDVQQDDBtjaGVjay10cnVz
dC1zaWduYXR1cmVzIHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4qWXg
VybmAlFzzPg2fEt+/R8L+Z4KOr7I7SmAGrB08K8GDzM9K5oLLWtGzRFfTx1ZwyIe
PUguoLA5UN8fyZ32o1MwUTAdBgNVHQ4EFgQUQHbn1kAAIO+HK0P/61YnET6qLQww
HwYDVR0jBBgwFoAUQHbn1kAAIO+HK0P/61YnET6qLQwwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiA/wn+FfBskIgkGF+aP/0ltO0NK+93ZOczXOcmv
yKYEBgIhANdT2V/lJuuVRe3qR1WPqbqZCX9r0vSLI2nqQm9++i6j
-----END CERTIFICATE-----
"""
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+Kll4Fcm5gJRc8z4NnxLfv0fC/me
Cjq+yO0pgBqwdPCvBg8zPSuaCy1rRs0RX08dWcMiHj1ILqCwOVDfH8md9g==
-----END PUBLIC KEY-----
"""
CERTIFICATE = base64.b64encode(CERTIFICATE_PEM).decode()
CERTIFICATE_DER = "".join(CERTIFICATE_PEM.decode().splitlines()[1:-1])
PUBLIC_KEY = base64.b64encode(PUBLIC_KEY_PEM).decode()
# The cert field forms that must not pass for a certificate.
NOT_CERTIFICATES = {
    "a public key": PUBLIC_KEY,
    "an unterminated certificate header before a public key": base64.b64encode(
        b"-----BEGIN CERTIFICATE-----\n" + PUBLIC_KEY_PEM
    ).decode(),
    "a certificate followed by a public key": base64.b64encode(
        CERTIFICATE_PEM + PUBLIC_KEY_PEM
    ).decode(),
    "a certificate header around a public key": base64.b64encode(
        PUBLIC_KEY_PEM.replace(b"PUBLIC KEY", b"CERTIFICATE")
    ).decode(),
}
RETRACTION = "trust/retractions/2026-08-15-aws-pcr0.json"
STAGE_D = ("gcp/stage-d-accepted.json", "trust/gcp/stage-d-accepted.json")

FAKE_COSIGN = r"""#!/usr/bin/env python3
import hashlib, json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_COSIGN_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
def value(flag):
    return args[args.index(flag) + 1]
bundle = json.load(open(value("--bundle")))
digest = hashlib.sha256(open(args[-1], "rb").read()).hexdigest()
ok = (
    args[0] == "verify-blob"
    and bundle["fake_sha256"] == digest
    and bundle["fake_identity"] == value("--certificate-identity")
    and value("--certificate-oidc-issuer") == "https://token.actions.githubusercontent.com"
    and ("--new-bundle-format" in args) == ("mediaType" in bundle)
)
if not ok:
    print("Error: the bundle does not verify this document", file=sys.stderr)
sys.exit(0 if ok else 1)
"""
FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_AWS_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
"""


def sign(document: Path, plane: str, key: str = CERTIFICATE) -> None:
    """Write the fake cosign's bundle for the document's current bytes."""
    bundle: dict[str, object] = {
        "fake_sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
        "fake_identity": IDENTITY.format(plane=plane),
    }
    if document.name == "stage-d-accepted.json":
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.3+json"
        if key == CERTIFICATE:
            bundle["verificationMaterial"] = {"certificate": {"rawBytes": CERTIFICATE_DER}}
        else:
            bundle["verificationMaterial"] = {"publicKey": {"hint": "a key"}}
    else:
        bundle["cert"] = key
    document.with_name(document.name + ".bundle").write_text(json.dumps(bundle))


def signed_site(root: Path) -> Path:
    """Every document each signer signs, signed, with root copies identical to
    trust/ copies as the publishers require; plus pages published unsigned."""
    site = root / "trust-page"
    for plane, patterns in check.SIGNED_BY.items():
        for pattern in patterns:
            name = RETRACTION if "*" in pattern else pattern
            document = site / name
            document.parent.mkdir(parents=True, exist_ok=True)
            document.write_text(f"{document.name}\n")
            sign(document, plane)
    # Published without a bundle, as on the real site: nothing to verify.
    (site / "index.html").write_text("<html></html>\n")
    for name in (
        "gcp-release.json",
        "image-digest-gcp.txt",
        "image-reference-gcp.txt",
        "accepted-image-digests-gcp.txt",
        "accepted-image-references-gcp.txt",
    ):
        (site / name).write_text(f"{name}\n")
    return site


def link_retractions_from_outside(site: Path) -> None:
    """Move trust/retractions/ out of the tree and link it back in, then
    change a retraction without re-signing it."""
    inside = site / "trust" / "retractions"
    outside = site.parent / "retractions-elsewhere"
    inside.rename(outside)
    inside.symlink_to(Path("..", "..", outside.name), target_is_directory=True)
    (outside / Path(RETRACTION).name).write_text("a corrected retraction\n")


def fake_bin(root: Path) -> Path:
    bin_dir = root / "bin"
    bin_dir.mkdir()
    for name, body in (("cosign", FAKE_COSIGN), ("aws", FAKE_AWS)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    for real in ("python3", "dirname", "openssl", "bash"):
        found = shutil.which(real)
        assert found, real
        (bin_dir / real).symlink_to(found)
    return bin_dir


class CheckTrustSignatures(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.site = signed_site(self.root)
        self.bin = fake_bin(self.root)
        self.cosign_log = self.root / "cosign.jsonl"
        self.aws_log = self.root / "aws.jsonl"
        self.cosign_log.touch()
        self.aws_log.touch()
        self.env = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "FAKE_COSIGN_LOG": str(self.cosign_log),
            "FAKE_AWS_LOG": str(self.aws_log),
        }

    def check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), str(self.site)],
            env=self.env,
            capture_output=True,
            text=True,
        )

    def verifications(self) -> dict[str, tuple[str, bool]]:
        calls = [json.loads(line) for line in self.cosign_log.read_text().splitlines()]
        return {
            Path(call[-1]).relative_to(self.site).as_posix(): (
                call[call.index("--certificate-identity") + 1],
                "--new-bundle-format" in call,
            )
            for call in calls
        }

    def test_bundles_that_sign_their_documents_pass(self) -> None:
        result = self.check()

        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {
            (RETRACTION if "*" in pattern else pattern): (
                IDENTITY.format(plane=plane),
                (RETRACTION if "*" in pattern else pattern) in STAGE_D,
            )
            for plane, patterns in check.SIGNED_BY.items()
            for pattern in patterns
        }
        self.assertEqual(self.verifications(), expected)

    def test_a_bundle_for_the_previous_bytes_is_refused(self) -> None:
        (self.site / "trust/aws-release.json").write_text("a newer record\n")

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"{self.site / 'trust/aws-release.json'} is not signed by", result.stderr)
        self.assertEqual(result.stderr.count(" is not signed by "), 1)

    def test_a_bundle_from_another_planes_signer_is_refused(self) -> None:
        sign(self.site / "trust/azure-release.json", "aws")

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("azure-release.json is not signed by", result.stderr)
        self.assertIn("publish-trust-azure.yml", result.stderr)

    def test_a_bundle_beside_a_document_no_signer_signs_is_refused(self) -> None:
        extra = self.site / "trust/extra.txt"
        extra.write_text("extra\n")
        sign(extra, "gcp")

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("no signer signs trust/extra.txt", result.stderr)

    def test_a_bundle_without_its_document_is_refused(self) -> None:
        (self.site / "pcr0.txt").unlink()

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("pcr0.txt is missing", result.stderr)

    def test_a_signed_document_without_its_bundle_is_refused(self) -> None:
        # Nothing would be verified for it, so it must not pass either.
        for document in ("trust/pcr0-aws.txt", "gcp/stage-d-accepted.json", RETRACTION):
            with self.subTest(document=document):
                path = self.site / document
                path.with_name(path.name + ".bundle").unlink()

                result = self.check()

                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{document} has no bundle beside it", result.stderr)
                sign(path, check.plane_of(document))
                self.assertEqual(self.check().returncode, 0)

    def test_a_bundle_that_is_not_a_bundle_is_refused(self) -> None:
        (self.site / "hostdata-azure.txt.bundle").write_text("not json\n")

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("hostdata-azure.txt.bundle is not a cosign bundle", result.stderr)

    def test_a_bundle_without_a_certificate_is_refused_without_asking_cosign(self) -> None:
        # cosign up to 2.6.4 accepted a legacy bundle holding a public key without
        # checking the identity (GHSA-fx35-mq7g-6g98); the fake cosign would
        # accept each of these too.
        cases = [("gcp/stage-d-accepted.json", "a public key", PUBLIC_KEY)] + [
            ("trust/pcr0-aws.txt", form, key) for form, key in NOT_CERTIFICATES.items()
        ]
        for document, form, key in cases:
            with self.subTest(document=document, form=form):
                plane = check.plane_of(document)
                sign(self.site / document, plane, key=key)
                self.cosign_log.write_text("")

                result = self.check()

                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{document}.bundle carries no signing certificate", result.stderr)
                self.assertNotIn(document, set(self.verifications()))
                sign(self.site / document, plane)

    def test_a_bundle_in_the_other_format_is_refused_without_asking_cosign(self) -> None:
        # The path decides the format: the Stage D policy's signer writes a
        # protobuf bundle and every other signer a legacy one. The fake cosign
        # would accept each of these, verifying the format the bundle claims.
        protobuf = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"certificate": {"rawBytes": CERTIFICATE_DER}},
        }
        for document, form, fields in (
            ("gcp/stage-d-accepted.json", "protobuf", {"cert": CERTIFICATE}),
            ("trust/gcp/stage-d-accepted.json", "protobuf", {"cert": CERTIFICATE}),
            ("trust/pcr0-aws.txt", "legacy", protobuf),
        ):
            with self.subTest(document=document):
                plane = check.plane_of(document)
                path = self.site / document
                path.with_name(path.name + ".bundle").write_text(
                    json.dumps(
                        {
                            "fake_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "fake_identity": IDENTITY.format(plane=plane),
                            **fields,
                        }
                    )
                )
                self.cosign_log.write_text("")

                result = self.check()

                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{document}.bundle is not a {form} bundle", result.stderr)
                self.assertNotIn(document, set(self.verifications()))
                sign(path, plane)
                self.assertEqual(self.check().returncode, 0)

    def test_text_around_the_one_certificate_block_is_ignored(self) -> None:
        # As a PEM parser ignores it; the block itself is what must be a certificate.
        sign(
            self.site / "trust/pcr0-aws.txt",
            "aws",
            key=base64.b64encode(b"a prefix\n" + CERTIFICATE_PEM + b"a suffix\n").decode(),
        )

        result = self.check()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_without_openssl_nothing_passes(self) -> None:
        (self.bin / "openssl").unlink()

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("openssl is not installed", result.stderr)

    def test_the_retraction_pattern_expands_as_the_signers_bash_glob_does(self) -> None:
        for name in ("trust/retractions/archive/copied.json", "trust/retractions/.hidden.json"):
            with self.subTest(name=name):
                document = self.site / name
                document.parent.mkdir(parents=True, exist_ok=True)
                document.write_text("retraction\n")
                sign(document, "aws")

                result = self.check()

                self.assertEqual(result.returncode, 1)
                self.assertIn(f"no signer signs {name}", result.stderr)
                document.unlink()
                document.with_name(document.name + ".bundle").unlink()

    def test_a_symbolic_link_in_the_tree_is_refused(self) -> None:
        # The publishers follow links; the check would not walk into one.
        link_retractions_from_outside(self.site)

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"{self.site / 'trust/retractions'} is a symbolic link", result.stderr)

        (self.site / "trust/retractions").unlink()
        (self.site / "trust/retractions").symlink_to(self.root / "retractions-elsewhere")
        (self.site / "copy.txt").symlink_to(self.site / "pcr0.txt")
        result = self.check()
        self.assertIn(f"{self.site / 'copy.txt'} is a symbolic link", result.stderr)

    def test_without_cosign_nothing_passes(self) -> None:
        (self.bin / "cosign").unlink()

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("cosign is not installed", result.stderr)

    def test_the_s3_publisher_syncs_only_a_tree_whose_bundles_sign_their_documents(self) -> None:
        publish = ["/bin/bash", str(PUBLISHER), str(self.site)]

        synced = subprocess.run(publish, env=self.env, capture_output=True, text=True)
        self.assertEqual(synced.returncode, 0, synced.stderr)
        self.assertEqual(len(self.aws_log.read_text().splitlines()), 1)

        self.aws_log.write_text("")
        (self.site / "trust/hostdata-azure.txt").write_text("a newer measurement\n")
        (self.site / "hostdata-azure.txt").write_text("a newer measurement\n")
        refused = subprocess.run(publish, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("hostdata-azure.txt is not signed by", refused.stderr)
        self.assertEqual(self.aws_log.read_text(), "")

    def test_the_s3_publisher_refuses_copies_that_differ_even_when_each_is_signed(self) -> None:
        root_copy = self.site / "pcr0-aws.txt"
        root_copy.write_text("a different measurement\n")
        sign(root_copy, "aws")

        refused = subprocess.run(
            ["/bin/bash", str(PUBLISHER), str(self.site)], env=self.env, capture_output=True, text=True
        )

        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("differ", refused.stderr)
        self.assertEqual(self.aws_log.read_text(), "")


def workflow_step(workflow: str, name: str) -> dict:
    document = yaml.safe_load((REPO / ".github/workflows" / workflow).read_text())
    (job,) = document["jobs"].values()
    (step,) = [step for step in job["steps"] if step.get("name") == name]
    return step


class TheWorkflowSteps(unittest.TestCase):
    """The publishers' steps as written, run the way Actions runs a step that
    names no shell (bash -e), in a copy of the repository layout."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.site = signed_site(self.root)
        (self.root / "tools").mkdir()
        for name in ("check-trust-copies.py", "check-trust-signatures.py", "publish-trust-s3.sh"):
            shutil.copy2(REPO / "tools" / name, self.root / "tools" / name)
        self.bin = fake_bin(self.root)
        self.aws_log = self.root / "aws.jsonl"
        self.aws_log.touch()
        (self.root / "cosign.jsonl").touch()
        self.env = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "FAKE_COSIGN_LOG": str(self.root / "cosign.jsonl"),
            "FAKE_AWS_LOG": str(self.aws_log),
        }

    def run_step(self, workflow: str, name: str) -> subprocess.CompletedProcess[str]:
        step = workflow_step(workflow, name)
        self.assertNotIn("shell", step)
        script = self.root / "step.sh"
        script.write_text(step["run"])
        return subprocess.run(
            ["bash", "-e", str(script)],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
        )

    def test_the_pages_check_passes_signed_documents_and_stops_on_a_stale_bundle(self) -> None:
        step = ("publish-trust-page.yml", "Verify each bundle signs its document")
        passed = self.run_step(*step)
        self.assertEqual(passed.returncode, 0, passed.stderr)

        (self.site / "trust/gcp-release.json").write_text("a newer record\n")
        stopped = self.run_step(*step)

        self.assertNotEqual(stopped.returncode, 0)
        self.assertIn("trust/gcp-release.json is not signed by", stopped.stderr)

    def test_the_s3_publish_syncs_signed_documents_and_stops_on_a_stale_bundle(self) -> None:
        step = ("publish-trust-s3.yml", "Publish independent S3 trust mirror")
        synced = self.run_step(*step)
        self.assertEqual(synced.returncode, 0, synced.stderr)
        self.assertEqual(len(self.aws_log.read_text().splitlines()), 1)

        self.aws_log.write_text("")
        for name in ("trust/hostdata-azure.txt", "hostdata-azure.txt"):
            (self.site / name).write_text("a newer measurement\n")
        stopped = self.run_step(*step)

        self.assertNotEqual(stopped.returncode, 0)
        self.assertIn("hostdata-azure.txt is not signed by", stopped.stderr)
        self.assertEqual(self.aws_log.read_text(), "")


    def test_both_publish_steps_stop_on_a_symbolic_link(self) -> None:
        link_retractions_from_outside(self.site)

        for step in (
            ("publish-trust-page.yml", "Verify each bundle signs its document"),
            ("publish-trust-s3.yml", "Publish independent S3 trust mirror"),
        ):
            with self.subTest(step=step[0]):
                stopped = self.run_step(*step)
                self.assertNotEqual(stopped.returncode, 0)
                self.assertIn("is a symbolic link", stopped.stderr)
        self.assertEqual(self.aws_log.read_text(), "")


class TheRepository(unittest.TestCase):
    def test_every_published_bundle_has_a_signer(self) -> None:
        bundles = sorted((REPO / "trust-page").rglob("*.bundle"))
        self.assertTrue(bundles)
        for bundle in bundles:
            document = bundle.relative_to(REPO / "trust-page").as_posix().removesuffix(".bundle")
            with self.subTest(document=document):
                self.assertIsNotNone(check.plane_of(document))

    def test_every_published_document_a_signer_signs_has_its_bundle(self) -> None:
        site = REPO / "trust-page"
        documents = [
            path
            for path in sorted(site.rglob("*"))
            if path.is_file()
            and not path.name.endswith(".bundle")
            and check.plane_of(path.relative_to(site).as_posix()) is not None
        ]
        self.assertTrue(documents)
        for path in documents:
            with self.subTest(document=path.relative_to(site).as_posix()):
                self.assertTrue(path.with_name(path.name + ".bundle").is_file())

    def test_every_published_bundle_is_in_the_format_its_signer_writes(self) -> None:
        for bundle in sorted((REPO / "trust-page").rglob("*.bundle")):
            document = bundle.relative_to(REPO / "trust-page").as_posix().removesuffix(".bundle")
            with self.subTest(document=document):
                content = json.loads(bundle.read_text())
                self.assertEqual("mediaType" in content, document in check.PROTOBUF)

    def test_every_published_bundle_carries_a_certificate(self) -> None:
        for bundle in sorted((REPO / "trust-page").rglob("*.bundle")):
            with self.subTest(bundle=bundle.name):
                der = check._certificate_der(json.loads(bundle.read_text()))
                self.assertIsNotNone(der)
                parsed = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-noout"], input=der, capture_output=True
                )
                self.assertEqual(parsed.returncode, 0)

    def test_every_workflow_installs_a_cosign_patched_for_legacy_bundles(self) -> None:
        # GHSA-fx35-mq7g-6g98: cosign up to 2.6.4, and 3.x up to 3.1.2, skips the
        # identity check for a legacy bundle holding a bare public key; fixed in
        # 2.6.5 and 3.1.3. The cosign release every workflow asks the installer
        # for must be patched. (The installer's own bootstrap cosign checks that
        # release's detached signature with a pinned key, not a bundle.)
        installers = {}
        workflows = REPO / ".github/workflows"
        for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
            workflow = yaml.safe_load(path.read_text())
            installers[path.name] = [
                str((step.get("with") or {}).get("cosign-release", ""))
                for job in workflow["jobs"].values()
                for step in job.get("steps", [])
                # GitHub resolves action names case-insensitively.
                if str(step.get("uses", "")).lower().startswith("sigstore/cosign-installer")
            ]
        # The workflows that sign or verify bundles each install cosign.
        for name in (
            "publish-trust-gcp.yml",
            "publish-trust-aws.yml",
            "publish-trust-azure.yml",
            "publish-trust-page.yml",
            "publish-trust-s3.yml",
            "deploy-enclave-gcp.yml",
        ):
            with self.subTest(workflow=name):
                self.assertTrue(installers[name])
        for name, releases in installers.items():
            for release in releases:
                with self.subTest(workflow=name, release=release):
                    self.assertTrue(_patched(release), f"{name} installs cosign {release!r}")

    def test_the_patched_version_rule(self) -> None:
        for release, patched in (
            ("v2.4.1", False), ("v2.6.4", False), ("v2.6.5", True), ("v2.7.0", True),
            ("v3.0.2", False), ("v3.1.2", False), ("v3.1.3", True), ("v3.2.0", True),
            ("v4.0.0", True), ("v1.13.1", False), ("", False), ("latest", False),
            # int() alone would accept each of these as a patched version.
            ("v2.6.+5", False), ("v2.6.5_0", False), ("v3.-1.0", False), ("v2.6. 5", False),
            ("v2.6.\u0665", False), ("v2.6.5 ", False),
            # Not written v<major>.<minor>.<patch>: the pin must be rewritten.
            ("2.6.5", False), ("v2.6.5-rc.1", False),
        ):
            with self.subTest(release=release):
                self.assertEqual(_patched(release), patched)

    def test_each_signer_signs_only_what_the_table_gives_its_plane(self) -> None:
        # A signer that starts signing a new document must add it to SIGNED_BY
        # under its own plane, or the publishers would refuse its bundle.
        for plane in check.SIGNED_BY:
            workflow = yaml.safe_load(
                (REPO / f".github/workflows/publish-trust-{plane}.yml").read_text()
            )
            runs = "\n".join(
                step.get("run", "")
                for job in workflow["jobs"].values()
                for step in job["steps"]
            )
            documents = {
                path
                for path in re.findall(r"trust-page/([^\s\"';$)]+)", runs)
                if not path.endswith(".bundle") and "." in path.rsplit("/", 1)[-1]
            }
            self.assertTrue(documents, plane)
            # A push that changes any of them must run the signer, or the
            # publishers refuse the stale bundle until someone dispatches it.
            triggers = set(workflow[True]["push"]["paths"])
            for document in documents:
                with self.subTest(plane=plane, document=document):
                    self.assertEqual(check.plane_of(document), plane)
                    self.assertIn(f"trust-page/{document}", triggers)


def _patched(release: str) -> bool:
    """Whether a cosign release is fixed for GHSA-fx35-mq7g-6g98: 2.6.5 on 2.x,
    3.1.3 on 3.x, anything later. A release not written v<major>.<minor>.<patch>
    in ASCII digits (unpinned, a pre-release, anything else) is not."""
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", release)
    if match is None:
        return False
    version = tuple(int(part) for part in match.groups())
    return version >= (2, 6, 5) and not (3, 0, 0) <= version < (3, 1, 3)


if __name__ == "__main__":
    unittest.main()
