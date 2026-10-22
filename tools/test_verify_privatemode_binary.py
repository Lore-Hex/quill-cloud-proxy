"""Offline negative tests for the vendor source-to-binary release gate."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_proxy", ROOT / "tools/verify_privatemode_binary.py")
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class VerifyPrivatemode(unittest.TestCase):
    def test_match_requires_both_executables_and_reviewed_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            rebuilt, vendor = Path(temp) / "rebuilt", Path(temp) / "vendor"
            rebuilt.write_bytes(b"same executable")
            vendor.write_bytes(rebuilt.read_bytes())
            expected = hashlib.sha256(rebuilt.read_bytes()).hexdigest()
            self.assertEqual(proxy.compare(rebuilt, vendor, expected)["rebuilt_sha256"], expected)
            with self.assertRaisesRegex(ValueError, "mismatch"):
                proxy.compare(rebuilt, vendor, "0" * 64)
            vendor.write_bytes(b"vendor changed")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                proxy.compare(rebuilt, vendor, expected)
            rebuilt.write_bytes(vendor.read_bytes())
            with self.assertRaisesRegex(ValueError, "mismatch"):
                proxy.compare(rebuilt, vendor, expected)

    def test_all_production_images_enforce_same_verified_executable(self):
        self.assertEqual(len(proxy.expected_digest()), 64)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in ["enclave-go/internal/privatemode/proxy.sha256", *[
                "enclave-go/" + name for name in proxy.DOCKERFILES
            ]]:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            changed = root / "enclave-go" / proxy.DOCKERFILES[0]
            original = changed.read_text()
            for before, after in ((proxy.IMAGE, "vendor:latest"),
                                  ("sha256sum -c", "echo"),
                                  ("COPY --from=builder /out/privatemode-proxy", "COPY --from=privatemode /bin/privatemode-proxy")):
                changed.write_text(original.replace(before, after))
                with self.assertRaises(ValueError):
                    proxy.expected_digest(root)

    def test_source_builder_has_no_vendor_cache_credentials_or_host_socket(self):
        command = proxy.build_command(Path("/source"), Path("/output"), "test-build")
        self.assertIn("no-new-privileges", command)
        self.assertIn("type=bind,source=/source,target=/src,readonly", command)
        self.assertIn(proxy.NIX, command)
        text = " ".join(command)
        self.assertIn("--option accept-flake-config false", text)
        self.assertIn("--option substituters https://cache.nixos.org", text)
        for forbidden in ("cachix", "docker.sock", "--privileged", "--env", ".config/gcloud", ".aws"):
            self.assertNotIn(forbidden, text)

    def test_ci_and_production_fail_closed_on_source_rebuild_failure(self):
        for filename, child in (("reproduce-enclave.yml", "compare"),
                                ("deploy-enclave-gcp.yml", "reproduce-image")):
            jobs = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())["jobs"]
            self.assertIn("privatemode-source", jobs[child]["needs"])
            job = jobs["privatemode-source"]
            self.assertNotIn("continue-on-error", job)
            check = next(step for step in job["steps"] if "run" in step)
            self.assertIn("verify_privatemode_binary.py", check["run"])
            self.assertNotIn("continue-on-error", check)


if __name__ == "__main__":
    unittest.main()
