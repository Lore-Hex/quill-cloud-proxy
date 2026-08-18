#!/usr/bin/env python3
"""Regression tests for Azure bundle input discovery."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import quill_secret_sources as sources


def load_sealer():
    path = Path(__file__).with_name("azure-seal-bundle.py")
    spec = importlib.util.spec_from_file_location("azure_seal_bundle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load azure-seal-bundle.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RequiredBundleNamesTest(unittest.TestCase):
    def test_includes_non_secret_suffix_bundle_entry(self) -> None:
        env = {
            "QUILL_DEVICE_KEYS_SECRET": "quill-device-keys",
            "QUILL_LIGHTNING_SECRET": "trustedrouter-lightning-api-key",
            "QUILL_AZURE_BUNDLE_SECRET": "tr-bootstrap-bundle",
            "QUILL_AZURE_SA_KEY_ENTRY": "tr-cross-cloud-sa-key",
        }

        self.assertEqual(
            sources.required_bundle_names(env),
            [
                "quill-device-keys",
                "tr-cross-cloud-sa-key",
                "trustedrouter-lightning-api-key",
            ],
        )

    def test_cross_cloud_entry_resolves_from_secret_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secrets_dir = Path(directory)
            (secrets_dir / "tr-cross-cloud-sa-key.json").write_text("credential-json\n")

            values, missing, provenance = sources.resolve(
                ["tr-cross-cloud-sa-key"],
                keys_file=secrets_dir / "missing.env",
                secrets_dir=secrets_dir,
            )

        self.assertEqual(values, {"tr-cross-cloud-sa-key": "credential-json"})
        self.assertEqual(missing, [])
        self.assertEqual(provenance["tr-cross-cloud-sa-key"], "dir:" + secrets_dir.name)


class SealerRequirementsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sealer = load_sealer()
        self.env = {
            "QUILL_GCP_PROJECT_ID": "project",
            "QUILL_DEVICE_KEYS_SECRET": "quill-device-keys",
            "QUILL_AZURE_MAA_ENDPOINT": "maa.example",
            "QUILL_AZURE_AKV_ENDPOINT": "vault.example",
            "QUILL_AZURE_SKR_KEY_ID": "wrap-key",
            "QUILL_AZURE_BUNDLE_SECRET": "bundle",
            "QUILL_AZURE_SA_KEY_ENTRY": "tr-cross-cloud-sa-key",
            "QUILL_OPENROUTER_SECRET": "openrouter-key",
        }

    def test_cache_enabled_requires_cross_cloud_key(self) -> None:
        self.env["QUILL_ACME_CACHE_GCS_BUCKET"] = "quill-acme-cache"
        entries = self.sealer.required_entries(self.env)

        sa_entry = next(entry for entry in entries if entry.name == "tr-cross-cloud-sa-key")
        self.assertFalse(sa_entry.optional)

    def test_independent_posture_keeps_cross_cloud_key_optional(self) -> None:
        entries = self.sealer.required_entries(self.env)

        sa_entry = next(entry for entry in entries if entry.name == "tr-cross-cloud-sa-key")
        self.assertTrue(sa_entry.optional)


if __name__ == "__main__":
    unittest.main()
