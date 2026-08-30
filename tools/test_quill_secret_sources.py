import importlib.util
import pathlib
import re
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("quill_secret_sources.py")
SPEC = importlib.util.spec_from_file_location("quill_secret_sources", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class QuillSecretSourcesTests(unittest.TestCase):
    def test_every_direct_provider_secret_has_an_operator_key_source(self) -> None:
        registry = (
            SCRIPT.parents[1]
            / "enclave-go"
            / "internal"
            / "directproviders"
            / "providers.go"
        ).read_text()
        direct_provider_secrets = set(
            re.findall(r'SecretName:\s*"([^"]+)"', registry)
        )
        mapped_secrets = set(MODULE.PROVIDER_KEY_ALIASES.values())
        for aliases in MODULE.COPIED_KEY_ALIASES.values():
            mapped_secrets.update(aliases)

        self.assertTrue(direct_provider_secrets)
        self.assertEqual(direct_provider_secrets - mapped_secrets, set())

    def test_new_provider_keys_are_copied_to_cloud_local_names(self) -> None:
        cases = {
            "ALIBABA_API_KEY": "trustedrouter-alibaba-api-key",
            "AZURE_FOUNDRY_API_KEY": "trustedrouter-azure-api-key",
            "ATLAS_CLOUD_API_KEY": "trustedrouter-atlas-cloud-api-key",
            "DATABRICKS_TOKEN": "trustedrouter-databricks-token",
            "ENGY_API_KEY": "trustedrouter-engy-api-key",
            "PEARL_RESEARCH_API_KEY": "trustedrouter-pearl-api-key",
            "FAL_API_KEY": "trustedrouter-fal-api-key",
            "TENCENT_API_KEY": "trustedrouter-tencent-tokenhub-api-key",
            "TELNYX_API_KEY": "trustedrouter-telnyx-api-key",
            "ZERO_G_ALL_API_KEY": "trustedrouter-zero-g-api-key",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            keys = root / "keys"
            secrets = root / "secrets"
            secrets.mkdir()
            keys.write_text(
                "\n".join(f"{env}=value-{index}" for index, env in enumerate(cases))
            )
            values, missing, _ = MODULE.resolve(
                list(cases.values()), keys_file=keys, secrets_dir=secrets
            )
            self.assertEqual(missing, [])
            self.assertEqual(set(values), set(cases.values()))

    def test_openai_key_is_copied_for_chat_and_video(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            keys = root / "keys"
            secrets = root / "secrets"
            secrets.mkdir()
            keys.write_text("CHATGPT_API_KEY=openai-value\n")
            names = ["trustedrouter-openai-api-key", "trustedrouter-openai-video-key"]
            values, missing, _ = MODULE.resolve(
                names, keys_file=keys, secrets_dir=secrets
            )
            self.assertEqual(missing, [])
            self.assertEqual(values, {name: "openai-value" for name in names})


if __name__ == "__main__":
    unittest.main()
