import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock


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

    def test_nextbit_key_is_copied_to_separate_global_and_eu_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            keys = root / "keys"
            secrets = root / "secrets"
            secrets.mkdir()
            keys.write_text("NEXTBIT_API_KEY=nextbit-value\n")
            names = ["trustedrouter-nextbit-api-key", "trustedrouter-nextbit-eu-api-key"]
            values, missing, _ = MODULE.resolve(names, keys_file=keys, secrets_dir=secrets)
            self.assertEqual(missing, [])
            self.assertEqual(values, {name: "nextbit-value" for name in names})


class PrivateOutputTests(unittest.TestCase):
    CANARY = "SYNTHETIC-NOT-A-CREDENTIAL-output-privacy-canary"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.output = self.root / "output.json"
        self.needed = self.root / "needed.json"
        self.needed.write_text('["trustedrouter-hixtube-api-key"]')
        self.keys = self.root / "keys"
        self.keys.write_text("HIXTUBE_API_KEY=" + self.CANARY + "\n")
        self.secrets = self.root / "secrets"
        self.secrets.mkdir()
        self.values = {"trustedrouter-hixtube-api-key": self.CANARY}
        self.argv = [str(SCRIPT), str(self.needed), str(self.output), str(self.keys), str(self.secrets)]

    def cli(self, *, umask: int = 0o022) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, *self.argv], capture_output=True, text=True,
            timeout=5, umask=umask,
        )
        self.assertNotIn(self.CANARY, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_fresh_cli_output_is_0600_for_permissive_and_restrictive_umasks(self) -> None:
        for mask in (0o000, 0o022, 0o077, 0o777):
            with self.subTest(mask=mask):
                result = self.cli(umask=mask)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
                self.assertEqual(json.loads(self.output.read_text()), self.values)
                self.output.unlink()

    def test_private_mktemp_output_remains_supported_and_is_truncated(self) -> None:
        self.output.write_text("old trailing bytes" * 100)
        self.output.chmod(0o600)
        inode = self.output.stat().st_ino
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.output.read_text()), self.values)

    def test_creation_is_private_before_chmod_and_before_serialization(self) -> None:
        chmod, dump = os.fchmod, json.dump

        def check_chmod(fd, mode):
            self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode) & 0o077, 0)
            chmod(fd, mode)

        def check_dump(values, output):
            self.assertEqual(stat.S_IMODE(os.fstat(output.fileno()).st_mode), 0o600)
            dump(values, output)

        previous = os.umask(0)
        try:
            with mock.patch.object(MODULE.os, "fchmod", side_effect=check_chmod), \
                 mock.patch.object(MODULE.json, "dump", side_effect=check_dump):
                MODULE.write_private_output(self.output, self.values)
        finally:
            os.umask(previous)

    def test_nonprivate_existing_output_is_not_chmodded_or_truncated(self) -> None:
        for mode in (0o644, 0o660, 0o700):
            with self.subTest(mode=mode):
                self.output.write_text("untouched")
                self.output.chmod(mode)
                self.assertNotEqual(self.cli().returncode, 0)
                self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), mode)
                self.assertEqual(self.output.read_text(), "untouched")

    def test_existing_and_dangling_symlinks_are_refused(self) -> None:
        target = self.root / "target"
        for exists in (False, True):
            with self.subTest(exists=exists):
                if exists:
                    target.write_text("untouched")
                    target.chmod(0o644)
                self.output.symlink_to(target)
                self.assertNotEqual(self.cli().returncode, 0)
                self.assertEqual(target.exists(), exists)
                if exists:
                    self.assertEqual(target.read_text(), "untouched")
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
                self.output.unlink()

    def test_hard_link_is_refused_without_modifying_the_other_name(self) -> None:
        target = self.root / "target"
        target.write_text("untouched")
        target.chmod(0o600)
        self.output.hardlink_to(target)
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(target.read_text(), "untouched")

    def test_nonregular_outputs_fail_without_blocking(self) -> None:
        self.output.mkdir()
        self.assertNotEqual(self.cli().returncode, 0)
        self.output.rmdir()
        os.mkfifo(self.output, 0o600)
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertTrue(stat.S_ISFIFO(self.output.stat().st_mode))

    def test_foreign_owner_is_refused_before_chmod_or_write(self) -> None:
        self.output.write_text("untouched")
        self.output.chmod(0o600)
        actual = self.output.stat()
        foreign = SimpleNamespace(st_mode=actual.st_mode, st_uid=os.geteuid() + 1, st_nlink=1)
        with mock.patch.object(MODULE.os, "fstat", return_value=foreign), \
             mock.patch.object(MODULE.os, "fchmod") as chmod:
            with self.assertRaises(ValueError):
                MODULE.write_private_output(self.output, self.values)
            chmod.assert_not_called()
        self.assertEqual(self.output.read_text(), "untouched")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_link_swap_between_create_and_open_is_refused(self) -> None:
        target = self.root / "target"
        target.write_text("untouched")
        target.chmod(0o600)
        self.output.touch(mode=0o600)
        original_open = os.open

        def swap(path, flags, *args):
            if flags & os.O_EXCL:
                self.output.unlink()
                self.output.symlink_to(target)
                raise FileExistsError()
            return original_open(path, flags, *args)

        with mock.patch.object(MODULE.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                MODULE.write_private_output(self.output, self.values)
        self.assertEqual(target.read_text(), "untouched")

    def test_serialization_failure_stays_private_and_does_not_log_values(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", self.argv), \
             mock.patch.object(MODULE.json, "dump", side_effect=OSError(self.CANARY)), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(MODULE.main(), 1)
        self.assertNotIn(self.CANARY, stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
