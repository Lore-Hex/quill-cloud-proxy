from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "recover-gcp-region.sh"


class RecoverGCPRegionTests(unittest.TestCase):
    def run_recovery(
        self, *, fail_verify: bool = False, final_drain_state: str = "active"
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            command_log = temp / "commands.log"

            commands = {
                "gcloud": r"""
                    #!/bin/bash
                    echo "gcloud $*" >> "${COMMAND_LOG}"
                    if [[ "$*" == *"instance-groups managed describe"* ]]; then
                      echo "new-template"
                    elif [[ "$*" == *"instance-templates describe"* ]]; then
                      printf '%s\n' '{"properties":{"metadata":{"items":[{"key":"tee-image-reference","value":"registry.example/enclave:old"}]}}}'
                    elif [[ "$*" == *"artifacts docker images describe"* ]]; then
                      echo "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    fi
                """,
                "uv": r"""
                    #!/bin/bash
                    echo "uv $*" >> "${COMMAND_LOG}"
                """,
                "python3": r"""
                    #!/bin/bash
                    echo "python3 $*" >> "${COMMAND_LOG}"
                """,
                "bash": r"""
                    #!/bin/bash
                    echo "bash $*" >> "${COMMAND_LOG}"
                    if [[ "${FAIL_VERIFY:-0}" == "1" && "$*" == *"verify-region-before-dns.sh"* ]]; then
                      exit 1
                    fi
                """,
            }
            for name, body in commands.items():
                path = bin_dir / name
                path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
                path.chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "COMMAND_LOG": str(command_log),
                    "FAIL_VERIFY": "1" if fail_verify else "0",
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                }
            )
            try:
                completed = subprocess.run(
                    [
                        "/bin/bash",
                        str(SCRIPT),
                        "europe-west4",
                        "quill-enclave-mig-eu",
                        "quill-enclave-mig-eu-",
                        "api.trustedrouter.com,api-europe-west4.quillrouter.com",
                        "old-template",
                        final_drain_state,
                    ],
                    cwd=ROOT,
                    env=env,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except subprocess.TimeoutExpired as exc:
                commands_run = command_log.read_text(encoding="utf-8")
                self.fail(
                    f"recovery script timed out after commands:\n{commands_run}\n"
                    f"stdout={exc.stdout!r}\nstderr={exc.stderr!r}"
                )
            commands = (
                command_log.read_text(encoding="utf-8")
                if command_log.exists()
                else ""
            )
            return completed, commands

    def test_verified_rollback_is_reenabled(self) -> None:
        completed, commands = self.run_recovery()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--set-drain-region europe-west4", commands)
        self.assertIn("wait-canonical-drained.sh europe-west4", commands)
        self.assertIn("--template=old-template", commands)
        self.assertIn(
            "verify-region-before-dns.sh europe-west4 quill-enclave-mig-eu- "
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            commands,
        )
        self.assertIn("--clear-drain-region europe-west4", commands)
        self.assertLess(
            commands.index("wait-canonical-drained.sh europe-west4"),
            commands.index("--template=old-template"),
        )
        self.assertLess(
            commands.index("verify-region-before-dns.sh"),
            commands.index("--clear-drain-region europe-west4"),
        )

    def test_failed_verification_preserves_drain(self) -> None:
        completed, commands = self.run_recovery(fail_verify=True)

        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("--clear-drain-region europe-west4", commands)
        self.assertGreaterEqual(commands.count("--set-drain-region europe-west4"), 2)
        self.assertIn(
            "recovery failed; preserving the canonical rollout drain", completed.stderr
        )

    def test_preexisting_drain_is_preserved_after_verified_recovery(self) -> None:
        completed, commands = self.run_recovery(final_drain_state="drained")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("--clear-drain-region europe-west4", commands)
        self.assertEqual(commands.count("--set-drain-region europe-west4"), 2)
        self.assertGreater(
            commands.rindex("--set-drain-region europe-west4"),
            commands.index("verify-region-before-dns.sh"),
        )
        self.assertIn("drain state restored to drained", completed.stdout)

    def test_empty_drain_state_fails_before_any_mutation(self) -> None:
        completed, commands = self.run_recovery(final_drain_state="")

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(commands, "")
        self.assertIn("invalid final drain state", completed.stderr)

    def test_missing_previous_template_never_mutates_dns_or_mig(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            command_log = temp / "commands.log"
            for name in ("gcloud", "uv", "python3", "bash"):
                path = bin_dir / name
                path.write_text(
                    '#!/bin/bash\necho "$0 $*" >> "${COMMAND_LOG}"\n',
                    encoding="utf-8",
                )
                path.chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "COMMAND_LOG": str(command_log),
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                }
            )
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(SCRIPT),
                    "europe-west4",
                    "quill-enclave-mig-eu",
                    "quill-enclave-mig-eu-",
                    "api.trustedrouter.com",
                    "",
                ],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to mutate DNS or the MIG", completed.stderr)
            self.assertFalse(command_log.exists())


if __name__ == "__main__":
    unittest.main()
