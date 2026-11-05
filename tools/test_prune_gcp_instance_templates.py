from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "prune-gcp-instance-templates.sh"
DEPLOY = ROOT / "tools" / "deploy-gcp-mig.sh"


class PruneGCPInstanceTemplatesTests(unittest.TestCase):
    def run_prune(
        self,
        templates: list[str],
        referenced: str = "",
        *,
        instances: str = "",
        fail_instances: bool = False,
        fail_list: bool = False,
        keep: int = 20,
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            command_log = temp / "commands.log"
            (temp / "templates.txt").write_text("\n".join(templates) + "\n")
            (temp / "referenced.txt").write_text(referenced + "\n")
            (temp / "instances.txt").write_text(instances + "\n")
            gcloud = bin_dir / "gcloud"
            gcloud.write_text(textwrap.dedent(r"""
                #!/bin/bash
                echo "$*" >> "${COMMAND_LOG}"
                if [[ "$*" == *"instance-templates list"* ]]; then
                  [[ "${FAIL_LIST:-0}" == "1" ]] && exit 1
                  cat "${STUB_DIR}/templates.txt"
                elif [[ "$*" == *"instance-groups managed list"* ]]; then
                  cat "${STUB_DIR}/referenced.txt"
                elif [[ "$*" == *"compute instances list"* ]]; then
                  [[ "${FAIL_INSTANCES:-0}" == "1" ]] && exit 1
                  cat "${STUB_DIR}/instances.txt"
                fi
            """).lstrip())
            gcloud.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "COMMAND_LOG": str(command_log),
                "STUB_DIR": str(temp),
                "FAIL_LIST": "1" if fail_list else "0",
                "FAIL_INSTANCES": "1" if fail_instances else "0",
            }
            result = subprocess.run(
                ["bash", str(SCRIPT), "proj", "quill-enclave-tpl-us", str(keep)],
                env=env, capture_output=True, text=True, check=False,
            )
            batches = [
                [w for w in line.split() if w.startswith("quill-enclave-tpl-")]
                for line in command_log.read_text().splitlines()
                if "instance-templates delete" in line
            ]
            return result, batches

    def test_keeps_newest_by_number_and_referenced_templates(self) -> None:
        # 990..1010: version order must put -1000.. after -999.
        names = [f"quill-enclave-tpl-us-{n}" for n in range(990, 1011)]
        result, batches = self.run_prune(
            names,
            referenced="quill-enclave-tpl-us-990\tprojects/proj/global/instanceTemplates/quill-enclave-tpl-us-991",
            keep=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        kept = set(names) - {n for batch in batches for n in batch}
        self.assertEqual(
            kept,
            {f"quill-enclave-tpl-us-{n}" for n in (990, 991, 1006, 1007, 1008, 1009, 1010)},
        )

    def test_keeps_templates_running_instances_were_created_from(self) -> None:
        names = [f"quill-enclave-tpl-us-{n:03d}" for n in range(1, 11)]
        result, batches = self.run_prune(
            names,
            referenced="quill-enclave-tpl-us-010\tquill-enclave-tpl-us-010;quill-enclave-tpl-us-004",
            instances="quill-enclave-tpl-us-002\n\nquill-enclave-tpl-us-010",
            keep=1,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        kept = set(names) - {n for batch in batches for n in batch}
        self.assertEqual(kept, {f"quill-enclave-tpl-us-{n:03d}" for n in (2, 4, 10)})

    def test_instance_list_failure_skips_pruning(self) -> None:
        result, batches = self.run_prune(
            ["quill-enclave-tpl-us-001", "quill-enclave-tpl-us-002"], fail_instances=True, keep=0,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(batches, [])

    def test_deletes_in_batches_of_fifty(self) -> None:
        names = [f"quill-enclave-tpl-us-{n:03d}" for n in range(1, 131)]
        result, batches = self.run_prune(names, keep=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([len(b) for b in batches], [50, 50, 10])
        deleted = {n for batch in batches for n in batch}
        self.assertNotIn("quill-enclave-tpl-us-111", deleted)
        self.assertIn("quill-enclave-tpl-us-110", deleted)

    def test_list_failure_skips_pruning_without_failing_the_deploy(self) -> None:
        result, batches = self.run_prune(["quill-enclave-tpl-us-001"], fail_list=True, keep=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(batches, [])

    def test_deploy_prunes_before_creating_and_picks_next_by_version(self) -> None:
        deploy = DEPLOY.read_text(encoding="utf-8")
        prune = deploy.index("prune-gcp-instance-templates.sh")
        create = deploy.index("gc compute instance-templates create")
        self.assertLess(prune, create)
        self.assertIn("sort -V | tail -1", deploy)


if __name__ == "__main__":
    unittest.main()
