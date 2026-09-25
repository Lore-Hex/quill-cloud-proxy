#!/usr/bin/env python3
"""ensure-trustedrouter-control-host-cert.sh on a proxy with and without a certificate map.

The script runs with PATH holding only a recording fake ``gcloud``,
``python3`` and, for the classic path, the text utilities it uses: any other
external command fails, and no real cloud CLI is reachable. The fake answers
from a JSON state file.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("ensure-trustedrouter-control-host-cert.sh")
MAP = "//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/control"
CERT = "projects/p/locations/global/certificates/control-trustedrouter-com"
OTHER = "projects/p/locations/global/certificates/eu-trustedrouter-com"
READS = [
    [
        "compute", "target-https-proxies", "describe", "trusted-router-control-https-proxy",
        "--project=quill-cloud-proxy", "--global", "--format=value(certificateMap)",
    ],
    [
        "certificate-manager", "maps", "entries", "list", "--map=control",
        "--location=global", "--project=quill-cloud-proxy", "--format=json",
    ],
    ["certificate-manager", "certificates", "list", "--location=global", "--project=quill-cloud-proxy", "--format=json"],
]

FAKE_GCLOUD = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
state = json.loads(open(os.environ["FAKE_STATE"]).read())
joined = " ".join(args)
if joined.startswith("compute target-https-proxies describe"):
    if "--format=value(certificateMap)" in args:
        print(state.get("certificate_map", ""))
    else:
        print(";".join(state.get("attached", [])))
elif joined.startswith("certificate-manager maps entries list"):
    print(json.dumps(state["entries"]))
elif joined.startswith("certificate-manager certificates list"):
    print(json.dumps(state["certificates"]))
elif joined.startswith("compute ssl-certificates describe"):
    if "--format=value(managed.domains)" in args:
        print(state["host"])
    elif "--format=value(managed.status)" in args:
        print("ACTIVE")
"""


def map_state(
    entries: dict[str, str],
    states: dict[str, str] | None = None,
    pem: str = "",
    entry_states: dict[str, str] | None = None,
) -> dict:
    states = states or {CERT: "ACTIVE"}
    return {
        "certificate_map": MAP,
        "entries": [{"matcher": "PRIMARY", "certificates": ["primary"], "state": "ACTIVE"}]
        + [
            {"hostname": host, "certificates": [cert], "state": (entry_states or {}).get(host, "ACTIVE")}
            for host, cert in entries.items()
        ],
        "certificates": [
            {"name": name, "managed": {"state": state}, "pemCertificate": pem}
            for name, state in states.items()
        ],
    }


class EnsureControlHostCertTests(unittest.TestCase):
    def run_script(self, host: str, state: dict, utilities: tuple[str, ...] = ()):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "gcloud"
        fake.write_text(FAKE_GCLOUD)
        fake.chmod(0o755)
        (bin_dir / "python3").symlink_to(sys.executable)
        for name in utilities:
            (bin_dir / name).symlink_to(shutil.which(name, path="/usr/bin:/bin"))
        (root / "state.json").write_text(json.dumps({**state, "host": host}))
        log = root / "gcloud.log"
        log.write_text("")
        (root / "cloudsdk").mkdir()
        result = subprocess.run(
            ["/bin/bash", str(SCRIPT), host],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                "PATH": str(bin_dir),
                "HOME": str(root),
                "CLOUDSDK_CONFIG": str(root / "cloudsdk"),
                "FAKE_LOG": str(log),
                "FAKE_STATE": str(root / "state.json"),
            },
        )
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        return result, calls

    @staticmethod
    def classic_writes(calls: list[list[str]]) -> list[list[str]]:
        return [
            c
            for c in calls
            if c[:3] == ["compute", "ssl-certificates", "create"]
            or c[:3] == ["compute", "target-https-proxies", "update"]
        ]

    def test_a_host_the_map_wildcard_covers_succeeds_without_classic_writes(self) -> None:
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state({"trustedrouter.com": CERT, "*.trustedrouter.com": CERT}),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("eu.trustedrouter.com has an ACTIVE entry and certificate there", result.stdout)
        self.assertEqual(calls, READS)

    def test_an_exact_entry_serves_the_apex(self) -> None:
        result, calls = self.run_script(
            "trustedrouter.com", map_state({"trustedrouter.com": CERT})
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, READS)

    def test_an_exact_entry_is_used_before_the_wildcard(self) -> None:
        # eu.trustedrouter.com's own entry has a certificate that is not ACTIVE;
        # the ACTIVE wildcard does not serve it, because Certificate Manager uses
        # the exact entry first.
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state(
                {"eu.trustedrouter.com": OTHER, "*.trustedrouter.com": CERT},
                {CERT: "ACTIVE", OTHER: "PROVISIONING"},
            ),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("no ACTIVE entry with an ACTIVE certificate for eu.trustedrouter.com", result.stderr)
        self.assertEqual(calls, READS)

    def test_a_pending_exact_entry_is_used_before_the_wildcard(self) -> None:
        # The exact entry is PENDING and both certificates are ACTIVE: the exact
        # entry is still the one selected, so the host fails until it is ACTIVE.
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state(
                {"eu.trustedrouter.com": OTHER, "*.trustedrouter.com": CERT},
                {CERT: "ACTIVE", OTHER: "ACTIVE"},
                entry_states={"eu.trustedrouter.com": "PENDING"},
            ),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("no ACTIVE entry with an ACTIVE certificate for eu.trustedrouter.com", result.stderr)
        self.assertEqual(calls, READS)

    def test_a_pending_map_entry_fails_even_with_an_active_certificate(self) -> None:
        # A PENDING entry has not reached every frontend yet.
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state({"*.trustedrouter.com": CERT}, entry_states={"*.trustedrouter.com": "PENDING"}),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("no ACTIVE entry with an ACTIVE certificate for eu.trustedrouter.com", result.stderr)
        self.assertEqual(calls, READS)

    def test_a_certificate_list_larger_than_an_environment_string_is_read(self) -> None:
        # Linux limits one environment string to 128 KiB; the list reaches
        # python3 on stdin, so its size does not matter.
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state({"*.trustedrouter.com": CERT}, pem="x" * 300_000),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, READS)

    def test_a_host_without_a_map_entry_fails(self) -> None:
        result, calls = self.run_script(
            "eu.trustedrouter.com", map_state({"trustedrouter.com": CERT})
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("no ACTIVE entry with an ACTIVE certificate for eu.trustedrouter.com", result.stderr)
        self.assertEqual(self.classic_writes(calls), [])

    def test_a_host_whose_map_certificate_is_not_active_fails(self) -> None:
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            map_state({"*.trustedrouter.com": CERT}, {CERT: "PROVISIONING"}),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("no ACTIVE entry with an ACTIVE certificate for eu.trustedrouter.com", result.stderr)
        self.assertEqual(self.classic_writes(calls), [])

    def test_without_a_map_it_keeps_the_classic_certificate_path(self) -> None:
        result, calls = self.run_script(
            "eu.trustedrouter.com",
            {"attached": ["trusted-router-apex-cert-v2"]},
            utilities=("tr", "sed", "seq"),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("certificate-manager", [c[0] for c in calls])
        [update] = [c for c in calls if c[:3] == ["compute", "target-https-proxies", "update"]]
        self.assertIn(
            "--ssl-certificates=trusted-router-apex-cert-v2,trusted-router-eu-trustedrouter-com-cert",
            update,
        )


if __name__ == "__main__":
    unittest.main()
