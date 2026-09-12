from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from provider_probe_status import is_provider_http_error

ROOT = Path(__file__).resolve().parents[1]


class ProviderProbeStatusTests(unittest.TestCase):
    def test_only_explicit_provider_origin_is_advisory(self) -> None:
        for source in ["provider", "router", "unknown", None, []]:
            for status in [0, 200, 401, 429, 500, 502, 503, 504, 600, True, "503"]:
                expected = source == "provider" and type(status) is int and 400 <= status <= 599
                self.assertEqual(is_provider_http_error(status, {"error": {"source": source}}), expected)
        for payload in [None, [], "provider", {"error": "provider"}, {"source": "provider"}]:
            self.assertFalse(is_provider_http_error(503, payload))

    def test_cli_distinguishes_success_provider_and_router_failure(self) -> None:
        cases = [
            (200, {"choices": [{"message": {"content": "PONG"}}]}, 0),
            (200, {"choices": [{"message": {"content": "wrong"}}]}, 1),
            (200, {"error": {"source": "provider"}}, 1),
            (503, {"error": {"source": "provider"}}, 3),
            (503, {"error": {"source": "router"}}, 1),
            (503, {"error": {"message": "provider timed out"}}, 1),
            (503, "invalid json", 1),
        ]
        with tempfile.TemporaryDirectory() as temp:
            body = Path(temp) / "body.json"
            for status, payload, expected in cases:
                body.write_text(payload if isinstance(payload, str) else json.dumps(payload))
                run = subprocess.run([sys.executable, str(ROOT / "tools/provider_probe_status.py"), str(status), str(body)], capture_output=True, timeout=5)
                self.assertEqual(run.returncode, expected, run.stderr)
                self.assertEqual(run.stdout, b"")

    def test_real_shell_keeps_billing_evidence_gate_after_provider_failure(self) -> None:
        source = (ROOT / "tools/verify-region-before-dns.sh").read_text()
        function = "verify_streaming_authorization() {" + source.split("verify_streaming_authorization() {", 1)[1].split("\nverify_instance() {", 1)[0]
        setup = r'''
set -euo pipefail
source "$TOOLS_DIR/stage-d-gate-lib.sh"
curl() {
  local output="" headers="" url=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) url="$1"; shift ;;
    esac
  done
  case "$url" in
    */receipt-key)
      printf '%s' '{"kid":"gcp-b1c0f84d-0001"}' >"$output" ;;
    */chat/completions)
      printf 'x-request-id: rlog_00112233445566778899aabbccddeeff\r\n' >"$headers"
      printf '{"error":{"source":"%s"}}' "$TEST_SOURCE" >"$output"
      printf '503' ;;
    */by-gateway-request-id/*)
      printf 'looked up\n' >>"$response_dir/lookups"
      cp "$TEST_EVIDENCE" "$output"
      printf '200' ;;
    *) return 99 ;;
  esac
}
'''
        for origin, evidence_change, success in [
            ("provider", {}, True),
            ("router", {}, False),
            ("unknown", {}, False),
            ("provider", {"settled": False}, False),
            ("provider", {"heartbeat_seq": 0}, False),
            ("provider", {"stage_d_boot_kid": "wrong"}, False),
            ("provider", {"gateway_request_id": "rlog_11112233445566778899aabbccddeeff"}, False),
        ]:
            with self.subTest(origin=origin, change=evidence_change), tempfile.TemporaryDirectory() as temp:
                evidence = json.loads((ROOT / "tools/testdata/stage-d-evidence-lookup.json").read_text())
                evidence["data"].update(evidence_change)
                evidence_path = Path(temp) / "fixture.json"
                evidence_path.write_text(json.dumps(evidence))
                env = {
                    **os.environ, "TOOLS_DIR": str(ROOT / "tools"), "response_dir": temp,
                    "REGION": "us-central1", "HEARTBEAT_FLAG": "on",
                    "STAGE_D_PROBE_KEY": "test-only", "STAGE_D_PROBE_KEY_IN_USE": "on",
                    "STAGE_D_PROBE_KEY_NAME": "test-only", "TEST_SOURCE": origin,
                    "TEST_EVIDENCE": str(evidence_path), "INTERNAL_GATEWAY_TOKEN": "test-only",
                    "AUTHORIZATION_LOOKUP_BASE_URL": "https://example.invalid/v1",
                    "STAGE_D_EVIDENCE_TIMEOUT_SECONDS": "1", "STAGE_D_EVIDENCE_RETRY_SLEEP": "1",
                }
                run = subprocess.run(["bash", "-c", setup + function + '\nverify_streaming_authorization example.invalid 127.0.0.1 regional'], env=env, cwd=ROOT, capture_output=True, text=True, timeout=5)
                self.assertEqual(run.returncode == 0, success, run.stderr)
                self.assertEqual((Path(temp) / "lookups").exists(), origin == "provider")


if __name__ == "__main__":
    unittest.main()
