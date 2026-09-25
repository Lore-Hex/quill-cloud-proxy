#!/usr/bin/env python3
"""Reviewed operator provisioning and shared validation for Cloud DNS liveness.

This script is never invoked by the reconciler. Review before running:
  python3 tools/dns_geo_health.py --project PROJECT --name canonical-dns-tcp --create
  python3 tools/dns_geo_health.py --project PROJECT --name canonical-dns-tcp
The second command only verifies. Both print the URL to configure in
QUILL_GEO_HEALTH_CHECK. No firewall or attestation policy is changed.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess

SOURCE_REGIONS = ("us-east1", "europe-west1", "asia-east1")


def health_check_url(project: str, name: str) -> str:
    return f"https://www.googleapis.com/compute/v1/projects/{project}/global/healthChecks/{name}"


def verify_health_check(url: str, project: str, read) -> None:
    """Read, never create/repair; refuse absent or non-reviewed configuration."""
    prefix = health_check_url(project, "")
    name = url.removeprefix(prefix)
    if not url.startswith(prefix) or not re.fullmatch(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?", name):
        raise ValueError("GEO requires a same-project global healthCheck URL")
    check = read(["compute", "health-checks", "describe", name, "--global"])
    if not isinstance(check, dict):
        raise ValueError("GEO health check is missing")
    expected = {"kind": "compute#healthCheck", "selfLink": url, "name": name,
                "type": "TCP", "checkIntervalSec": 30, "timeoutSec": 5,
                "healthyThreshold": 2, "unhealthyThreshold": 2}
    if any(check.get(key) != value for key, value in expected.items()) or check.get("region"):
        raise ValueError("GEO health check must match the reviewed global TCP configuration")
    if sorted(check.get("sourceRegions", [])) != sorted(SOURCE_REGIONS):
        raise ValueError("GEO health check requires the three reviewed source regions")
    tcp = check.get("tcpHealthCheck", {})
    if (not isinstance(tcp, dict) or tcp.get("port") != 443
            or tcp.get("portSpecification", "USE_FIXED_PORT") != "USE_FIXED_PORT"
            or tcp.get("proxyHeader", "NONE") != "NONE"
            or any(tcp.get(key) for key in ("request", "response", "portName"))
            or any(check.get(key) for key in ("sslHealthCheck", "httpHealthCheck",
                "httpsHealthCheck", "http2HealthCheck", "grpcHealthCheck", "grpcTlsHealthCheck"))):
        raise ValueError("GEO health check requires TCP connect-only on fixed port 443")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--name", default="canonical-dns-tcp")
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    if args.create:
        subprocess.run(["gcloud", "compute", "health-checks", "create", "tcp", args.name,
                        "--project", args.project, "--global", "--port=443",
                        "--source-regions=" + ",".join(SOURCE_REGIONS),
                        "--check-interval=30s", "--timeout=5s",
                        "--healthy-threshold=2", "--unhealthy-threshold=2"], check=True)
    def read(command):
        result = subprocess.run(["gcloud", *command, "--project", args.project, "--format=json"],
                                check=True, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)
    url = health_check_url(args.project, args.name)
    verify_health_check(url, args.project, read)
    print(url)


if __name__ == "__main__":
    main()
