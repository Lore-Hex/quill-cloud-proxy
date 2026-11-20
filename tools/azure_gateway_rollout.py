#!/usr/bin/env python3
"""Per-region Azure gateway rollout steps for rollout-azure-gateway.yml.

docs/runbooks/azure-enclave.md §3.4-§3.6, non-interactive. The measured deploy
itself stays in tools/deploy-azure-aci.sh (bind -> deploy -> verify, narrow
after publication); this tool owns what the runbook left to the operator:

    env               the region's deploy environment, as KEY=VALUE lines
    peer-check        prove the OTHER region serves the shared hostname with an
                      independently derived HOST_DATA before draining this one
    drain             disable this region's Traffic Manager endpoint and wait
                      out both TTLs, then confirm the shared name avoids it
    enable            re-enable it and verify it over the shared hostname
    publication-args  read the deploy's MEASUREMENT NOT PUBLISHED gate and
                      emit the exact --azure-region value it names
    oldest-build      the build the OTHER region serves (the record's floor
                      while the regions differ)

It never changes a key release policy or a container group.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORDER = ("dubai", "sydney")
SHARED_HOST = "api-azure.trustedrouter.com"
TM_RG = "tr-azure"
TM_PROFILE = "trquill-azure-gw"
# Traffic Manager TTL 30 s + origin record TTL 300 s, per the runbook.
DRAIN_SECONDS = 330
REGIONS = {
    "dubai": {
        "LOCATION": "uaenorth",
        "RESOURCE_GROUP": "TR-TEE-DUBAI",
        "MAA_ENDPOINT": "trquilluaen.uaen.attest.azure.net",
        "API_HOST": "api-azure.trustedrouter.com",
        "CONTAINER_GROUP": "quill-enclave-uaenorth",
    },
    "sydney": {
        "LOCATION": "australiaeast",
        "RESOURCE_GROUP": "tr-tee-sydney",
        "MAA_ENDPOINT": "trquillsyd.eau.attest.azure.net",
        "API_HOST": "api-azure-syd.trustedrouter.com",
        "CONTAINER_GROUP": "quill-enclave-australiaeast",
    },
}
GATE_ARG = re.compile(
    r"--azure-region (quill-enclave-[a-z]+)=([0-9a-f]{32}),([0-9a-f]{40}),(sha256:[0-9a-f]{64})")
GATE_HOSTDATA = re.compile(r"MEASUREMENT NOT PUBLISHED: this region attests hostdata\s+\S*\s*([0-9a-f]{64})")


def peer(region: str) -> str:
    return ORDER[1 - ORDER.index(region)]


def az(*args: str, timeout: int = 180) -> str:
    try:
        return subprocess.run(["az", *args, "--only-show-errors"], check=True, capture_output=True,
                              text=True, timeout=timeout).stdout.strip()
    except subprocess.CalledProcessError:
        raise SystemExit(f"az {' '.join(args[:3])} failed") from None


def hostdata_from_policy(encoded_policy: str) -> str:
    """HOST_DATA is the SHA-256 of the decoded CCE policy (runbook §5)."""
    return hashlib.sha256(base64.b64decode(encoded_policy, validate=True)).hexdigest()


def container(region: str) -> dict:
    cfg = REGIONS[region]
    return json.loads(az("container", "show", "--resource-group", cfg["RESOURCE_GROUP"],
                         "--name", cfg["CONTAINER_GROUP"], "-o", "json"))


def endpoints() -> dict[str, dict]:
    listing = json.loads(az("network", "traffic-manager", "endpoint", "list", "--resource-group", TM_RG,
                            "--profile-name", TM_PROFILE, "-o", "json"))
    return {item["name"]: item for item in listing}


def verify_over_shared_name(region: str) -> None:
    """Attest `region` through the SHARED SNI, pinned to its own origin IP and its
    independently derived HOST_DATA and MAA issuer."""
    cfg = REGIONS[region]
    group = container(region)
    ip = group["ipAddress"]["ip"]
    hostdata = hostdata_from_policy(group["confidentialComputeProperties"]["ccePolicy"])
    subprocess.run([sys.executable, str(ROOT / "tools" / "verify-attestation.py"),
                    "--api-host", SHARED_HOST, "--connect-ip", ip,
                    "--expected-maa-issuer", f"https://{cfg['MAA_ENDPOINT']}",
                    "--expected-hostdata", hostdata], cwd=ROOT, check=True, timeout=180)
    print(f"{region}: {SHARED_HOST} via {ip} attests hostdata {hostdata}")


def cmd_env(args: argparse.Namespace) -> None:
    for key, value in REGIONS[args.region].items():
        print(f"{key}={value}")


def cmd_peer_check(args: argparse.Namespace) -> None:
    other = peer(args.region)
    state = endpoints()
    if state[other]["endpointStatus"] != "Enabled" or state[other]["endpointMonitorStatus"] != "Online":
        raise SystemExit(f"peer {other} is not Enabled/Online in Traffic Manager; refusing to drain {args.region}")
    verify_over_shared_name(other)


def resolved(host: str) -> set[str]:
    return {info[4][0] for info in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}


def cmd_drain(args: argparse.Namespace) -> None:
    cmd_peer_check(args)
    region_ip = container(args.region)["ipAddress"]["ip"]
    az("network", "traffic-manager", "endpoint", "update", "--resource-group", TM_RG,
       "--profile-name", TM_PROFILE, "--name", args.region, "--type", "externalEndpoints",
       "--endpoint-status", "Disabled", "--output", "none")
    print(f"{args.region}: endpoint disabled; waiting {args.wait}s for the TM and origin TTLs")
    time.sleep(args.wait)
    state = endpoints()
    if state[args.region]["endpointStatus"] != "Disabled":
        raise SystemExit(f"{args.region}: endpoint is not Disabled after the drain")
    deadline = time.monotonic() + 300
    while region_ip in resolved(SHARED_HOST):
        if time.monotonic() > deadline:
            raise SystemExit(f"{SHARED_HOST} still resolves to {args.region} ({region_ip}) after the drain")
        time.sleep(15)
    # The peer must still answer the shared name before this region is replaced.
    verify_over_shared_name(peer(args.region))
    print(f"{args.region}: drained; {SHARED_HOST} no longer resolves to {region_ip}")


def cmd_enable(args: argparse.Namespace) -> None:
    verify_over_shared_name(args.region)
    az("network", "traffic-manager", "endpoint", "update", "--resource-group", TM_RG,
       "--profile-name", TM_PROFILE, "--name", args.region, "--type", "externalEndpoints",
       "--endpoint-status", "Enabled", "--output", "none")
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        state = endpoints()[args.region]
        if state["endpointStatus"] == "Enabled" and state["endpointMonitorStatus"] == "Online":
            break
        time.sleep(15)
    else:
        raise SystemExit(f"{args.region}: endpoint did not come back Online")
    verify_over_shared_name(args.region)
    verify_over_shared_name(peer(args.region))
    print(f"{args.region}: re-enabled and Online; both regions attest over {SHARED_HOST}")


def publication_args(log: str, region: str) -> tuple[str, str]:
    """(--azure-region value, hostdata) from the deploy's publication gate."""
    if "MEASUREMENT NOT PUBLISHED" not in log:
        raise ValueError("deploy did not stop at the publication gate")
    found = set(GATE_ARG.findall(log))
    if len(found) != 1:
        raise ValueError("publication gate named no unique build")
    (group, bundle, commit, digest), = found
    if group != REGIONS[region]["CONTAINER_GROUP"]:
        raise ValueError(f"publication gate names {group}, not {region}")
    hostdata = set(GATE_HOSTDATA.findall(log))
    if len(hostdata) != 1:
        raise ValueError("publication gate named no unique hostdata")
    return f"{group}={bundle},{commit},{digest}", hostdata.pop()


def cmd_publication_args(args: argparse.Namespace) -> None:
    value, hostdata = publication_args(Path(args.log).read_text(), args.region)
    print(f"azure_region={value}")
    print(f"hostdata={hostdata}")


def cmd_oldest_build(args: argparse.Namespace) -> None:
    record = json.loads(Path(args.record).read_text())
    group = REGIONS[peer(args.region)]["CONTAINER_GROUP"]
    matches = [r for r in record["regions"] if group in r.get("origin_hostname", "")]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{40}", matches[0].get("image_build_commit", "")):
        raise SystemExit(f"published record has no build for {group}")
    print(matches[0]["image_build_commit"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("env", "peer-check", "drain", "enable", "publication-args", "oldest-build"):
        p = sub.add_parser(name)
        p.add_argument("--region", required=True, choices=ORDER)
        if name == "drain":
            p.add_argument("--wait", type=int, default=DRAIN_SECONDS)
        if name == "enable":
            p.add_argument("--timeout", type=int, default=600)
        if name == "publication-args":
            p.add_argument("--log", required=True)
        if name == "oldest-build":
            p.add_argument("--record", required=True)
    args = parser.parse_args()
    if getattr(args, "wait", DRAIN_SECONDS) < DRAIN_SECONDS:
        raise SystemExit(f"--wait must cover both TTLs (>= {DRAIN_SECONDS}s)")
    globals()["cmd_" + args.command.replace("-", "_")](args)


if __name__ == "__main__":
    main()
