#!/usr/bin/env python3
"""The parent's vsock-proxy units and the enclave's tunnel maps must agree.

A Nitro enclave has no network stack. It reaches an upstream only through a
vsock tunnel to the parent, so a hostname is reachable exactly when THREE
things line up:

  1. the parent runs a `vsock-proxy <port> <host> 443` unit   (deploy-aws-nitro.sh)
  2. the enclave maps that host to that same port             (the Go tunnel maps)
  3. the host is in the parent's vsock-proxy address allowlist (vsock-proxy.yaml)

None of that is type-checked, and the failure is silent: the enclave dials a
port that forwards somewhere else, or nowhere.

This shipped. Port 8042 was assigned twice in deploy-aws-nitro.sh — to
`api-github-proxy.tinfoil.sh` (the sidecar's tinfoil release-digest lookup) and
to a MaaS provider host. Both render the SAME systemd unit file, so the second
overwrote the first. And because `write_vsock_unit` ends in `systemctl enable
--now`, which does NOT restart an already-running service, the unit file on
disk and the running process disagreed until something restarted it — meaning
*which* upstream was broken depended on restart history.

Run directly; no pytest, matching the other tools/test_*.py scripts.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "tools" / "deploy-aws-nitro.sh"
DIRECT_PROVIDERS = ROOT / "enclave-go" / "internal" / "directproviders" / "providers.go"
GO_TUNNEL_FILES = [
    ROOT / "enclave-go" / "internal" / "llm" / "http_client_aws.go",
    ROOT / "enclave-go" / "internal" / "enclavetls" / "gcscache_http_aws.go",
    ROOT / "enclave-go" / "internal" / "trustedrouter" / "http_client_aws.go",
    ROOT / "enclave-go" / "sidecar" / "vsock_transport.go",
]

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"[FAIL] {msg}")


def parent_units() -> list[tuple[int, str]]:
    out = []
    for line in DEPLOY.read_text().splitlines():
        m = re.match(r"^write_vsock_unit\s+(\d+)\s+(\S+)\s*$", line.strip())
        if m:
            out.append((int(m.group(1)), m.group(2)))
    return out


def enclave_tunnels() -> dict[str, list[tuple[int, str]]]:
    """host -> [(port, source)] across every enclave-side map."""
    found: dict[str, list[tuple[int, str]]] = {}
    for path in GO_TUNNEL_FILES:
        if not path.exists():
            fail(f"expected tunnel map file is missing: {path}")
            continue
        text = path.read_text()
        # Struct form: {Host: "x", CID: 3, Port: 1234},
        for host, port in re.findall(
            r'\{Host:\s*"([^"]+)",\s*CID:\s*\d+,\s*Port:\s*(\d+)\}', text
        ):
            found.setdefault(host, []).append((int(port), path.name))
        # Map form: "x": 1234,
        for host, port in re.findall(r'"([a-z0-9.-]+\.[a-z]{2,})":\s*(\d+)\s*,', text):
            found.setdefault(host, []).append((int(port), path.name))
    return found


units = parent_units()
if not units:
    fail(f"no write_vsock_unit lines parsed from {DEPLOY} — did the format change?")

# 1. No port may be assigned twice on the parent.
by_port: dict[int, list[str]] = {}
for port, host in units:
    by_port.setdefault(port, []).append(host)
for port, hosts in sorted(by_port.items()):
    if len(hosts) > 1:
        fail(
            f"vsock port {port} is assigned to {len(hosts)} hosts ({', '.join(hosts)}). "
            "Both render the same systemd unit file, so one upstream is silently "
            "unreachable."
        )

# 2. A host should not be split across two ports either.
by_host: dict[str, list[int]] = {}
for port, host in units:
    by_host.setdefault(host, []).append(port)
for host, ports in sorted(by_host.items()):
    if len(set(ports)) > 1:
        fail(f"host {host} is proxied on multiple ports {sorted(set(ports))}")

# 3. Every host the enclave dials must have a parent unit on the SAME port.
parent_by_host = {host: port for port, host in units}
tunnels = enclave_tunnels()
for host, entries in sorted(tunnels.items()):
    for port, source in entries:
        if host not in parent_by_host:
            fail(
                f"{source} dials {host} on vsock {port}, but deploy-aws-nitro.sh "
                "starts no vsock-proxy for it — the enclave cannot reach it."
            )
        elif parent_by_host[host] != port:
            fail(
                f"{source} dials {host} on vsock {port}, but the parent proxies "
                f"that host on {parent_by_host[host]}."
            )

# Cloud DNS is not an LLM provider and used to sit outside this test's input
# files, which let the renewal path drift independently of the parent map.
# Keep the durable DNS-01 egress assignment explicit: a green aggregate
# count is not useful if dns.googleapis.com silently moves or disappears.
if tunnels.get("dns.googleapis.com") != [(8069, "gcscache_http_aws.go")]:
    fail(
        "Cloud DNS renewal must dial dns.googleapis.com on vsock 8069 from "
        "gcscache_http_aws.go"
    )

# 4. Every proxied host must also be in the vsock-proxy address allowlist, or
#    vsock-proxy itself refuses to forward.
deploy_text = DEPLOY.read_text()
allowlisted = set(re.findall(r"-\s*\{address:\s*([^,\s]+)\s*,\s*port:\s*443\}", deploy_text))
for _port, host in units:
    if host not in allowlisted:
        fail(
            f"{host} has a vsock-proxy unit but is not in the vsock-proxy.yaml "
            "address allowlist, so vsock-proxy will refuse to forward to it."
        )

# 5. Every immutable endpoint in the shared direct-provider table must be
# reachable through the AWS parent. This closes the gap where dispatch and
# bootstrap agree on a provider, but Nitro silently lacks its tunnel.
direct_source = DIRECT_PROVIDERS.read_text()
direct_urls = re.findall(r'BaseURL:\s*"(https://[^"]+)"', direct_source)
if not direct_urls:
    fail(f"no direct-provider BaseURL entries parsed from {DIRECT_PROVIDERS}")
for base_url in direct_urls:
    host = urlparse(base_url).hostname
    if not host:
        fail(f"direct-provider BaseURL has no hostname: {base_url}")
    elif host not in parent_by_host:
        fail(f"direct-provider host {host} has no AWS vsock-proxy unit")
    elif host not in tunnels:
        fail(f"direct-provider host {host} has no enclave AWS tunnel")

if failures:
    print(f"\n{len(failures)} problem(s) found.")
    sys.exit(1)

print(
    f"[ok] {len(units)} vsock units, no duplicate ports, "
    f"every enclave tunnel matches its parent unit and is allowlisted"
)
