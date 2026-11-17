"""Build complete AWS BootstrapData from reviewed local values, without cloud I/O."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

PARENT = Path(__file__).resolve().parents[1] / "parent/src/quill_parent/bootstrap_server.py"


def catalog() -> dict[str, Any]:
    # Parse only the literal catalog, never execute the parent or its AWS clients.
    names = {"_PROVIDER_KEYS", "_SEALED_ONLY_PROVIDER_KEYS", "_DIRECT_PROVIDER_KEYS", "_PROMPT_KEYS",
             "_TR_INTERNAL_TOKEN_SECRET_SUFFIX", "_SPEND_LEASE_ISSUER_CONFIG_SECRET_SUFFIX",
             "_CLOUDFLARE_API_TOKEN_SECRET_SUFFIX", "_CLOUDFLARE_ZONE_ID_SECRET_SUFFIX"}
    result = {}
    for node in ast.parse(PARENT.read_text()).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
            result[node.target.id] = ast.literal_eval(node.value)
    if set(result) != names:
        raise ValueError("parent bootstrap catalog changed; review the bundle builder")
    return result


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate bootstrap source field")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number in bootstrap source")


def build(values: dict[str, str], *, region: str, service_account: str,
          omitted: list[str]) -> dict[str, Any]:
    if region not in {"eu-west-1", "eu-west-3"}:
        raise ValueError("invalid bootstrap region")
    if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                         or not v.strip() for k, v in values.items()):
        raise ValueError("bootstrap values must be nonempty strings")
    config = catalog()
    fields = dict(config["_PROVIDER_KEYS"] + config["_SEALED_ONLY_PROVIDER_KEYS"] + config["_PROMPT_KEYS"])
    fields.update({
        "trustedrouter_internal_token": config["_TR_INTERNAL_TOKEN_SECRET_SUFFIX"],
        "cloudflare_api_token": config["_CLOUDFLARE_API_TOKEN_SECRET_SUFFIX"],
        "cloudflare_zone_id": config["_CLOUDFLARE_ZONE_ID_SECRET_SUFFIX"],
    })
    providers = dict(config["_DIRECT_PROVIDER_KEYS"])
    lease_name = config["_SPEND_LEASE_ISSUER_CONFIG_SECRET_SUFFIX"]
    required = set(fields.values()) | set(providers.values()) | {lease_name}
    if len(set(omitted)) != len(omitted) or set(omitted) - required or set(omitted) & values.keys():
        raise ValueError("invalid or contradictory explicit omissions")
    missing = required - values.keys() - set(omitted)
    if missing:
        # Logical names are metadata, not secret values.
        raise ValueError("local values are incomplete; explicitly review missing names: " + ", ".join(sorted(missing)))
    if values.keys() - required:
        raise ValueError("values include entries outside the AWS enclave catalog")
    if fields["trustedrouter_internal_token"] not in values:
        raise ValueError("internal gateway credential cannot be omitted")
    account = json.loads(service_account, object_pairs_hook=unique_object, parse_constant=reject_constant)
    if not isinstance(account, dict) or account.get("type") != "service_account" or not account.get("private_key"):
        raise ValueError("unwrapped local ACME service-account JSON is required")
    payload: dict[str, Any] = {
        "region": region, "devices": [], "trustedrouter_base_url": "https://trustedrouter.com",
        "gcp_service_account_key_json": service_account,
    }
    for field, name in fields.items():
        if name in values:
            payload[field] = values[name].strip()
    direct = {provider: values[name].strip() for provider, name in providers.items() if name in values}
    if direct:
        payload["provider_api_keys"] = direct
    if lease_name in values:
        payload["spend_lease_issuer_config"] = json.loads(
            values[lease_name], object_pairs_hook=unique_object, parse_constant=reject_constant,
        )
        if not isinstance(payload["spend_lease_issuer_config"], dict):
            raise ValueError("issuer configuration must be an object")
    return payload
