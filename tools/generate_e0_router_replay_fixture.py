#!/usr/bin/env python3
"""Offline source-extracted router serializer harness; no router imports/writes.

Run with the read-only router checkout as argv[1]. Uses literal existing Stage C
state and real unmodified function ASTs, substituting only storage/catalog/config
adapters. Full router imports require unavailable pydantic_settings locally.
"""
import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS

router = Path(sys.argv[1]) / "src/trusted_router"
root = Path(__file__).resolve().parents[1]
fixtures = root / "enclave-go/internal/trustedrouter/testdata"
data = json.loads((fixtures / "stage_c/admission_accepted_response.json").read_bytes())["data"]
claims = json.loads((fixtures / "stage_c/authoritative_lease_payload.json").read_bytes())
request = json.loads((fixtures / "stage_c/receipt_bearing_authorize_request.json").read_bytes())


def extract(path, *names):
    tree = ast.parse((router / path).read_text())
    nodes = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names), (path, names)
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)] + nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(router / path), "exec"), globals())


class UsageType:
    value = "Credits"
    @staticmethod
    def for_endpoint(endpoint):
        return UsageType()
    @staticmethod
    def coerce(value):
        assert value == "Credits"
        return UsageType()
    def is_byok(self):
        return False


# Seed the stored authorization/receipt/nonce, not a fresh-response dictionary.
stored = NS(id=data["authorization_id"], credit_reservation_id=data["credit_reservation_id"],
            invocation_nonce=request.get("invocation_nonce"),
            spend_lease_receipt_hash=data["spend_lease_admission"]["receipt_hash"],
            spend_lease_token=data["spend_lease"]["token"], spend_lease_status="active",
            spend_lease_exp=claims["exp"], usage_type="Credits", region=data["region"],
            estimated_microdollars=data["estimated_cost_microdollars"],
            additional_cost_reservation_microdollars=0, receipt_fee_basis_points=0,
            native_batch_eligible=False, tags={})
# Execute storage_gcp_authorize.py:465's actual stored-receipt replay decision.
extract("spend_lease_admission.py", "classify_receipt_replay")
extract("storage_gcp_authorize.py", "_replay")
spend_lease_admission_replay_protection = True
spend_lease_receipt_hash = stored.spend_lease_receipt_hash
pt = None
UNSHARDED = 0
AuthorizeOutcome = NS(REPLAY="replay", ADMISSION_SCOPE_CONFLICT="scope_conflict", IDEMPOTENCY_MISMATCH="mismatch")
class _Reject(Exception):
    pass

def read_gateway_authorization_admission_columns(transaction, tables, authorization_id):
    assert authorization_id == stored.id
    return {"spend_lease_receipt_hash": stored.spend_lease_receipt_hash}

replayed = _replay(None, {"authorization_id": stored.id, "reservation_id": stored.credit_reservation_id})
assert replayed["outcome"] == "replay"

# Execute gateway.py:1366 replay builder and its real serialization helpers.
extract("routes/internal/gateway.py", "_replay_response", "_gateway_authorize_response",
        "_gateway_stage_d_payload", "_gateway_spend_lease_payload", "_gateway_candidate_payload",
        "_gateway_snapshot_candidate_payload", "_gateway_provider_route_payload", "_gateway_byok_payload")
extract("money.py", "money_pair", "microdollars_to_float")
MICRODOLLARS_PER_DOLLAR = 1_000_000
extract("regions.py", "region_payload")
settings = NS(primary_region="us-central1", multi_region_enabled=True,
              api_base_url="https://api.trustedrouter.com/v1",
              regional_api_hostname_template="api-{region}.quillrouter.com")
choose_region = lambda settings: settings.primary_region
configured_regions = lambda settings: [r["id"] for r in data["regions"]]
time = NS(time=lambda: 2_000_000_005)
PROVIDERS = {"anthropic": NS(name="Anthropic")}
PRIVATE_PROXY_MODEL_TARGETS = {}
REQUEST_METADATA_VERSION = 1
POLYPHEMUS_SELECT_ROUTE_TYPE = "polyphemus.select"
body = NS(route_type=request["route_type"])
workspace = NS(id=data["workspace_id"])
api_key = NS(hash=data["api_key_hash"])
model = NS(id=data["model"])
endpoint = NS(id=data["endpoint_id"], provider=data["provider"], upstream_id=data["upstream_model"])
endpoint_candidates = [(model, endpoint)]
_authorization_endpoint_candidates = lambda authorization, candidates: candidates
requested_model_id = data["requested_model"]
region = data["region"]
broadcast_destinations = []
custom_model = None
admission_remaining_micro = data["spend_lease"]["remaining_micro"]
admission_snapshot_candidates = tuple(claims["catalog"]["candidates"])
result = _replay_response(stored)
raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
target = fixtures / "stage_c_replay_response.json"
if "--check" in sys.argv:
    assert target.read_bytes() == raw, "replay fixture differs from router serializer"
else:
    target.write_bytes(raw)
print("PASS: router stored-receipt replay + serializer matches literal fixture")
