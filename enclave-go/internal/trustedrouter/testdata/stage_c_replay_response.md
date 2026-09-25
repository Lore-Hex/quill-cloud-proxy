<!-- Router source: Lore-Hex/quill-router be3661239a2d5e7b6e787d80dd5fc5c7d78675eb,
 src/trusted_router/routes/internal/gateway.py:1366-1405 (stored replay),
 :2970-3101 (serializer), :3036-3041 (stored nonce), :3053-3063 (marker);
 src/trusted_router/storage_gcp_authorize.py:465-498 (stored receipt replay).
 These comments deliberately live beside the literal, not inside JSON. -->

`stage_c_replay_response.json` is sorted-key compact canonical JSON, with no
trailing newline. Its inputs reuse the existing `stage_c` fixed seed, lease,
receipt, authorization `gwa-stage-c-fixture` and reservation `res-stage-c-fixture`.
It is a stored replay, with `invocation_nonce: null`, not a fresh acceptance.

`tools/generate_e0_router_replay_fixture.py <router-checkout> --check` executes
unmodified function ASTs extracted from the pinned router, backed by seeded
stored authorization/receipt state. Storage reads, catalog/provider records,
configuration and time are explicit harness adapters. It executes the actual
storage `_replay`, receipt classification, `_replay_response`, serializer and
serialization helpers. It does not import the complete router application or
exercise a live database. The later router PR should verify this same literal
through its integrated store/route harness.

All paths below are relative to `src/trusted_router/` in that router snapshot.
Every field, including nested fields, is accounted for:

| JSON fields | Source / fixed input |
| --- | --- |
| `data` | `routes/internal/gateway.py:3010`, serializer envelope |
| `authorization_id` | `:3012`, stored authorization ID; storage replay preserves it at `storage_gcp_authorize.py:495` |
| `workspace_id`, `api_key_hash` | `:3013-3014`; authenticated workspace/key passed by replay builder `:1386-1387`; existing fixture identities |
| `model`, `endpoint_id`, `provider` | `:3015,3017-3018`; stored route resolution in `:1375-1378`; existing fixture model/endpoint/provider |
| `upstream_model` | `:2999-3003,3016`; frozen lease catalog's `upstream_model` |
| `provider_name` | `:3019`; `PROVIDERS["anthropic"].name`, `Anthropic` |
| `requested_model` | `:3021`; request's fixture model passed at `:1390` |
| `response_model`, `hide_public_metadata` | `:2994-2996,3022-3023`; no private alias, null/false |
| `usage_type`, `limit_usage_type` | `:3024-3025`; stored endpoint Credits and stored authorization Credits (`:1379,1391-1392`) |
| `estimated_cost`, `estimated_cost_microdollars` | `:3026`; stored estimate 634 (`:1393`), `money.py:26-33` emits 0.000634 and 634 |
| `credit_reservation_id` | `:3027`; stored reservation (`:1394`), replay preserves at `storage_gcp_authorize.py:494` |
| `byok_secret_ref`, `byok_encrypted_secret`, `byok_cache_key`, `byok_key_hint`, `byok_provider` | `:3028`; `_gateway_byok_payload` `:4875-4884`, no BYOK on Credits, all null |
| `content_storage_enabled` | `:3029`, literal false |
| `region` | `:3030`; stored authorization region `us-central1` (`:1396`) |
| `regions[]`: `id`, `name`, `primary`, `enabled`, `api_base_url`, `control_plane_url` | `:3031`; `regions.py:199-225`, existing fixture's four configured regions, primary `us-central1`, multi-region enabled, canonical primary API URL and regional hostname template; control-plane URLs null |
| `broadcast_destinations` | `:3032`; replay builder argument `:1398`, empty list |
| `idempotent_replay` | `:3033`; replay builder passes true (`:1400`) |
| `invocation_nonce` | `:3038`; **stored** original `body.invocation_nonce` (`:1945`), absent Stage C request becomes null |
| `additional_cost_reservation_microdollars`, `receipt_fee_basis_points`, `native_batch_eligible` | `:3042-3048`; stored authorization 0, 0, false |
| `request_metadata_version` | `:3046`; `REQUEST_METADATA_VERSION = 1` (`:297`) |
| `stage_d.eligible`, `stage_d.reason` | `:3049`; replay override `"replayed"` (`:1402`), `_gateway_stage_d_payload` `:3146-3152` emits false/"replayed" |
| `spend_lease.token` | `:3050-3052`; stored original fixture token (`:3173`) |
| `spend_lease.lease_status` | `:3176-3182`; stored active status, frozen time 2000000005 precedes expiration 2000000060 |
| `spend_lease.remaining_micro` | `:3183-3185`; current ledger value 999366, read on replay `:2055-2060` and passed via `:1403` |
| `spend_lease_admission.accepted`, `.receipt_hash` | `:3055-3062`; true plus stored receipt hash, after equality/scope checks in `storage_gcp_authorize.py:465-489` and `spend_lease_admission.py:197-207` |
| `tags` | `:3065`; stored empty authorization tags |
| `custom_model` | `:3066-3075`; none, null |
| `route_candidates[]`: `endpoint_id`, `model`, `provider`, `provider_name`, `region` | `:3076-3100`, `_gateway_snapshot_candidate_payload` `:4849-4867` uses `_gateway_candidate_payload` `:4824-4846` with stored route and region |
| `route_candidates[].upstream_model`, `.usage_type` | `:4860-4861`; frozen catalog dispatch values |
| `route_candidates[]` BYOK fields (same five as top level) | `:4844`, `_gateway_byok_payload` `:4875-4884`; all null |

The false frozen `wafer_zdr_required` is omitted by `:3004-3009,4862-4866`.
Replay Stage D suppression omits `candidate_prices` and `cap_micro`.

## Reconciliation evidence boundary

The approved `docs/design/stage-c-wire-reconciliation.md` supersedes this seeded
AST oracle as acceptance evidence. This literal and the accepted response are
legacy serializer/decoder fixtures, not outputs from a passing integrated R0.
Keep all fields when comparing canonical responses. The amended router candidate
must produce accepted and replay literals through the real route after commit,
then copy both byte-for-byte here (landing order item 4). Do not silently remove
Stage D pricing/cap fields or regenerate this legacy fixture to bless drift.
The Go transport-loss tests consume the exact current replay literal at both
boundaries; they prove enclave decoding/ownership, not router allocation safety.
