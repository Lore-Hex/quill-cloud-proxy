#!/usr/bin/env bash
# Shared, source-only helpers for the Stage D per-instance rollout gate.

stage_d_select_probe_key() {
  local heartbeat_flag="$1" project="$2" region="$3"
  STAGE_D_PROBE_KEY="${STAGE_D_PROBE_API_KEY:-}"

  if [ -n "${STAGE_D_PROBE_KEY}" ]; then
    STAGE_D_PROBE_KEY_NAME="STAGE_D_PROBE_API_KEY"
    STAGE_D_PROBE_KEY_IN_USE="on"
    return 0
  fi
  if [ "${heartbeat_flag}" = "on" ]; then
    echo "${region}: STAGE_D_PROBE_API_KEY is unavailable while QUILL_USAGE_HEARTBEAT=on; failing closed" >&2
    return 1
  fi

  echo "WARNING: ${region}: STAGE_D_PROBE_API_KEY is unavailable while QUILL_USAGE_HEARTBEAT=off; falling back to Secret Manager secret trustedrouter-synthetic-monitor-api-key for plain streaming health and settled authorization only" >&2
  STAGE_D_PROBE_KEY="$(gcloud secrets versions access latest \
    --secret=trustedrouter-synthetic-monitor-api-key \
    --project="${project}" 2>/dev/null || true)"
  if [ -z "${STAGE_D_PROBE_KEY}" ]; then
    echo "${region}: fallback synthetic monitor key is unavailable; failing closed" >&2
    return 1
  fi
  # These globals are consumed by the sourcing gate.
  # shellcheck disable=SC2034
  STAGE_D_PROBE_KEY_NAME="trustedrouter-synthetic-monitor-api-key"
  # shellcheck disable=SC2034
  STAGE_D_PROBE_KEY_IN_USE="off"
}

stage_d_accept_missing_evidence_route() {
  local heartbeat_flag="$1" http_code="$2" region="$3" stage="$4"

  if [ "${heartbeat_flag}" != "off" ] || [ "${http_code}" != "404" ]; then
    return 1
  fi
  if [ "${STAGE_D_MISSING_EVIDENCE_ROUTE_WARNED:-0}" != "1" ]; then
    echo "WARNING: ${region}: ${stage} authorization evidence route /internal/gateway/authorizations/by-gateway-request-id/{x-request-id} returned HTTP 404 while the selected template has QUILL_USAGE_HEARTBEAT=off; passing the gate on plain streaming health alone" >&2
    STAGE_D_MISSING_EVIDENCE_ROUTE_WARNED=1
  fi
}

stage_d_evidence_state() {
  local evidence_file="$1" gateway_request_id="$2"
  local heartbeat_flag="$3" expected_boot_kid="$4"
  local probe_key_in_use="$5"

  jq -er \
    --arg gateway_request_id "${gateway_request_id}" \
    --arg heartbeat_flag "${heartbeat_flag}" \
    --arg expected_boot_kid "${expected_boot_kid}" \
    --arg probe_key_in_use "${probe_key_in_use}" '
      def exact_shape:
        type == "object" and
        keys == ["data"] and
        (.data | type == "object") and
        (.data | keys) == [
          "authorization_id",
          "authorization_kind",
          "disposition",
          "gateway_request_id",
          "heartbeat_seq",
          "settled",
          "stage_d_boot_kid",
          "workspace_id"
        ] and
        (.data.authorization_id | type == "string" and test("^gwa-[0-9a-f]{32}$")) and
        (.data.gateway_request_id | type == "string" and test("^rlog_[0-9a-f]{32}$")) and
        (.data.workspace_id | type == "string" and length > 0) and
        (.data.authorization_kind | type == "string") and
        (.data.settled | type == "boolean") and
        ((.data.disposition | type) == "string" or
          (.data.disposition | type) == "null") and
        ((.data.stage_d_boot_kid | type) == "string" or
          (.data.stage_d_boot_kid | type) == "null") and
        (((.data.heartbeat_seq | type) == "number" and
          (.data.heartbeat_seq | floor) == .data.heartbeat_seq) or
          (.data.heartbeat_seq | type) == "null");

      if ($probe_key_in_use != "on" and $probe_key_in_use != "off") then
        error("probe key selection state is invalid")
      elif exact_shape | not then
        error("authorization lookup response does not have the literal Stage D shape")
      elif .data.gateway_request_id != $gateway_request_id then
        error("authorization lookup returned a different gateway_request_id")
      elif .data.settled == false then
        "pending"
      elif ($heartbeat_flag == "on" or $probe_key_in_use == "on") and
          .data.authorization_kind != "local_typed" then
        error("Stage D probe key did not produce authorization_kind local_typed")
      elif $probe_key_in_use == "off" and
          (.data.authorization_kind != "local_typed" and
            .data.authorization_kind != "regional_lease") then
        error("synthetic monitor key did not produce an accepted authorization_kind")
      elif $heartbeat_flag == "on" and .data.stage_d_boot_kid != $expected_boot_kid then
        error("authorization stage_d_boot_kid does not match the instance receipt")
      elif $heartbeat_flag == "on" and
          ((.data.heartbeat_seq | type) != "number" or .data.heartbeat_seq <= 0) then
        error("authorization heartbeat_seq is not positive")
      else
        "valid"
      end
    ' "${evidence_file}"
}
