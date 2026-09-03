#!/usr/bin/env bash
# Shared, source-only helpers for the Stage D per-instance rollout gate.

stage_d_select_probe_key() {
  local heartbeat_flag="$1" project="$2" region="$3"
  STAGE_D_PROBE_KEY="${STAGE_D_PROBE_API_KEY:-}"

  if [ -n "${STAGE_D_PROBE_KEY}" ]; then
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
}

stage_d_evidence_state() {
  local evidence_file="$1" gateway_request_id="$2"
  local heartbeat_flag="$3" expected_boot_kid="$4"

  jq -er \
    --arg gateway_request_id "${gateway_request_id}" \
    --arg heartbeat_flag "${heartbeat_flag}" \
    --arg expected_boot_kid "${expected_boot_kid}" '
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
        (.data.authorization_id | type == "string" and test("^[0-9a-f]{32}$")) and
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

      if exact_shape | not then
        error("authorization lookup response does not have the literal Stage D shape")
      elif .data.gateway_request_id != $gateway_request_id then
        error("authorization lookup returned a different gateway_request_id")
      elif .data.settled == false then
        "pending"
      elif .data.authorization_kind != "local_typed" then
        error("Stage D probe key did not produce authorization_kind local_typed")
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
