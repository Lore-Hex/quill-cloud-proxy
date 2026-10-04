# Go speculation mutation results

Every mutant ran the full 442 protocol + 24 verdict corpus, fixture pins and equality regressions in a temporary copy. Baseline passed. No git commands were used. `Selected` indicates whether the inventory's named literal failed.

| Mutation | Result | Selected | Failing test |
|---|---|---|---|
| integer:guard:0:integer | red | true | TestLiterals/money_negative |
| stringValue:guard:0:string | red | true | TestLiterals/string_empty |
| stringValue:guard:1:string | red | true | TestLiterals/string_less |
| hashValue:guard:0:hash | red | true | TestLiterals/hash_type |
| hashValue:guard:1:hash | red | true | TestLiterals/invalid_hash |
| object:guard:1:fields | red | true | TestLiterals/unknown_field |
| byteRule:guard:0:json | red | true | TestLiterals/payload_escaped_ascii |
| depthCheck:guard:0:json | red | true | TestLiterals/depth17 |
| parseJSON:guard:1:duplicate_key | red | true | TestLiterals/payload_duplicate |
| rawInteger:guard:0:integer | survived | false | — |
| rawInteger:guard:1:integer | red | true | TestLiterals/header_number_negative |
| verify:guard:0:compact | red | true | TestLiterals/compact_extra |
| verify:guard:1:canonical_header | red | true | TestLiterals/header_whitespace |
| verify:guard:2:algorithm | red | true | TestLiterals/algorithm_none |
| verify:guard:3:type | red | true | TestLiterals/unknown_type |
| verify:guard:4:key | red | true | TestLiterals/key_ambiguous |
| verify:guard:5:purpose | red | true | TestLiterals/real_type_shadow_key |
| verify:guard:6:fields | survived | false | — |
| routeSchema:guard:0:stage_d | red | true | TestLiterals/precedence_stage_schema_version |
| grantSchema:guard:0:permits | red | true | TestLiterals/empty_permits |
| CostCeiling:guard:0:overflow | red | true | TestLiterals/money_product_overflow |
| CostCeiling:guard:1:overflow | red | true | TestLiterals/money_sum_overflow |
| VerifyGrant:guard:0:version | red | true | TestLiterals/unknown_version |
| VerifyGrant:guard:1:identity | red | true | TestLiterals/identity_iss |
| VerifyGrant:guard:2:binding | red | true | TestLiterals/binding_key_id |
| VerifyGrant:guard:3:stage_d | red | true | TestLiterals/stage_d_false |
| VerifyGrant:guard:4:route | red | true | TestLiterals/route_endpoint_id |
| VerifyGrant:guard:5:route | red | true | TestLiterals/route_region_disagrees |
| VerifyGrant:guard:6:token_bound | red | true | TestLiterals/output_bound_over |
| VerifyGrant:guard:7:adapter | red | true | TestLiterals/adapter_zero |
| VerifyGrant:guard:8:tier | red | true | TestLiterals/tier_one |
| VerifyGrant:guard:9:paid_headroom | red | true | TestLiterals/unpaid |
| VerifyGrant:guard:10:history_count | red | true | TestLiterals/history_19 |
| VerifyGrant:guard:11:history_time | red | true | TestLiterals/stale_last_success |
| VerifyGrant:guard:12:lifetime | red | true | TestLiterals/ttl_too_long |
| VerifyGrant:guard:13:start_window | red | true | TestLiterals/start_plus_28 |
| VerifyGrant:guard:14:ceiling | red | true | TestLiterals/over_cap_money |
| VerifyGrant:guard:15:cost | red | true | TestLiterals/cost_10001 |
| VerifyGrant:guard:16:ordinal | red | true | TestLiterals/duplicate_ordinal |
| VerifyGrant:guard:17:permit_cost | red | true | TestLiterals/underfunded_permit |
| VerifyGrant:guard:18:tier_ceiling | red | true | TestLiterals/missing_tier_ceiling |
| VerifyGrant:guard:19:allowance | red | true | TestLiterals/allowance_sum_not_max |
| VerifyDescriptor:guard:0:dry_run_cannot_dispatch | red | true | TestLiterals/dry_run_cannot_dispatch |
| VerifyDescriptor:guard:1:version | red | true | TestLiterals/descriptor_version |
| VerifyDescriptor:guard:2:descriptor_boot | red | true | TestLiterals/descriptor_wrong_boot_signer |
| VerifyDescriptor:guard:3:descriptor_binding | red | true | TestLiterals/descriptor_key_id |
| VerifyDescriptor:guard:4:grant_hash | red | true | TestLiterals/descriptor_shadow_hash |
| VerifyDescriptor:guard:5:request_hash | red | true | TestLiterals/descriptor_wire_lf |
| VerifyDescriptor:guard:6:invocation | red | true | TestLiterals/descriptor_nonce |
| VerifyDescriptor:guard:8:descriptor_route | red | true | TestLiterals/descriptor_endpoint |
| VerifyDescriptor:guard:11:descriptor_permit | red | true | TestLiterals/descriptor_ordinal |
| VerifyAcceptance:guard:0:authorization | red | true | TestLiterals/response_stage_d_integer |
| VerifyAcceptance:guard:1:authorization | red | true | TestLiterals/marker_unmarked_key |
| VerifyAcceptance:guard:2:authorization | red | true | TestLiterals/unmarked_spend_lease |
| VerifyAcceptance:guard:3:version | red | true | TestLiterals/marker_version |
| VerifyAcceptance:guard:4:descriptor_hash | red | true | TestLiterals/marker_hash |
| VerifyAcceptance:guard:5:marker_binding | red | true | TestLiterals/marker_invocation_nonce |
| VerifyAcceptance:guard:6:authorization | red | true | TestLiterals/marker_authorization_id |
| VerifyAcceptance:guard:7:authorization | red | true | TestLiterals/authorization_stage_d |
| RenewalVerdict:guard:0:renewal | red | true | TestLiterals/renewal_domain_isolated |
| RenewalVerdict:guard:1:renewal | red | true | TestLiterals/renewal_boot_changed |
| RenewalVerdict:guard:2:renewal | red | true | TestLiterals/renewal_same_generation |
| RenewalVerdict:guard:5:renewal | red | true | TestLiterals/renewal_old_history_sequence |
| DescriptorReplay:guard:0:replay_conflict | red | true | TestLiterals/descriptor_permit_reuse |
| ClassifyVerdict:guard:0:verdict_source | red | true | TestLiterals/provider_source |
| ClassifyVerdict:guard:1:verdict_status | red | true | TestLiterals/success_status |
| dry-run accepted as real | red | true | TestLiterals/dry_run_cannot_dispatch |
| ignore binding workspace_id | red | true | TestLiterals/binding_workspace_id |
| ignore binding key_id | red | true | TestLiterals/binding_key_id |
| ignore binding lookup_digest | red | true | TestLiterals/binding_lookup_digest |
| ignore binding boot_id | red | true | TestLiterals/binding_boot_id |
| ignore binding stable_slot_id | red | true | TestLiterals/binding_stable_slot_id |
| ignore binding region | red | true | TestLiterals/binding_region |
| ignore binding generation | red | true | TestLiterals/binding_generation |
| ignore binding workspace_epoch | red | true | TestLiterals/binding_workspace_epoch |
| ignore binding key_epoch | red | true | TestLiterals/binding_key_epoch |
| ignore binding image_policy_version | red | true | TestLiterals/binding_image_policy_version |
| ignore route binding | red | true | TestLiterals/route_endpoint_id |
| all 402 to workspace | red | true | TestVerdicts/lifetime_limit |
| all 429 to key | red | true | TestVerdicts/rate_workspace |
| round B down | red | true | TestLiterals/money_fractional |
| shadow-purpose key for real grant | red | true | TestLiterals/real_type_shadow_key |
| skip canonical payload | red | true | TestLiterals/payload_whitespace |
| accept padded base64 | red | true | TestLiterals/signature_padded |
| accept CR LF in base64 | red | true | TestLiterals/base64_cr |
| skip byte rule | red | true | TestLiterals/trailing_newline |
| semantic check before syntax | red | true | TestLiterals/payload_number_later_syntax |
| duplicate detection disabled | red | true | TestLiterals/payload_duplicate |
| float accepted as integer | red | true | TestLiterals/context_coercion_input_rate_micro_per_m |
| Ed25519 wrong-length key panics | red | true | TestLiterals/key_short_public |
| fixture byte changed | red | true | TestFixturePins |
| VerifyGrant:skip identity_iss | red | true | TestLiterals/identity_iss |
| VerifyGrant:skip identity_aud | red | true | TestLiterals/identity_aud |
| VerifyGrant:skip identity_environment | red | true | TestLiterals/identity_environment |
| VerifyGrant:skip identity_plane | red | true | TestLiterals/identity_plane |
| VerifyDescriptor:skip descriptor_grant_id | red | true | TestLiterals/descriptor_grant_id |
| VerifyDescriptor:skip descriptor_workspace_id | red | true | TestLiterals/descriptor_workspace_id |
| VerifyDescriptor:skip descriptor_key_id | red | true | TestLiterals/descriptor_key_id |
| VerifyDescriptor:skip descriptor_boot_id | red | true | TestLiterals/descriptor_boot_id |
| VerifyDescriptor:skip descriptor_workspace_epoch | red | true | TestLiterals/descriptor_workspace_epoch |
| VerifyDescriptor:skip descriptor_key_epoch | red | true | TestLiterals/descriptor_key_epoch |
| RenewalVerdict:skip renewal_identity_workspace_id | red | true | TestLiterals/renewal_identity_workspace_id |
| RenewalVerdict:skip renewal_identity_key_id | red | true | TestLiterals/renewal_identity_key_id |
| RenewalVerdict:skip renewal_identity_lookup_digest | red | true | TestLiterals/renewal_identity_lookup_digest |
| RenewalVerdict:skip renewal_identity_boot_id | red | true | TestLiterals/renewal_identity_boot_id |
| RenewalVerdict:skip renewal_identity_stable_slot_id | red | true | TestLiterals/renewal_identity_stable_slot_id |
| RenewalVerdict:skip renewal_identity_iss | red | true | TestLiterals/renewal_identity_iss |
| RenewalVerdict:skip renewal_identity_aud | red | true | TestLiterals/renewal_identity_aud |
| RenewalVerdict:skip renewal_identity_environment | red | true | TestLiterals/renewal_identity_environment |
| RenewalVerdict:skip renewal_identity_plane | red | true | TestLiterals/renewal_identity_plane |
| RenewalVerdict:skip renewal_identity_region | red | true | TestLiterals/renewal_identity_region |
| VerifyAcceptance:skip unmarked_invocation_nonce | red | true | TestLiterals/unmarked_invocation_nonce |
| VerifyAcceptance:skip unmarked_workspace_id | red | true | TestLiterals/unmarked_workspace_id |
| VerifyAcceptance:skip unmarked_key_id | red | true | TestLiterals/unmarked_key_id |
| VerifyAcceptance:skip marker_invocation_nonce | red | true | TestLiterals/marker_invocation_nonce |
| VerifyAcceptance:skip marker_endpoint_id | red | true | TestLiterals/marker_endpoint_id |
| VerifyAcceptance:skip marker_routing_policy_hash | red | true | TestLiterals/marker_routing_policy_hash |
| VerifyAcceptance:skip authorization_authorization_id | red | true | TestLiterals/authorization_authorization_id |
| VerifyAcceptance:skip authorization_invocation_nonce | survived | false | — |
| VerifyAcceptance:skip authorization_endpoint_id | red | true | TestLiterals/authorization_endpoint_id |
| VerifyAcceptance:skip authorization_routing_policy_hash | red | true | TestLiterals/authorization_routing_policy_hash |
| VerifyAcceptance:skip authorization_workspace_id | survived | false | — |
| VerifyAcceptance:skip authorization_key_id | survived | false | — |
| VerifyGrant:skip check route_policy_hash_format | red | true | TestLiterals/route_policy_hash_format |
| VerifyGrant:skip check route_hash_bad | red | true | TestLiterals/route_hash_bad |
| VerifyDescriptor:skip check descriptor_grant_hash_format | red | true | TestLiterals/descriptor_grant_hash_format |
| VerifyDescriptor:skip check descriptor_hash_malformed | red | true | TestLiterals/descriptor_hash_malformed |
| VerifyDescriptor:skip check descriptor_route_hash_format | red | true | TestLiterals/descriptor_route_hash_format |
| VerifyDescriptor:skip check descriptor_endpoint | red | true | TestLiterals/descriptor_endpoint |
| VerifyDescriptor:skip check descriptor_routing_policy_hash | red | true | TestLiterals/descriptor_routing_policy_hash |
| VerifyGrant:atom:input_bound_zero | red | true | TestLiterals/input_bound_zero |
| VerifyGrant:atom:input_bound_over | red | true | TestLiterals/input_bound_over |
| VerifyGrant:atom:output_bound_zero | red | true | TestLiterals/output_bound_zero |
| VerifyGrant:atom:output_bound_over | red | true | TestLiterals/output_bound_over |
| VerifyGrant:atom:history_19 | red | true | TestLiterals/history_19 |
| VerifyGrant:atom:history_retry_dedupe | red | true | TestLiterals/history_retry_dedupe |
| VerifyGrant:atom:old_history_window | red | true | TestLiterals/old_history_window |
| VerifyGrant:atom:future_history_window | red | true | TestLiterals/future_history_window |
| VerifyGrant:atom:future_last_success | red | true | TestLiterals/future_last_success |
| VerifyGrant:atom:stale_last_success | red | true | TestLiterals/stale_last_success |
| VerifyGrant:atom:unclean_history | red | true | TestLiterals/unclean_history |
| VerifyGrant:atom:ttl_zero | red | true | TestLiterals/ttl_zero |
| VerifyGrant:atom:ttl_too_long | red | true | TestLiterals/ttl_too_long |
| VerifyGrant:atom:start_before_issue | red | true | TestLiterals/start_before_issue |
| VerifyGrant:atom:future_iat | red | true | TestLiterals/future_iat |
| VerifyGrant:atom:start_plus_28 | red | true | TestLiterals/start_plus_28 |
| VerifyGrant:atom:zero_ceiling | red | true | TestLiterals/zero_ceiling |
| VerifyGrant:atom:over_cap_money | red | true | TestLiterals/over_cap_money |
| VerifyGrant:atom:cost_zero | red | true | TestLiterals/cost_zero |
| VerifyGrant:atom:cost_10001 | red | true | TestLiterals/cost_10001 |
| VerifyGrant:atom:underfunded_permit | red | true | TestLiterals/underfunded_permit |
| VerifyGrant:atom:over_cap_permit | red | true | TestLiterals/over_cap_permit |
| VerifyDescriptor:atom:descriptor_execution | red | true | TestLiterals/descriptor_execution |
| VerifyDescriptor:atom:descriptor_nonce | red | true | TestLiterals/descriptor_nonce |
| VerifyDescriptor:atom:descriptor_ordinal | red | true | TestLiterals/descriptor_ordinal |
| VerifyDescriptor:atom:descriptor_cost | red | true | TestLiterals/descriptor_cost |
| VerifyAcceptance:atom:authorization_stage_d | red | true | TestLiterals/authorization_stage_d |
| RenewalVerdict:atom:renewal_same_grant_id | red | true | TestLiterals/renewal_same_grant_id |
| RenewalVerdict:atom:renewal_same_generation | red | true | TestLiterals/renewal_same_generation |
| RenewalVerdict:atom:renewal_old_iat | red | true | TestLiterals/renewal_old_iat |
| RenewalVerdict:atom:renewal_old_workspace_epoch | red | true | TestLiterals/renewal_old_workspace_epoch |
| RenewalVerdict:atom:renewal_old_key_epoch | red | true | TestLiterals/renewal_old_key_epoch |
| RenewalVerdict:atom:renewal_old_history_sequence | red | true | TestLiterals/renewal_old_history_sequence |
| ClassifyVerdict:atom:success_status | red | true | TestLiterals/success_status |
| ClassifyVerdict:atom:verdict_status_upper | red | true | TestLiterals/verdict_status_upper |
| allowance tier | red | true | TestLiterals/allowance_tier2 |
| allowance headroom | red | true | TestLiterals/allowance_odd_headroom |
| allowance cap | red | true | TestLiterals/allowance_dollar_cap |
| deadline short_explicit_at | red | true | TestLiterals/short_explicit_at |
| deadline short_expiry_at | red | true | TestLiterals/short_expiry_at |
| deadline short_key_at | red | true | TestLiterals/short_key_at |
| deadline short_price_at | red | true | TestLiterals/short_price_at |
| deadline short_trust_at | red | true | TestLiterals/short_trust_at |
| reason credit_exhausted | red | true | TestLiterals/reason_credit_exhausted |
| reason billing_denied | red | true | TestLiterals/reason_billing_denied |
| reason trust_ineligible | red | true | TestLiterals/reason_trust_ineligible |
| reason trust_demoted | red | true | TestLiterals/reason_trust_demoted |
| reason abuse_latched | red | true | TestLiterals/reason_abuse_latched |
| reason payment_failed | red | true | TestLiterals/reason_payment_failed |
| reason trust_reconciliation_stale | red | true | TestLiterals/reason_trust_reconciliation_stale |
| reason workspace_paused | red | true | TestLiterals/reason_workspace_paused |
| reason billing_paused | red | true | TestLiterals/reason_billing_paused |
| reason key_revoked | red | true | TestLiterals/reason_key_revoked |
| reason key_disabled | red | true | TestLiterals/reason_key_disabled |
| reason key_expired | red | true | TestLiterals/reason_key_expired |
| reason key_invalid | red | true | TestLiterals/reason_key_invalid |
| reason key_limit_exceeded | red | true | TestLiterals/reason_key_limit_exceeded |
| reason key_window_limit_exceeded | red | true | TestLiterals/reason_key_window_limit_exceeded |
| reason key_strict_limit_exceeded | red | true | TestLiterals/reason_key_strict_limit_exceeded |
| reason key_spend_limit_imposed | red | true | TestLiterals/reason_key_spend_limit_imposed |
| breaker authorize_timeout | red | true | TestLiterals/breaker_authorize_timeout |
| breaker transport_error | red | true | TestLiterals/breaker_transport_error |
| breaker infrastructure_error | red | true | TestLiterals/breaker_infrastructure_error |
| marker null treated as absent | red | true | TestLiterals/marker_null |
| renewal exact replay skipped | red | true | TestLiterals/renewal_exact_replay |
| permit sum uses max | red | true | TestLiterals/allowance_sum_not_max |
| skip payload byte precheck | red | true | TestLiterals/precedence_payload_bytes_signature |
| constant accepted | red | true | TestLiterals/nan |
| decode nonstrict trailing bits | red | true | TestLiterals/base64_trailing_bits |
| ordinary billing not required | red | true | TestLiterals/unmarked_spend_lease |
| storage failure preserves status | red | true | TestVerdicts/credit |
| string scalar type | survived | false | — |
| string lower bound | red | true | TestLiterals/context_string_control |
| string upper bound | red | true | TestLiterals/context_string_unicode |
| string forbidden characters | red | true | TestLiterals/string_less |
| object missing field set | survived | false | — |
| number syntax error code | red | true | TestLiterals/json_bad |
| base64 empty | red | true | TestLiterals/base64_empty |
| base64 decode error code | red | true | TestLiterals/base64_length |
| compact type predicate | survived | false | — |
| compact length limit | red | true | TestLiterals/compact_too_long |
| key selection | red | true | TestLiterals/real_valid |
| signature message | red | true | TestLiterals/real_valid |
| skip signature verification | red | true | TestLiterals/signature_bitflip |
| permit array type | survived | false | — |
| mandatory fees omitted | red | true | TestLiterals/money_fees |
| allowance tier rounds up | red | true | TestLiterals/allowance_odd_tier |
| missing binding presence | survived | false | — |
| skip context route schema | red | true | TestLiterals/context_coercion_stage_d |
| tier upper bound | red | true | TestLiterals/tier_four |
| key reason unresolved workspace | red | true | TestLiterals/verdict_key_without_workspace |
| key reason unresolved key | red | true | TestLiterals/verdict_key_without_key |
| workspace reason unresolved workspace | red | true | TestLiterals/verdict_workspace_without_workspace |
| skip workspace reason | red | true | TestLiterals/verdict_billing_paused |
| skip generic billing | red | true | TestLiterals/verdict_reasonless_402 |
| skip rate classification | red | true | TestVerdicts/rate_unknown |
| rate unresolved workspace | red | true | TestLiterals/verdict_rate_without_workspace |
| key rate unresolved key | red | true | TestLiterals/verdict_rate_key_missing_id |
| unknown rate treated as key | red | true | TestVerdicts/rate_unknown |
| breaker overrides scope | red | true | TestLiterals/verdict_workspace_reason_500 |
| skip generic infrastructure | red | true | TestLiterals/verdict_generic_500 |
| depth ignores quotes | red | true | TestLiterals/depth_in_string |
| depth never closes string | red | true | TestLiterals/depth17_after_string |
| depth never decrements | red | true | TestLiterals/depth_siblings |
| input refusal leaks panic | red | true | TestLiterals/input_boundary |
| shadow type ignored | red | true | TestLiterals/shadow_valid |
| shadow purpose ignored | red | true | TestLiterals/shadow_valid |
| byte upper bound | red | true | TestLiterals/raw_del |
| early float conversion | red | true | TestLiterals/payload_number_later_syntax |
| external int float equality | red | true | TestLiterals/response_nested_int_float |
| external bool integer equality | red | true | TestLiterals/response_nested_bool_int |
| external object key equality | red | true | TestLiterals/response_nested_keys |
| external array length equality | red | true | TestLiterals/response_nested_length |
| external array order equality | red | true | TestLiterals/response_nested_order |
| object root type | survived | false | — |
| exponent accepted as integer | red | true | TestLiterals/exponent |
| configured key error leaks base64 | red | true | TestLiterals/key_zero_public |
| equality unsupported values | red | true | TestEqualValues/unsupported |
| equality depth cutoff | red | true | TestLiterals/acceptance_depth_130_unmarked |
| equality identity sets removed | red | true | TestEqualRings/800_vs_801 |
| equality repeated containers accepted | red | true | TestEqualSharedDAG |
| equality left map identity ignored | red | true | TestEqualValues/shared_map_left |
| equality right map identity ignored | red | true | TestEqualValues/shared_map_right |
| equality empty traversal | red | true | TestLiterals/response_nested_order |
| equality successful completion | red | true | TestLiterals/acceptance_depth_130_unmarked |
| equality input identity sets merged | red | true | TestEqualValues/same_tree |
| equality left slice identity ignored | red | true | TestEqualValues/shared_slice_left |
| equality right slice identity ignored | red | true | TestEqualValues/shared_slice_right |
| equality slice view length | red | true | TestEqualValues/independent_views |
| equality member order dependent | red | true | TestEqualMemberOrder |
| equality empty map identity ignored | red | true | TestEqualValues/shared_empty_map |
| equality map children | red | true | TestLiterals/response_nested_bool_int |
| equality empty slice identity ignored | red | true | TestEqualValues/shared_empty_slice |

Red: 252; survived: 11; build-broken: 0; selected literal not red: 11.
