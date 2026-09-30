package speculation

import "strings"

const workspaceReasons = "credit_exhausted billing_denied trust_ineligible trust_demoted abuse_latched payment_failed trust_reconciliation_stale workspace_paused billing_paused"
const keyReasons = "key_revoked key_disabled key_expired key_invalid key_limit_exceeded key_window_limit_exceeded key_strict_limit_exceeded key_spend_limit_imposed"

func member(s, values string) bool {
	for _, v := range strings.Fields(values) {
		if s == v {
			return true
		}
	}
	return false
}

// VerdictInput contains one normalized, authenticated router reason. Upstream
// normalization selects workspace state before key state, then rate limiting.
type VerdictInput struct {
	Source      string
	Status      any
	Reason      string
	WorkspaceID string
	KeyID       string
	RateScope   string
}

// Verdict is a pure plan for a denial, not a durable state update.
type Verdict struct {
	DiscardThisExecution               bool   `json:"discard_this_execution"`
	DurableScope                       string `json:"durable_scope"`
	LocalInfrastructureBreaker         string `json:"local_infrastructure_breaker"`
	CommitRequiredWithRealRights       bool   `json:"commit_required_with_real_rights"`
	CommitRequiredShadowOnly           bool   `json:"commit_required_shadow_only"`
	StorageFailureStatusWithRealRights int64  `json:"storage_failure_status_with_real_rights"`
}

// ClassifyVerdict refuses provider responses and preserves state-reason priority.
func ClassifyVerdict(in VerdictInput) (verdict Verdict, err error) {
	defer refusal(&err)
	require(in.Source == "authenticated_router", "verdict_source")
	status := integer(in.Status)
	require(status >= 400 && status <= 599, "verdict_status")
	scope := "none"
	if member(in.Reason, keyReasons) && in.WorkspaceID != "" && in.KeyID != "" {
		scope = "key"
	} else if in.WorkspaceID != "" && (member(in.Reason, workspaceReasons) || status == 402) {
		scope = "workspace"
	} else if status == 429 && in.WorkspaceID != "" {
		scope = "workspace"
		if in.RateScope == "key" && in.KeyID != "" {
			scope = "key"
		}
	}
	breaker := "none"
	if scope == "none" && (status >= 500 || member(in.Reason, "authorize_timeout transport_error infrastructure_error")) {
		breaker = "key_boot"
	}
	failure := status
	if scope != "none" {
		failure = 503
	}
	return Verdict{true, scope, breaker, scope != "none", false, failure}, nil
}
