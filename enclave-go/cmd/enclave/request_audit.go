package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const errorIdentityLookupTimeout = 750 * time.Millisecond

// requestAuditIdentity contains only content-free identifiers. The credential
// fingerprint is the same one-way lookup digest already sent to the control
// plane; credentialID is the salted stored-key digest returned by that plane.
// Neither value can be used as an API credential.
type requestAuditIdentity struct {
	credentialFingerprint string
	workspaceID           string
	credentialID          string
	attribution           string
	rejectionStatus       int
	rejectionParameter    string
}

func (identity *requestAuditIdentity) bindBearer(bearer string) {
	if bearer == "" {
		identity.attribution = "anonymous"
		return
	}
	identity.credentialFingerprint = trustedrouter.LookupHash(bearer)
	identity.attribution = "fingerprint_only"
}

func (identity *requestAuditIdentity) bindAuthorization(authorization *trustedrouter.Authorization) {
	if authorization == nil {
		return
	}
	identity.workspaceID = authorization.WorkspaceID
	identity.credentialID = authorization.APIKeyHash
	identity.attribution = "authorization"
}

// resolveFailure fills the ownership gap for requests rejected before the
// normal billing authorization call. Validation is metadata-only and creates
// no hold. It runs only for failed requests, after the response bytes have
// already been written, so successful-request latency and billing are
// unchanged. The bounded timeout prevents observability from delaying close.
func (identity *requestAuditIdentity) resolveFailure(
	ctx context.Context,
	gateway *trustedrouter.Client,
	bearer string,
	route string,
	status int,
) {
	if status > 0 && status < 400 {
		return
	}
	if identity.workspaceID != "" || bearer == "" || gateway == nil || !gateway.Enabled() {
		return
	}
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), errorIdentityLookupTimeout)
	defer cancel()
	lookupCtx = trustedrouter.WithContractRejection(lookupCtx, identity.rejectionStatus, identity.rejectionParameter)
	verified, err := gateway.ValidateKeyInfo(lookupCtx, bearer, route)
	if err != nil || verified == nil || verified.WorkspaceID == "" {
		identity.attribution = "unresolved"
		return
	}
	identity.workspaceID = verified.WorkspaceID
	identity.credentialID = verified.APIKeyHash
	identity.attribution = "validation"
}

func (identity *requestAuditIdentity) recordContractRejection(
	w io.Writer, requestLogID string, route string, status int, parameter string,
) {
	identity.rejectionStatus = status
	identity.rejectionParameter = trustedrouter.ContractParameterCategory(parameter)
	writeRequestContractRejection(w, requestLogID, route, status, parameter)
}

func writeRequestStartLog(
	w io.Writer,
	requestLogID string,
	method string,
	route string,
	bodyBytes int,
	identity requestAuditIdentity,
) {
	fmt.Fprintf(w,
		"enclave.request_start request_log_id=%q method=%q route=%q body_bytes=%d credential_fingerprint=%q\n",
		requestLogID,
		method,
		route,
		bodyBytes,
		identity.credentialFingerprint,
	)
}

// request_end timing fields follow requesttiming's phase-sum contract:
// accept_to_start + authorize + route + upstream + retry_wait + settle + receipt
// equals elapsed before truncation when Start/invoke occur, authorization is
// serial and between Start and first invoke, retry waits are complete and
// disjoint from each other and other phases, settlement is outside pre-invoke
// phases/retry waits, and retry waits/settlements cover all gaps between
// invocations. Upstream is a
// wall-clock union; settle excludes that union, counting overlap only once.
// Partial means any invocation is active at End, including normal streams;
// its elapsed part runs through End and receipt is zero. Otherwise receipt is
// the post-invocation tail minus settlement in that tail. Rejections, concurrent
// authorization/retry work, unfinished waits and unmeasured orchestration gaps
// need not sum to elapsed. Logged millisecond truncation can also lower the sum.
func writeRequestEndLog(
	w io.Writer,
	requestLogID string,
	method string,
	route string,
	status int,
	bodyBytes int,
	responseBytes int,
	elapsed time.Duration,
	identity requestAuditIdentity,
	outcome string,
	phases requesttiming.Fields,
) {
	if outcome == "" {
		outcome = outcomeForStatus(status)
	}
	if phases.SettleOutcome == "" {
		phases.SettleOutcome = "skipped"
	}
	fmt.Fprintf(w,
		"enclave.request_end request_log_id=%q method=%q route=%q status=%d outcome=%q body_bytes=%d response_bytes=%d elapsed_ms=%d workspace_id=%q credential_id=%q credential_fingerprint=%q attribution=%q accept_to_start_ms=%d authorize_ms=%d authorize_attempts=%d route_ms=%d upstream_ms=%d upstream_partial=%d ttfb_ms=%d retry_wait_ms=%d settle_ms=%d settle_outcome=%q receipt_ms=%d cp_endpoint=%q\n",
		requestLogID,
		method,
		route,
		status,
		outcome,
		bodyBytes,
		responseBytes,
		elapsed.Milliseconds(),
		identity.workspaceID,
		identity.credentialID,
		identity.credentialFingerprint,
		identity.attribution,
		phases.AcceptToStartMS,
		phases.AuthorizeMS,
		phases.AuthorizeAttempts,
		phases.RouteMS,
		phases.UpstreamMS,
		phases.UpstreamPartial,
		phases.TTFBMS,
		phases.RetryWaitMS,
		phases.SettleMS,
		phases.SettleOutcome,
		phases.ReceiptMS,
		phases.CPEndpoint,
	)
}

// writeRequestContractRejection records only the bounded option name and
// status. It deliberately excludes the request body and field value. The
// enclave has no Sentry SDK. recordContractRejection also attaches a sanitized
// category to the existing post-response lookup for a control-plane warning.
func writeRequestContractRejection(
	w io.Writer,
	requestLogID string,
	route string,
	status int,
	parameter string,
) {
	parameter = trustedrouter.ContractParameterCategory(parameter)
	fmt.Fprintf(
		w,
		"enclave.request_contract_rejected request_log_id=%q route=%q status=%d parameter=%q\n",
		requestLogID,
		route,
		status,
		parameter,
	)
}
