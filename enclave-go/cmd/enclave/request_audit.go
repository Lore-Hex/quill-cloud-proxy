package main

import (
	"context"
	"fmt"
	"io"
	"time"

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
	verified, err := gateway.ValidateKeyInfo(lookupCtx, bearer, route)
	if err != nil || verified == nil || verified.WorkspaceID == "" {
		identity.attribution = "unresolved"
		return
	}
	identity.workspaceID = verified.WorkspaceID
	identity.credentialID = verified.APIKeyHash
	identity.attribution = "validation"
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
) {
	fmt.Fprintf(w,
		"enclave.request_end request_log_id=%q method=%q route=%q status=%d outcome=%q body_bytes=%d response_bytes=%d elapsed_ms=%d workspace_id=%q credential_id=%q credential_fingerprint=%q attribution=%q\n",
		requestLogID,
		method,
		route,
		status,
		outcomeForStatus(status),
		bodyBytes,
		responseBytes,
		elapsed.Milliseconds(),
		identity.workspaceID,
		identity.credentialID,
		identity.credentialFingerprint,
		identity.attribution,
	)
}
