package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type spendLeaseProtocol struct {
	signer        spendLeaseBootSigner
	state         *spendlease.ShadowState
	verifierReady bool
	now           func() time.Time
}

type spendLeaseBootSigner interface {
	spendlease.DigestSigner
	spendlease.MessageSigner
}

type BootRegistrationEvidence struct {
	Attestation     string
	AttestationKind string
}

// BootCapabilities is what this boot declares about itself when it registers
// (quill-router `GatewayBootCapabilities`). The control plane stores the
// declarations of the latest registration on the boot record; a missing
// declaration means undeclared. Declare only what this boot actually does.
type BootCapabilities struct {
	// UsageHeartbeat is true when this boot heartbeats every stream the router
	// marks Stage D eligible (QUILL_USAGE_HEARTBEAT). The heartbeat at stream
	// open (`stream_open_heartbeat`) is a separate declaration this enclave
	// does not make: its first heartbeat waits for the provider to answer.
	UsageHeartbeat bool
	// SettleOutbox is true when this boot parks a settle or refund it could
	// not deliver as a durable object for a later replay (E4 E3; the control
	// plane stores it as declares_settle_outbox, E4 R2). Declared only when
	// the outbox is configured and this build can write to it.
	SettleOutbox bool
}

// bootRegistrationCapabilities is the wire form. Only declarations that are
// true are sent, and with none the whole object is omitted, so a boot that
// declares nothing posts exactly the pre-capabilities registration body.
type bootRegistrationCapabilities struct {
	UsageHeartbeat bool `json:"usage_heartbeat,omitempty"`
	SettleOutbox   bool `json:"settle_outbox,omitempty"`
}

func (c BootCapabilities) wire() *bootRegistrationCapabilities {
	if !c.UsageHeartbeat && !c.SettleOutbox {
		return nil
	}
	return &bootRegistrationCapabilities{UsageHeartbeat: c.UsageHeartbeat, SettleOutbox: c.SettleOutbox}
}

// RegisteredBootSigner is the boot key a registration path was started for:
// Stage D, spend lease or the speculation shadow, in that order. nil when this
// boot registers nowhere, so the control plane knows no kid for it.
// Registration is asynchronous, so a non-nil signer means "the router was
// told this kid", not "the router verified it".
func (c *Client) RegisteredBootSigner() spendlease.DigestSigner {
	if signer := c.stageDBootDigestSigner(); signer != nil {
		return signer
	}
	if c != nil && c.shadowSigner != nil {
		return c.shadowSigner
	}
	return nil
}

type bootRegistrationRequest struct {
	KID                 string                        `json:"kid"`
	ReceiptPublicKey    receipt.JWK                   `json:"receipt_public_key"`
	AttestationEvidence string                        `json:"attestation_evidence"`
	AttestationKind     string                        `json:"attestation_kind"`
	Capabilities        *bootRegistrationCapabilities `json:"capabilities,omitempty"`
}

// DeclareBootCapabilities sets what every boot registration from this client
// declares, on whichever registration path the boot runs (Stage D, spend-lease
// or speculation shadow). Call it before any Start*BootRegistration: the
// registration goroutines read it without a lock.
func (c *Client) DeclareBootCapabilities(capabilities BootCapabilities) {
	if c != nil {
		c.bootCapabilities = capabilities
	}
}

// ConfigureSpendLeaseShadow enables only the additive Stage A protocol. It is
// called before the serving loop; a nil verifier keeps the protocol dormant.
func (c *Client) ConfigureSpendLeaseShadow(signer *receipt.Signer, verifier *spendlease.Verifier) {
	if c == nil || signer == nil {
		return
	}
	c.spendLease = &spendLeaseProtocol{
		signer: signer, state: spendlease.NewShadowState(verifier, signer.Kid()),
		verifierReady: verifier != nil, now: time.Now,
	}
}

// ConfigureSpendLeaseLocalAdmission makes authoritative verification and CAS
// admission consequential. Callers pass the separately allowlisted, default-
// off GCP boot flag; setting it false preserves Stage A behavior exactly.
func (c *Client) ConfigureSpendLeaseLocalAdmission(enabled bool) {
	if c == nil || c.spendLease == nil || c.spendLease.state == nil {
		return
	}
	c.spendLease.state.SetLocalAdmission(enabled)
}

// ConfigureStageDBoot installs the boot identity used to sign heartbeat and
// disposition calls without enabling the Stage A authorize echo.
func (c *Client) ConfigureStageDBoot(signer *receipt.Signer) {
	if c != nil && signer != nil {
		c.stageDBootSigner = signer
	}
}

func (c *Client) stageDBootDigestSigner() spendlease.DigestSigner {
	if c == nil {
		return nil
	}
	if c.stageDBootSigner != nil {
		return c.stageDBootSigner
	}
	if c.spendLease != nil {
		return c.spendLease.signer
	}
	return nil
}

// StartStageDBootRegistration registers the same attested boot key used by
// Stage A, but does not activate any lease echo or local lease state.
func (c *Client) StartStageDBootRegistration(ctx context.Context, signer *receipt.Signer, evidence func() BootRegistrationEvidence) {
	if c == nil || signer == nil || evidence == nil {
		return
	}
	go func() {
		if !c.registerAttestedBoot(ctx, signer, evidence, "stage_d", bootRegistrationRetryPolicy()) {
			return
		}
		fmt.Fprintf(os.Stderr, "stage_d.boot_registered kid=%q\n", signer.Kid())
	}()
}

// StartSpendLeaseBootRegistration is intentionally asynchronous and
// non-fatal. Missing evidence and rejected registrations retry with capped
// backoff until shutdown; ShadowState remains closed until verification succeeds.
func (c *Client) StartSpendLeaseBootRegistration(ctx context.Context, signer *receipt.Signer, evidence func() BootRegistrationEvidence) {
	if c == nil || c.spendLease == nil || signer == nil || evidence == nil {
		return
	}
	go func() {
		if !c.registerAttestedBoot(ctx, signer, evidence, "spendlease", bootRegistrationRetryPolicy()) {
			return
		}
		if c.spendLease.state == nil || !c.spendLease.verifierReady {
			fmt.Fprintln(os.Stderr, "spendlease.boot_registration_failed reason=boot_not_verified")
			return
		}
		c.spendLease.state.SetRegistered(true)
		fmt.Fprintf(os.Stderr, "spendlease.boot_registered kid=%q\n", signer.Kid())
	}()
}

func bootRegistrationRetryPolicy() retryPolicy {
	return normalizeRetryPolicy(retryPolicy{baseDelay: 5 * time.Second, maxDelay: time.Minute})
}

// Evidence is loaded anew on every round: an initial mint failure must not
// permanently disable registration after the attestation reminter recovers.
func (c *Client) registerAttestedBoot(ctx context.Context, signer *receipt.Signer, source func() BootRegistrationEvidence, label string, policy retryPolicy) bool {
	for attempt := 1; ctx.Err() == nil; attempt = min(attempt+1, 16) {
		evidence := source()
		reason := "attestation_unavailable"
		var retryAfter time.Duration
		if evidence.Attestation != "" && evidence.AttestationKind != "" {
			payload := bootRegistrationRequest{
				KID: signer.Kid(), ReceiptPublicKey: signer.JWK(),
				AttestationEvidence: evidence.Attestation, AttestationKind: evidence.AttestationKind,
				Capabilities: c.bootCapabilities.wire(),
			}
			var decoded struct {
				Data struct {
					Verified bool `json:"verified"`
				} `json:"data"`
			}
			err := c.postJSONWithRetry(ctx, spendlease.RegisterPath, payload, &decoded, c.authorizeRetry)
			if ctx.Err() != nil {
				return false
			}
			if err == nil && decoded.Data.Verified {
				return true
			}
			reason = "boot_not_verified"
			if err != nil {
				reason = "control_plane_unavailable"
				retryAfter = retryAfterDuration(err)
			}
		}
		delay := max(time.Second, authorizationRetryDelay(attempt, policy, retryAfter))
		fmt.Fprintf(os.Stderr, "%s.boot_registration_retry reason=%s attempt=%d delay_ms=%d\n", label, reason, attempt, delay.Milliseconds())
		if policy.sleep(ctx, delay) != nil {
			return false
		}
	}
	return false
}

// authorizeAtDecodeSeam is the only authorize POST/decode seam. All public
// chat, messages, responses, embeddings, images, fusion, partner, batch, and
// video paths inherit its echo/sign/verify behavior through the two authorize
// entry points.
func (c *Client) authorizeAtDecodeSeam(
	ctx context.Context,
	lookupHash string,
	body map[string]any,
	estimateRequest spendlease.EstimateRequest,
) (*Authorization, int, error) {
	return c.authorizeAtDecodeSeamWithAdmission(ctx, lookupHash, body, estimateRequest, nil)
}

func (c *Client) authorizeAtDecodeSeamWithAdmission(
	ctx context.Context,
	lookupHash string,
	body map[string]any,
	estimateRequest spendlease.EstimateRequest,
	plan *SpendLeaseAdmissionPlan,
) (result *Authorization, endpoint int, resultErr error) {
	authorizeStarted := requesttiming.FromContext(ctx).Now()
	defer requesttiming.FromContext(ctx).AuthorizeDone(authorizeStarted)
	ctx, finishShadow := c.observeShadowAuthorize(ctx, lookupHash)
	if finishShadow != nil {
		defer func() { finishShadow(result, resultErr) }()
	}
	invocation := authorizationInvocationFromContext(ctx)
	invocationNonce, err := invocation.invocationNonce()
	if err != nil {
		return nil, -1, err
	}
	if plan == nil && c.spendLease != nil && c.shadow == nil {
		// Always overwrite this field at the last ordinary-authorize seam. No
		// caller-controlled request field can select or influence the nonce.
		body["invocation_nonce"] = invocationNonce
		body["spend_lease_echo"] = c.spendLease.state.BeforeRequest(lookupHash, estimateRequest, c.spendLease.now())
	} else if plan == nil {
		body["invocation_nonce"] = invocationNonce
	}
	// Marshal once: SignAuthorize and the retry transport share this exact
	// slice, so the digest cannot drift from the bytes put on the wire.
	var bodyBytes []byte
	if plan != nil {
		bodyBytes = plan.body
	} else {
		bodyBytes, err = json.Marshal(body)
	}
	if err != nil {
		return nil, -1, err
	}
	bootAuthHeader := ""
	if signer := c.stageDBootDigestSigner(); signer != nil {
		bootAuth, err := spendlease.SignAuthorize(signer, http.MethodPost, spendlease.AuthorizePath, bodyBytes)
		if err != nil {
			return nil, -1, err
		}
		bootAuthHeader = bootAuth.HeaderValue()
	}
	var wire struct {
		Data json.RawMessage `json:"data"`
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	var out any = &decoded
	var capture *shadowCapture
	if c.asyncShadow {
		capture = &shadowCapture{}
		if plan == nil {
			ctx = context.WithValue(ctx, shadowCaptureKey{}, capture)
		}
	}
	policy := c.authorizeRetry
	if plan != nil {
		out = &wire
		policy.retryable = retryableAdmissionAuthorizationError
	}
	controlPlaneEndpoint, err := c.postJSONBytesWithRetryAtEndpoint(
		ctx, spendlease.AuthorizePath, bodyBytes, out, policy, bootAuthHeader,
	)
	if err != nil {
		return nil, controlPlaneEndpoint, err
	}
	if plan != nil {
		// Decode the marker separately: null, scalars and bad member types are
		// malformed acceptance, never a markerless version-skew response.
		var data struct {
			*Authorization
			Marker json.RawMessage `json:"spend_lease_admission"`
		}
		data.Authorization = &decoded.Data
		err = json.Unmarshal(wire.Data, &data)

		if data.Marker != nil {
			if err != nil || json.Unmarshal(data.Marker, &decoded.Data.SpendLeaseAdmission) != nil || decoded.Data.SpendLeaseAdmission == nil {
				return nil, controlPlaneEndpoint, invalidAdmissionResponse()
			}
		}
	}
	if err != nil {
		return nil, controlPlaneEndpoint, err
	}
	if capture != nil {
		if plan != nil {
			// RawMessage selects only the last data occurrence. Observe that
			// selected value, never metadata from discarded envelope members.
			_, _ = capture.Write([]byte(`{"data":`))
			_, _ = capture.Write(wire.Data)
			_, _ = capture.Write([]byte(`}`))
		}
		capture.finish(&decoded.Data)
	}
	if plan != nil && decoded.Data.SpendLease != nil && decoded.Data.SpendLeaseRemainingMicro == nil {
		decoded.Data.SpendLeaseRemainingMicro = decoded.Data.SpendLease.RemainingMicro
	}
	marked := plan != nil && decoded.Data.SpendLeaseAdmission != nil
	if marked {
		// Receipt identity can replace the stored nonce only after all checks.
		if err := plan.validateAcceptance(&decoded.Data); err != nil {
			return nil, controlPlaneEndpoint, err
		}
	}
	idempotencyKey, _ := body["idempotency_key"].(string)
	if plan != nil {
		idempotencyKey = plan.key
	}
	if !marked && decoded.Data.IdempotentReplay && decoded.Data.InvocationNonce != invocationNonce {
		return nil, controlPlaneEndpoint, videoReplayConflict(body, &decoded.Data, controlPlaneEndpoint)
	}
	// Transport retries precede this single claim; validation failures cannot
	// acquire dispatch rights. Ordinary calls cannot steal a prepared plan.
	if !invocation.claimPlan(idempotencyKey, plan) {
		return nil, controlPlaneEndpoint, idempotencyReplayConflict()
	}
	if c.spendLease != nil && c.shadow == nil && decoded.Data.SpendLease != nil {
		var leaseErr error
		if c.spendLease.state.LocalAdmissionEnabled() {
			leaseErr = c.spendLease.state.HandleAdmissionResponse(lookupHash, decoded.Data.APIKeyHash, decoded.Data.WorkspaceID, decoded.Data.SpendLease, c.spendLease.now())
		} else {
			leaseErr = c.spendLease.state.HandleResponse(lookupHash, decoded.Data.WorkspaceID, decoded.Data.SpendLease, c.spendLease.now())
		}
		if leaseErr != nil {
			// Stage A artifacts are advisory. Verification failure is fail-closed
			// to lease-less shadow accounting, never a failure of today's paid
			// synchronous authorization.
			fmt.Fprintf(os.Stderr, "spendlease.response_rejected err=%q\n", leaseErr.Error())
		}
		decoded.Data.SpendLease = nil // never retain or accidentally log token material
	}
	return &decoded.Data, controlPlaneEndpoint, nil
}

// admissionAuthorizeBody narrows a locally admitted reserve to the router's
// canonical Stage-C request contract. The receipt and boot proof replace the
// ordinary invocation nonce and advisory echo for this path.
func admissionAuthorizeBody(c *Client, lookupHash string, ordinary map[string]any, admission *spendlease.Admission) map[string]any {
	body := map[string]any{
		"api_key_lookup_hash":    lookupHash,
		"estimated_input_tokens": ordinary["estimated_input_tokens"],
		"idempotency_key":        ordinary["idempotency_key"],
		"max_tokens":             ordinary["max_tokens"],
		"model":                  ordinary["model"],
		"region":                 c.region,
		"route_type":             ordinary["route_type"],
		"spend_lease_admission":  admission.Receipt,
		"stream":                 ordinary["stream"],
	}
	if provider, ok := ordinary["provider"].(*qtypes.ProviderRouting); ok && provider != nil {
		canonicalProvider := map[string]any{}
		if provider.AllowFallbacks != nil {
			canonicalProvider["allow_fallbacks"] = *provider.AllowFallbacks
		}
		if provider.DataCollection != "" {
			canonicalProvider["data_collection"] = provider.DataCollection
		}
		if len(provider.Ignore) > 0 {
			canonicalProvider["ignore"] = provider.Ignore
		}
		if len(provider.Only) > 0 {
			canonicalProvider["only"] = provider.Only
		}
		if len(provider.Order) > 0 {
			canonicalProvider["order"] = provider.Order
		}
		if provider.RequireParameters != nil {
			canonicalProvider["require_parameters"] = *provider.RequireParameters
		}
		if provider.Usage != "" {
			canonicalProvider["usage"] = provider.Usage
		}
		body["provider"] = canonicalProvider
	}
	for _, field := range []string{"allow_fallbacks", "requested_parameters", "service_tier"} {
		if value, ok := ordinary[field]; ok {
			body[field] = value
		}
	}
	return body
}

func idempotencyReplayConflict() error {
	return &ControlPlaneError{
		Path:       spendlease.AuthorizePath,
		StatusCode: http.StatusConflict,
		Message:    "The idempotency key has already been used by another invocation.",
		Type:       "idempotency_replay",
		Reason:     "idempotency_replay",
	}
}

func spendLeaseRequestForChat(region, routeType string, req *qtypes.OpenAIChatRequest) spendlease.EstimateRequest {
	request := spendlease.EstimateRequest{
		Model: req.Model, RouteType: routeType, Region: region, ServiceTier: req.ServiceTier,
		EstimatedInputTokens: int64(EstimateInputTokens(req)),
	}
	if req.MaxTokens != nil {
		value := int64(*req.MaxTokens)
		request.MaxTokens = &value
	}
	if req.Provider != nil && len(req.Provider.Only) > 0 {
		request.ProviderConstraints = append([]string(nil), req.Provider.Only...)
	} else if req.Provider != nil && req.Provider.AllowFallbacks != nil && !*req.Provider.AllowFallbacks && len(req.Provider.Order) > 0 {
		// With fallbacks disabled, the ordered providers are an exact allowed
		// set. With fallbacks enabled, Order is only a preference and must not
		// exclude other frozen candidates.
		request.ProviderConstraints = append([]string(nil), req.Provider.Order...)
	}
	return request
}

// Only receipt-bearing reserves recover transport-level lost acknowledgements.
// The selected authority is pinned even when it failed before sending headers.
func retryableAdmissionAuthorizationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var transportErr *url.Error
	return retryableAuthorizationError(err) || errors.As(err, &transportErr) ||
		retryableSettlementError(err)
}
