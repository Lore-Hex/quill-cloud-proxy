package trustedrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type spendLeaseProtocol struct {
	signer        spendlease.DigestSigner
	state         *spendlease.ShadowState
	verifierReady bool
}

type BootRegistrationEvidence struct {
	Attestation     string
	AttestationKind string
}

type bootRegistrationRequest struct {
	KID                 string      `json:"kid"`
	ReceiptPublicKey    receipt.JWK `json:"receipt_public_key"`
	AttestationEvidence string      `json:"attestation_evidence"`
	AttestationKind     string      `json:"attestation_kind"`
}

// ConfigureSpendLeaseShadow enables only the additive Stage A protocol. It is
// called before the serving loop; a nil verifier keeps the protocol dormant.
func (c *Client) ConfigureSpendLeaseShadow(signer *receipt.Signer, verifier *spendlease.Verifier) {
	if c == nil || signer == nil {
		return
	}
	c.spendLease = &spendLeaseProtocol{
		signer: signer, state: spendlease.NewShadowState(verifier, signer.Kid()),
		verifierReady: verifier != nil,
	}
}

// StartSpendLeaseBootRegistration is intentionally asynchronous and
// non-fatal. The existing retry policy supplies bounded exponential backoff;
// any final failure leaves ShadowState's registration gate closed.
func (c *Client) StartSpendLeaseBootRegistration(ctx context.Context, signer *receipt.Signer, evidence BootRegistrationEvidence) {
	if c == nil || c.spendLease == nil || signer == nil {
		return
	}
	go func() {
		if evidence.Attestation == "" || evidence.AttestationKind == "" {
			fmt.Fprintln(os.Stderr, "spendlease.boot_registration_failed reason=attestation_unavailable")
			return
		}
		payload := bootRegistrationRequest{
			KID: signer.Kid(), ReceiptPublicKey: signer.JWK(),
			AttestationEvidence: evidence.Attestation, AttestationKind: evidence.AttestationKind,
		}
		var decoded struct {
			Data struct {
				Verified bool `json:"verified"`
			} `json:"data"`
		}
		if err := c.postJSONWithRetry(ctx, spendlease.RegisterPath, payload, &decoded, c.authorizeRetry); err != nil {
			fmt.Fprintf(os.Stderr, "spendlease.boot_registration_failed err=%q\n", err.Error())
			return
		}
		if !decoded.Data.Verified || c.spendLease.state == nil || !c.spendLease.verifierReady {
			fmt.Fprintln(os.Stderr, "spendlease.boot_registration_failed reason=boot_not_verified")
			return
		}
		c.spendLease.state.SetRegistered(true)
		fmt.Fprintf(os.Stderr, "spendlease.boot_registered kid=%q\n", signer.Kid())
	}()
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
	if c.spendLease != nil {
		body["spend_lease_echo"] = c.spendLease.state.BeforeRequest(lookupHash, estimateRequest, time.Now())
	}
	// Marshal once: SignAuthorize and the retry transport share this exact
	// slice, so the digest cannot drift from the bytes put on the wire.
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, -1, err
	}
	bootAuthHeader := ""
	if c.spendLease != nil {
		bootAuth, err := spendlease.SignAuthorize(c.spendLease.signer, http.MethodPost, spendlease.AuthorizePath, bodyBytes)
		if err != nil {
			return nil, -1, err
		}
		bootAuthHeader = bootAuth.HeaderValue()
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	controlPlaneEndpoint, err := c.postJSONBytesWithRetryAtEndpoint(
		ctx, spendlease.AuthorizePath, bodyBytes, &decoded, c.authorizeRetry, bootAuthHeader,
	)
	if err != nil {
		return nil, controlPlaneEndpoint, err
	}
	if c.spendLease != nil && decoded.Data.SpendLease != nil {
		if err := c.spendLease.state.HandleResponse(lookupHash, decoded.Data.WorkspaceID, decoded.Data.SpendLease, time.Now()); err != nil {
			// Stage A artifacts are advisory. Verification failure is fail-closed
			// to lease-less shadow accounting, never a failure of today's paid
			// synchronous authorization.
			fmt.Fprintf(os.Stderr, "spendlease.response_rejected err=%q\n", err.Error())
		}
		decoded.Data.SpendLease = nil // never retain or accidentally log token material
	}
	return &decoded.Data, controlPlaneEndpoint, nil
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
