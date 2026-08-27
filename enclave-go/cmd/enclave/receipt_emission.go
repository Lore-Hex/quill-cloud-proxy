package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var receiptBase64 = base64.RawURLEncoding

type receiptEmissionState struct {
	signer      *receipt.Signer
	attestation []byte
	attKind     string
}

func receiptState(req *types.OpenAIChatRequest) (receiptEmissionState, bool) {
	if req == nil || !req.InferenceReceipt.Requested || receiptSigner == nil {
		return receiptEmissionState{}, false
	}
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 || cached.kind == "" {
		return receiptEmissionState{}, false
	}
	return receiptEmissionState{
		signer:      receiptSigner,
		attestation: append([]byte(nil), cached.document...),
		attKind:     cached.kind,
	}, true
}

func receiptClaims(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	route string,
	responseID string,
	generationID string,
	requestedModel string,
	selectedRoute *selectedRouteTracker,
	authorization *trustedrouter.Authorization,
	responseDigest [32]byte,
	responseDomain string,
	events *int,
	attestation []byte,
) receipt.Claims {
	issuedAt := time.Now().Unix()
	upstream := receipt.Upstream{Tier: "tls-webpki"}
	if verified, ok := llm.FromContext(ctx); ok {
		upstream = receipt.Upstream{
			Tier:                  "tee-verified",
			Policy:                verified.Policy,
			VerifiedAt:            verified.VerifiedAt.Unix(),
			VerificationExpiresAt: verified.ExpiresAt.Unix(),
		}
	} else if certSHA256, ok := llm.UpstreamCertSHA256FromContext(ctx); ok {
		upstream.CertSHA256 = certSHA256
	}
	claims := receipt.Claims{
		RV:         1,
		Issuer:     receiptIssuer,
		IssuedAt:   issuedAt,
		JTI:        responseID,
		Generation: generationID,
		Nonce:      req.InferenceReceipt.NonceEcho,
		Route:      route,
		Request: receipt.HashRecord{
			Algorithm: "sha256",
			Hash:      receiptBase64.EncodeToString(req.InferenceReceipt.RequestBodySHA256[:]),
			Of:        "body",
		},
		Response: receipt.ResponseRecord{
			Algorithm: "sha256",
			Hash:      receiptBase64.EncodeToString(responseDigest[:]),
			Of:        responseDomain,
			Events:    events,
		},
		Model: receipt.Model{
			Requested: requestedModel,
			Selected:  selectedRoute.Model(req.Model, authorization),
			Provider:  selectedRoute.Provider("", authorization),
			Endpoint:  selectedRoute.Endpoint("", authorization),
		},
		Upstream: upstream,
	}
	if len(attestation) > 0 {
		digest := sha256.Sum256(attestation)
		claims.AttSHA256 = receiptBase64.EncodeToString(digest[:])
	}
	return claims
}

func writeJSONResponseWithReceipt(
	ctx context.Context,
	w io.Writer,
	body []byte,
	req *types.OpenAIChatRequest,
	route string,
	responseID string,
	generationID string,
	requestedModel string,
	selectedRoute *selectedRouteTracker,
	authorization *trustedrouter.Authorization,
) {
	state, ok := receiptState(req)
	if !ok {
		writeJSONResponse(w, 200, body)
		return
	}
	responseDigest := sha256.Sum256(body)
	claims := receiptClaims(ctx, req, route, responseID, generationID, requestedModel, selectedRoute, authorization, responseDigest, "body", nil, state.attestation)
	serialized, err := state.signer.SignCompact(claims)
	if err != nil {
		writeJSONResponse(w, 200, body)
		return
	}
	writeJSONResponseWithHeaders(w, 200, body, map[string]string{"x-inference-receipt": serialized})
}

func writeStreamingReceiptEvent(
	ctx context.Context,
	w io.Writer,
	state receiptEmissionState,
	req *types.OpenAIChatRequest,
	route string,
	responseID string,
	wireModel string,
	requestedModel string,
	selectedRoute *selectedRouteTracker,
	authorization *trustedrouter.Authorization,
	responseDigest [32]byte,
	responseDomain string,
	eventCount int,
	created int64,
) error {
	claims := receiptClaims(ctx, req, route, responseID, "", requestedModel, selectedRoute, authorization, responseDigest, responseDomain, &eventCount, nil)
	serialized, err := state.signer.SignFlattened(claims, state.attestation, state.attKind)
	if err != nil {
		return nil
	}
	payload := map[string]any{
		"id":                responseID,
		"object":            "chat.completion.chunk",
		"created":           created,
		"model":             wireModel,
		"choices":           []any{},
		"inference_receipt": json.RawMessage(serialized),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", body)
	return err
}
