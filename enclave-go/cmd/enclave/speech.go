package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speech"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type speechGenerator interface {
	Generate(context.Context, *speech.Request) (*speech.Result, error)
}

var speechProviderGateway speechGenerator

func serveSpeech(ctx context.Context, conn io.Writer, raw []byte, gateway *trustedrouter.Client, bearer, idempotencyKey string, attribution requestAttributionHeaders, requestLogID string) {
	started := time.Now()
	req, err := speech.Parse(raw)
	if err != nil {
		var invalid *speech.RequestError
		if errors.As(err, &invalid) {
			writeOpenAIError(conn, 400, invalid.Message, "invalid_request_error", "invalid_speech_request", invalid.Param)
		} else {
			writeError(conn, 400, "invalid speech request")
		}
		return
	}
	if gateway == nil || !gateway.Enabled() || speechProviderGateway == nil {
		writeError(conn, 503, "speech is unavailable on this gateway")
		return
	}
	if attribution.InferenceReceipt != "" {
		writeOpenAIError(conn, 400, "Signed inference receipts are not supported for speech", "invalid_request_error", "unsupported_receipt", "")
		return
	}
	maxTokens := 1
	meta := &types.OpenAIChatRequest{
		Model: req.Model, Provider: req.Provider, MaxTokens: &maxTokens,
		User: req.User, SessionID: req.SessionID, Metadata: req.Metadata, Tags: req.Tags,
		IdempotencyKey: idempotencyKey, SpeechInputCharacters: utf8.RuneCountInString(req.Input),
	}
	applyAttributionHeaders(meta, attribution)
	if err := validateOrObserveRequestMetadata(meta, requestLogID); err != nil {
		writeError(conn, 400, "invalid request metadata")
		return
	}
	// HMAC prevents dictionary attacks on short text in stored fingerprints.
	canonical, _ := json.Marshal(req)
	digest := hmac.New(sha256.New, []byte(bearer))
	digest.Write([]byte("audio.speech\x00"))
	digest.Write(canonical)
	meta.RequestFingerprint = hex.EncodeToString(digest.Sum(nil))
	authorization, err := gateway.AuthorizeWithRoute(ctx, bearer, meta, "audio.speech")
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	if authorization.IdempotentReplay {
		// Audio is never stored. Do not regenerate (or refund another active
		// request) when replaying an authorization whose response was lost.
		writeOpenAIError(conn, 409, "This speech idempotency key was already used; audio responses are not retained", "invalid_request_error", "speech_not_replayable", "")
		return
	}
	refund := func(status int, reason string) {
		// A disconnected client must not cancel the credit release.
		refundCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = gateway.Refund(refundCtx, authorization, status, reason, time.Since(started).Seconds(), nil)
	}
	spec := speech.Models[req.Model]
	if authorization.Model != req.Model || authorization.Provider != spec.Provider || authorization.UsageType != "Credits" || authorization.UpstreamModel != spec.Upstream {
		refund(502, "speech_catalog_mismatch")
		writeError(conn, 502, "speech route configuration mismatch")
		return
	}
	generationCtx, cancelGeneration := context.WithCancel(ctx)
	defer cancelGeneration()
	clientClosed := cancelUserModelOnDisconnect(generationCtx, cancelGeneration, conn)
	result, err := speechProviderGateway.Generate(generationCtx, req)
	if clientClosed.Load() {
		refund(499, "client_closed")
		return
	}
	if err != nil {
		status := http.StatusBadGateway
		var upstream *speech.ProviderError
		if errors.As(err, &upstream) {
			switch upstream.Status {
			case 400, 403, 422, 429, 503:
				status = upstream.Status
			}
		}
		refund(status, "speech_provider_error")
		writeProviderError(conn, status, "speech generation failed")
		return
	}
	usage := trustedrouter.Usage{
		RequestID: newRequestID(), ElapsedSeconds: maxDurationSeconds(time.Since(started), 0.001),
		RouteType: "audio.speech", FinishReason: "stop",
		AdditionalCostMicrodollars: authorization.AdditionalCostReservationMicrodollars,
		SelectedModel:              req.Model, SelectedEndpoint: authorization.EndpointID,
		User: meta.User, SessionID: meta.SessionID, Metadata: meta.Metadata,
	}
	applyUsageAttribution(&usage, meta)
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	settled, err := gateway.Settle(settleCtx, authorization, usage)
	if err != nil {
		writeSpentError(conn, 502, "speech settlement failed")
		return
	}
	// No text/audio reaches logs, broadcasts, or storage. Cost remains available
	// through generation metadata as well as these binary-response headers.
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Generation-Id: %s\r\nX-Request-Id: %s\r\nX-Usage-Input-Characters: %d\r\nX-Usage-Cost: %v\r\nConnection: %s\r\n\r\n", result.ContentType, len(result.Audio), settled.GenerationID, requestLogID, meta.SpeechInputCharacters, settled.Cost, responseConnection(conn))
	if err == nil {
		_, _ = conn.Write(result.Audio)
	}
}
