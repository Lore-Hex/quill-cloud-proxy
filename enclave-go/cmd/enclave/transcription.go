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
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type transcriber interface {
	Transcribe(context.Context, *transcription.Request) (map[string]any, error)
}

var transcriptionProviderGateway transcriber
var transcriptionSlots = make(chan struct{}, 2)

func serveTranscription(ctx context.Context, conn io.Writer, raw []byte, gateway *trustedrouter.Client, bearer, idempotencyKey string, attribution requestAttributionHeaders, requestLogID string) {
	started := time.Now()
	if gateway == nil || !gateway.Enabled() || transcriptionProviderGateway == nil {
		writeError(conn, 503, "transcription unavailable")
		return
	}
	if err := gateway.CheckCredential(ctx, bearer); err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	select {
	case transcriptionSlots <- struct{}{}:
		defer func() { <-transcriptionSlots }()
	default:
		writeError(conn, 503, "transcription capacity temporarily exhausted")
		return
	}
	if err := gateway.ValidateKey(ctx, bearer, "audio.transcriptions"); err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	req, err := transcription.Parse(raw, attribution.ContentType)
	if err == nil {
		err = transcription.Measure(ctx, req)
	}
	if err != nil {
		var invalid *transcription.RequestError
		if errors.As(err, &invalid) {
			writeOpenAIError(conn, 400, invalid.Message, "invalid_request_error", "invalid_transcription_request", invalid.Param)
		} else {
			writeError(conn, 400, "invalid audio upload")
		}
		return
	}
	if attribution.InferenceReceipt != "" {
		writeOpenAIError(conn, 400, "Signed receipts are not supported for transcription", "invalid_request_error", "unsupported_receipt", "")
		return
	}
	if trustedrouter.ConfidentialOnly(ctx) {
		if err := trustedrouter.ValidateConfidentialRouting(req.Provider); err != nil {
			writeConfidentialHostError(conn, "/v1/audio/transcriptions", err)
			return
		}
	}
	if req.Provider != nil && req.Provider.MinPrivacy == "confidential" && !transcription.Models[req.Model].Confidential() {
		writeOpenAIError(conn, 400, "This transcription model has no verified confidential route", "invalid_request_error", "no_matching_provider", "provider.min_privacy")
		return
	}
	maxTokens := 1
	meta := &types.OpenAIChatRequest{Model: req.Model, Provider: req.Provider, MaxTokens: &maxTokens, User: req.User, SessionID: req.SessionID, Trace: req.Trace, IdempotencyKey: idempotencyKey, TranscriptionDurationMS: req.DurationMS}
	if transcription.Models[req.Model].TokenBilled() {
		maxTokens = transcription.MaxOutputTokens
	}
	applyAttributionHeaders(meta, attribution)
	if validateOrObserveRequestMetadata(meta, requestLogID) != nil {
		writeError(conn, 400, "invalid request metadata")
		return
	}
	canonical, _ := json.Marshal(req)
	digest := hmac.New(sha256.New, []byte(bearer))
	digest.Write([]byte("audio.transcriptions\x00"))
	digest.Write(canonical)
	digest.Write([]byte{0})
	digest.Write(req.Audio)
	meta.RequestFingerprint = hex.EncodeToString(digest.Sum(nil))
	auth, err := gateway.AuthorizeWithRoute(ctx, bearer, meta, "audio.transcriptions")
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	if auth.IdempotentReplay {
		writeOpenAIError(conn, 409, "Transcription responses are not retained; this idempotency key was already used", "invalid_request_error", "transcription_not_replayable", "")
		return
	}
	refund := func(status int, reason string) {
		refundCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = gateway.Refund(refundCtx, auth, status, reason, time.Since(started).Seconds(), nil)
	}
	spec := transcription.Models[req.Model]
	if auth.Model != req.Model || auth.Provider != spec.Provider || auth.UpstreamModel != spec.Upstream || auth.UsageType != "Credits" || (!spec.TokenBilled() && auth.AdditionalCostReservationMicrodollars <= 0) || (spec.TokenBilled() && (auth.AdditionalCostReservationMicrodollars != 0 || auth.EstimatedCostMicrodollars <= 0)) {
		refund(502, "transcription_catalog_mismatch")
		writeError(conn, 502, "transcription route configuration mismatch")
		return
	}
	providerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	closed := cancelUserModelOnDisconnect(providerCtx, cancel, conn)
	auth.RecordShadowInvocation(auth.EndpointID, auth.Provider)
	result, err := transcriptionProviderGateway.Transcribe(providerCtx, req)
	if closed.Load() {
		refund(499, "client_closed")
		return
	}
	if err != nil {
		status := 502
		var upstream *transcription.ProviderError
		if errors.As(err, &upstream) && upstream.Status == 429 {
			status = 429
		}
		refund(status, "transcription_provider_error")
		writeProviderError(conn, status, "transcription failed")
		return
	}
	usage := trustedrouter.Usage{RequestID: newRequestID(), ElapsedSeconds: maxDurationSeconds(time.Since(started), 0.001), RouteType: "audio.transcriptions", FinishReason: "stop", AdditionalCostMicrodollars: auth.AdditionalCostReservationMicrodollars, SelectedModel: req.Model, SelectedEndpoint: auth.EndpointID, User: meta.User, SessionID: meta.SessionID}
	if spec.TokenBilled() {
		tokens, err := transcription.TakeTokenUsage(result)
		if err != nil {
			refund(502, "transcription_usage_invalid")
			writeProviderError(conn, 502, "transcription usage unavailable")
			return
		}
		usage.InputTokens, usage.OutputTokens = tokens.Input, tokens.Output
	}
	applyUsageAttribution(&usage, meta)
	settleCtx, settleCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer settleCancel()
	settled, err := gateway.Settle(settleCtx, auth, usage)
	if err != nil {
		writeSpentError(conn, 502, "transcription settlement failed")
		return
	}
	result["usage"] = map[string]any{"type": "duration", "cost": settled.Cost, "seconds": float64(req.DurationMS) / 1000}
	if spec.TokenBilled() {
		result["usage"] = map[string]any{"type": "tokens", "cost": settled.Cost, "input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens, "total_tokens": usage.InputTokens + usage.OutputTokens}
	}
	body, _ := json.Marshal(result)
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-Generation-Id: %s\r\nX-Request-Id: %s\r\nConnection: %s\r\n\r\n", len(body), settled.GenerationID, requestLogID, responseConnection(conn))
	if err == nil {
		_, _ = conn.Write(body)
	}
}
