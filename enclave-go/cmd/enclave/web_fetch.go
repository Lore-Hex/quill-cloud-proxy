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
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/webfetch"
)

type webFetcher interface {
	Fetch(context.Context, *webfetch.Request) (*webfetch.Result, error)
}

var webFetchProviderGateway webFetcher

func serveWebFetch(ctx context.Context, conn io.Writer, raw []byte, gateway *trustedrouter.Client, bearer, idempotencyKey string, attribution requestAttributionHeaders, requestLogID string) {
	started := time.Now()
	req, err := webfetch.Parse(raw)
	if err != nil {
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "invalid_fetch_request", "url")
		return
	}
	if gateway == nil || !gateway.Enabled() || webFetchProviderGateway == nil {
		writeError(conn, 503, "Fetch is unavailable on this gateway")
		return
	}
	if attribution.InferenceReceipt != "" {
		writeOpenAIError(conn, 400, "Signed inference receipts are not supported for Fetch", "invalid_request_error", "unsupported_receipt", "")
		return
	}
	maxTokens := 1
	meta := &types.OpenAIChatRequest{Model: webfetch.ModelID, Provider: req.Provider, MaxTokens: &maxTokens, IdempotencyKey: idempotencyKey}
	applyAttributionHeaders(meta, attribution)
	if err := validateOrObserveRequestMetadata(meta, requestLogID); err != nil {
		writeError(conn, 400, "invalid request metadata")
		return
	}
	// Bind idempotency without disclosing the URL, including sensitive queries.
	canonical, _ := json.Marshal(req)
	digest := hmac.New(sha256.New, []byte(bearer))
	digest.Write([]byte(webfetch.RouteType + "\x00"))
	digest.Write(canonical)
	meta.RequestFingerprint = hex.EncodeToString(digest.Sum(nil))
	authorization, err := gateway.AuthorizeWithRoute(ctx, bearer, meta, webfetch.RouteType)
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	if authorization.IdempotentReplay {
		writeOpenAIError(conn, 409, "This Fetch idempotency key was already used; fetched content is not retained", "invalid_request_error", "fetch_not_replayable", "")
		return
	}
	refund := func(status int, reason string) {
		refundCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = gateway.Refund(refundCtx, authorization, status, reason, time.Since(started).Seconds(), nil)
	}
	if authorization.Model != webfetch.ModelID || authorization.Provider != "deepseek" || authorization.UpstreamModel != "fetch" || authorization.UsageType != "Credits" || authorization.EstimatedCostMicrodollars <= 0 || authorization.AdditionalCostReservationMicrodollars != 0 {
		refund(502, "fetch_catalog_mismatch")
		writeError(conn, 502, "Fetch route configuration mismatch")
		return
	}
	fetchCtx, cancelFetch := context.WithCancel(ctx)
	defer cancelFetch()
	clientClosed := cancelUserModelOnDisconnect(fetchCtx, cancelFetch, conn)
	authorization.RecordShadowInvocation(authorization.EndpointID, authorization.Provider)
	result, err := webFetchProviderGateway.Fetch(fetchCtx, req)
	if err != nil || result == nil || strings.TrimSpace(result.Content) == "" {
		status := 502
		var upstream *webfetch.ProviderError
		if errors.As(err, &upstream) {
			switch upstream.Status {
			case 400, 403, 404, 408, 413, 429, 503, 504:
				status = upstream.Status
			}
		}
		refund(status, "fetch_provider_error")
		if !clientClosed.Load() {
			writeProviderError(conn, status, "Fetch failed")
		}
		return
	}
	// Successful upstream work is billable even if the caller disconnects.
	usage := trustedrouter.Usage{
		RequestID: newRequestID(), ElapsedSeconds: maxDurationSeconds(time.Since(started), 0.001),
		RouteType: webfetch.RouteType, FinishReason: "stop", SelectedModel: webfetch.ModelID,
		SelectedEndpoint: authorization.EndpointID,
	}
	applyUsageAttribution(&usage, meta)
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	settled, err := gateway.Settle(settleCtx, authorization, usage)
	if err != nil {
		// Never refund completed upstream work after an ambiguous settlement.
		writeSpentError(conn, 502, "Fetch settlement failed")
		return
	}
	data, _ := json.Marshal(result)
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Generation-Id: %s\r\nX-Request-Id: %s\r\nX-Usage-Cost: %v\r\nConnection: %s\r\n\r\n", len(data), settled.GenerationID, requestLogID, settled.Cost, responseConnection(conn))
	if err == nil {
		_, _ = conn.Write(data)
	}
}
