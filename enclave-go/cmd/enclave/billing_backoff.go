package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Metadata, discovery and job polling must remain available to exhausted keys.
// These are the synchronous inference surfaces using the gateway error path.
func billingBackoffRoute(method, route string) bool {
	if method != http.MethodPost {
		return false
	}
	switch route {
	case "/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/embeddings", "/v1/images":
		return true
	default:
		return isDecidePath(route)
	}
}

func billingBackoffIdempotent(header string, body []byte) bool {
	if header != "" {
		return true
	}
	// Check the body as well, even on adapters that currently overwrite it with
	// the header. Retain neither the body nor its idempotency value in the cache.
	var fields struct {
		IdempotencyKey json.RawMessage `json:"idempotency_key"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return true
	}
	return len(fields.IdempotencyKey) > 0
}

func observeBillingAuthorizationError(w io.Writer, err error, message string) {
	if conn, ok := w.(*responseStatsConn); ok && conn.billingDenial != nil && trustedrouter.IsInsufficientCredits(err) {
		var controlErr *trustedrouter.ControlPlaneError
		if errors.As(err, &controlErr) {
			// Some routes supply their own fallback message for an empty router
			// message. Preserve the text actually rendered to the caller.
			denial := *controlErr
			denial.Message = message
			conn.billingDenial(&denial)
		}
	}
}

func writeBillingBackoff(w io.Writer, route string, rejection trustedrouter.BillingRejection) {
	if route == "/v1/messages" {
		writeAnthropicGatewayAuthorizationError(w, &rejection.Error)
	} else if isDecidePath(route) {
		writeDecideFailure(w, rejection.Error.StatusCode, messageFromControlPlaneError(&rejection.Error, "gateway authorization failed"), &rejection.Error, false)
	} else {
		writeGatewayAuthorizationError(w, &rejection.Error)
	}
}

// billingBackoffHeaderGroups audits readRequestWithHeadersRead,
// applyAttributionHeaders, chatAuthorizeBody, AuthorizeWithRoute and
// parseClientContext for validation and authorization inputs:
//   - Attribution: HTTP-Referer, X-OpenRouter-Title / X-Title (parsed precedence),
//     X-OpenRouter-Categories (parsed ordered list), X-Session-ID, and
//     X-OpenRouter-Metadata / X-OpenRouter-Experimental-Metadata (parsed flag).
//     User, trace and body session_id are body-only inputs, already body-hashed.
//   - Receipts: X-Inference-Receipt is the sole extracted receipt header; its
//     parsed value includes opt-in and nonce. Disabled support ignores it.
//   - Host plus effective confidential mode (Host OR TLS SNI) affect validation
//     and authorize routing. SNI must not alias an ordinary-host request.
//
// Exclusions: Client telemetry (User-Agent, X-TR-Client, and all X-Stainless
// fields, presence flags and oversize counters) is observational only: forwarded
// to settle/refund, never to authorize, and never validated to rejection. It is
// parsed before lookup; malformed telemetry is dropped and diagnosed on misses,
// while hits stay silent. Attempt-varying telemetry must not split a window.
// HTTP syntax/size validation still runs before lookup for these headers too.
// Authorization / X-API-Key are covered by the credential digest;
// Idempotency-Key bypasses caching entirely. Content-Length / Transfer-Encoding
// and header syntax/size limits are checked by the reader BEFORE lookup; exact
// body bytes are hashed. Connection / HTTP version only select transport reuse.
// Date and incoming request IDs are neither extracted nor validated beyond that
// syntax check, nor forwarded to authorize; gateway_request_id is generated
// for audit/settlement, and authorization idempotency IDs are generated per
// request. Both are per-request randomness, not client equivalence inputs.
// All other ignored headers likewise have no downstream validation/authorize
// effect. No transport or random identifiers enter the key.
//
// Fixed group/field order, eight-byte lengths and parsed alias precedence give a
// canonical encoding for identical parsed inputs, regardless of wire spelling
// or ordering. Categories retain order (authorize does too). Each group is
// itself length-framed by the key.
func billingBackoffHeaderGroups(a requestAttributionHeaders, confidential bool) [][]byte {
	attribution := billingBackoffFrame(append([]string{
		a.SessionID, a.HTTPReferer, a.App, strconv.FormatBool(a.OpenRouterMetadata),
	}, a.AppCategories...)...)
	receipt := billingBackoffFrame(a.InferenceReceipt)
	return [][]byte{attribution, receipt, billingBackoffFrame(a.Host, strconv.FormatBool(confidential))}
}

func billingBackoffFrame(fields ...string) []byte {
	var framed []byte
	for _, field := range fields {
		framed = binary.BigEndian.AppendUint64(framed, uint64(len(field)))
		framed = append(framed, field...)
	}
	return framed
}
