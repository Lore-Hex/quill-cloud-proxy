package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

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
