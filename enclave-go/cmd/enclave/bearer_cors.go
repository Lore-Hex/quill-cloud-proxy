package main

import (
	"fmt"
	"io"
)

// These routes use explicit API keys, never cookie/session authentication.
// Wildcard origins do not permit credentialed browser requests. Keep browser
// access scoped to these API routes rather than control-plane/account routes.
func isBearerCORSRoute(path string) bool {
	switch path {
	case "/v1/chat/completions", "/v1/responses", "/v1/messages",
		"/v1/embeddings", "/v1/images", "/v1/audio/speech",
		"/v1/audio/transcriptions", "/v1/responses/input_tokens", "/v1/key":
		return true
	}
	return false
}

const bearerCORSResponseHeaders = "Access-Control-Allow-Origin: *\r\n" +
	"Access-Control-Expose-Headers: X-Request-ID, Request-ID, Retry-After, X-Should-Retry, X-Inference-Receipt\r\n"

func maybeServeBearerPreflight(w io.Writer, method, path string) bool {
	if method != "OPTIONS" || !isBearerCORSRoute(path) {
		return false
	}
	// responseStatsConn adds the origin header to every response on these routes.
	// Authorization must be explicit: the Fetch wildcard excludes it. The other
	// headers include SDK telemetry and optional API headers such as idempotency.
	// A 204 has no Content-Length and does not authenticate or contact upstreams.
	fmt.Fprintf(w, "HTTP/1.1 204 No Content\r\n"+
		"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"+
		"Access-Control-Allow-Headers: Authorization, Content-Type, *\r\n"+
		"Access-Control-Max-Age: 600\r\nConnection: %s\r\n\r\n", responseConnection(w))
	return true
}
