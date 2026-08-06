package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// maybeServePublicModels exposes public catalog metadata on the canonical
// attested API origin. Only GET is anonymous; all other methods continue into
// the normal authentication gate.
func maybeServePublicModels(
	ctx context.Context,
	w io.Writer,
	method string,
	routePath string,
	gateway *trustedrouter.Client,
) bool {
	if method != "GET" || routePath != "/v1/models" {
		return false
	}
	if gateway == nil {
		writeError(w, 503, "model catalog unavailable")
		return true
	}
	body, err := gateway.PublicModels(ctx)
	if err != nil {
		writeError(w, 503, "model catalog unavailable")
		return true
	}
	writePublicModelsResponse(w, body)
	return true
}

func writePublicModelsResponse(w io.Writer, body []byte) {
	fmt.Fprintf(
		w,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: public, max-age=60, stale-if-error=300\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
		len(body),
	)
	_, _ = w.Write(body)
}
