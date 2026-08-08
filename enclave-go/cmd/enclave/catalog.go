package main

import (
	"context"
	"fmt"
	"io"
	"os"

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
		// Distinct from a fetch failure: the control-plane client was never
		// constructed, so no request was even attempted. Both used to emit the
		// same opaque 503, making the two indistinguishable from outside.
		fmt.Fprintf(os.Stderr, "enclave.public_models_unavailable reason=%q\n", "no control-plane client")
		writeError(w, 503, "model catalog unavailable")
		return true
	}
	body, err := gateway.PublicModels(ctx)
	if err != nil {
		// The error was DISCARDED here. The enclave knew exactly why the
		// catalog was unavailable — unreachable control plane, non-200,
		// oversized body, malformed envelope — and threw it away, leaving a
		// 503 whose cause cannot be recovered from outside or from the logs.
		//
		// PublicModels serves a stale copy for 30 minutes, so a PERSISTENT 503
		// means no fetch has ever succeeded since boot. That is a
		// configuration or egress fault, not a blip, and the text below is the
		// only thing that says which.
		fmt.Fprintf(os.Stderr, "enclave.public_models_unavailable reason=%q\n", err.Error())
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
