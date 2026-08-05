package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const batchInternalMaxResponseBytes = 64 * 1024 * 1024

// The value is deliberately not a usable API key. Authorization for this
// in-memory request comes only from the unforgeable Go context below.
const batchInternalBearer = "trustedrouter-batch-internal"

type batchExecutionContextKey struct{}

func isBatchExecutionContext(ctx context.Context) bool {
	value, _ := ctx.Value(batchExecutionContextKey{}).(bool)
	return value
}

// batchEnclaveExecutor feeds a batch item through the ordinary enclave request
// handler over an in-memory connection. This deliberately reuses the exact
// authorization, provider fallback, settlement, refund, and idempotency path
// without putting a raw API key or prompt onto DNS or a regional network hop.
type batchEnclaveExecutor struct {
	registry   *auth.Registry
	backend    llm.Client
	deviceBlob []byte
	gateway    *trustedrouter.Client
	byok       *byokcache.Cache
}

func (e *batchEnclaveExecutor) Execute(
	ctx context.Context,
	apiKeyLookupHash string,
	endpoint string,
	body []byte,
	idempotencyKey string,
) (int, string, []byte, error) {
	ctx = context.WithValue(ctx, batchExecutionContextKey{}, true)
	ctx, err := trustedrouter.WithAPIKeyLookupHash(ctx, apiKeyLookupHash)
	if err != nil {
		return 0, "", nil, err
	}
	serverConn, clientConn := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serveOne(ctx, serverConn, e.registry, e.backend, nil, e.deviceBlob, e.gateway, e.byok)
	}()
	defer func() {
		_ = clientConn.Close()
		<-serverDone
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://batch.enclave"+endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	request.Host = "batch.enclave"
	request.Close = true
	request.Header.Set("Authorization", "Bearer "+batchInternalBearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-OpenRouter-Title", "TrustedRouter Batch")

	writeDone := make(chan error, 1)
	go func() { writeDone <- request.Write(clientConn) }()
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		_ = clientConn.Close()
		if writeErr := <-writeDone; writeErr != nil && ctx.Err() == nil {
			return 0, "", nil, fmt.Errorf("batch internal request: %w", writeErr)
		}
		return 0, "", nil, fmt.Errorf("batch internal response: %w", err)
	}
	if writeErr := <-writeDone; writeErr != nil {
		_ = response.Body.Close()
		return 0, "", nil, fmt.Errorf("batch internal request: %w", writeErr)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, batchInternalMaxResponseBytes+1))
	if err != nil {
		return 0, "", nil, fmt.Errorf("batch internal response body: %w", err)
	}
	if len(responseBody) > batchInternalMaxResponseBytes {
		return 0, "", nil, fmt.Errorf("batch internal response too large")
	}
	return response.StatusCode, response.Header.Get("X-Request-ID"), responseBody, nil
}
