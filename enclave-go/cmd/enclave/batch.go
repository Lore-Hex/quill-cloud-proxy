package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
)

var batchGateway *batchapi.Service

type batchRuntimeConfig struct {
	Bucket      string
	KMSKey      string
	WIFProvider string
}

func maybeServeBatchRoute(
	ctx context.Context,
	conn io.Writer,
	method string,
	routePath string,
	body []byte,
	bearer string,
) bool {
	const base = "/api/beta/batches"
	if routePath != base && !strings.HasPrefix(routePath, base+"/") {
		return false
	}
	if batchGateway == nil {
		writeBatchError(conn, &batchapi.APIError{
			Status:  503,
			Message: "batch service is temporarily unavailable",
			Type:    "server_error",
			Code:    "batch_unavailable",
		})
		return true
	}
	if routePath == base {
		if method != http.MethodPost {
			writeBatchError(conn, &batchapi.APIError{Status: 404, Message: "route not found", Type: "invalid_request_error", Code: "not_found"})
			return true
		}
		created, apiErr := batchGateway.Create(ctx, bearer, body)
		if apiErr != nil {
			writeBatchError(conn, apiErr)
			return true
		}
		writeBatchJSON(conn, http.StatusAccepted, created)
		return true
	}
	if method != http.MethodGet || strings.Contains(strings.TrimPrefix(routePath, base+"/"), "/") {
		writeBatchError(conn, &batchapi.APIError{Status: 404, Message: "route not found", Type: "invalid_request_error", Code: "not_found"})
		return true
	}
	id := strings.TrimPrefix(routePath, base+"/")
	result, apiErr := batchGateway.PrepareGet(ctx, bearer, id)
	if apiErr != nil {
		writeBatchError(conn, apiErr)
		return true
	}
	if !result.ResultSet {
		writeBatchJSON(conn, http.StatusOK, &result.Batch)
		return true
	}
	// Result objects can contain tens of thousands of large provider bodies.
	// Stream one decrypted checkpoint at a time so response size does not become
	// enclave memory usage. An interrupted object read leaves an incomplete
	// chunked response, which makes clients retry instead of accepting partial
	// results as a completed batch.
	_ = writePreparedBatch(ctx, conn, result)
	return true
}

func writePreparedBatch(ctx context.Context, w io.Writer, prepared *batchapi.PreparedBatch) error {
	batch := prepared.Batch
	prefix, err := json.Marshal(struct {
		ID               string                 `json:"id"`
		Object           string                 `json:"object"`
		Endpoint         string                 `json:"endpoint"`
		Model            string                 `json:"model"`
		CompletionWindow string                 `json:"completion_window"`
		Status           string                 `json:"status"`
		CreatedAt        int64                  `json:"created_at"`
		FinalizedAt      *int64                 `json:"finalized_at"`
		RequestCounts    batchapi.RequestCounts `json:"request_counts"`
		Usage            *batchapi.Usage        `json:"usage"`
	}{
		ID:               batch.ID,
		Object:           batch.Object,
		Endpoint:         batch.Endpoint,
		Model:            batch.Model,
		CompletionWindow: batch.CompletionWindow,
		Status:           batch.Status,
		CreatedAt:        batch.CreatedAt,
		FinalizedAt:      batch.FinalizedAt,
		RequestCounts:    batch.RequestCounts,
		Usage:            batch.Usage,
	})
	if err != nil {
		return err
	}
	errorJSON, err := json.Marshal(batch.Error)
	if err != nil {
		return err
	}
	if len(prefix) == 0 || prefix[len(prefix)-1] != '}' {
		return errors.New("batch response prefix is invalid")
	}
	if err := writeResponseHead(w, http.StatusOK, "application/json"); err != nil {
		return err
	}
	chunked := newChunkedWriter(w)
	if _, err := chunked.Write(append(prefix[:len(prefix)-1], []byte(`,"results":[`)...)); err != nil {
		return err
	}
	first := true
	for {
		result, ok, err := prepared.Next(ctx)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if !first {
			if _, err := chunked.Write([]byte(",")); err != nil {
				clear(encoded)
				return err
			}
		}
		first = false
		if _, err := chunked.Write(encoded); err != nil {
			clear(encoded)
			return err
		}
		clear(encoded)
	}
	if _, err := chunked.Write(append([]byte(`],"error":`), append(errorJSON, '}')...)); err != nil {
		return err
	}
	return chunked.Close()
}

func writeBatchJSON(w io.Writer, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		writeBatchError(w, &batchapi.APIError{Status: 500, Message: "batch encoding error", Type: "server_error", Code: "internal_error"})
		return
	}
	writeJSONResponse(w, status, body)
}

func writeBatchError(w io.Writer, apiErr *batchapi.APIError) {
	if apiErr == nil {
		apiErr = &batchapi.APIError{Status: 500, Message: "batch error", Type: "server_error", Code: "internal_error"}
	}
	writeOpenAIError(w, apiErr.Status, apiErr.Message, apiErr.Type, apiErr.Code, apiErr.Param)
}
