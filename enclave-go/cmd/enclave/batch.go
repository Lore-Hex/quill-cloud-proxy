package main

import (
	"context"
	"encoding/json"
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
	result, apiErr := batchGateway.Get(ctx, bearer, id)
	if apiErr != nil {
		writeBatchError(conn, apiErr)
		return true
	}
	writeBatchJSON(conn, http.StatusOK, result)
	return true
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
