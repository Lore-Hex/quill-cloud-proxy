package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

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
	rawTarget string,
	gateway *trustedrouter.Client,
) bool {
	if method != "GET" {
		return false
	}
	var fetch func(context.Context) ([]byte, error)
	label := "model"
	switch {
	case routePath == "/v1/models":
		fetch = gateway.PublicModels
	case routePath == "/v1/images/models":
		label = "image model"
		fetch = gateway.PublicImageModels
	case strings.HasPrefix(routePath, "/v1/images/models/") && strings.HasSuffix(routePath, "/endpoints"):
		parts := strings.Split(strings.TrimPrefix(routePath, "/v1/images/models/"), "/")
		if len(parts) != 3 || parts[2] != "endpoints" || parts[0] == "" || parts[1] == "" {
			return false
		}
		label = "image endpoint"
		modelID := parts[0] + "/" + parts[1]
		fetch = func(ctx context.Context) ([]byte, error) {
			return gateway.PublicImageModelEndpoints(ctx, modelID)
		}
	default:
		return false
	}
	if gateway == nil {
		// Distinct from a fetch failure: the control-plane client was never
		// constructed, so no request was even attempted. Both used to emit the
		// same opaque 503, making the two indistinguishable from outside.
		fmt.Fprintf(os.Stderr, "enclave.public_models_unavailable reason=%q\n", "no control-plane client")
		writeRetryableError(w, 503, "model catalog unavailable")
		return true
	}
	body, err := fetch(ctx)
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
		fmt.Fprintf(os.Stderr, "enclave.public_models_unavailable catalog=%q reason=%q\n", label, err.Error())
		writeRetryableError(w, 503, label+" catalog unavailable")
		return true
	}
	if routePath == "/v1/models" {
		body, err = filterPublicModelsByOutputModalities(body, rawTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclave.public_models_invalid reason=%q\n", err.Error())
			writeRetryableError(w, 503, "model catalog unavailable")
			return true
		}
	}
	writePublicModelsResponse(w, body)
	return true
}

func filterPublicModelsByOutputModalities(body []byte, rawTarget string) ([]byte, error) {
	target, err := url.ParseRequestURI(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid catalog request target: %w", err)
	}
	requested := map[string]struct{}{}
	for _, raw := range target.Query()["output_modalities"] {
		for _, value := range strings.Split(raw, ",") {
			if normalized := strings.ToLower(strings.TrimSpace(value)); normalized != "" {
				requested[normalized] = struct{}{}
			}
		}
	}
	if len(requested) == 0 {
		return body, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode model catalog: %w", err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(envelope["data"], &rows); err != nil {
		return nil, fmt.Errorf("decode model rows: %w", err)
	}
	filtered := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		var shape struct {
			Architecture struct {
				OutputModalities []string `json:"output_modalities"`
			} `json:"architecture"`
		}
		if err := json.Unmarshal(row, &shape); err != nil {
			return nil, fmt.Errorf("decode model row: %w", err)
		}
		available := map[string]struct{}{}
		for _, modality := range shape.Architecture.OutputModalities {
			available[strings.ToLower(modality)] = struct{}{}
		}
		matches := true
		for modality := range requested {
			if _, ok := available[modality]; !ok {
				matches = false
				break
			}
		}
		if matches {
			filtered = append(filtered, row)
		}
	}
	envelope["data"], err = json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("encode model rows: %w", err)
	}
	return json.Marshal(envelope)
}

func writePublicModelsResponse(w io.Writer, body []byte) {
	fmt.Fprintf(
		w,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: public, max-age=60, stale-if-error=300\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
		len(body),
	)
	_, _ = w.Write(body)
}
