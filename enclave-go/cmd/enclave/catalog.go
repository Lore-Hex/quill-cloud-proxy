package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// maybeServePublicModels exposes public catalog metadata on the canonical
// attested API origin. Only GET is anonymous; all other methods continue into
// the normal authentication gate (an OPTIONS preflight is answered earlier by
// maybeServePublicPreflight).
func maybeServePublicModels(
	ctx context.Context,
	w io.Writer,
	method string,
	routePath string,
	rawTarget string,
	acceptGzip bool,
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
		if publicModelsIncludeEndpoints(rawTarget) {
			fetch = gateway.PublicModelsWithEndpoints
		}
	case routePath == "/v1/images/models":
		label = "image model"
		fetch = gateway.PublicImageModels
	case strings.HasPrefix(routePath, "/v1/images/models/"):
		modelID, ok := publicEndpointsModelID(routePath, "/v1/images/models/")
		if !ok {
			return false
		}
		label = "image endpoint"
		fetch = func(ctx context.Context) ([]byte, error) {
			return gateway.PublicImageModelEndpoints(ctx, modelID)
		}
	case strings.HasPrefix(routePath, "/v1/models/"):
		modelID, ok := publicEndpointsModelID(routePath, "/v1/models/")
		if !ok {
			return false
		}
		label = "model endpoint"
		fetch = func(ctx context.Context) ([]byte, error) {
			return gateway.PublicModelEndpoints(ctx, modelID)
		}
	default:
		return false
	}
	if gateway == nil {
		// Distinct from a fetch failure: the control-plane client was never
		// constructed, so no request was even attempted. Both used to emit the
		// same opaque 503, making the two indistinguishable from outside.
		fmt.Fprintf(os.Stderr, "enclave.public_models_unavailable reason=%q\n", "no control-plane client")
		writePublicRetryableError(w, 503, "model catalog unavailable")
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
		writePublicRetryableError(w, 503, label+" catalog unavailable")
		return true
	}
	if routePath == "/v1/models" {
		body, err = filterPublicModelsByOutputModalities(body, rawTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclave.public_models_invalid reason=%q\n", err.Error())
			writePublicRetryableError(w, 503, "model catalog unavailable")
			return true
		}
	}
	writePublicModelsResponse(w, body, acceptGzip)
	return true
}

// publicEndpointsModelID extracts a valid {author}/{slug} from
// <prefix>{author}/{slug}/endpoints. Anything else, including an ID the relay
// would refuse, is not a public route and continues into the authentication
// gate exactly as before.
func publicEndpointsModelID(routePath, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(routePath, prefix)
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[2] != "endpoints" {
		return "", false
	}
	modelID := parts[0] + "/" + parts[1]
	return modelID, trustedrouter.ValidPublicModelID(modelID)
}

// publicModelsIncludeEndpoints mirrors the control plane's include parameter:
// case-insensitive, comma-separated or repeated, unknown values ignored.
func publicModelsIncludeEndpoints(rawTarget string) bool {
	target, err := url.ParseRequestURI(rawTarget)
	if err != nil {
		return false
	}
	for _, raw := range target.Query()["include"] {
		for _, value := range strings.Split(raw, ",") {
			if strings.EqualFold(strings.TrimSpace(value), "endpoints") {
				return true
			}
		}
	}
	return false
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

// writePublicModelsResponse serves catalog metadata. The body is gzip-encoded
// only when the client's Accept-Encoding allows it; either way the response
// says it varies by Accept-Encoding so a shared cache never hands the encoded
// form to a client that did not ask for it.
func writePublicModelsResponse(w io.Writer, body []byte, acceptGzip bool) {
	contentEncoding := ""
	if acceptGzip {
		if compressed, err := gzipPublicBody(body); err == nil {
			body = compressed
			contentEncoding = "Content-Encoding: gzip\r\n"
		} else {
			fmt.Fprintf(os.Stderr, "enclave.public_models_gzip_failed reason=%q\n", err.Error())
		}
	}
	fmt.Fprintf(
		w,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\nCache-Control: public, max-age=60, stale-if-error=300\r\nVary: Accept-Encoding\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nConnection: %s\r\n\r\n",
		contentEncoding, len(body), responseConnection(w),
	)
	_, _ = w.Write(body)
}

// Public catalog and attestation responses are readable from any web origin.
// They are anonymous and identical for every caller, the enclave sets no
// cookies, and Access-Control-Allow-Credentials is never sent, so a browser
// never attaches ambient credentials to these requests. Prompt-bearing routes
// carry no CORS headers at all and are unchanged.
const publicCORSOriginHeader = "Access-Control-Allow-Origin"

// writePublicRetryableError is writeRetryableError for the anonymous public
// routes: a browser client can read why discovery failed instead of seeing an
// opaque CORS error.
func writePublicRetryableError(w io.Writer, status int, message string) {
	writeErrorWithSourceHeaders(w, status, message, "router", map[string]string{
		shouldRetryHeader:      "true",
		publicCORSOriginHeader: "*",
	})
}

func writePublicError(w io.Writer, status int, message string) {
	writeErrorWithSourceHeaders(w, status, message, "router", map[string]string{publicCORSOriginHeader: "*"})
}

// isPublicCORSRoute lists the anonymous GET routes that answer browsers.
func isPublicCORSRoute(routePath string) bool {
	switch routePath {
	case "/attestation", "/v1/models", "/v1/images/models":
		return true
	}
	_, image := publicEndpointsModelID(routePath, "/v1/images/models/")
	_, model := publicEndpointsModelID(routePath, "/v1/models/")
	return image || model
}

// maybeServePublicPreflight answers a CORS preflight for the anonymous GET
// routes. Browsers preflight a GET that carries a non-safelisted header, such
// as an SDK that always sends Authorization; without this the preflight fell
// into the authentication gate and failed with a 401 that had no CORS headers.
//
// Authorization is listed by name because the "*" wildcard does not cover it.
// "*" covers every other request header (SDK telemetry such as x-stainless-*
// varies by client). These routes ignore every request header except
// Accept-Encoding and never check the bearer, so allowing headers grants no
// capability; only GET is allowed. Other routes, including inference, still
// answer OPTIONS through the authentication gate.
func maybeServePublicPreflight(w io.Writer, method, routePath string) bool {
	if method != "OPTIONS" || !isPublicCORSRoute(routePath) {
		return false
	}
	// RFC 9110 forbids Content-Length on a 204; the status alone frames the
	// empty response, so the connection stays reusable.
	fmt.Fprintf(
		w,
		"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, *\r\nAccess-Control-Max-Age: 600\r\nConnection: %s\r\n\r\n",
		responseConnection(w),
	)
	return true
}

// acceptsGzip reports whether an Accept-Encoding value (RFC 9110 section
// 12.5.3) permits gzip: a gzip or x-gzip coding with a nonzero q-value, or
// failing an explicit gzip entry, a "*" with a nonzero q-value. An unparsable
// q-value counts as zero, so a malformed header gets the identity encoding.
func acceptsGzip(header string) bool {
	gzipQ, wildcardQ := -1.0, -1.0
	for _, member := range strings.Split(header, ",") {
		coding, params, _ := strings.Cut(member, ";")
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(param, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				parsed = 0
			}
			q = parsed
		}
		switch strings.ToLower(strings.TrimSpace(coding)) {
		case "gzip", "x-gzip":
			gzipQ = max(gzipQ, q)
		case "*":
			wildcardQ = max(wildcardQ, q)
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return wildcardQ > 0
}

const (
	// Bodies at least this large are compressed once and memoized: the
	// complete catalog is about 4.2 MB, and compressing it on every anonymous
	// request would hand any caller a cheap way to spend enclave CPU.
	publicGzipMemoMinBytes = 64 << 10
	publicGzipMemoEntries  = 8
)

var publicGzipMemo struct {
	sync.Mutex
	entries map[[sha256.Size]byte][]byte
	order   [][sha256.Size]byte
}

// gzipPublicBody returns the gzip encoding of a public catalog body. Large
// bodies are memoized by content hash; the lock is held while compressing so
// concurrent requests for a new catalog revision compress it once. The
// returned slice is shared and must not be modified.
func gzipPublicBody(body []byte) ([]byte, error) {
	if len(body) < publicGzipMemoMinBytes {
		return gzipBytes(body)
	}
	key := sha256.Sum256(body)
	publicGzipMemo.Lock()
	defer publicGzipMemo.Unlock()
	if compressed, ok := publicGzipMemo.entries[key]; ok {
		return compressed, nil
	}
	compressed, err := gzipBytes(body)
	if err != nil {
		return nil, err
	}
	if publicGzipMemo.entries == nil {
		publicGzipMemo.entries = make(map[[sha256.Size]byte][]byte, publicGzipMemoEntries)
	}
	if len(publicGzipMemo.order) >= publicGzipMemoEntries {
		delete(publicGzipMemo.entries, publicGzipMemo.order[0])
		publicGzipMemo.order = publicGzipMemo.order[1:]
	}
	publicGzipMemo.entries[key] = compressed
	publicGzipMemo.order = append(publicGzipMemo.order, key)
	return compressed, nil
}

func gzipBytes(body []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(body); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}
