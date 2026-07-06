// Package broadcast delivers opt-in content exports from inside the attested
// gateway. Failures are intentionally isolated from inference and settlement.
package broadcast

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type Generation struct {
	ID                string
	WorkspaceID       string
	APIKeyHash        string
	Model             string
	Provider          string
	Region            string
	RouteType         string
	RequestID         string
	InputTokens       int
	OutputTokens      int
	ElapsedSeconds    float64
	FirstTokenSeconds float64
	Streamed          bool
	FinishReason      string
	CostMicrodollars  int
	User              string
	SessionID         string
	Trace             map[string]any
	Metadata          map[string]any
}

// StripContent returns a copy of destinations with IncludeContent cleared, so
// the content-delivery path (DeliverContent) never POSTs prompt or completion
// text to any of them.
//
// DevProof G5: broadcast destinations arrive from the UNATTESTED control plane,
// which the enclave cannot trust to carry only user-set destinations — a
// malicious operator could inject one and exfiltrate plaintext. The enclave is
// the trust boundary, so it refuses to honor content-broadcast instructions
// from the control plane rather than trying to make the control plane
// trustworthy. Metadata broadcast (token counts + timing) is done
// control-plane-side and never carried content, so it is unaffected. A future
// user-facing content-broadcast feature must AUTHENTICATE destinations to the
// user (e.g. an HMAC keyed on the raw API key the operator never sees) rather
// than trusting the control plane.
func StripContent(destinations []trustedrouter.BroadcastDestination) []trustedrouter.BroadcastDestination {
	if len(destinations) == 0 {
		return nil
	}
	out := make([]trustedrouter.BroadcastDestination, len(destinations))
	for i, d := range destinations {
		d.IncludeContent = false
		out[i] = d
	}
	return out
}

func DeliverContent(
	ctx context.Context,
	httpc *http.Client,
	cache *byokcache.Cache,
	destinations []trustedrouter.BroadcastDestination,
	generation Generation,
	input any,
	output string,
) {
	if len(destinations) == 0 {
		return
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 5 * time.Second}
	}
	for _, destination := range destinations {
		if !destination.IncludeContent {
			continue
		}
		if err := deliverOne(ctx, httpc, cache, destination, generation, input, output); err != nil {
			// Keep the diagnostic metadata-only: no body, prompt, completion, or
			// decrypted destination secret.
			fmt.Fprintf(
				os.Stderr,
				"broadcast.delivery_failed destination_id=%q type=%q err=%v\n",
				destination.ID,
				destination.Type,
				err,
			)
		}
	}
}

func deliverOne(
	ctx context.Context,
	httpc *http.Client,
	cache *byokcache.Cache,
	destination trustedrouter.BroadcastDestination,
	generation Generation,
	input any,
	output string,
) error {
	adapter, ok := adapterFor(destination.Type)
	if !ok {
		return unsupportedDestinationError(destination.Type)
	}
	return adapter.Deliver(ctx, httpc, cache, destination, generation, input, output)
}

func posthogPayload(apiKey string, generation Generation, input any, output string) map[string]any {
	properties := aiProperties(generation)
	properties["$ai_input"] = input
	properties["$ai_output_choices"] = []map[string]any{{
		"message": map[string]any{"role": "assistant", "content": output},
	}}
	return map[string]any{
		"api_key":     apiKey,
		"event":       "$ai_generation",
		"distinct_id": distinctID(generation),
		"properties":  properties,
	}
}

func aiProperties(generation Generation) map[string]any {
	properties := map[string]any{
		"$ai_trace_id":             firstString(traceValue(generation, "trace_id"), generation.RequestID),
		"$ai_session_id":           firstString(generation.SessionID, traceValue(generation, "session_id")),
		"$ai_span_id":              generation.ID,
		"$ai_span_name":            firstString(traceValue(generation, "generation_name"), traceValue(generation, "span_name"), "llm.generation"),
		"$ai_model":                generation.Model,
		"$ai_provider":             generation.Provider,
		"$ai_input_tokens":         generation.InputTokens,
		"$ai_output_tokens":        generation.OutputTokens,
		"$ai_latency":              generation.ElapsedSeconds,
		"$ai_time_to_first_token":  generation.FirstTokenSeconds,
		"$ai_stream":               generation.Streamed,
		"$ai_http_status":          200,
		"$ai_stop_reason":          generation.FinishReason,
		"$ai_total_cost_usd":       float64(generation.CostMicrodollars) / 1_000_000,
		"trustedrouter_region":     generation.Region,
		"trustedrouter_route_type": generation.RouteType,
	}
	for key, value := range generation.Trace {
		if _, exists := properties[key]; !exists {
			properties[key] = scalar(value)
		}
	}
	for key, value := range generation.Metadata {
		properties["metadata."+key] = scalar(value)
	}
	return properties
}

func otlpPayload(generation Generation, includeContent bool, input any, output string) map[string]any {
	now := time.Now()
	start := now.Add(-time.Duration(maxFloat(generation.ElapsedSeconds, 0.001) * float64(time.Second)))
	attrs := []map[string]any{
		attr("gen_ai.system", "trustedrouter"),
		attr("gen_ai.operation.name", generation.RouteType),
		attr("gen_ai.request.model", generation.Model),
		attr("gen_ai.response.model", generation.Model),
		attr("gen_ai.provider.name", generation.Provider),
		attr("gen_ai.usage.prompt_tokens", generation.InputTokens),
		attr("gen_ai.usage.completion_tokens", generation.OutputTokens),
		attr("gen_ai.usage.total_tokens", generation.InputTokens+generation.OutputTokens),
		attr("gen_ai.response.finish_reasons", generation.FinishReason),
		attr("trustedrouter.cost.microdollars", generation.CostMicrodollars),
		attr("trustedrouter.cost.usd", float64(generation.CostMicrodollars)/1_000_000),
		attr("trustedrouter.region", generation.Region),
		attr("trustedrouter.streamed", generation.Streamed),
		attr("user.id", generation.User),
		attr("session.id", generation.SessionID),
	}
	for key, value := range generation.Trace {
		attrs = append(attrs, attr("trace.metadata."+key, scalar(value)))
	}
	for key, value := range generation.Metadata {
		attrs = append(attrs, attr("trace.metadata.metadata."+key, scalar(value)))
	}
	if includeContent {
		inputBytes, _ := json.Marshal(input)
		attrs = append(attrs, attr("gen_ai.prompt", string(inputBytes)))
		attrs = append(attrs, attr("gen_ai.completion", output))
	}
	return map[string]any{
		"resourceSpans": []map[string]any{{
			"resource": map[string]any{"attributes": []map[string]any{
				attr("service.name", "trustedrouter"),
				attr("service.namespace", "trustedrouter"),
			}},
			"scopeSpans": []map[string]any{{
				"scope": map[string]any{"name": "trustedrouter.broadcast", "version": "1"},
				"spans": []map[string]any{{
					"traceId":           hexDigest(firstString(traceValue(generation, "trace_id"), generation.RequestID), 32),
					"spanId":            hexDigest(generation.ID, 16),
					"name":              firstString(traceValue(generation, "generation_name"), traceValue(generation, "span_name"), "llm.generation"),
					"kind":              2,
					"startTimeUnixNano": fmt.Sprintf("%d", start.UnixNano()),
					"endTimeUnixNano":   fmt.Sprintf("%d", now.UnixNano()),
					"attributes":        attrs,
					"status":            map[string]any{"code": 1},
				}},
			}},
		}},
	}
}

func postJSON(ctx context.Context, httpc *http.Client, endpoint string, headers map[string]string, payload map[string]any) error {
	return sendJSON(ctx, httpc, http.MethodPost, endpoint, headers, payload)
}

func sendJSON(ctx context.Context, httpc *http.Client, method string, endpoint string, headers map[string]string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("destination http %d", resp.StatusCode)
	}
	return nil
}

func resolveSecret(
	ctx context.Context,
	cache *byokcache.Cache,
	workspaceID string,
	contextName string,
	envelope *byokcache.EncryptedSecretEnvelope,
) (string, error) {
	if envelope == nil {
		return "", fmt.Errorf("encrypted secret is missing")
	}
	if cache == nil {
		return "", fmt.Errorf("secret cache is unavailable")
	}
	value, _, err := cache.Resolve(ctx, workspaceID, contextName, "", *envelope)
	return value, err
}

func resolveHeaders(
	ctx context.Context,
	cache *byokcache.Cache,
	workspaceID string,
	destination trustedrouter.BroadcastDestination,
) (map[string]string, error) {
	if destination.EncryptedHeaders == nil {
		return nil, nil
	}
	raw, err := resolveSecret(ctx, cache, workspaceID, destination.HeadersContext, destination.EncryptedHeaders)
	if err != nil {
		return nil, err
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func posthogURL(endpoint string) string {
	base := strings.TrimRight(endpoint, "/")
	if base == "" {
		base = "https://us.i.posthog.com"
	}
	return base + "/i/v0/e/"
}

func distinctID(generation Generation) string {
	if generation.User != "" {
		return generation.User
	}
	if len(generation.APIKeyHash) >= 16 {
		return generation.APIKeyHash[:16]
	}
	return generation.WorkspaceID
}

func traceValue(generation Generation, key string) string {
	if generation.Trace == nil {
		return ""
	}
	return stringFromAny(generation.Trace[key])
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func scalar(value any) any {
	switch value.(type) {
	case string, int, int64, float64, bool:
		return value
	default:
		body, _ := json.Marshal(value)
		return string(body)
	}
}

func attr(key string, value any) map[string]any {
	out := map[string]any{"key": key}
	switch v := value.(type) {
	case bool:
		out["value"] = map[string]any{"boolValue": v}
	case int:
		out["value"] = map[string]any{"intValue": fmt.Sprintf("%d", v)}
	case int64:
		out["value"] = map[string]any{"intValue": fmt.Sprintf("%d", v)}
	case float64:
		out["value"] = map[string]any{"doubleValue": v}
	default:
		out["value"] = map[string]any{"stringValue": stringFromAny(v)}
	}
	return out
}

func stringFromAny(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", value)
}

func hexDigest(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:length]
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
