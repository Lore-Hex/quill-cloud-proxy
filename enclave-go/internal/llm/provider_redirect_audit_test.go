//go:build !cloud_aws

package llm

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
)

type providerRedirectProbe struct {
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint"`
	SecretName      string `json:"secret_name"`
	WithCredentials bool   `json:"with_credentials"`
	Status          int    `json:"status"`
	Location        string `json:"location,omitempty"`
	Error           string `json:"error,omitempty"`
}

func providerRedirectProbes(t *testing.T) []providerRedirectProbe {
	t.Helper()
	endpoints := map[string]string{}
	add := func(provider, endpoint string) { endpoints[endpoint] = provider }
	for _, spec := range directproviders.All() {
		if spec.MediaOnly || spec.Provider == "maple" || spec.Provider == "privatemode" {
			continue // Encrypted helpers and media use different request protocols.
		}
		path := spec.ChatPath()
		switch spec.Provider {
		case "telluvian":
			path = "/modelSelect"
		case "typesafe", "system1models", "system1models-eu":
			path = "/systemone"
		case "vercel-ai-gateway":
			path = "/evaluate"
		case "jina":
			path = "/embeddings"
		}
		add(spec.Provider, spec.BaseURL+path)
	}
	// Read the real legacy switch, rather than maintain a second list of providers.
	f, err := parser.ParseFile(token.NewFileSet(), "byok.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "directBaseURL" {
			continue
		}
		ast.Inspect(fn, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok || len(clause.List) == 0 {
				return true
			}
			label, ok := clause.List[0].(*ast.BasicLit)
			if !ok {
				return false
			}
			provider, _ := strconv.Unquote(label.Value)
			for _, statement := range clause.Body {
				ret, ok := statement.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				lit, ok := ret.Results[0].(*ast.BasicLit)
				if !ok {
					continue
				}
				base, _ := strconv.Unquote(lit.Value)
				path := "/chat/completions"
				if provider == "voyage" {
					path = "/embeddings"
				}
				add(provider, base+path)
			}
			return false
		})
	}
	for provider, endpoint := range map[string]string{
		"anthropic-messages":   "https://api.anthropic.com/v1/messages",
		"azure-messages":       "https://trustedrouter-foundry-eastus2.services.ai.azure.com/anthropic/v1/messages",
		"azure-decision":       "https://trustedrouter-foundry-eastus2.services.ai.azure.com/providers/microsoft/v1/systemone",
		"databricks-chat":      "https://dbc-7ccfd8c0-c0da.cloud.databricks.com/serving-endpoints/chat/completions",
		"chutes-chat":          "https://llm.chutes.ai/v1/chat/completions",
		"cohere-embed":         "https://api.cohere.com/v2/embed",
		"openai-responses":     "https://api.openai.com/v1/responses",
		"openai-image":         "https://api.openai.com/v1/images/generations",
		"xai-image":            "https://api.x.ai/v1/images/generations",
		"recraft-image":        "https://external.api.recraft.ai/v1/images/generations",
		"nscale-image":         "https://inference.api.nscale.com/v1/images/generations",
		"bfl-image":            "https://api.bfl.ai/v1/flux-2-klein-4b",
		"decart-image":         "https://api.decart.ai/v1/generate/lucy-image-2",
		"krea-image":           "https://api.krea.ai/generate/image/krea-2-medium",
		"riverflow-image":      "https://design-api.sourceful.com/v2/generations/t2i",
		"fal-image":            "https://fal.run/fal-ai/flux/schnell",
		"openai-video":         "https://api.openai.com/v1/videos",
		"xai-video":            "https://api.x.ai/v1/videos/generations",
		"minimax-video":        "https://api.minimax.io/v2/video_generation",
		"ltx-video":            "https://api.ltx.io/v2/text-to-video",
		"runway-video":         "https://api.dev.runwayml.com/v1/text_to_video",
		"byteplus-video":       "https://ark.ap-southeast.bytepluses.com/api/v3/contents/generations/tasks",
		"alibaba-video":        "https://ws-el6e4bpnggpx7g88.eu-central-1.maas.aliyuncs.com/api/v1/services/aigc/video-generation/video-synthesis",
		"atlas-cloud-video":    "https://api.atlascloud.ai/api/v1/model/generateVideo",
		"kling-video":          "https://api-singapore.klingai.com/text-to-video/kling-3.0",
		"exa-search":           "https://api.exa.ai/search",
		"deepseek-fetch":       "https://api.deepseek.com/v1/tools/fetch",
		"openai-transcription": "https://api.openai.com/v1/audio/transcriptions",
		"openai-speech":        "https://api.openai.com/v1/audio/speech",
	} {
		add(provider, endpoint)
	}
	probes := make([]providerRedirectProbe, 0, len(endpoints))
	for endpoint, provider := range endpoints {
		probes = append(probes, providerRedirectProbe{Provider: provider, Endpoint: endpoint, SecretName: providerRedirectSecret(provider)})
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].Endpoint < probes[j].Endpoint })
	return probes
}

func providerRedirectSecret(provider string) string {
	if spec, ok := directproviders.Lookup(provider); ok {
		return spec.SecretName
	}
	for _, suffix := range []string{"-messages", "-decision", "-chat", "-embed", "-responses", "-image", "-video", "-search", "-fetch", "-transcription", "-speech"} {
		provider = strings.TrimSuffix(provider, suffix)
	}
	switch provider {
	case "xai":
		provider = "grok"
	case "openrouter":
		return "quill-openrouter-key"
	case "phala":
		provider = "phala-confidential"
	case "thinkingmachines":
		provider = "thinking-machines"
	case "databricks":
		return "trustedrouter-databricks-token"
	}
	if spec, ok := directproviders.Lookup(provider); ok {
		return spec.SecretName
	}
	return "trustedrouter-" + provider + "-api-key"
}

func setProviderAuditAuth(req *http.Request, key string) {
	switch req.URL.Hostname() {
	case "api.anthropic.com":
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "trustedrouter-foundry-eastus2.openai.azure.com", "trustedrouter-foundry-eastus2.services.ai.azure.com":
		if req.URL.Path == "/anthropic/v1/messages" {
			req.Header.Set("x-api-key", key)
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("api-key", key)
		}
	case "api.exa.ai", "api.decart.ai":
		req.Header.Set("x-api-key", key)
	case "api.bfl.ai":
		req.Header.Set("x-key", key)
	case "fal.run":
		req.Header.Set("Authorization", "Key "+key)
	default:
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if req.URL.Hostname() == "pass.wafer.ai" {
		req.Header.Set("Wafer-ZDR", "required")
	}
	if req.URL.Hostname() == "api.dev.runwayml.com" {
		req.Header.Set("X-Runway-Version", "2024-11-06")
	}
}

func TestProviderRedirectAuditAuth(t *testing.T) {
	for _, tc := range []struct{ endpoint, header, prefix string }{
		{"https://api.anthropic.com/v1/messages", "x-api-key", ""},
		{"https://trustedrouter-foundry-eastus2.services.ai.azure.com/anthropic/v1/messages", "x-api-key", ""},
		{"https://trustedrouter-foundry-eastus2.services.ai.azure.com/providers/microsoft/v1/systemone", "api-key", ""},
		{"https://trustedrouter-foundry-eastus2.openai.azure.com/openai/v1/chat/completions", "api-key", ""},
		{"https://api.bfl.ai/v1/flux-2-klein-4b", "x-key", ""},
		{"https://fal.run/fal-ai/flux/schnell", "Authorization", "Key "},
		{"https://api.openai.com/v1/responses", "Authorization", "Bearer "},
	} {
		req, err := http.NewRequest(http.MethodPost, tc.endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		setProviderAuditAuth(req, "audit-fixture")
		for _, header := range []string{"Authorization", "api-key", "x-api-key", "x-key"} {
			want := ""
			if header == tc.header {
				want = tc.prefix + "audit-fixture"
			}
			if req.Header.Get(header) != want {
				t.Errorf("%s: incorrect %s header", tc.endpoint, header)
			}
		}
	}
}

func TestProviderRedirectAuditInventory(t *testing.T) {
	probes := providerRedirectProbes(t)
	if len(probes) < 100 {
		t.Fatalf("unexpectedly small configured-endpoint audit: %d", len(probes))
	}
	for _, probe := range probes {
		row, _ := json.Marshal(probe)
		t.Logf("REDIRECT_INVENTORY %s", row)
		u, err := url.Parse(probe.Endpoint)
		if err != nil || !approvedProviderURL(u) {
			t.Errorf("audit endpoint outside compiled policy: %s", probe.Endpoint)
		}
	}
}

// Opt-in empty-request probes, without prompts, model selection or output
// generation. Keys are optional and explicitly supplied through stdin only.
// A 401/403 does NOT establish authenticated inference behavior.
// Provider outages are reported as inconclusive, not silently treated as passes.
func TestProviderRedirectAuditLive(t *testing.T) {
	if os.Getenv("QUILL_LIVE_PROVIDER_REDIRECT_AUDIT") != "1" {
		t.Skip("optional configured-provider redirect audit")
	}
	credentials := map[string]string{}
	if os.Getenv("QUILL_PROVIDER_REDIRECT_AUDIT_AUTH") == "1" {
		// Use a pipe to a compiled test binary, not command-line args or a key file.
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&credentials); err != nil {
			t.Fatal("cannot read audit credentials from stdin")
		}
	}
	for _, probe := range providerRedirectProbes(t) {
		t.Run(probe.Provider, func(t *testing.T) {
			t.Parallel() // Bound by go test -parallel; use four for the live audit.
			client := NewProviderHTTPClient()
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, probe.Endpoint, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "TrustedRouter/1.0")
			if probe.Provider == "system1models-eu" {
				req.Header.Set("S1-Region", "eu")
			}
			key := credentials[probe.SecretName]
			if key != "" {
				setProviderAuditAuth(req, key)
				probe.WithCredentials = true
			}
			resp, err := client.Do(req)
			if err != nil {
				probe.Error = err.Error()
			} else {
				probe.Status = resp.StatusCode
				if location, locationErr := resp.Location(); locationErr == nil {
					location.RawQuery, location.Fragment, location.User = "", "", nil
					probe.Location = location.String()
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				_ = resp.Body.Close()
			}
			// Never retain credentials echoed by an upstream in a redirect or error.
			if key != "" {
				for _, value := range []string{key, url.QueryEscape(key), url.PathEscape(key)} {
					probe.Error = strings.ReplaceAll(probe.Error, value, "[redacted]")
					probe.Location = strings.ReplaceAll(probe.Location, value, "[redacted]")
				}
			}
			row, _ := json.Marshal(probe)
			t.Logf("REDIRECT_AUDIT %s", row)
			if probe.Error != "" || (probe.Status >= 300 && probe.Status < 400) || probe.Status >= 500 {
				t.Error("redirect or inconclusive probe; review REDIRECT_AUDIT record")
			}
		})
	}
}
