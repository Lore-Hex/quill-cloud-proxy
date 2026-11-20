package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

func TestCallerSafetyValidation(t *testing.T) {
	for _, raw := range []string{"false", "123", "[]", "{}", `""`, `"   "`, `"a\nb"`, fmt.Sprintf("%q", strings.Repeat("é", 33))} {
		if _, err := parseCallerSafety(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted invalid safety_identifier: %s", raw)
		}
	}
	for _, raw := range []string{"", "null"} {
		if got, err := parseCallerSafety(json.RawMessage(raw)); err != nil || got != "" {
			t.Fatal("omission or null must not opt in")
		}
	}
	if got, err := parseCallerSafety(json.RawMessage(fmt.Sprintf("%q", strings.Repeat("é", 32)))); len(got) != 64 || err != nil {
		t.Fatal("valid 64-byte identifier did not produce a digest")
	}
}

func TestCallerSafetyIngressThroughAuthorizationAndUpstreamBody(t *testing.T) {
	type result struct{ activity, upstream string }
	run := func(route, id, ws, key, provider string, loseTag bool) result {
		t.Helper()
		model := "openai/gpt-4o-mini"
		if route == "responses" {
			model = "openai/gpt-5.5"
		}
		fields := map[string]any{"model": model, "tags": map[string]string{"project": "demo"}, "user": "legacy-user"}
		if route == "responses" {
			fields["input"] = "hi"
			fields["tools"] = []any{map[string]any{"type": "function", "name": "synthetic", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}}}
		} else {
			fields["messages"] = []map[string]string{{"role": "user", "content": "hi"}}
		}
		if id != "" {
			fields["safety_identifier"] = id
		}
		body, _ := json.Marshal(fields)
		owner := strings.Repeat("a", 64)
		var activity string
		var validates, settles int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if id != "" && bytes.Contains(raw, []byte(id)) {
				t.Error("raw subject reached the control plane")
			}
			data := map[string]any{}
			switch r.URL.Path {
			case "/internal/gateway/validate":
				validates++
				data["workspace_id"], data["api_key_hash"] = ws, "key"
			case "/internal/gateway/authorize":
				var billed struct {
					User string
					Tags map[string]string
				}
				if json.Unmarshal(raw, &billed) != nil || billed.Tags["project"] != "demo" || billed.User != "legacy-user" {
					t.Error("existing attribution was lost")
				}
				activity = billed.Tags["safety_identifier"]
				if loseTag {
					delete(billed.Tags, "safety_identifier")
				}
				data = map[string]any{"authorization_id": "auth_test", "workspace_id": ws, "api_key_hash": "key", "model": model,
					"endpoint_id": model + "@" + provider + "/prepaid", "provider": provider, "usage_type": "Credits", "limit_usage_type": "Credits",
					"request_metadata_version": 1, "tags": billed.Tags, "openai_safety_identifier": owner}
			case "/internal/gateway/settle":
				settles++
				data = map[string]any{"settled": true, "generation_id": "gen_test", "cost_microdollars": 12, "model": model, "provider": provider, "region": "us-central1"}
			case "/internal/gateway/refund":
				data["refunded"] = true
			default:
				t.Errorf("unexpected call: %s", r.URL.Path)
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		}))
		defer server.Close()
		resp, _, fake, logs := serveLenientRequest(t, server, "/v1/"+route, key, "", string(body))
		if id != "" && strings.Contains(logs, id) {
			t.Fatal("raw subject reached logs")
		}
		if loseTag {
			if resp.StatusCode < 400 || fake.request != nil || settles != 0 {
				t.Fatal("unbound attribution reached inference")
			}
			return result{}
		}
		if resp.StatusCode != 200 || len(fake.options) != 1 || settles != 1 || (id != "") != (validates == 1) || (id == "" && validates != 0) {
			t.Fatalf("route=%s status=%d options=%d validates=%d settles=%d", route, resp.StatusCode, len(fake.options), validates, settles)
		}
		wire, err := llm.PrepareChatRequest(provider, model, fake.request, fake.body, nil, llm.ChatPreparationOptions{OpenAISafetyIdentifier: fake.options[0].OpenAISafetyIdentifier})
		if err != nil {
			t.Fatal(err)
		}
		var fieldsOut map[string]any
		if (route == "responses") != wire.NativeResponses || fake.options[0].OpenAICallerSafety != (id != "" && provider == "openai") {
			t.Fatal("wrong upstream endpoint or identity scope")
		}
		if err := json.Unmarshal(wire.Bytes, &fieldsOut); err != nil {
			t.Fatal(err)
		}
		actual, _ := fieldsOut["safety_identifier"].(string)
		if id == "" {
			if actual != owner || activity != "" {
				t.Fatal("legacy owner or attribution changed")
			}
		} else {
			if b, err := hex.DecodeString(activity); err != nil || len(b) != 32 {
				t.Fatal("missing usage pseudonym")
			}
			if provider == "openai" {
				if b, err := hex.DecodeString(actual); err != nil || len(b) != 32 || actual == activity || actual == owner {
					t.Fatal("wrong provider pseudonym")
				}
			} else if actual != "" {
				t.Fatal("caller identifier forwarded to another provider")
			}
			if bytes.Contains(wire.Bytes, []byte(id)) {
				t.Fatal("raw subject leaked to upstream body")
			}
		}
		return result{activity, actual}
	}
	a := run("chat/completions", "synthetic-account-417", "workspace-A", "sk-synthetic-one", "openai", false)
	b := run("responses", "synthetic-account-417", "workspace-A", "sk-rotated-test", "openai", false)
	if a != b {
		t.Fatal("key rotation or endpoint changed the identity")
	}
	for _, other := range []result{
		run("chat/completions", "synthetic-account-418", "workspace-A", "sk-synthetic-one", "openai", false),
		run("chat/completions", "synthetic-account-417", "workspace-B", "sk-independent", "openai", false),
	} {
		if other.activity == a.activity || other.upstream == a.upstream {
			t.Fatal("identities collided across users or workspaces")
		}
	}
	run("chat/completions", "", "workspace-A", "sk-synthetic-one", "openai", false)
	run("chat/completions", "synthetic-account-417", "workspace-A", "sk-synthetic-one", "openrouter", false)
	run("chat/completions", "synthetic-account-417", "workspace-A", "sk-synthetic-one", "openai", true)
}
