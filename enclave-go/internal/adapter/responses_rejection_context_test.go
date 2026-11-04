package adapter_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestResponsesValidationIdentifiesFieldWithoutExportingContent(t *testing.T) {
	for _, tc := range []struct {
		name, body, field, preview string
	}{
		{"missing model", `{"input":"private prompt"}`, "model", ""},
		{"missing input", `{"model":"m"}`, "input", ""},
		{"empty input", `{"model":"m","input":[]}`, "input", `"[redacted:array]"`},
		{"blank input", `{"model":"m","input":" "}`, "input", `"[redacted:string]"`},
		{"invalid role", `{"model":"m","input":[{"role":"private role","content":"private prompt"}]}`, "input[0].role", `"[redacted:string]"`},
		{"missing content", `{"model":"m","input":[{"role":"user"}]}`, "input[0].content", ""},
		{"empty content", `{"model":"m","input":[{"role":"user","content":""}]}`, "input[0].content", `"[redacted:string]"`},
		{"invalid content part", `{"model":"m","input":[{"role":"user","content":["private prompt"]}]}`, "input[0].content", `"[redacted:array]"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req types.OpenAIResponsesRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatal(err)
			}
			_, err := adapter.ResponsesToChat(&req)
			var rejected *adapter.AdapterError
			if !errors.As(err, &rejected) || rejected.Status != 400 || rejected.Context != tc.field {
				t.Fatalf("error = %#v; want 400 with field %q", err, tc.field)
			}
			if path := trustedrouter.ContractParameterPath(rejected.Context); path != tc.field {
				t.Fatalf("diagnostic field = %q, want %q", path, tc.field)
			}
			if preview, truncated := trustedrouter.ContractParameterValue([]byte(tc.body), rejected.Context); preview != tc.preview || truncated {
				t.Fatal("content-bearing rejected field must export only its redacted type")
			}
		})
	}
}
