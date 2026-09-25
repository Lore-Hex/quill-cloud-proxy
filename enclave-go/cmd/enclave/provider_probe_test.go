package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

func TestHealthReportsBoundedBootProbeEvidence(t *testing.T) {
	privatemodeProbeResults.Store(nil)
	t.Cleanup(func() { privatemodeProbeResults.Store(nil) })
	var initial bytes.Buffer
	writeHealthResponse(&initial, false, time.Now())
	_, initialBody := readRawHTTPResponse(t, initial.Bytes())
	if string(initialBody) != `{"status":"ok"}` {
		t.Fatalf("unconfigured health changed: %s", initialBody)
	}
	for i := 0; i < 4; i++ {
		recordPrivatemodeProbe(llm.PrivatemodeProbeResult{
			Event: "privatemode.encrypted_probe", Model: "glm-5.3", Success: true, Reason: "ok",
			InputTokens: 21, OutputTokens: 4,
		})
	}
	for i := 0; i < 2; i++ {
		var out bytes.Buffer
		writeHealthResponse(&out, false, time.Now())
		_, body := readRawHTTPResponse(t, out.Bytes())
		var result struct {
			Status string                       `json:"status"`
			Probes []llm.PrivatemodeProbeResult `json:"privatemode_probes"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if result.Status != "ok" || len(result.Probes) != 3 || !result.Probes[0].Success {
			t.Fatalf("unexpected health metadata: %s", body)
		}
	}
}
