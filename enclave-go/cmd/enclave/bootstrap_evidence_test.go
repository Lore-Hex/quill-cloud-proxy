package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestHealthReportsAWSBootstrapEvidence(t *testing.T) {
	previous, previousProbes := awsBootstrapEvidence.Load(), privatemodeProbeResults.Load()
	t.Cleanup(func() {
		awsBootstrapEvidence.Store(previous)
		privatemodeProbeResults.Store(previousProbes)
	})
	privatemodeProbeResults.Store(nil)
	fixture, err := os.ReadFile(filepath.Join("..", "..", "internal", "types", "testdata", "aws_bootstrap_health.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wire []json.RawMessage
	if err := json.Unmarshal(fixture, &wire); err != nil || len(wire) != 3 {
		t.Fatalf("invalid shared bootstrap wire fixture: %v", err)
	}
	for i, evidence := range []types.AWSBootstrapEvidence{
		{Policy: "transition", Mode: "legacy"},
		{Policy: "transition", Mode: "attested", BundleVersion: 7},
		{Policy: "strict", Mode: "attested", BundleVersion: 8},
	} {
		input := evidence
		recordAWSBootstrapEvidence(&input)
		input.Mode = "mutated-after-publication"
		var output bytes.Buffer
		writeHealthResponse(&output, false, time.Now())
		_, body := readRawHTTPResponse(t, output.Bytes())
		var expected bytes.Buffer
		if err := json.Compact(&expected, wire[i]); err != nil || !bytes.Equal(body, expected.Bytes()) {
			t.Fatalf("health wire contract changed: %s (%v)", body, err)
		}
		var result struct {
			Status    string                     `json:"status"`
			Bootstrap types.AWSBootstrapEvidence `json:"aws_bootstrap"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.Status != "ok" || result.Bootstrap != evidence {
			t.Fatalf("incorrect boot evidence: %s (%v)", body, err)
		}
		if !bytes.Contains(output.Bytes(), []byte("Cache-Control: no-store")) {
			t.Fatal("bootstrap evidence must not be cached")
		}
	}
	recordPrivatemodeProbe(llm.PrivatemodeProbeResult{Success: true, Reason: "ok"})
	var combined bytes.Buffer
	writeHealthResponse(&combined, false, time.Now())
	_, body := readRawHTTPResponse(t, combined.Bytes())
	if !bytes.Contains(body, []byte(`"aws_bootstrap":{`)) || !bytes.Contains(body, []byte(`"privatemode_probes":[`)) {
		t.Fatalf("one boot diagnostic displaced the other: %s", body)
	}
	recordAWSBootstrapEvidence(nil)
	var probesOnly bytes.Buffer
	writeHealthResponse(&probesOnly, false, time.Now())
	_, body = readRawHTTPResponse(t, probesOnly.Bytes())
	if bytes.Contains(body, []byte(`"aws_bootstrap"`)) || !bytes.Contains(body, []byte(`"privatemode_probes":[`)) {
		t.Fatalf("non-AWS probe evidence changed: %s", body)
	}
	privatemodeProbeResults.Store(nil)
	recordAWSBootstrapEvidence(nil)
	var empty bytes.Buffer
	writeHealthResponse(&empty, false, time.Now())
	_, body = readRawHTTPResponse(t, empty.Bytes())
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("non-AWS health changed: %s", body)
	}
}
