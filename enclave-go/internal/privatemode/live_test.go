//go:build linux && live_provider_wave

package privatemode

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveManifestMismatchFailsClosed(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if key == "" {
		t.Skip("set PRIVATEMODE_API_KEY for encrypted negative-control test")
	}
	original := manifest
	defer func() { manifest = original }()
	var expected map[string]any
	if err := json.Unmarshal(manifest, &expected); err != nil {
		t.Fatal(err)
	}
	for policy := range expected["Policies"].(map[string]any) {
		delete(expected["Policies"].(map[string]any), policy)
		break
	}
	var err error
	manifest, err = json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	client, err := Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"/chat/completions", bytes.NewBufferString(
		`{"model":"gpt-oss-120b","messages":[{"role":"user","content":"Synthetic mismatch test"}],"max_tokens":16}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode < 400 || !bytes.Contains(bytes.ToLower(body), []byte("manifest")) {
		t.Fatalf("expected attestation failure, status=%d response_bytes=%d", resp.StatusCode, len(body))
	}
	t.Logf("changed manifest rejected: HTTP %d", resp.StatusCode)
}
