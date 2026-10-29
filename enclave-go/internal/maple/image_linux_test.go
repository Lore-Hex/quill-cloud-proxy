//go:build linux && !cloud_aws

package maple

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMapleMeasuredHelperPaidSynthetic(t *testing.T) {
	if os.Getenv("TR_MAPLE_PAID_IMAGE_TEST") != "1" {
		t.Skip("requires explicit paid synthetic probe with credential on stdin")
	}
	key, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(key) == 0 || len(key) > 8192 {
		t.Fatal("missing or invalid bounded credential input")
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	body := []byte(`{"model":"deepseek-v4-1-flash-1017-uncensored","messages":[{"role":"user","content":"Reply with exactly PONG."}],"max_tokens":1024,"temperature":0,"stream":true}`)
	status, response, err := Start(ctx, strings.TrimSpace(string(key)), "", body)
	if err != nil {
		t.Fatalf("measured helper failed: %v", err)
	}
	defer response.Close()
	data, err := io.ReadAll(io.LimitReader(response, 1024*1024))
	if err != nil || status != 200 || !bytes.HasSuffix(data, []byte("data: [DONE]\n\n")) {
		t.Fatalf("encrypted response did not complete: status=%d error=%v", status, err)
	}
	var answer strings.Builder
	var input, output int64
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data: {")) {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				Input  int64 `json:"prompt_tokens"`
				Output int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line[len("data: "):], &chunk) != nil {
			t.Fatal("invalid helper JSON")
		}
		for _, choice := range chunk.Choices {
			answer.WriteString(choice.Delta.Content)
		}
		if chunk.Usage != nil {
			input, output = chunk.Usage.Input, chunk.Usage.Output
		}
	}
	if strings.Trim(answer.String(), " \n\t\".!'") != "PONG" || input <= 0 || output <= 0 {
		t.Fatal("synthetic response or integer usage did not match")
	}
	t.Logf("authenticated synthetic completed with %d input and %d output tokens", input, output)
}

// Runs only in the isolated image harness with the actual launcher and helper
// installed at their measured paths. It needs no account credential or tokens.
func TestMapleMeasuredHelperRejectsFakeCredential(t *testing.T) {
	if os.Getenv("TR_MAPLE_IMAGE_TEST") != "1" {
		t.Skip("requires isolated image harness and live attestation endpoint")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	body := []byte(`{"model":"deepseek-v4-1-flash-1017-uncensored","messages":[{"role":"user","content":"PONG"}],"max_tokens":1,"stream":true}`)
	status, response, err := Start(ctx, "deliberately-invalid-maple-key", "isolated-image-test", body)
	if err != nil {
		t.Fatalf("measured helper failed before authenticated status: %v", err)
	}
	defer response.Close()
	content, err := io.ReadAll(response)
	if err != nil || status != 401 || len(content) != 0 {
		t.Fatalf("expected empty authenticated 401, got status=%d length=%d error=%v", status, len(content), err)
	}
}
