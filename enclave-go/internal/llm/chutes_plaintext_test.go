package llm

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type chutesPlaintextCase struct {
	name, plaintext, content string
	failure                  bool
}

func TestChutesAuthenticatedPrettyJSONAcrossAPIs(t *testing.T) {
	testChutesAuthenticatedChunksAcrossAPIs(t, []chutesPlaintextCase{
		{"pretty error", "{\n\"error\":{\"code\":403,\"message\":\"denied\"}\n}", "", true},
		{"prefixed pretty error", "data: {\n\"error\":{\"code\":403,\"message\":\"denied\"}\n}", "", true},
		{"pretty content", "{\n\"choices\":[{\"delta\":{\"content\":\"delivered\"}}]\n}", "delivered", false},
		{"prefixed pretty content", "data: {\n\"choices\":[{\"delta\":{\"content\":\"delivered\"}}]\n}", "delivered", false},
		{"token text", `The API returns {"error":"bad"} on failure.`, `The API returns {"error":"bad"} on failure.`, false},
	})
}

func TestChutesAuthenticatedJSONTextCompletesAcrossAPIs(t *testing.T) {
	testChutesAuthenticatedChunksAcrossAPIs(t, []chutesPlaintextCase{
		{"array containing error", `[{"error":"validation failed"}]`, `[{"error":"validation failed"}]`, false},
		{"array preserves whitespace", `[ 1, 2 ]`, `[ 1, 2 ]`, false},
		{"JSON string", `"validation failed"`, `"validation failed"`, false},
		{"JSON number", `42`, `42`, false},
		{"JSON boolean", `true`, `true`, false},
		{"JSON null", `null`, `null`, false},
	})
}

func TestChutesPrefixedNonObjectJSONKeepsFraming(t *testing.T) {
	for _, plaintext := range []string{`[{"error":"validation failed"}]`, `[ 1, 2 ]`, `"validation failed"`, `42`, `true`, `null`} {
		got, terminal, err := frameChutesDecryptedChunk([]byte("data: " + plaintext))
		want := "data: " + plaintext + "\n\n"
		if err != nil || terminal || string(got) != want {
			t.Errorf("non-object framing changed for %q: got=%q terminal=%t err=%v", plaintext, got, terminal, err)
		}
	}
}

func testChutesAuthenticatedChunksAcrossAPIs(t *testing.T, cases []chutesPlaintextCase) {
	t.Helper()
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				wire := chutesTestEncryptedStream(t, base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), tc.plaintext, `{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
				pr, pw := io.Pipe()
				defer pr.Close()
				done := make(chan error, 1)
				go func() {
					err := translateChutesEncryptedStream(strings.NewReader(wire), pw, key)
					_ = pw.CloseWithError(err)
					done <- err
				}()
				var out bytes.Buffer
				terminals := 0
				finish := func(int64) error { terminals++; return nil }
				var streamErr error
				switch route {
				case "messages":
					_, streamErr = adapter.RelayAnthropicStreamWithTerminalHook(pr, &out, "msg", "model", func(adapter.StreamTerminal) error { terminals++; return nil })
				case "chat.completions":
					_, streamErr = adapter.TransformStreamCaptureWithRouterMetadataAndFinishHook(pr, &out, "msg", "model", true, nil, finish)
				case "responses":
					_, streamErr = adapter.TransformResponsesStreamWithFinishHook(pr, &out, "msg", "model", 0, nil, nil, finish)
				}
				_ = pr.Close()
				providerErr := <-done
				if tc.failure {
					d := upstreamerror.Parse(providerErr)
					if providerErr == nil || streamErr == nil || terminals != 0 || d.Status != 403 || d.Message != "denied" {
						t.Fatalf("decrypted failure completed: provider=%v stream=%v terminals=%d detail=%+v", providerErr, streamErr, terminals, d)
					}
				} else {
					encoded, _ := json.Marshal(tc.content)
					if providerErr != nil || streamErr != nil || terminals != 1 || !bytes.Contains(out.Bytes(), encoded) {
						t.Fatalf("authenticated content lost: provider=%v stream=%v terminals=%d out=%s", providerErr, streamErr, terminals, &out)
					}
				}
			})
		}
	}
}
