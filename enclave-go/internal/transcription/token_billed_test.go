package transcription

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTokenAudioContract(t *testing.T) {
	for _, scenario := range []string{"success", "missing-usage", "over-input", "over-output", "zero-output", "length", "null-text", "fractional-usage", "redirect", "private-error"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			verified := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != Models["mistralai/voxtral-small-24b"].URL {
					t.Fatal("incorrect authority")
				}
				var wire map[string]any
				if json.NewDecoder(r.Body).Decode(&wire) != nil || wire["max_tokens"] != float64(MaxOutputTokens) || wire["model"] != "voxtral-small-24b" {
					t.Fatal("budget or model lost")
				}
				messages := wire["messages"].([]any)
				parts := messages[0].(map[string]any)["content"].([]any)
				audio := parts[0].(map[string]any)["input_audio"].(map[string]any)
				if audio["data"] != base64.StdEncoding.EncodeToString([]byte("synthetic-audio")) || audio["format"] != "wav" {
					t.Fatal("audio altered")
				}
				if wire["user"] != nil || wire["trace"] != nil {
					t.Fatal("metadata leaked")
				}
				body := `{"choices":[{"message":{"content":"Paris"},"finish_reason":"stop"}],"usage":{"prompt_tokens":391,"completion_tokens":13}}`
				status := 200
				switch scenario {
				case "missing-usage":
					body = strings.Replace(body, `"usage"`, `"ignored"`, 1)
				case "over-input":
					body = strings.Replace(body, "391", "28673", 1)
				case "over-output":
					body = strings.Replace(body, ":13", ":4097", 1)
				case "zero-output":
					body = strings.Replace(body, ":13", ":0", 1)
				case "length":
					body = strings.Replace(body, `"stop"`, `"length"`, 1)
				case "null-text":
					body = strings.Replace(body, `"Paris"`, `null`, 1)
				case "fractional-usage":
					body = strings.Replace(body, "391", "391.5", 1)
				case "redirect":
					status = 307
				case "private-error":
					status = 400
					body = "private-user-content"
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Location": []string{"https://unverified.example"}}}, nil
			})}
			plain := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unverified transport used"); return nil, nil })}
			c := New(plain, map[string]string{"tinfoil": "synthetic-key"}, func() (*http.Client, error) { return verified, nil })
			result, err := c.Transcribe(t.Context(), &Request{Model: "mistralai/voxtral-small-24b", Audio: []byte("synthetic-audio"), AudioFormat: "wav", Format: "json", User: "private-user"})
			if calls != 1 {
				t.Fatal("unexpected retries")
			}
			if scenario != "success" {
				if err == nil || strings.Contains(err.Error(), "private-user-content") {
					t.Fatal("invalid response accepted or leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			usage, err := TakeTokenUsage(result)
			if err != nil || usage.Input != 391 || usage.Output != 13 || result["_token_usage"] != nil || result["text"] != "Paris" {
				t.Fatal("usage extraction failed")
			}
		})
	}
}

func TestJSONOnlyAudioPreflight(t *testing.T) {
	for _, model := range []string{"mistralai/voxtral-small-24b", "mistralai/voxtral-mini-3b-2507"} {
		for _, format := range []string{"json", "verbose_json"} {
			raw, _ := json.Marshal(map[string]any{"model": model, "response_format": format, "input_audio": map[string]string{"format": "wav", "data": "YXVkaW8="}})
			_, err := Parse(raw, "application/json")
			if (err == nil) != (format == "json") {
				t.Fatalf("wrong format admission %s %s", model, format)
			}
		}
	}
}
