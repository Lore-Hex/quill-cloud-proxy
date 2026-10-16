package transcription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type TokenUsage struct{ Input, Output int }

func TakeTokenUsage(result map[string]any) (TokenUsage, error) {
	usage, ok := result["_token_usage"].(TokenUsage)
	delete(result, "_token_usage")
	if !ok || usage.Input <= 0 || usage.Input > MaxInputTokens || usage.Output <= 0 || usage.Output > MaxOutputTokens {
		return TokenUsage{}, errors.New("invalid transcription token usage")
	}
	return usage, nil
}

// The upstream transcription endpoint omits tokens despite charging by tokens.
// Audio chat returns exact usage and enforces the same reserved output limit.
func transcribeTokenBilled(ctx context.Context, client *http.Client, key string, req *Request, spec Spec) (map[string]any, error) {
	instruction := "Transcribe the audio verbatim. Return only the transcript."
	if req.Language != "" {
		instruction += " The audio language code is " + req.Language + "."
	}
	if req.Prompt != "" {
		instruction += " Transcription context: " + req.Prompt
	}
	temperature := 0.0
	if req.Temperature != nil {
		temperature = *req.Temperature
	}
	body, err := json.Marshal(map[string]any{
		"model": spec.Upstream, "max_tokens": MaxOutputTokens, "temperature": temperature,
		"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "input_audio", "input_audio": map[string]string{"data": base64.StdEncoding.EncodeToString(req.Audio), "format": req.AudioFormat}},
			map[string]string{"type": "text", "text": instruction},
		}}},
	})
	if err != nil {
		return nil, errors.New("audio request encoding failed")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("audio endpoint configuration failed")
	}
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return nil, errors.New("transcription transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &ProviderError{resp.StatusCode}
	}
	const limit = 4 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(b) > limit {
		return nil, errors.New("invalid audio response size")
	}
	var wire struct {
		Choices []struct {
			Message struct {
				Content *string `json:"content"`
			}
			FinishReason string `json:"finish_reason"`
		}
		Usage struct {
			Input  int `json:"prompt_tokens"`
			Output int `json:"completion_tokens"`
		}
	}
	if json.Unmarshal(b, &wire) != nil || len(wire.Choices) != 1 || wire.Choices[0].Message.Content == nil || wire.Choices[0].FinishReason != "stop" {
		return nil, errors.New("incomplete transcription response")
	}
	result := map[string]any{"text": *wire.Choices[0].Message.Content, "_token_usage": TokenUsage{wire.Usage.Input, wire.Usage.Output}}
	if _, err := TakeTokenUsage(result); err != nil {
		return nil, err
	}
	result["_token_usage"] = TokenUsage{wire.Usage.Input, wire.Usage.Output}
	return result, nil
}
