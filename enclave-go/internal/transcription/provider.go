package transcription

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

type Client struct {
	http    *http.Client
	keys    map[string]string
	tinfoil func() (*http.Client, error)
}

func New(client *http.Client, keys map[string]string, tinfoil func() (*http.Client, error)) *Client {
	return &Client{client, keys, tinfoil}
}

type ProviderError struct{ Status int }

func (e *ProviderError) Error() string { return "transcription provider failed" }

func (c *Client) Transcribe(ctx context.Context, req *Request) (map[string]any, error) {
	spec, ok := Models[req.Model]
	if !ok || c.keys[spec.Provider] == "" {
		return nil, errors.New("transcription credentials unavailable")
	}
	client := c.http
	if spec.Provider == "tinfoil" {
		if c.tinfoil == nil {
			return nil, errors.New("transcription attestation unavailable")
		}
		verified, err := c.tinfoil()
		if err != nil || verified == nil {
			return nil, errors.New("transcription attestation failed")
		}
		client = verified
	}
	if client == nil {
		return nil, errors.New("transcription transport unavailable")
	}
	bounded := *client
	bounded.Timeout = 3 * time.Minute
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("model", spec.Upstream)
	if spec.Provider != "mistral" {
		_ = w.WriteField("response_format", req.Format)
	}
	if req.Language != "" {
		_ = w.WriteField("language", req.Language)
	}
	if req.Prompt != "" {
		_ = w.WriteField("prompt", req.Prompt)
	}
	if req.Temperature != nil {
		_ = w.WriteField("temperature", strconv.FormatFloat(*req.Temperature, 'f', -1, 64))
	}
	for _, granularity := range req.Timestamps {
		field := "timestamp_granularities[]"
		if spec.Provider == "mistral" {
			field = "timestamp_granularities"
		}
		_ = w.WriteField(field, granularity)
	}
	if req.Diarize {
		_ = w.WriteField("diarize", "true")
	}
	for _, term := range req.Keyterms {
		_ = w.WriteField("context_bias", term)
	}
	file, err := w.CreateFormFile("file", "audio."+req.AudioFormat)
	if err != nil {
		return nil, errors.New("transcription upload encoding failed")
	}
	_, _ = file.Write(req.Audio)
	_ = w.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.URL, &body)
	if err != nil {
		return nil, errors.New("transcription endpoint configuration failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.keys[spec.Provider])
	request.Header.Set("Content-Type", w.FormDataContentType())
	response, err := bounded.Do(request)
	if err != nil {
		return nil, errors.New("transcription transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, &ProviderError{response.StatusCode}
	}
	const responseLimit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(data) > responseLimit {
		return nil, errors.New("invalid transcription response size")
	}
	var upstream map[string]json.RawMessage
	if json.Unmarshal(data, &upstream) != nil {
		return nil, errors.New("invalid transcription JSON")
	}
	var text string
	if upstream["text"] == nil || bytes.Equal(upstream["text"], []byte("null")) || json.Unmarshal(upstream["text"], &text) != nil {
		return nil, errors.New("missing transcription text")
	}
	// Silence legitimately produces empty text. Never forward request echoes,
	// arbitrary top-level response fields, headers, or upstream error bodies.
	result := map[string]any{"text": text}
	if req.Format == "verbose_json" {
		result["task"], result["duration"] = "transcribe", float64(req.DurationMS)/1000
		for _, field := range []string{"language", "segments", "words"} {
			if value := upstream[field]; value != nil {
				var decoded any
				if json.Unmarshal(value, &decoded) != nil {
					return nil, errors.New("invalid transcription details")
				}
				result[field] = decoded
			}
		}
		if spec.Provider == "mistral" && len(req.Timestamps) == 1 && req.Timestamps[0] == "word" {
			segments, ok := result["segments"].([]any)
			if !ok {
				return nil, errors.New("provider omitted word timestamps")
			}
			words := make([]map[string]any, 0, len(segments))
			for _, value := range segments {
				segment, ok := value.(map[string]any)
				if !ok {
					return nil, errors.New("invalid word timestamp")
				}
				words = append(words, map[string]any{"word": segment["text"], "start": segment["start"], "end": segment["end"]})
			}
			result["words"] = words
		}
		for _, granularity := range req.Timestamps {
			field := "segments"
			if granularity == "word" {
				field = "words"
			}
			if _, ok := result[field].([]any); !ok {
				if _, converted := result[field].([]map[string]any); converted {
					continue
				}
				return nil, errors.New("provider omitted requested timestamps")
			}
		}
	}
	return result, nil
}
