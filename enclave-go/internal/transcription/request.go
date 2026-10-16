// Package transcription handles audio only inside the attested runtime.
package transcription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const MaxAudioBytes = 7 << 20 // Base64 plus metadata fits the gateway's 10 MiB body cap.
const MaxDurationMS = 600_000
const MaxInputTokens = 28672
const MaxOutputTokens = 4096

type Spec struct{ Provider, Upstream, URL string }

var Models = map[string]Spec{
	"mistralai/voxtral-small-24b":    {"tinfoil", "voxtral-small-24b", "https://inference.tinfoil.sh/v1/chat/completions"},
	"openai/whisper-large-v3-turbo":  {"tinfoil", "whisper-large-v3-turbo", "https://inference.tinfoil.sh/v1/audio/transcriptions"},
	"openai/whisper-1":               {"openai", "whisper-1", "https://api.openai.com/v1/audio/transcriptions"},
	"mistralai/voxtral-mini-2602":    {"mistral", "voxtral-mini-2602", "https://api.mistral.ai/v1/audio/transcriptions"},
	"mistralai/voxtral-mini-3b-2507": {"privatemode", "voxtral-mini-3b", "https://privatemode.internal:18489/v1/audio/transcriptions"},
	"openai/whisper-large-v3":        {"privatemode", "whisper-large-v3", "https://privatemode.internal:18489/v1/audio/transcriptions"},
}

func (s Spec) Confidential() bool { return s.Provider == "tinfoil" || s.Provider == "privatemode" }

func (s Spec) TokenBilled() bool { return s.Provider == "tinfoil" && s.Upstream == "voxtral-small-24b" }

func (s Spec) JSONOnly() bool {
	return s.TokenBilled() || (s.Provider == "privatemode" && s.Upstream == "voxtral-mini-3b")
}

type Request struct {
	Model      string `json:"model"`
	InputAudio *struct {
		Data   string `json:"data"`
		Format string `json:"format"`
	} `json:"input_audio,omitempty"`
	Language    string                 `json:"language,omitempty"`
	Prompt      string                 `json:"prompt,omitempty"`
	Temperature *float64               `json:"temperature,omitempty"`
	Format      string                 `json:"response_format,omitempty"`
	Timestamps  []string               `json:"timestamp_granularities,omitempty"`
	Diarize     bool                   `json:"diarize,omitempty"`
	Keyterms    []string               `json:"keyterms,omitempty"`
	Provider    *types.ProviderRouting `json:"provider,omitempty"`
	User        string                 `json:"user,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Trace       map[string]any         `json:"trace,omitempty"`
	Audio       []byte                 `json:"-"`
	AudioFormat string                 `json:"-"`
	DurationMS  int                    `json:"-"`
}

type RequestError struct{ Param, Message string }

func (e *RequestError) Error() string     { return e.Message }
func invalid(param, message string) error { return &RequestError{param, message} }

// Parse never uses ParseMultipartForm: that API can spill confidential audio to disk.
func Parse(raw []byte, contentType string) (*Request, error) {
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, invalid("content_type", "Expected application/json or multipart/form-data")
	}
	var req Request
	switch media {
	case "application/json":
		if err := decode(raw, &req); err != nil {
			return nil, invalid("body", "Invalid or unsupported transcription field")
		}
		if req.InputAudio == nil || len(req.InputAudio.Data) > base64.StdEncoding.EncodedLen(MaxAudioBytes) {
			return nil, invalid("input_audio", "Provide bounded base64 audio")
		}
		req.Audio, err = base64.StdEncoding.Strict().DecodeString(req.InputAudio.Data)
		if err != nil {
			return nil, invalid("input_audio", "Invalid base64 audio")
		}
		req.AudioFormat = strings.ToLower(req.InputAudio.Format)
		req.InputAudio = nil
	case "multipart/form-data":
		reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
		fields := map[string]json.RawMessage{}
		nested := map[string]map[string]json.RawMessage{}
		for count := 0; ; count++ {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil || count >= 32 {
				return nil, invalid("body", "Invalid multipart upload")
			}
			name := part.FormName()
			if name == "file" {
				if req.Audio != nil {
					return nil, invalid("file", "Only one audio file is allowed")
				}
				req.Audio, err = io.ReadAll(io.LimitReader(part, MaxAudioBytes+1))
				if err != nil || len(req.Audio) > MaxAudioBytes {
					return nil, invalid("file", "Audio exceeds 7 MiB")
				}
				continue
			}
			value, err := io.ReadAll(io.LimitReader(part, 16_385))
			if err != nil || len(value) > 16_384 {
				return nil, invalid("body", "Transcription metadata is too large")
			}
			// OpenAI's multipart SDK uses provider[only][] and
			// provider[min_privacy], not a single JSON provider field.
			if strings.HasPrefix(name, "provider[") || strings.HasPrefix(name, "trace[") {
				root, tail, _ := strings.Cut(name, "[")
				key, suffix, ok := strings.Cut(tail, "]")
				if !ok || key == "" || len(key) > 100 || strings.ContainsAny(key, "[]") || (suffix != "" && suffix != "[]") {
					return nil, invalid("body", "Unsupported nested multipart field; use JSON metadata")
				}
				if nested[root] == nil {
					nested[root] = map[string]json.RawMessage{}
				}
				if suffix == "[]" {
					var values []string
					if existing := nested[root][key]; existing != nil && json.Unmarshal(existing, &values) != nil {
						return nil, invalid(root, "Conflicting multipart field")
					}
					values = append(values, string(value))
					nested[root][key], _ = json.Marshal(values)
				} else {
					if nested[root][key] != nil {
						return nil, invalid(root, "Duplicate multipart field")
					}
					if root == "provider" && (key == "allow_fallbacks" || key == "require_parameters" || key == "zdr" || key == "preferred_max_latency" || key == "preferred_min_throughput") {
						nested[root][key] = value
					} else {
						nested[root][key], _ = json.Marshal(string(value))
					}
				}
				continue
			}
			if name == "timestamp_granularities[]" || name == "keyterms[]" {
				key := strings.TrimSuffix(name, "[]")
				var values []string
				if existing := fields[key]; existing != nil {
					_ = json.Unmarshal(existing, &values)
				}
				values = append(values, string(value))
				fields[key], _ = json.Marshal(values)
				continue
			}
			if _, exists := fields[name]; exists {
				return nil, invalid("body", "Duplicate transcription field")
			}
			switch name {
			case "provider", "trace", "temperature", "diarize", "timestamp_granularities", "keyterms":
				fields[name] = value
			case "input_audio":
				return nil, invalid("input_audio", "Use file for multipart uploads")
			default:
				fields[name], _ = json.Marshal(string(value))
			}
		}
		audio := req.Audio
		for root, values := range nested {
			if fields[root] != nil {
				return nil, invalid(root, "Do not mix JSON and nested multipart metadata")
			}
			fields[root], _ = json.Marshal(values)
		}
		data, err := json.Marshal(fields)
		if err != nil || decode(data, &req) != nil {
			return nil, invalid("body", "Invalid or unsupported transcription field")
		}
		req.Audio = audio
	default:
		return nil, invalid("content_type", "Expected application/json or multipart/form-data")
	}
	if _, ok := Models[req.Model]; !ok {
		return nil, invalid("model", "Model does not support transcription")
	}
	if len(req.Audio) == 0 || len(req.Audio) > MaxAudioBytes {
		return nil, invalid("file", "Audio must contain 1 byte to 7 MiB")
	}
	if req.Format == "" {
		req.Format = "json"
	}
	if req.Format != "json" && req.Format != "verbose_json" {
		return nil, invalid("response_format", "Use json or verbose_json")
	}
	if req.Temperature != nil && (*req.Temperature < 0 || *req.Temperature > 1) {
		return nil, invalid("temperature", "Temperature must be between 0 and 1")
	}
	if len(req.Language) > 0 && (len(req.Language) != 2 || req.Language[0] < 'a' || req.Language[0] > 'z' || req.Language[1] < 'a' || req.Language[1] > 'z') {
		return nil, invalid("language", "Use a two-letter lowercase language code")
	}
	if len(req.User) > 256 || len(req.SessionID) > 256 || len(req.Prompt) > 2048 {
		return nil, invalid("body", "Transcription metadata exceeds its limit")
	}
	if len(req.Timestamps) > 2 {
		return nil, invalid("timestamp_granularities", "Use word and/or segment")
	}
	for _, value := range req.Timestamps {
		if (value != "word" && value != "segment") || req.Format != "verbose_json" {
			return nil, invalid("timestamp_granularities", "Timestamps require verbose_json and word or segment")
		}
	}
	spec := Models[req.Model]
	if spec.JSONOnly() && (req.Format != "json" || len(req.Timestamps) > 0) {
		return nil, invalid("response_format", "This model supports json without timestamps")
	}
	if spec.Provider == "mistral" {
		if len(req.Timestamps) > 1 {
			return nil, invalid("timestamp_granularities", "Mistral supports one timestamp granularity per request")
		}
		if req.Prompt != "" || req.Temperature != nil || (req.Language != "" && len(req.Timestamps) > 0) {
			return nil, invalid("body", "Mistral does not support prompt, temperature, or language with timestamps")
		}
	} else if req.Diarize || len(req.Keyterms) > 0 {
		return nil, invalid("diarize", "This model does not support diarization or keyterms")
	}
	if req.Diarize && req.Format != "verbose_json" {
		return nil, invalid("diarize", "Diarization requires verbose_json")
	}
	if len(req.Keyterms) > 100 {
		return nil, invalid("keyterms", "At most 100 keyterms are supported")
	}
	for _, term := range req.Keyterms {
		if len(term) == 0 || len(term) > 100 {
			return nil, invalid("keyterms", "Keyterms must contain 1 to 100 bytes")
		}
	}
	return &req, nil
}

func decode(data []byte, target any) error {
	if err := decide.CheckNoDuplicateKeys(data); err != nil {
		return errors.New("duplicate or invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
