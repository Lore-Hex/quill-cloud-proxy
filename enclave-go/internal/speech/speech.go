// Package speech normalizes the OpenRouter/OpenAI speech contract without
// forwarding prompt content to the control plane or arbitrary provider URLs.
package speech

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const MaxAudioBytes = 64 << 20

type Spec struct {
	Provider, Upstream string
	Voices, Formats    []string
	MaxCharacters      int
	MinSpeed, MaxSpeed float64
}

var Models = map[string]Spec{
	"x-ai/grok-voice-tts-1.0":         {"grok", "grok-voice-tts-1.0", []string{"eve", "ara", "rex", "sal", "leo"}, []string{"mp3", "pcm"}, 60000, 0.7, 1.5},
	"mistralai/voxtral-mini-tts-2603": {"mistral", "voxtral-mini-tts-2603", []string{"en_paul_neutral"}, []string{"mp3"}, 10000, 1, 1},
}

type Request struct {
	Model     string                 `json:"model"`
	Input     string                 `json:"input"`
	Voice     string                 `json:"voice"`
	Format    string                 `json:"response_format,omitempty"`
	Speed     *float64               `json:"speed,omitempty"`
	Provider  *types.ProviderRouting `json:"provider,omitempty"`
	User      string                 `json:"user,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Metadata  map[string]any         `json:"metadata,omitempty"`
	Tags      *types.RequestTags     `json:"tags,omitempty"`
}

type RequestError struct{ Param, Message string }

func (e *RequestError) Error() string { return e.Message }

func Parse(raw []byte) (*Request, error) {
	if !utf8.Valid(raw) {
		return nil, &RequestError{"input", "request must be valid UTF-8"}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var req Request
	if err := d.Decode(&req); err != nil {
		return nil, &RequestError{"", "invalid or unsupported speech request field"}
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, &RequestError{"", "request must contain one JSON object"}
	}
	spec, ok := Models[req.Model]
	if !ok {
		return nil, &RequestError{"model", "model does not support speech"}
	}
	if strings.TrimSpace(req.Input) == "" || utf8.RuneCountInString(req.Input) > spec.MaxCharacters {
		return nil, &RequestError{"input", "input must be non-empty text within the model character limit"}
	}
	if !slices.Contains(spec.Voices, req.Voice) {
		return nil, &RequestError{"voice", "unsupported voice; see the model's supported_voices"}
	}
	if req.Format == "" {
		req.Format = "pcm"
	}
	if !slices.Contains(spec.Formats, req.Format) {
		return nil, &RequestError{"response_format", "unsupported response_format for this model; use mp3"}
	}
	if req.Speed == nil {
		speed := 1.0
		req.Speed = &speed
	}
	if *req.Speed < spec.MinSpeed || *req.Speed > spec.MaxSpeed {
		return nil, &RequestError{"speed", "speed is outside this model's supported range"}
	}
	// Never silently forward unpriced options, voice cloning, or URL inputs.
	if req.Provider != nil && req.Provider.Options != nil {
		return nil, &RequestError{"provider.options", "speech provider options are not supported"}
	}
	return &req, nil
}

type Result struct {
	Audio       []byte
	ContentType string
}
type ProviderError struct{ Status int }

func (e *ProviderError) Error() string { return "speech provider failed" }

type Client struct {
	http *http.Client
	keys map[string]string
}

func New(client *http.Client, keys map[string]string) *Client {
	copyClient := *client
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	copyClient.Timeout = 3 * time.Minute
	return &Client{http: &copyClient, keys: keys}
}

func (c *Client) Generate(ctx context.Context, req *Request) (*Result, error) {
	spec, ok := Models[req.Model]
	if !ok {
		return nil, errors.New("unknown speech model")
	}
	key := c.keys[spec.Provider]
	if key == "" {
		return nil, &ProviderError{Status: 503}
	}
	url := "https://api.x.ai/v1/tts"
	body := map[string]any{
		"text": req.Input, "voice_id": req.Voice, "language": "auto",
		"speed": *req.Speed, "output_format": map[string]any{"codec": req.Format, "sample_rate": 24000},
	}
	if spec.Provider == "mistral" {
		url = "https://api.mistral.ai/v1/audio/speech"
		body = map[string]any{"model": spec.Upstream, "input": req.Input, "voice_id": req.Voice, "response_format": req.Format}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("invalid speech request")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("invalid speech endpoint")
	}
	httpReq.Header.Set("Authorization", "Bearer "+key)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, errors.New("speech provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &ProviderError{Status: resp.StatusCode}
	}
	// Mistral wraps audio in base64 JSON; xAI returns binary. Buffer before
	// charging so truncated/error payloads cannot become successful generations.
	limit := int64(MaxAudioBytes)
	if spec.Provider == "mistral" {
		limit = MaxAudioBytes*4/3 + 65536
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid speech response")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, errors.New("invalid speech content type")
	}
	if spec.Provider == "mistral" {
		if mediaType != "application/json" {
			return nil, errors.New("invalid speech response type")
		}
		var envelope struct {
			Audio string `json:"audio_data"`
		}
		if json.Unmarshal(data, &envelope) != nil {
			return nil, errors.New("invalid speech envelope")
		}
		data, err = base64.StdEncoding.Strict().DecodeString(envelope.Audio)
		if err != nil {
			return nil, errors.New("invalid speech encoding")
		}
	} else if (req.Format == "mp3" && mediaType != "audio/mpeg") || (req.Format == "pcm" && mediaType != "audio/pcm") {
		return nil, errors.New("speech content type mismatch")
	}
	if len(data) == 0 || len(data) > MaxAudioBytes {
		return nil, errors.New("empty or oversized audio")
	}
	if req.Format == "mp3" {
		if len(data) < 4 || !(bytes.HasPrefix(data, []byte("ID3")) || (data[0] == 0xff && data[1]&0xe0 == 0xe0)) {
			return nil, errors.New("invalid MP3 response")
		}
		return &Result{data, "audio/mpeg"}, nil
	}
	if len(data)%2 != 0 {
		return nil, errors.New("invalid PCM response")
	}
	return &Result{data, "audio/pcm;rate=24000;channels=1"}, nil
}
