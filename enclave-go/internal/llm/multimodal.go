package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"mime"
	"net/http"
	"net/url"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	maxImageBytes     = 10 << 20
	maxImagePixels    = 16_777_216
	maxImageDimension = 8192
	maxImageRedirect  = 3
)

type imageInputError struct {
	err error
}

func (e *imageInputError) Error() string {
	return e.err.Error()
}

func (e *imageInputError) Unwrap() error {
	return e.err
}

func (e *imageInputError) ClientInputMessage() string {
	return "invalid image input"
}

func markImageInputError(err error) error {
	if err == nil {
		return nil
	}
	var existing *imageInputError
	if errors.As(err, &existing) {
		return err
	}
	return &imageInputError{err: err}
}

func anthropicBodyWithFetchedImages(
	ctx context.Context,
	body *qtypes.AnthropicMessagesRequest,
) (*qtypes.AnthropicMessagesRequest, error) {
	messages, err := anthropicMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return nil, err
	}
	copy := *body
	copy.Messages = messages
	return &copy, nil
}

func anthropicMessagesWithFetchedImages(
	ctx context.Context,
	body *qtypes.AnthropicMessagesRequest,
) ([]qtypes.AnthropicMessage, error) {
	if body == nil {
		return nil, nil
	}
	messages := make([]qtypes.AnthropicMessage, 0, len(body.Messages))
	for _, message := range body.Messages {
		content, err := anthropicContentWithFetchedImages(ctx, message.Content)
		if err != nil {
			return nil, err
		}
		messages = append(messages, qtypes.AnthropicMessage{
			Role:    message.Role,
			Content: content,
		})
	}
	return messages, nil
}

func anthropicContentWithFetchedImages(ctx context.Context, content any) (any, error) {
	switch value := content.(type) {
	case string:
		return value, nil
	case []qtypes.ChatContentPart:
		return anthropicPartsWithFetchedImages(ctx, value)
	case []any:
		parts := make([]qtypes.ChatContentPart, 0, len(value))
		for _, item := range value {
			part, err := chatPartFromAny(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return anthropicPartsWithFetchedImages(ctx, parts)
	default:
		return content, nil
	}
}

func anthropicPartsWithFetchedImages(
	ctx context.Context,
	parts []qtypes.ChatContentPart,
) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		switch part.Type {
		case "text":
			if strings.TrimSpace(part.Text) != "" {
				block := map[string]any{"type": "text", "text": part.Text}
				withCacheControl(block, part.CacheControl)
				out = append(out, block)
			}
		case "image_url":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, fmt.Errorf("llm/image: image_url is required")
			}
			source, err := loadAnthropicImageSource(ctx, part.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			block := map[string]any{"type": "image", "source": source}
			withCacheControl(block, part.CacheControl)
			out = append(out, block)
		default:
			return nil, fmt.Errorf("llm/image: unsupported content part %q", part.Type)
		}
	}
	return out, nil
}

// withCacheControl re-attaches a client-sent prompt-cache breakpoint to an
// Anthropic content block. The OpenAI chat path rebuilds every content block
// as a fresh map (to fetch images / normalize part types), so a cache_control
// member on the inbound block is dropped unless it is copied forward here —
// which is exactly why /v1/chat/completions used to lose prompt-cache markers
// while /v1/messages (verbatim passthrough) kept them.
func withCacheControl(block map[string]any, cacheControl any) {
	if cacheControl != nil {
		block["cache_control"] = cacheControl
	}
}

func chatPartFromAny(item any) (qtypes.ChatContentPart, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return qtypes.ChatContentPart{}, fmt.Errorf("llm/image: content part must be object")
	}
	partType := stringValue(m["type"])
	// cache_control rides along on the part it annotates so the anthropic
	// content builder can re-emit it on the rebuilt block.
	cacheControl := m["cache_control"]
	switch partType {
	case "", "text", "input_text":
		return qtypes.ChatContentPart{Type: "text", Text: stringValue(m["text"]), CacheControl: cacheControl}, nil
	case "image_url", "input_image":
		imageURL, detail := imageURLAndDetail(m)
		if strings.TrimSpace(imageURL) == "" {
			return qtypes.ChatContentPart{}, fmt.Errorf("llm/image: image_url is required")
		}
		return qtypes.ChatContentPart{
			Type: "image_url",
			ImageURL: &qtypes.ChatImageURL{
				URL:    imageURL,
				Detail: detail,
			},
			CacheControl: cacheControl,
		}, nil
	default:
		return qtypes.ChatContentPart{}, fmt.Errorf("llm/image: unsupported content part %q", partType)
	}
}

func loadAnthropicImageSource(ctx context.Context, raw string) (map[string]any, error) {
	mediaType, data, err := loadImageBytes(ctx, raw)
	if err != nil {
		return nil, err
	}
	normalizedType, normalizedData, err := normalizeImageBytes(mediaType, data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"type":       "base64",
		"media_type": normalizedType,
		"data":       base64.StdEncoding.EncodeToString(normalizedData),
	}, nil
}

// loadImageBytes resolves an image reference to (media_type, raw bytes).
//
//   - data: URLs are decoded inline (no network).
//   - http(s): URLs delegate to fetchHTTPImage which is build-tag-split:
//     direct DNS+TCP on GCP (multimodal_direct.go), control-plane proxy
//     on AWS Nitro (multimodal_aws.go) where the enclave has no
//     network stack to do its own DNS.
//
// SSRF protection (private/loopback/link-local IP rejection) lives in
// each fetchHTTPImage variant: the GCP variant rejects locally;
// the AWS variant delegates to the TR control plane which performs the
// same checks server-side.
func loadImageBytes(ctx context.Context, raw string) (string, []byte, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "data:") {
		mediaType, data, err := imageBytesFromDataURL(raw)
		return mediaType, data, markImageInputError(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, markImageInputError(fmt.Errorf("llm/image: invalid image URL"))
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", nil, markImageInputError(fmt.Errorf("llm/image: unsupported image URL scheme"))
	}
	mediaType, data, err := fetchHTTPImage(ctx, u.String())
	return mediaType, data, markImageInputError(err)
}

func imageBytesFromDataURL(raw string) (string, []byte, error) {
	header, encoded, ok := strings.Cut(raw, ",")
	if !ok {
		return "", nil, fmt.Errorf("llm/image: malformed data URL")
	}
	if !strings.Contains(header, ";base64") {
		return "", nil, fmt.Errorf("llm/image: data URL must be base64")
	}
	mediaType := strings.TrimPrefix(strings.TrimSuffix(header, ";base64"), "data:")
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: invalid data URL image")
	}
	if len(data) > maxImageBytes {
		return "", nil, fmt.Errorf("llm/image: image too large")
	}
	return mediaType, data, nil
}

func normalizeImageBytes(mediaType string, data []byte) (string, []byte, error) {
	normalizedType, normalizedData, err := normalizeImageBytesUnchecked(mediaType, data)
	return normalizedType, normalizedData, markImageInputError(err)
}

func normalizeImageBytesUnchecked(mediaType string, data []byte) (string, []byte, error) {
	mediaType = contentTypeMedia(mediaType)
	if mediaType == "" {
		mediaType = contentTypeMedia(http.DetectContentType(data))
	}
	if mediaType == "image/jpg" {
		mediaType = "image/jpeg"
	}
	switch mediaType {
	case "image/jpeg":
		if err := validateImageConfig(data); err != nil {
			return "", nil, err
		}
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return "", nil, fmt.Errorf("llm/image: decode jpeg: %w", err)
		}
		var out bytes.Buffer
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 92}); err != nil {
			return "", nil, fmt.Errorf("llm/image: encode jpeg: %w", err)
		}
		return mediaType, out.Bytes(), nil
	case "image/png":
		if err := validateImageConfig(data); err != nil {
			return "", nil, err
		}
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return "", nil, fmt.Errorf("llm/image: decode png: %w", err)
		}
		var out bytes.Buffer
		if err := png.Encode(&out, img); err != nil {
			return "", nil, fmt.Errorf("llm/image: encode png: %w", err)
		}
		return mediaType, out.Bytes(), nil
	default:
		return "", nil, fmt.Errorf("llm/image: unsupported image media type")
	}
}

func validateImageConfig(data []byte) error {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("llm/image: decode config: %w", err)
	}
	if config.Width <= 0 || config.Height <= 0 {
		return fmt.Errorf("llm/image: invalid image dimensions")
	}
	if config.Width > maxImageDimension || config.Height > maxImageDimension {
		return fmt.Errorf("llm/image: image dimensions too large")
	}
	if config.Width > maxImagePixels/config.Height {
		return fmt.Errorf("llm/image: image dimensions too large")
	}
	return nil
}

func contentTypeMedia(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(value)
	}
	return strings.ToLower(mediaType)
}

func imageURLAndDetail(part map[string]any) (string, string) {
	detail := stringValue(part["detail"])
	switch value := part["image_url"].(type) {
	case string:
		return value, detail
	case map[string]any:
		if detail == "" {
			detail = stringValue(value["detail"])
		}
		return stringValue(value["url"]), detail
	default:
		return "", detail
	}
}

func stringValue(value any) string {
	out, _ := value.(string)
	return out
}
