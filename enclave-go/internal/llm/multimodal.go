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
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	maxImageBytes     = 10 << 20
	maxImagePixels    = 16_777_216
	maxImageDimension = 8192
	maxImageRedirect  = 3
)

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
				out = append(out, map[string]any{"type": "text", "text": part.Text})
			}
		case "image_url":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, fmt.Errorf("llm/image: image_url is required")
			}
			source, err := loadAnthropicImageSource(ctx, part.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"type": "image", "source": source})
		default:
			return nil, fmt.Errorf("llm/image: unsupported content part %q", part.Type)
		}
	}
	return out, nil
}

func chatPartFromAny(item any) (qtypes.ChatContentPart, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return qtypes.ChatContentPart{}, fmt.Errorf("llm/image: content part must be object")
	}
	partType := stringValue(m["type"])
	switch partType {
	case "", "text", "input_text":
		return qtypes.ChatContentPart{Type: "text", Text: stringValue(m["text"])}, nil
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

func loadImageBytes(ctx context.Context, raw string) (string, []byte, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "data:") {
		return imageBytesFromDataURL(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: invalid image URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", nil, fmt.Errorf("llm/image: unsupported image URL scheme")
	}
	httpc := safeImageHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: build image request: %w", err)
	}
	req.Header.Set("Accept", "image/png,image/jpeg")
	resp, err := httpc.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("llm/image: fetch http %d", resp.StatusCode)
	}
	mediaType := contentTypeMedia(resp.Header.Get("Content-Type"))
	data, err := readLimited(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if mediaType == "" {
		mediaType = contentTypeMedia(http.DetectContentType(data))
	}
	return mediaType, data, nil
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

func safeImageHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: safeImageDialContext,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxImageRedirect {
				return errors.New("llm/image: too many redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return errors.New("llm/image: unsupported redirect scheme")
			}
			return nil
		},
	}
}

func safeImageDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("llm/image: invalid address")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("llm/image: resolve failed")
	}
	for _, ip := range ips {
		if !allowedImageIP(ip) {
			continue
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return nil, fmt.Errorf("llm/image: image host resolves to a private address")
}

func allowedImageIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		as4 := ip.As4()
		if as4[0] == 169 && as4[1] == 254 {
			return false
		}
	}
	return true
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxImageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("llm/image: read failed")
	}
	if len(data) > maxImageBytes {
		return nil, fmt.Errorf("llm/image: image too large")
	}
	return data, nil
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
