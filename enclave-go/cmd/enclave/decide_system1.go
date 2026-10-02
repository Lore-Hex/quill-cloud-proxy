package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// Inline images keep EU decisions from fetching arbitrary remote content
// outside the promised region. Existing image decoders are linked by llm.
func validateSystem1Decision(req *decideRequest) (string, string) {
	if !decide.IsSystem1Model(req.Model) {
		if len(req.Images) != 0 {
			return "images are supported only on System1 vision decision models", "images"
		}
		return "", ""
	}
	if len(req.Questions) != 1 {
		return "System1 accepts exactly one question per request", "questions"
	}
	var state bytes.Buffer
	if json.Compact(&state, req.State) != nil || state.Len() > 16*1024 {
		return "System1 state must be at most 16 KiB of serialized JSON", "state"
	}
	if len(req.Images) == 0 {
		return "", ""
	}
	if !strings.HasSuffix(req.Model, "/s1-vision") || len(req.Images) != 1 {
		return "System1 s1-vision accepts exactly one image; text models do not accept images", "images"
	}
	prefix, encoded, ok := strings.Cut(req.Images[0], ",")
	formats := map[string]string{"data:image/png;base64": "png", "data:image/jpeg;base64": "jpeg", "data:image/webp;base64": "webp"}
	if !ok || formats[prefix] == "" || len(encoded) > base64.StdEncoding.EncodedLen(4*1024*1024) {
		return "images must contain a PNG, JPEG or WebP base64 data URL, at most 4 MiB decoded", "images"
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) > 4*1024*1024 {
		return "invalid image data or image larger than 4 MiB", "images"
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || format != formats[prefix] || config.Width <= 0 || config.Height <= 0 || config.Width > 2_000_000/config.Height {
		return "invalid image format or image exceeds 2 megapixels", "images"
	}
	return "", ""
}
