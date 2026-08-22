package video

import (
	"fmt"
	"strconv"
	"strings"
)

type ResolvedRequest struct {
	Model           Model
	Prompt          string
	NegativePrompt  string
	DurationSeconds int
	Resolution      string
	AspectRatio     string
	GenerateAudio   bool
	Seed            *int64
	InputMode       string
	FirstFrame      string
	LastFrame       string
	ReferenceImages []string
	AudioReference  string
	VideoReference  string
	VeniceModel     string
	veniceQueue     map[string]any
	veniceQuote     map[string]any
}

func ResolveRequest(req *CreateRequest) (*ResolvedRequest, error) {
	model, queue, quote, err := Resolve(req)
	if err != nil {
		return nil, err
	}
	metadata := Metadata(model, queue)
	request := &ResolvedRequest{
		Model:           model,
		Prompt:          req.Prompt,
		NegativePrompt:  req.NegativePrompt,
		DurationSeconds: metadata.DurationSeconds,
		Resolution:      metadata.Resolution,
		AspectRatio:     metadata.AspectRatio,
		GenerateAudio:   metadata.GenerateAudio,
		Seed:            req.Seed,
		InputMode:       metadata.InputMode,
		FirstFrame:      stringValue(queue["image_url"]),
		LastFrame:       stringValue(queue["end_image_url"]),
		ReferenceImages: stringSliceValue(queue["reference_image_urls"]),
		AudioReference:  stringValue(queue["audio_url"]),
		VideoReference:  stringValue(queue["video_url"]),
		VeniceModel:     stringValue(queue["model"]),
		veniceQueue:     cloneMap(queue),
		veniceQuote:     cloneMap(quote),
	}
	if request.DurationSeconds <= 0 {
		return nil, fmt.Errorf("resolved video duration is invalid")
	}
	return request, nil
}

func (r *ResolvedRequest) VeniceQueuePayload() map[string]any {
	if r == nil {
		return nil
	}
	return cloneMap(r.veniceQueue)
}

func (r *ResolvedRequest) VeniceQuotePayload() map[string]any {
	if r == nil {
		return nil
	}
	return cloneMap(r.veniceQuote)
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func stringSliceValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := stringValue(item); normalized != "" {
				out = append(out, normalized)
			}
		}
		return out
	default:
		return nil
	}
}

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		switch typed := value.(type) {
		case []string:
			cloned[key] = append([]string(nil), typed...)
		case []any:
			cloned[key] = append([]any(nil), typed...)
		default:
			cloned[key] = value
		}
	}
	return cloned
}

func staticCustomerQuote(rateMicrodollarsPerSecond, seconds int, fixedMicrodollars int) (int, error) {
	if rateMicrodollarsPerSecond <= 0 || seconds <= 0 || fixedMicrodollars < 0 {
		return 0, fmt.Errorf("video quote: invalid pricing inputs")
	}
	maxInt := int(^uint(0) >> 1)
	if seconds > (maxInt-fixedMicrodollars)/rateMicrodollarsPerSecond {
		return 0, fmt.Errorf("video quote: amount is too large")
	}
	return customerVideoPrice(rateMicrodollarsPerSecond*seconds + fixedMicrodollars)
}

func durationString(seconds int) string { return strconv.Itoa(seconds) + "s" }
