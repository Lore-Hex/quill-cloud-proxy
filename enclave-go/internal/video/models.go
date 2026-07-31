package video

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxPromptBytes = 10_000

type FrameImage struct {
	FrameType string `json:"frame_type"`
	ImageURL  string `json:"image_url"`
	URL       string `json:"url"`
}

type InputReference struct {
	Type     string `json:"type"`
	URL      string `json:"url"`
	ImageURL string `json:"image_url"`
	AudioURL string `json:"audio_url"`
	VideoURL string `json:"video_url"`
}

type CreateRequest struct {
	Model           string           `json:"model"`
	Prompt          string           `json:"prompt"`
	AspectRatio     string           `json:"aspect_ratio,omitempty"`
	CallbackURL     string           `json:"callback_url,omitempty"`
	Duration        int              `json:"duration,omitempty"`
	Resolution      string           `json:"resolution,omitempty"`
	Size            string           `json:"size,omitempty"`
	FrameImages     []FrameImage     `json:"frame_images,omitempty"`
	InputReferences []InputReference `json:"input_references,omitempty"`
	GenerateAudio   *bool            `json:"generate_audio,omitempty"`
	Seed            *int64           `json:"seed,omitempty"`
	Provider        map[string]any   `json:"provider,omitempty"`
	NegativePrompt  string           `json:"negative_prompt,omitempty"`
}

type Model struct {
	ID                     string
	Name                   string
	Description            string
	DefaultDuration        int
	DefaultResolution      string
	DefaultAspectRatio     string
	TextProviderModel      string
	ImageProviderModel     string
	ReferenceProviderModel string
	SupportsAudio          bool
	AudioAlwaysOn          bool
	SupportsImage          bool
	SupportsReferences     bool
	SupportsAudioReference bool
	SupportsVideoReference bool
	PromptCharacterLimit   int
	MinimumDuration        int
	MaximumDuration        int
	AllowedDurations       []int
	AllowedResolutions     []string
	AllowedAspectRatios    []string
	OmitResolution         bool
	ImageUsesSourceAspect  bool
}

var models = map[string]Model{
	"bytedance/seedance-2.0": {
		ID: "bytedance/seedance-2.0", Name: "ByteDance Seedance 2.0",
		Description:     "Seedance 2.0 text, image, and reference video generation.",
		DefaultDuration: 5, DefaultResolution: "720p", DefaultAspectRatio: "16:9",
		TextProviderModel:      "seedance-2-0-text-to-video",
		ImageProviderModel:     "seedance-2-0-image-to-video",
		ReferenceProviderModel: "seedance-2-0-reference-to-video",
		SupportsAudio:          true, SupportsImage: true, SupportsReferences: true,
		SupportsAudioReference: true, SupportsVideoReference: true,
		PromptCharacterLimit: 10_000, MinimumDuration: 4, MaximumDuration: 15,
	},
	"bytedance/seedance-2.0-fast": {
		ID: "bytedance/seedance-2.0-fast", Name: "ByteDance Seedance 2.0 Fast",
		Description:     "Faster Seedance 2.0 text, image, and reference video generation.",
		DefaultDuration: 5, DefaultResolution: "720p", DefaultAspectRatio: "16:9",
		TextProviderModel:      "seedance-2-0-fast-text-to-video",
		ImageProviderModel:     "seedance-2-0-fast-image-to-video",
		ReferenceProviderModel: "seedance-2-0-fast-reference-to-video",
		SupportsAudio:          true, SupportsImage: true, SupportsReferences: true,
		SupportsAudioReference: true, SupportsVideoReference: true,
		PromptCharacterLimit: 10_000, MinimumDuration: 4, MaximumDuration: 15,
	},
	"lightricks/ltx-2.3": {
		ID: "lightricks/ltx-2.3", Name: "Lightricks LTX 2.3",
		Description:     "LTX 2.3 full-quality text and image video generation.",
		DefaultDuration: 6, DefaultResolution: "1080p", DefaultAspectRatio: "16:9",
		TextProviderModel:  "ltx-2-v2-3-full-text-to-video",
		ImageProviderModel: "ltx-2-v2-3-full-image-to-video",
		SupportsAudio:      true, SupportsImage: true,
		PromptCharacterLimit: 2500,
		AllowedDurations:     []int{6, 8, 10},
		AllowedResolutions:   []string{"1080p", "1440p", "2160p"},
		AllowedAspectRatios:  []string{"16:9", "9:16"},
	},
	"lightricks/ltx-2.3-fast": {
		ID: "lightricks/ltx-2.3-fast", Name: "Lightricks LTX 2.3 Fast",
		Description:     "LTX 2.3 optimized for faster text and image video generation.",
		DefaultDuration: 6, DefaultResolution: "1080p", DefaultAspectRatio: "16:9",
		TextProviderModel:  "ltx-2-v2-3-fast-text-to-video",
		ImageProviderModel: "ltx-2-v2-3-fast-image-to-video",
		SupportsAudio:      true, SupportsImage: true,
		PromptCharacterLimit: 2500,
		AllowedDurations:     []int{6, 8, 10, 12, 14, 16, 18, 20},
		AllowedResolutions:   []string{"1080p", "1440p", "2160p"},
		AllowedAspectRatios:  []string{"16:9", "9:16"},
	},
	"google/gemini-omni-flash": {
		ID: "google/gemini-omni-flash", Name: "Google Gemini Omni Flash",
		Description:     "Fast Gemini Omni text and image video generation.",
		DefaultDuration: 4, DefaultResolution: "720p", DefaultAspectRatio: "16:9",
		TextProviderModel:      "gemini-omni-flash-text-to-video",
		ImageProviderModel:     "gemini-omni-flash-image-to-video",
		ReferenceProviderModel: "gemini-omni-flash-reference-to-video",
		SupportsAudio:          false, SupportsImage: true, SupportsReferences: true,
		PromptCharacterLimit: 2500,
		AllowedDurations:     []int{4, 6, 8, 10},
		AllowedResolutions:   []string{"720p"},
		AllowedAspectRatios:  []string{"16:9", "9:16"},
		OmitResolution:       true,
	},
	"minimax/hailuo-3": {
		ID: "minimax/hailuo-3", Name: "MiniMax Hailuo 3 (H3)",
		Description:     "MiniMax Hailuo 3, also known as H3, for text, image, and audio-reference video generation.",
		DefaultDuration: 5, DefaultResolution: "2K", DefaultAspectRatio: "16:9",
		TextProviderModel:      "minimax-h3-text-to-video",
		ImageProviderModel:     "minimax-h3-image-to-video",
		ReferenceProviderModel: "minimax-h3-reference-to-video",
		AudioAlwaysOn:          true, SupportsImage: true, SupportsReferences: true,
		SupportsAudioReference: true,
		PromptCharacterLimit:   2500, MinimumDuration: 5, MaximumDuration: 15,
		AllowedResolutions:    []string{"2K"},
		AllowedAspectRatios:   []string{"16:9", "21:9", "4:3", "1:1", "3:4", "9:16"},
		ImageUsesSourceAspect: true,
	},
}

func Models() []Model {
	order := []string{
		"bytedance/seedance-2.0-fast", "bytedance/seedance-2.0",
		"lightricks/ltx-2.3-fast", "lightricks/ltx-2.3",
		"google/gemini-omni-flash", "minimax/hailuo-3",
	}
	out := make([]Model, 0, len(order))
	for _, id := range order {
		out = append(out, models[id])
	}
	return out
}

func Resolve(req *CreateRequest) (Model, map[string]any, map[string]any, error) {
	if req == nil {
		return Model{}, nil, nil, fmt.Errorf("request is required")
	}
	model, ok := models[strings.TrimSpace(req.Model)]
	if !ok {
		return Model{}, nil, nil, fmt.Errorf("video model is not supported")
	}
	if req.CallbackURL != "" {
		return Model{}, nil, nil, &UnsupportedError{Field: "callback_url"}
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return Model{}, nil, nil, fmt.Errorf("prompt is required")
	}
	promptLimit := model.PromptCharacterLimit
	if promptLimit <= 0 {
		promptLimit = MaxPromptBytes
	}
	if utf8.RuneCountInString(req.Prompt) > promptLimit {
		return Model{}, nil, nil, fmt.Errorf("prompt is too long")
	}
	if utf8.RuneCountInString(req.NegativePrompt) > promptLimit {
		return Model{}, nil, nil, fmt.Errorf("negative_prompt is too long")
	}

	duration := req.Duration
	if duration == 0 {
		duration = model.DefaultDuration
	}
	if err := validateDuration(model, duration); err != nil {
		return Model{}, nil, nil, err
	}
	resolution := strings.TrimSpace(req.Resolution)
	aspect := strings.TrimSpace(req.AspectRatio)
	if req.Size != "" {
		var err error
		resolution, aspect, err = resolutionAndAspectForSize(req.Size, resolution, aspect)
		if err != nil {
			return Model{}, nil, nil, err
		}
	}
	if resolution == "" {
		resolution = model.DefaultResolution
	}
	resolution = normalizeResolution(resolution)
	if aspect == "" {
		aspect = model.DefaultAspectRatio
	}
	if err := validateResolutionAndAspect(model, resolution, aspect); err != nil {
		return Model{}, nil, nil, err
	}

	providerModel := model.TextProviderModel
	queue := map[string]any{
		"model":        model.TextProviderModel,
		"prompt":       req.Prompt,
		"duration":     strconv.Itoa(duration) + "s",
		"aspect_ratio": aspect,
	}
	if !model.OmitResolution {
		queue["resolution"] = resolution
	}
	if req.NegativePrompt != "" {
		queue["negative_prompt"] = req.NegativePrompt
	}
	if req.GenerateAudio != nil {
		switch {
		case model.AudioAlwaysOn:
			if !*req.GenerateAudio {
				return Model{}, nil, nil, fmt.Errorf("model always generates audio and does not support disabling it")
			}
			// Venice advertises H3 audio as always-on and rejects an explicit
			// audio field, even when it is true. Accept the portable request
			// semantic while omitting the invalid provider toggle.
		case model.SupportsAudio:
			queue["audio"] = *req.GenerateAudio
		case *req.GenerateAudio:
			return Model{}, nil, nil, fmt.Errorf("model does not support generated audio")
		default:
			// An explicit false is equivalent to the default for video-only
			// models. Do not forward a field the provider does not support.
		}
	}
	if req.Seed != nil {
		queue["seed"] = *req.Seed
	}

	first, last, references, audioRef, videoRef, err := mediaInputs(req)
	if err != nil {
		return Model{}, nil, nil, err
	}
	if first != "" || last != "" {
		if !model.SupportsImage {
			return Model{}, nil, nil, fmt.Errorf("model does not support image input")
		}
		providerModel = model.ImageProviderModel
		queue["image_url"] = first
		if last != "" {
			queue["end_image_url"] = last
		}
		if model.ImageUsesSourceAspect {
			delete(queue, "aspect_ratio")
		}
	}
	if len(references) > 0 || audioRef != "" || videoRef != "" {
		if !model.SupportsReferences || model.ReferenceProviderModel == "" {
			return Model{}, nil, nil, fmt.Errorf("model does not support reference assets")
		}
		providerModel = model.ReferenceProviderModel
		if len(references) > 0 {
			queue["reference_image_urls"] = references
		}
		if audioRef != "" {
			if !model.SupportsAudioReference {
				return Model{}, nil, nil, fmt.Errorf("model does not support audio references")
			}
			queue["audio_url"] = audioRef
		}
		if videoRef != "" {
			if !model.SupportsVideoReference {
				return Model{}, nil, nil, fmt.Errorf("model does not support video references")
			}
			queue["video_url"] = videoRef
		}
	}
	queue["model"] = providerModel

	// The provider can price from generation settings alone. Keeping prompt
	// and reference URLs out of the quote is what lets authorization happen
	// before any user content reaches an upstream provider.
	quote := map[string]any{"model": providerModel, "duration": strconv.Itoa(duration) + "s"}
	for _, key := range []string{"resolution", "aspect_ratio", "audio"} {
		if value, ok := queue[key]; ok {
			quote[key] = value
		}
	}
	return model, queue, quote, nil
}

func validateDuration(model Model, duration int) error {
	if len(model.AllowedDurations) > 0 {
		for _, allowed := range model.AllowedDurations {
			if duration == allowed {
				return nil
			}
		}
		return fmt.Errorf("duration is not supported by this model")
	}
	minimum := model.MinimumDuration
	maximum := model.MaximumDuration
	if minimum == 0 {
		minimum = 1
	}
	if maximum == 0 {
		maximum = 30
	}
	if duration < minimum || duration > maximum {
		return fmt.Errorf("duration must be between %d and %d seconds", minimum, maximum)
	}
	return nil
}

func validateResolutionAndAspect(model Model, resolution, aspect string) error {
	if len(model.AllowedResolutions) > 0 && !containsFold(model.AllowedResolutions, resolution) {
		return fmt.Errorf("resolution is not supported by this model")
	}
	validAspects := []string{"1:1", "2:3", "3:2", "3:4", "4:3", "9:16", "16:9", "21:9"}
	if !containsFold(validAspects, aspect) {
		return fmt.Errorf("aspect_ratio is not supported")
	}
	if len(model.AllowedAspectRatios) > 0 && !containsFold(model.AllowedAspectRatios, aspect) {
		return fmt.Errorf("aspect_ratio is not supported by this model")
	}
	return nil
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

type UnsupportedError struct{ Field string }

func (e *UnsupportedError) Error() string { return e.Field + " is not supported" }

func mediaInputs(req *CreateRequest) (first, last string, refs []string, audioRef, videoRef string, err error) {
	for _, frame := range req.FrameImages {
		value := strings.TrimSpace(frame.ImageURL)
		if value == "" {
			value = strings.TrimSpace(frame.URL)
		}
		if err = validateMediaURL(value); err != nil {
			return
		}
		switch frame.FrameType {
		case "first_frame", "first", "":
			if first != "" {
				err = fmt.Errorf("only one first frame is supported")
				return
			}
			first = value
		case "last_frame", "last":
			if last != "" {
				err = fmt.Errorf("only one last frame is supported")
				return
			}
			last = value
		default:
			err = fmt.Errorf("frame_type must be first_frame or last_frame")
			return
		}
	}
	for _, ref := range req.InputReferences {
		kind := strings.ToLower(strings.TrimSpace(ref.Type))
		value := strings.TrimSpace(ref.URL)
		if value == "" {
			switch kind {
			case "audio":
				value = strings.TrimSpace(ref.AudioURL)
			case "video":
				value = strings.TrimSpace(ref.VideoURL)
			default:
				value = strings.TrimSpace(ref.ImageURL)
			}
		}
		if err = validateMediaURL(value); err != nil {
			return
		}
		switch kind {
		case "", "image":
			refs = append(refs, value)
		case "audio":
			if audioRef != "" {
				err = fmt.Errorf("only one audio reference is supported")
				return
			}
			audioRef = value
		case "video":
			if videoRef != "" {
				err = fmt.Errorf("only one video reference is supported")
				return
			}
			videoRef = value
		default:
			err = fmt.Errorf("reference type must be image, audio, or video")
			return
		}
	}
	return
}

func validateMediaURL(value string) error {
	if value == "" {
		return fmt.Errorf("reference URL is required")
	}
	if strings.HasPrefix(value, "data:") {
		if !strings.Contains(value, ";base64,") {
			return fmt.Errorf("media data URLs must be base64 encoded")
		}
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("media URLs must use https or a base64 data URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
		return fmt.Errorf("local and metadata URLs are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("private network URLs are not allowed")
	}
	return nil
}

func resolutionAndAspectForSize(size, resolution, aspect string) (string, string, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(size)), "x")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("size must use WIDTHxHEIGHT")
	}
	w, errW := strconv.Atoi(parts[0])
	h, errH := strconv.Atoi(parts[1])
	if errW != nil || errH != nil || w <= 0 || h <= 0 {
		return "", "", fmt.Errorf("size must use positive WIDTHxHEIGHT values")
	}
	if resolution == "" {
		switch h {
		case 480, 540, 720, 1080, 1440, 2160:
			resolution = strconv.Itoa(h) + "p"
		default:
			return "", "", fmt.Errorf("size height is not supported")
		}
	}
	if aspect == "" {
		g := gcd(w, h)
		aspect = fmt.Sprintf("%d:%d", w/g, h/g)
	}
	return resolution, aspect, nil
}

func normalizeResolution(value string) string {
	if strings.EqualFold(value, "2k") {
		return "2K"
	}
	return strings.ToLower(value)
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func ModelsJSON() ([]byte, error) {
	data := make([]map[string]any, 0, len(models))
	for _, model := range Models() {
		inputModalities := []string{"text"}
		if model.SupportsImage {
			inputModalities = append(inputModalities, "image")
		}
		if model.SupportsAudioReference {
			inputModalities = append(inputModalities, "audio")
		}
		if model.SupportsVideoReference {
			inputModalities = append(inputModalities, "video")
		}
		parameters := []string{"prompt", "duration", "resolution", "aspect_ratio", "size", "seed"}
		if model.SupportsAudio || model.AudioAlwaysOn {
			parameters = append(parameters, "generate_audio")
		}
		audioMode := "none"
		if model.SupportsAudio {
			audioMode = "configurable"
		} else if model.AudioAlwaysOn {
			audioMode = "always"
		}
		if model.SupportsImage {
			parameters = append(parameters, "frame_images")
		}
		if model.SupportsReferences {
			parameters = append(parameters, "input_references")
		}
		data = append(data, map[string]any{
			"id": model.ID, "canonical_slug": model.ID, "name": model.Name,
			"description":          model.Description,
			"architecture":         map[string]any{"input_modalities": inputModalities, "output_modalities": []string{"video"}},
			"supported_parameters": parameters,
			"trustedrouter": map[string]any{
				"attested_gateway":             true,
				"provider":                     "venice",
				"provider_e2ee":                false,
				"provider_zero_data_retention": false,
				"stores_content":               false,
				"audio_mode":                   audioMode,
				"provider_temporarily_stores_generated_media": true,
			},
		})
	}
	return json.Marshal(map[string]any{"data": data})
}
