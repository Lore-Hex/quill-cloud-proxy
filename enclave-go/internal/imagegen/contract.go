// Package imagegen implements the normalized /v1/images contract and native
// provider adapters. ModelSpec is the enclave's single source of truth for
// validation, parameter translation, and billing quotes.
package imagegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const MaxPromptBytes = 512 << 10

type PricingKind string

const (
	PricingGeminiTokens PricingKind = "gemini_tokens"
	PricingOpenAITokens PricingKind = "openai_tokens"
	PricingFixed        PricingKind = "fixed"
)

type ModelSpec struct {
	ID                 string
	Provider           string
	UpstreamID         string
	Pricing            PricingKind
	SupportsStreaming  bool
	NMin               int
	NMax               int
	Resolutions        []string
	AspectRatios       []string
	Qualities          []string
	Backgrounds        []string
	OutputFormats      []string
	NativeSizes        map[string]string // normalized aspect ratio -> provider-native pixels
	Compression        bool
	MaxInputReferences int
	AllowedPassthrough []string
	FixedOutputPrices  map[string]int // provider list-price microdollars
	FixedInputPrice    int
}

type NativeSize struct {
	Resolution  string
	AspectRatio string
}

type nativeImageShape struct {
	AspectRatio string
	Size        string
}

type ImageReference struct {
	Type     string `json:"type"`
	ImageURL struct {
		URL string `json:"url"`
	} `json:"image_url"`
}

type Request struct {
	Model             string                 `json:"model"`
	Prompt            string                 `json:"prompt"`
	N                 *int                   `json:"n,omitempty"`
	Resolution        string                 `json:"resolution,omitempty"`
	AspectRatio       string                 `json:"aspect_ratio,omitempty"`
	Size              string                 `json:"size,omitempty"`
	Quality           string                 `json:"quality,omitempty"`
	OutputFormat      string                 `json:"output_format,omitempty"`
	Background        string                 `json:"background,omitempty"`
	OutputCompression *int                   `json:"output_compression,omitempty"`
	Seed              *int                   `json:"seed,omitempty"`
	Stream            bool                   `json:"stream,omitempty"`
	InputReferences   []ImageReference       `json:"input_references,omitempty"`
	Provider          *types.ProviderRouting `json:"provider,omitempty"`
	Metadata          map[string]any         `json:"metadata,omitempty"`
	Trace             map[string]any         `json:"trace,omitempty"`
	User              string                 `json:"user,omitempty"`
	SessionID         string                 `json:"session_id,omitempty"`
	Tags              *types.RequestTags     `json:"tags,omitempty"`
}

type ResolvedRequest struct {
	Request     Request
	Spec        ModelSpec
	N           int
	Resolution  string
	AspectRatio string
	Quality     string
	Background  string
	Format      string
}

type RequestError struct {
	Message string
	Param   string
}

func (e *RequestError) Error() string { return e.Message }

var googleOutputTokensByResolution = map[string]int{
	"512": 747,
	"1K":  1120,
	"2K":  1680,
	"4K":  2520,
}

var googleAspectRatios = []string{
	"1:1", "1:4", "1:8", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4",
	"8:1", "9:16", "16:9", "21:9",
}

var xaiAspectRatios = []string{
	"1:1", "3:4", "4:3", "9:16", "16:9", "2:3", "3:2", "9:19.5", "19.5:9",
	"9:20", "20:9", "1:2", "2:1", "auto",
}

var googleNativeSizes = buildGoogleNativeSizes()

func buildGoogleNativeSizes() map[string]NativeSize {
	base := map[string][2]int{
		"1:1": {512, 512}, "1:4": {256, 1024}, "1:8": {192, 1536}, "2:3": {424, 632},
		"3:2": {632, 424}, "3:4": {448, 600}, "4:1": {1024, 256}, "4:3": {600, 448},
		"4:5": {464, 576}, "5:4": {576, 464}, "8:1": {1536, 192}, "9:16": {384, 688},
		"16:9": {688, 384}, "21:9": {792, 168},
	}
	tiers := []struct {
		name       string
		multiplier int
	}{{"512", 1}, {"1K", 2}, {"2K", 4}, {"4K", 8}}
	result := make(map[string]NativeSize, len(base)*len(tiers))
	for _, tier := range tiers {
		for ratio, size := range base {
			key := fmt.Sprintf("%dx%d", size[0]*tier.multiplier, size[1]*tier.multiplier)
			result[key] = NativeSize{Resolution: tier.name, AspectRatio: ratio}
		}
	}
	return result
}

func googleSpec(id string) ModelSpec {
	return ModelSpec{
		ID: id, Provider: "google-ai-studio", UpstreamID: strings.TrimPrefix(id, "google/"),
		Pricing: PricingGeminiTokens, SupportsStreaming: false, NMin: 1, NMax: 1,
		Resolutions: []string{"512", "1K", "2K", "4K"}, AspectRatios: slices.Clone(googleAspectRatios),
		MaxInputReferences: 14,
	}
}

func openAISpec(id string, shapes []nativeImageShape, backgrounds []string) ModelSpec {
	ratios := make([]string, 0, len(shapes)+1)
	nativeSizes := make(map[string]string, len(shapes))
	for _, shape := range shapes {
		ratios = append(ratios, shape.AspectRatio)
		nativeSizes[shape.AspectRatio] = shape.Size
	}
	ratios = append(ratios, "auto")
	return ModelSpec{
		ID: id, Provider: "openai", UpstreamID: strings.TrimPrefix(id, "openai/"),
		Pricing: PricingOpenAITokens, SupportsStreaming: false, NMin: 1, NMax: 10,
		AspectRatios: ratios, Qualities: []string{"auto", "low", "medium", "high"},
		Backgrounds: slices.Clone(backgrounds), OutputFormats: []string{"png", "jpeg", "webp"},
		NativeSizes: nativeSizes, Compression: true, AllowedPassthrough: []string{"moderation"},
	}
}

func xaiSpec(id string, qualities []string, prices map[string]int) ModelSpec {
	return ModelSpec{
		ID: id, Provider: "grok", UpstreamID: strings.TrimPrefix(id, "x-ai/"),
		Pricing: PricingFixed, SupportsStreaming: false, NMin: 1, NMax: 1,
		Resolutions: []string{"1K", "2K"}, AspectRatios: slices.Clone(xaiAspectRatios),
		Qualities: slices.Clone(qualities), FixedOutputPrices: maps.Clone(prices),
	}
}

var modelSpecs = func() map[string]ModelSpec {
	classicShapes := []nativeImageShape{
		{AspectRatio: "1:1", Size: "1024x1024"},
		{AspectRatio: "3:2", Size: "1536x1024"},
		{AspectRatio: "2:3", Size: "1024x1536"},
	}
	gpt2Shapes := append(slices.Clone(classicShapes),
		nativeImageShape{AspectRatio: "4:3", Size: "1536x1152"},
		nativeImageShape{AspectRatio: "3:4", Size: "1152x1536"},
		nativeImageShape{AspectRatio: "16:9", Size: "1536x864"},
		nativeImageShape{AspectRatio: "9:16", Size: "864x1536"},
		nativeImageShape{AspectRatio: "21:9", Size: "1536x672"},
	)
	specs := []ModelSpec{
		googleSpec("google/gemini-3.1-flash-image"),
		googleSpec("google/gemini-3.1-flash-image-preview"),
		openAISpec("openai/gpt-image-1-mini", classicShapes, []string{"auto", "transparent", "opaque"}),
		openAISpec("openai/gpt-image-1", classicShapes, []string{"auto", "transparent", "opaque"}),
		openAISpec("openai/gpt-image-2", gpt2Shapes, []string{"auto", "opaque"}),
		xaiSpec("x-ai/grok-imagine-image-quality", nil, map[string]int{"1k": 50_000, "2k": 70_000}),
		xaiSpec("x-ai/grok-imagine-image-2.0", []string{"low", "medium"}, map[string]int{
			"low_1k": 40_000, "low_2k": 60_000, "medium_1k": 60_000, "medium_2k": 80_000,
		}),
	}
	result := make(map[string]ModelSpec, len(specs))
	for _, spec := range specs {
		result[spec.ID] = cloneSpec(spec)
	}
	return result
}()

func cloneSpec(spec ModelSpec) ModelSpec {
	spec.Resolutions = slices.Clone(spec.Resolutions)
	spec.AspectRatios = slices.Clone(spec.AspectRatios)
	spec.Qualities = slices.Clone(spec.Qualities)
	spec.Backgrounds = slices.Clone(spec.Backgrounds)
	spec.OutputFormats = slices.Clone(spec.OutputFormats)
	spec.NativeSizes = maps.Clone(spec.NativeSizes)
	spec.AllowedPassthrough = slices.Clone(spec.AllowedPassthrough)
	spec.FixedOutputPrices = maps.Clone(spec.FixedOutputPrices)
	return spec
}

func Spec(model string) (ModelSpec, bool) {
	spec, ok := modelSpecs[model]
	return cloneSpec(spec), ok
}

func ModelIDs() []string {
	ids := slices.Collect(maps.Keys(modelSpecs))
	slices.Sort(ids)
	return ids
}

func Parse(raw []byte) (*ResolvedRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req Request
	if err := decoder.Decode(&req); err != nil {
		return nil, &RequestError{Message: "invalid image request"}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, &RequestError{Message: "invalid image request"}
	}
	req.Model = strings.TrimSpace(req.Model)
	spec, ok := Spec(req.Model)
	if !ok {
		return nil, &RequestError{Message: "model does not support image generation", Param: "model"}
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return nil, &RequestError{Message: "prompt is required", Param: "prompt"}
	}
	if len(req.Prompt) > MaxPromptBytes {
		return nil, &RequestError{Message: "prompt is too long", Param: "prompt"}
	}
	n := 1
	if req.N != nil {
		n = *req.N
	}
	if n < spec.NMin || n > spec.NMax {
		return nil, unsupportedRange("n", spec.NMin, spec.NMax)
	}
	if len(req.InputReferences) > spec.MaxInputReferences {
		return nil, unsupportedRange("input_references", 0, spec.MaxInputReferences)
	}
	for i, reference := range req.InputReferences {
		if reference.Type != "image_url" || strings.TrimSpace(reference.ImageURL.URL) == "" {
			return nil, &RequestError{
				Message: "each input reference must be an image_url with a non-empty url",
				Param:   fmt.Sprintf("input_references[%d]", i),
			}
		}
	}
	if err := validateProviderOptions(req.Provider, spec); err != nil {
		return nil, err
	}
	if req.Seed != nil {
		return nil, &RequestError{Message: "seed is not supported by the selected endpoint", Param: "seed"}
	}
	if req.OutputCompression != nil {
		if !spec.Compression {
			return nil, &RequestError{Message: "output_compression is not supported by the selected endpoint", Param: "output_compression"}
		}
		if *req.OutputCompression < 0 || *req.OutputCompression > 100 {
			return nil, unsupportedRange("output_compression", 0, 100)
		}
	}

	resolution, err := resolveEnum("resolution", req.Resolution, spec.Resolutions, defaultResolution(spec))
	if err != nil {
		return nil, err
	}
	aspectRatio, err := resolveEnum("aspect_ratio", req.AspectRatio, spec.AspectRatios, defaultAspectRatio(spec))
	if err != nil {
		return nil, err
	}
	quality, err := resolveQuality(req.Quality, spec)
	if err != nil {
		return nil, err
	}
	background, err := resolveEnum("background", req.Background, spec.Backgrounds, defaultValue(spec.Backgrounds))
	if err != nil {
		return nil, err
	}
	format, err := resolveEnum("output_format", req.OutputFormat, spec.OutputFormats, defaultOutputFormat(spec))
	if err != nil {
		return nil, err
	}
	if background == "transparent" && format != "png" && format != "webp" {
		return nil, &RequestError{Message: "transparent background requires png or webp output", Param: "background"}
	}
	if req.Size != "" {
		resolution, aspectRatio, err = resolveSize(
			req.Size, resolution, aspectRatio, spec,
			strings.TrimSpace(req.Resolution) != "", strings.TrimSpace(req.AspectRatio) != "",
		)
		if err != nil {
			return nil, err
		}
	}
	return &ResolvedRequest{
		Request: req, Spec: spec, N: n, Resolution: resolution, AspectRatio: aspectRatio,
		Quality: quality, Background: background, Format: format,
	}, nil
}

func defaultResolution(spec ModelSpec) string {
	if spec.Pricing == PricingGeminiTokens || spec.Pricing == PricingFixed {
		return "1K"
	}
	return ""
}

func defaultAspectRatio(spec ModelSpec) string {
	if slices.Contains(spec.AspectRatios, "auto") {
		return "auto"
	}
	if slices.Contains(spec.AspectRatios, "1:1") {
		return "1:1"
	}
	return ""
}

func defaultOutputFormat(spec ModelSpec) string {
	if spec.Provider == "openai" {
		return "png"
	}
	return ""
}

func defaultValue(values []string) string {
	if slices.Contains(values, "auto") {
		return "auto"
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func resolveQuality(raw string, spec ModelSpec) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if len(spec.Qualities) == 0 {
		// OpenRouter's normalized contract explicitly ignores quality for
		// providers without a native quality knob.
		return "", nil
	}
	fallback := defaultValue(spec.Qualities)
	if spec.ID == "x-ai/grok-imagine-image-2.0" {
		fallback = "medium"
	}
	return resolveEnum("quality", value, spec.Qualities, fallback)
}

func resolveEnum(field, raw string, values []string, fallback string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}
	if field == "resolution" {
		value = normalizeResolution(value)
	} else if field != "aspect_ratio" {
		value = strings.ToLower(value)
	}
	if len(values) == 0 || !slices.Contains(values, value) {
		return "", &RequestError{Message: field + " is not supported by the selected endpoint", Param: field}
	}
	return value, nil
}

func normalizeResolution(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "512":
		return "512"
	case "1K":
		return "1K"
	case "2K":
		return "2K"
	case "4K":
		return "4K"
	default:
		return strings.TrimSpace(raw)
	}
}

func resolveSize(
	raw, resolution, aspectRatio string,
	spec ModelSpec,
	resolutionExplicit, aspectRatioExplicit bool,
) (string, string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if tier := normalizeResolution(value); slices.Contains(spec.Resolutions, tier) {
		if resolutionExplicit && resolution != tier {
			return "", "", &RequestError{Message: "size conflicts with resolution", Param: "size"}
		}
		return tier, aspectRatio, nil
	}
	if spec.Pricing == PricingGeminiTokens {
		native, ok := googleNativeSizes[value]
		if !ok {
			return "", "", &RequestError{Message: "size is not a native size for this model", Param: "size"}
		}
		if resolutionExplicit && resolution != native.Resolution {
			return "", "", &RequestError{Message: "size conflicts with resolution", Param: "size"}
		}
		if aspectRatioExplicit && aspectRatio != native.AspectRatio {
			return "", "", &RequestError{Message: "size conflicts with aspect_ratio", Param: "size"}
		}
		return native.Resolution, native.AspectRatio, nil
	}
	if spec.Provider == "openai" {
		ratio := ""
		for candidate, size := range spec.NativeSizes {
			if size == value {
				ratio = candidate
				break
			}
		}
		if ratio == "" {
			return "", "", &RequestError{Message: "size is not a native size for this model", Param: "size"}
		}
		if aspectRatioExplicit && aspectRatio != ratio {
			return "", "", &RequestError{Message: "size conflicts with aspect_ratio", Param: "size"}
		}
		return resolution, ratio, nil
	}
	return "", "", &RequestError{Message: "size is not supported by the selected endpoint", Param: "size"}
}

func validateProviderOptions(provider *types.ProviderRouting, spec ModelSpec) error {
	if provider == nil || len(provider.Options) == 0 {
		return nil
	}
	for slug, rawOptions := range provider.Options {
		if slug != spec.Provider {
			return &RequestError{Message: "provider.options contains an unsupported provider", Param: "provider.options." + slug}
		}
		options, ok := rawOptions.(map[string]any)
		if !ok {
			return &RequestError{Message: "provider options must be an object", Param: "provider.options." + slug}
		}
		for key := range options {
			if !slices.Contains(spec.AllowedPassthrough, key) {
				return &RequestError{Message: "provider option is not allowed by the selected endpoint", Param: "provider.options." + slug + "." + key}
			}
		}
	}
	return nil
}

func unsupportedRange(field string, minimum, maximum int) *RequestError {
	return &RequestError{
		Message: field + " must be between " + strconv.Itoa(minimum) + " and " + strconv.Itoa(maximum),
		Param:   field,
	}
}

func (r *ResolvedRequest) MaxOutputTokens() int {
	if r.Spec.Pricing == PricingGeminiTokens {
		return googleOutputTokensByResolution[r.Resolution]
	}
	if r.Spec.Pricing == PricingOpenAITokens {
		// All normalized OpenAI sizes are at most 1536 px on the long edge.
		// Eight thousand covers the high-quality output-token ceiling for those
		// native sizes without placing a punitive 20k-token hold on every image.
		return 8_000 * r.N
	}
	return 1
}

func (r *ResolvedRequest) BilledGeminiOutputTokens() int {
	return googleOutputTokensByResolution[r.Resolution]
}

func (r *ResolvedRequest) FixedProviderCostMicrodollars() int {
	if r.Spec.Pricing != PricingFixed {
		return 0
	}
	variant := strings.ToLower(r.Resolution)
	if r.Quality != "" {
		variant = r.Quality + "_" + variant
	}
	return r.Spec.FixedOutputPrices[variant]*r.N + r.Spec.FixedInputPrice*len(r.Request.InputReferences)
}

func (r *ResolvedRequest) FixedCustomerCostMicrodollars() int {
	providerCost := r.FixedProviderCostMicrodollars()
	if providerCost == 0 {
		return 0
	}
	// ceil(provider * 1.055), exactly matching control-plane prepaid markup.
	return (providerCost*211 + 199) / 200
}

func (r *ResolvedRequest) PassthroughOptions() map[string]any {
	if r.Request.Provider == nil {
		return nil
	}
	options, _ := r.Request.Provider.Options[r.Spec.Provider].(map[string]any)
	return maps.Clone(options)
}

func GoogleNativeDimensions(resolution, aspectRatio string) (int, int, bool) {
	for size, native := range googleNativeSizes {
		if native.Resolution != resolution || native.AspectRatio != aspectRatio {
			continue
		}
		var width, height int
		if _, err := fmt.Sscanf(size, "%dx%d", &width, &height); err == nil {
			return width, height, true
		}
	}
	return 0, 0, false
}
