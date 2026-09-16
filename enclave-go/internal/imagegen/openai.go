package imagegen

import "fmt"

type openAIImageInputDetails struct {
	TextTokens   int `json:"text_tokens"`
	ImageTokens  int `json:"image_tokens"`
	CachedTokens int `json:"cached_tokens"`
}

func applyOpenAIImageUsage(usage *Usage, details *openAIImageInputDetails) error {
	if details == nil {
		return nil // Older generation models report aggregate usage only.
	}
	// Reject image input accounting rather than charge it at the text rate.
	if details.TextTokens != usage.InputTokens || details.ImageTokens != 0 ||
		details.CachedTokens < 0 || details.CachedTokens > usage.InputTokens {
		return fmt.Errorf("image provider returned inconsistent input usage")
	}
	usage.CachedInputTokens = details.CachedTokens
	return nil
}
