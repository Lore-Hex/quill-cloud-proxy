package types

import "strings"

func ContentEmpty(content any) bool {
	return strings.TrimSpace(ContentText(content)) == "" && ContentImageCount(content) == 0
}

func ContentText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []ChatContentPart:
		parts := make([]string, 0, len(value))
		for _, part := range value {
			if isTextPart(part.Type) && strings.TrimSpace(part.Text) != "" {
				parts = append(parts, part.Text)
			}
		}
		return strings.Join(parts, "\n")
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			if m, ok := item.(map[string]any); ok && isTextPart(stringValue(m["type"])) {
				if text := stringValue(m["text"]); strings.TrimSpace(text) != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func ContentImageCount(content any) int {
	switch value := content.(type) {
	case []ChatContentPart:
		count := 0
		for _, part := range value {
			if part.Type == "image_url" && part.ImageURL != nil && strings.TrimSpace(part.ImageURL.URL) != "" {
				count++
			}
		}
		return count
	case []any:
		count := 0
		for _, item := range value {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if isImagePart(stringValue(m["type"])) {
				count++
			}
		}
		return count
	default:
		return 0
	}
}

func RequestInputModalities(req *OpenAIChatRequest) []string {
	if req == nil {
		return nil
	}
	hasImage := false
	for _, message := range req.Messages {
		if ContentImageCount(message.Content) > 0 {
			hasImage = true
			break
		}
	}
	if hasImage {
		return []string{"text", "image"}
	}
	return nil
}

func ContentTokenEstimate(content any) int {
	textTokens := len(ContentText(content)) / 4
	if textTokens < 0 {
		textTokens = 0
	}
	imageTokens := 0
	switch value := content.(type) {
	case []ChatContentPart:
		for _, part := range value {
			if part.Type == "image_url" && part.ImageURL != nil {
				imageTokens += imageTokenEstimate(part.ImageURL.Detail)
			}
		}
	case []any:
		for _, item := range value {
			m, ok := item.(map[string]any)
			if !ok || !isImagePart(stringValue(m["type"])) {
				continue
			}
			imageTokens += imageTokenEstimate(imageDetail(m))
		}
	}
	total := textTokens + imageTokens
	if total < 1 {
		return 1
	}
	return total
}

func imageTokenEstimate(detail string) int {
	switch strings.ToLower(strings.TrimSpace(detail)) {
	case "low":
		return 85
	case "high", "original":
		return 1700
	default:
		return 1024
	}
}

func imageDetail(m map[string]any) string {
	if detail := stringValue(m["detail"]); detail != "" {
		return detail
	}
	imageURL, ok := m["image_url"].(map[string]any)
	if ok {
		return stringValue(imageURL["detail"])
	}
	return ""
}

func isTextPart(partType string) bool {
	switch strings.TrimSpace(partType) {
	case "", "text", "input_text":
		return true
	default:
		return false
	}
}

func isImagePart(partType string) bool {
	switch strings.TrimSpace(partType) {
	case "image_url", "input_image":
		return true
	default:
		return false
	}
}

func stringValue(value any) string {
	out, _ := value.(string)
	return out
}
