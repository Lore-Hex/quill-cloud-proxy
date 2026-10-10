package llm

import (
	"fmt"
	"strings"
)

// geminiFlashDefaultThinkingLevel keeps every Google transport aligned.
// Gemini 3.7 removed the minimal level; low is its smallest accepted value.
func geminiFlashDefaultThinkingLevel(modelID string) string {
	if geminiVersionAtLeast(modelID, 3, 7) {
		return "low"
	}
	return "minimal"
}

func geminiVersionAtLeast(modelID string, wantMajor, wantMinor int) bool {
	modelID = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(modelID)), "google/")
	modelID = strings.TrimPrefix(modelID, "gemini-")
	// Major-only IDs such as gemini-3-flash-preview mean minor version 0.
	var major, minor int
	if n, _ := fmt.Sscanf(modelID, "%d.%d", &major, &minor); n == 0 {
		return false
	}
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}
