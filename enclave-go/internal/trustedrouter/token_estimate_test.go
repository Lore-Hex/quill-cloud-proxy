package trustedrouter

import (
	"strings"
	"testing"
)

func TestEstimateOutputTokensTreatsImageDataURLsAsImageTokens(t *testing.T) {
	text := "caption\ndata:image/png;base64," + strings.Repeat("A", 200_000)
	got := EstimateOutputTokens(text)
	if got < imageOutputTokenEstimate || got > imageOutputTokenEstimate+10 {
		t.Fatalf("EstimateOutputTokens = %d, want one image plus small text", got)
	}
}

func TestEstimateOutputTokensCountsPlainTextNormally(t *testing.T) {
	if got := EstimateOutputTokens(strings.Repeat("x", 400)); got != 100 {
		t.Fatalf("EstimateOutputTokens = %d, want 100", got)
	}
}
