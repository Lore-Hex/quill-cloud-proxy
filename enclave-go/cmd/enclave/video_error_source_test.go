package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestVideoProviderErrorSource(t *testing.T) {
	const fallback = "video provider rejected the job"
	tests := []struct {
		name       string
		err        error
		status     int
		source     string
		errorType  string
		code       string
		message    string
		inputParam bool
	}{
		{"rate limit", &video.HTTPError{Status: 429}, 429, "provider", "provider_error", "rate_limit_exceeded", fallback, false},
		{"wrapped provider error", fmt.Errorf("submit: %w", &video.HTTPError{Status: 503}), 503, "provider", "provider_error", "video_provider_error", fallback, false},
		{"provider rejection", &video.HTTPError{Status: 400}, 400, "provider", "provider_error", "video_provider_error", fallback, false},
		{"provider transport", errors.New("private upstream detail"), 502, "provider", "provider_error", "video_provider_error", fallback, false},
		{"local input rejection", &video.InputError{Message: "invalid input reference"}, 400, "router", "invalid_request_error", "invalid_video_input", "invalid input reference", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw bytes.Buffer
			writeVideoProviderError(&raw, tt.err, fallback)
			response, err := http.ReadResponse(bufio.NewReader(&raw), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, tt.status)
			}
			var payload struct {
				Error struct {
					Source  string  `json:"source"`
					Type    string  `json:"type"`
					Code    string  `json:"code"`
					Message string  `json:"message"`
					Param   *string `json:"param"`
				} `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			got := payload.Error
			if got.Source != tt.source || got.Type != tt.errorType || got.Code != tt.code || got.Message != tt.message {
				t.Fatalf("error = %+v, want source=%s type=%s code=%s message=%q", got, tt.source, tt.errorType, tt.code, tt.message)
			}
			if tt.inputParam {
				if got.Param == nil || *got.Param != "input_references" {
					t.Fatalf("input param = %v", got.Param)
				}
			} else if got.Param != nil {
				t.Fatalf("provider param = %v, want null", got.Param)
			}
		})
	}
}
