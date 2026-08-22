//go:build live_provider_wave && !cloud_aws

package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveDecartVideoQueuePollAndDownload(t *testing.T) {
	if os.Getenv("TR_LIVE_PROVIDER_WAVE") != "1" {
		t.Skip("set TR_LIVE_PROVIDER_WAVE=1 to run the paid Decart video smoke")
	}
	key := strings.TrimSpace(os.Getenv("DECART_API_KEY"))
	if key == "" {
		t.Fatal("DECART_API_KEY is required")
	}
	videoBytes, err := os.ReadFile("testdata/decart-smoke.mp4")
	if err != nil {
		t.Fatalf("read embedded MP4: %v", err)
	}
	if duration, durationErr := mp4DurationSeconds(bytes.NewReader(videoBytes), int64(len(videoBytes))); durationErr != nil || duration != 1 {
		t.Fatalf("embedded MP4 preflight duration=%d err=%v", duration, durationErr)
	}
	request, err := ResolveRequest(&CreateRequest{
		Model: "decart/lucy-2.5", Prompt: "Keep the frame unchanged.",
		Duration: 1, Resolution: "720p",
		InputReferences: []InputReference{{
			Type: "video", URL: "data:video/mp4;base64," + base64.StdEncoding.EncodeToString(videoBytes),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := NewDecartVideoClient(key, &http.Client{Timeout: 10 * time.Minute})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	queued, err := client.QueueResolved(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("queued Decart job %s", queued.QueueID)
	for {
		result, retrieveErr := client.Retrieve(ctx, queued.ProviderModel, queued.QueueID)
		if retrieveErr != nil {
			t.Fatal(retrieveErr)
		}
		switch result.State {
		case PollProcessing:
			if err := waitForVideoSmokePoll(ctx, 2*time.Second); err != nil {
				t.Fatal(err)
			}
		case PollFailed:
			t.Fatalf("Decart job failed with status %s", result.ProviderStatus)
		case PollCompleted:
			downloaded, downloadErr := client.Download(ctx, result.DownloadURL)
			if downloadErr != nil {
				t.Fatal(downloadErr)
			}
			defer downloaded.Body.Close()
			payload, readErr := io.ReadAll(io.LimitReader(downloaded.Body, 64<<20))
			if readErr != nil || len(payload) == 0 {
				t.Fatalf("download bytes=%d err=%v", len(payload), readErr)
			}
			return
		}
	}
}

func waitForVideoSmokePoll(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
