//go:build live_provider_wave && !cloud_aws

package video

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveSeedance25QuoteQueueDownloadAndCleanup(t *testing.T) {
	if os.Getenv("TR_LIVE_SEEDANCE_25") != "1" {
		t.Skip("set TR_LIVE_SEEDANCE_25=1 to run the paid Seedance 2.5 smoke")
	}
	client := NewVeniceClient(os.Getenv("VENICE_API_KEY"), &http.Client{Timeout: 2 * time.Minute})
	if !client.Enabled() {
		t.Fatal("VENICE_API_KEY is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	request, err := ResolveRequest(&CreateRequest{
		Model: "bytedance/seedance-2.5", Prompt: "A red cube slowly rotates on a plain white table. Static camera.",
		Duration: 4, Resolution: "480p", GenerateAudio: boolPointer(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := client.QuoteResolved(ctx, request)
	if err != nil || quote <= 0 || quote > 2_000_000 {
		t.Fatalf("quote=%d err=%v; refusing generation above $2", quote, err)
	}
	t.Logf("quote including video fee: %d microdollars", quote)
	job, err := client.QueueResolved(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("queued model=%s job=%s", job.ProviderModel, job.QueueID)
	for {
		result, err := client.Retrieve(ctx, job.ProviderModel, job.QueueID)
		if err != nil {
			t.Fatal(err)
		}
		switch result.State {
		case PollProcessing:
			if err := waitForVideoSmokePoll(ctx, 10*time.Second); err != nil {
				t.Fatal(err)
			}
		case PollFailed:
			t.Fatalf("generation failed: %s", result.ProviderStatus)
		case PollCompleted:
			if result.Body == nil {
				result, err = client.Download(ctx, result.DownloadURL)
				if err != nil {
					t.Fatal(err)
				}
			}
			payload, readErr := io.ReadAll(io.LimitReader(result.Body, 64<<20))
			result.Body.Close()
			if err := client.Complete(ctx, job.ProviderModel, job.QueueID); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if readErr != nil || len(payload) < 1024 || !bytes.Contains(payload[:min(64, len(payload))], []byte("ftyp")) {
				t.Fatalf("invalid MP4: bytes=%d err=%v", len(payload), readErr)
			}
			t.Logf("downloaded %d MP4 bytes; provider cleanup succeeded", len(payload))
			return
		}
	}
}
