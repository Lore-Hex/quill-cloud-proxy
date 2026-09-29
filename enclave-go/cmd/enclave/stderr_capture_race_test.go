package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Sol's reproduction: a non-streaming chat's provider goroutine logs after the
// response is written. captureStderr must not race it (it redirects fd 2
// rather than swapping os.Stderr), whichever launch site started it.
func TestStderrCaptureDoesNotRaceALeftoverProvider(t *testing.T) {
	provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
		err := writeAnthropicTextTestStream(out, req.Model, "answer")
		time.Sleep(100 * time.Millisecond)
		return err
	})
	var out bytes.Buffer
	req := &types.OpenAIChatRequest{Model: "model/test"}
	serveChatNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, nil, nil, nil, nil, time.Now(), nil, "round3-repro", req.Model)
	_ = captureStderr(t, func() { time.Sleep(200 * time.Millisecond) })
}
