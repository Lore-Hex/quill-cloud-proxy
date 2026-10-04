package main

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFusionCallJoinsProviderBeforeValidationAndReturn(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "completed"
		if reject {
			name = "validation failure"
		}
		t.Run(name, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t)
			cleanupStarted := make(chan struct{})
			releaseCleanup := make(chan struct{})
			var cleanedUp atomic.Bool
			provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
				if err := writeAnthropicTextTestStream(out, req.Model, "complete"); err != nil {
					return err
				}
				// A terminal event is not the end of InvokeStreaming: adapters
				// still unwind canceled reads and close their response bodies.
				<-ctx.Done()
				close(cleanupStarted)
				<-releaseCleanup
				cleanedUp.Store(true)
				return ctx.Err()
			})
			validationErr := errors.New("invalid answer")
			var validatedBeforeCleanup atomic.Bool
			validate := func(adapter.StreamResult) error {
				validatedBeforeCleanup.Store(!cleanedUp.Load())
				if reject {
					return validationErr
				}
				return nil
			}
			req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := runFusionCallValidated(ctx, provider, req, gateway, nil, "bearer", "fusion.panel", "id", "log", nil, false, validate, true)
				done <- err
			}()
			select {
			case <-cleanupStarted:
			case <-time.After(2 * time.Second):
				close(releaseCleanup)
				t.Fatal("collector did not cancel the provider after message_stop")
			}
			var err error
			returnedEarly := false
			select {
			case err = <-done:
				returnedEarly = true
			case <-time.After(20 * time.Millisecond):
			}
			close(releaseCleanup)
			if !returnedEarly {
				select {
				case err = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("fusion call did not join the released provider")
				}
			}
			if returnedEarly || validatedBeforeCleanup.Load() {
				t.Error("fusion call validated/returned before provider cleanup finished")
			}
			if reject && !errors.Is(err, validationErr) || !reject && err != nil {
				t.Fatalf("validation outcome changed: %v", err)
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			wantSettled, wantRefunded := 1, 0
			if reject {
				wantSettled, wantRefunded = 0, 1
			}
			if len(recorder.settle) != wantSettled || len(recorder.refund) != wantRefunded {
				t.Fatalf("settled=%d refunded=%d, want %d/%d", len(recorder.settle), len(recorder.refund), wantSettled, wantRefunded)
			}
		})
	}
}
