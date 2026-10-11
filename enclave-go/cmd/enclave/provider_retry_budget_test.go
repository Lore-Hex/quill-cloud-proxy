package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func runRetryBudgetTest(t *testing.T, budget time.Duration, provider streamingProviderFunc) ([]byte, error) {
	t.Helper()
	oldBudget := finalCandidateFirstByteBudget
	finalCandidateFirstByteBudget = budget
	t.Cleanup(func() { finalCandidateFirstByteBudget = oldBudget })
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	invocation := startProviderInvocation(ctx, provider,
		&types.OpenAIChatRequest{Model: "pinned-model"}, nil,
		[]llm.InvokeOptions{{Model: "pinned-model", Provider: "pinned-provider", EndpointID: "pinned"}},
		true, nil, "retry-budget-test")
	defer invocation.reader.Close()
	body, err := io.ReadAll(invocation.reader)
	invocation.join()
	return body, err
}

func TestProviderRetryBudgetCannotFitBackoff(t *testing.T) {
	oldSleep := sleepBeforeTransientRetry
	sleeps := 0
	sleepBeforeTransientRetry = func(context.Context, time.Duration) error {
		sleeps++
		return nil
	}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	attempts := 0
	upstreamErr := errors.New("llm/upstream: HTTP 503")
	body, err := runRetryBudgetTest(t, 500*time.Millisecond, func(_ context.Context, _ io.Writer, option llm.InvokeOptions) error {
		attempts++
		if option.EndpointID != "pinned" {
			t.Errorf("unexpected fallback: %q", option.EndpointID)
		}
		return upstreamErr
	})
	if attempts != 1 || sleeps != 0 || len(body) != 0 || !errors.Is(err, upstreamErr) {
		t.Fatalf("attempts=%d sleeps=%d body=%q err=%v", attempts, sleeps, body, err)
	}
}

func TestProviderRetryBudgetIncludesAttemptAndBackoff(t *testing.T) {
	oldSleep := sleepBeforeTransientRetry
	sleeps := 0
	sleepBeforeTransientRetry = func(context.Context, time.Duration) error {
		sleeps++
		return nil
	}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	attempts := 0
	upstreamErr := errors.New("llm/upstream: HTTP 504")
	_, err := runRetryBudgetTest(t, 1100*time.Millisecond, func(_ context.Context, _ io.Writer, _ llm.InvokeOptions) error {
		attempts++
		time.Sleep(200 * time.Millisecond)
		return upstreamErr
	})
	if attempts != 1 || sleeps != 0 || !errors.Is(err, upstreamErr) {
		t.Fatalf("slow failure refreshed budget: attempts=%d sleeps=%d err=%v", attempts, sleeps, err)
	}
}

func TestProviderRetryBudgetDoesNotRefreshTimer(t *testing.T) {
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(ctx context.Context, _ time.Duration) error {
		return oldSleep(ctx, 1750*time.Millisecond)
	}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	attempts := 0
	start := time.Now()
	body, err := runRetryBudgetTest(t, 2*time.Second, func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
		attempts++
		if attempts == 1 {
			return errors.New("llm/upstream: HTTP 503")
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("retry reset the candidate budget: %s", elapsed)
	}
	if attempts != 2 || len(body) != 0 || errorClass(err) != "ttfb_exceeded" {
		t.Fatalf("attempts=%d body=%q err=%v", attempts, body, err)
	}
}

func TestProviderRetryBudgetDoesNotTruncateAcceptedStream(t *testing.T) {
	body, err := runRetryBudgetTest(t, 200*time.Millisecond, func(_ context.Context, out io.Writer, _ llm.InvokeOptions) error {
		if _, err := io.WriteString(out, "first"); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)
		_, err := io.WriteString(out, "last")
		return err
	})
	if err != nil || string(body) != "firstlast" {
		t.Fatalf("accepted stream was truncated: body=%q err=%v", body, err)
	}
}

func TestProviderRetryBudgetRecheckedAfterDelayedBackoff(t *testing.T) {
	oldSleep := sleepBeforeTransientRetry
	sleeps := 0
	sleepBeforeTransientRetry = func(ctx context.Context, _ time.Duration) error {
		sleeps++
		return oldSleep(ctx, 1200*time.Millisecond)
	}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	attempts := 0
	upstreamErr := errors.New("llm/upstream: HTTP 503")
	_, err := runRetryBudgetTest(t, 1100*time.Millisecond, func(context.Context, io.Writer, llm.InvokeOptions) error {
		attempts++
		return upstreamErr
	})
	if attempts != 1 || sleeps != 1 || !errors.Is(err, upstreamErr) {
		t.Fatalf("expired retry started: attempts=%d sleeps=%d err=%v", attempts, sleeps, err)
	}
}

func TestProviderRetryBudgetAllowsFastRecoveryOnSameRoute(t *testing.T) {
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	attempts := 0
	body, err := runRetryBudgetTest(t, 2*time.Second, func(_ context.Context, out io.Writer, option llm.InvokeOptions) error {
		attempts++
		if option.EndpointID != "pinned" || option.Model != "pinned-model" || option.Provider != "pinned-provider" {
			t.Errorf("retry changed the authorized route: %+v", option)
		}
		if attempts == 1 {
			return errors.New("llm/upstream: HTTP 503")
		}
		_, err := io.WriteString(out, "recovered")
		return err
	})
	if attempts != 2 || err != nil || string(body) != "recovered" {
		t.Fatalf("fast retry failed: attempts=%d body=%q err=%v", attempts, body, err)
	}
}

func TestProviderRetryBudgetRefundsOnceAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	oldBudget := finalCandidateFirstByteBudget
	finalCandidateFirstByteBudget = 500 * time.Millisecond
	t.Cleanup(func() { finalCandidateFirstByteBudget = oldBudget })
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", route, stream), func(t *testing.T) {
				gateway, auth, options, refunds := errorTestGateway(t, false, false)
				attempts := 0
				provider := streamingProviderFunc(func(_ context.Context, _ io.Writer, option llm.InvokeOptions) error {
					attempts++
					if option.EndpointID != "first" {
						t.Errorf("unauthorized route: %+v", option)
					}
					return &upstreamerror.Error{Status: 504, Body: `{"error":{"message":"upstream timed out"}}`}
				})
				var out bytes.Buffer
				serveErrorTestRoute(t.Context(), route, stream, &out, provider, gateway, auth, options)
				if attempts != 1 || *refunds != 1 || !strings.Contains(out.String(), "HTTP/1.1 504") {
					t.Fatalf("attempts=%d refunds=%d response=%s", attempts, *refunds, out.String())
				}
			})
		}
	}
}
