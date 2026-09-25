package privatemode

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Supervise restarts a crashed proxy with bounded backoff, independently of
// other providers. Listener readiness is not evidence of remote attestation:
// the vendor proxy must verify the pinned workload before each key release.
func Supervise(ctx context.Context, publish func(*http.Client)) {
	supervise(ctx, publish, startProcess, time.Second, time.Minute)
}

func supervise(ctx context.Context, publish func(*http.Client), start func(context.Context) (*http.Client, <-chan struct{}, error), initial, maximum time.Duration) {
	delay := initial
	defer publish(nil)
	for ctx.Err() == nil {
		publish(nil)
		started := time.Now()
		client, done, err := start(ctx)
		if err == nil {
			publish(client)
			select {
			case <-ctx.Done():
				return
			case <-done:
			}
			publish(nil)
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= maximum {
			delay = initial
		}
		fmt.Fprintf(os.Stderr, "privatemode.proxy_restart delay_ms=%d\n", delay.Milliseconds())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, maximum)
	}
}
