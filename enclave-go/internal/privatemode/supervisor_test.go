package privatemode

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestSupervisorClearsDeadClientAndRestarts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := &http.Client{}
	attempts, published := 0, 0
	var current *http.Client
	supervise(ctx, func(c *http.Client) {
		current = c
		if c != nil {
			published++
		}
	},
		func(context.Context) (*http.Client, <-chan struct{}, error) {
			if current != nil {
				t.Fatal("dead proxy remains available")
			}
			attempts++
			if attempts == 1 {
				return nil, nil, errors.New("synthetic startup failure")
			}
			if attempts == 3 {
				cancel()
				return nil, nil, ctx.Err()
			}
			done := make(chan struct{})
			close(done)
			return client, done, nil
		}, time.Millisecond, 4*time.Millisecond)
	if current != nil || published != 1 || attempts != 3 {
		t.Fatalf("current=%p published=%d attempts=%d", current, published, attempts)
	}
}
