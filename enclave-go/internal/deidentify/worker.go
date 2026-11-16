// Package deidentify runs Rampart inside the enclave, before provider admission.
package deidentify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"time"
)

var ErrUnavailable = errors.New("de-identification unavailable; request not sent to provider")
var ErrUnsupported = errors.New("request shape is not supported with deidentify enabled")

type Result struct {
	Texts        []string          `json:"texts"`
	Replacements map[string]string `json:"replacements"`
}

type Runner interface {
	Protect(context.Context, []string) (Result, error)
}

// Processes are lazy, bounded, and short-lived. They receive no gateway secrets
// in their environment and leave no conversation table in a reusable worker.
type Worker struct {
	Node, Script string
	slots        chan struct{}
}

func NewWorker(node, script string) *Worker {
	return &Worker{Node: node, Script: script, slots: make(chan struct{}, 2)}
}

func (w *Worker) Protect(ctx context.Context, texts []string) (Result, error) {
	select {
	case w.slots <- struct{}{}:
		defer func() { <-w.slots }()
	default:
		return Result{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	input, err := json.Marshal(struct {
		Texts []string `json:"texts"`
	}{texts})
	if err != nil || len(input) > 1<<20 {
		return Result{}, ErrUnsupported
	}
	// Paths are fixed by the gateway (or local tests), never request fields;
	// all untrusted text travels over stdin, without a shell.
	cmd := exec.CommandContext(ctx, w.Node, "--max-old-space-size=256", w.Script) // #nosec G204
	cmd.Env = []string{"OMP_NUM_THREADS=1", "OPENBLAS_NUM_THREADS=1"}
	cmd.Stdin = bytes.NewReader(input)
	var output boundedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return Result{}, ErrUnavailable
	}
	var result Result
	if json.Unmarshal(output.Bytes(), &result) != nil || len(result.Texts) != len(texts) {
		return Result{}, ErrUnavailable
	}
	for token, value := range result.Replacements {
		if !validToken(token) || value == "" {
			return Result{}, ErrUnavailable
		}
	}
	return result, nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
