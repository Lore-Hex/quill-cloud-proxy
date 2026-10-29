// Package maple supervises the measured Transport V2 helper. It never falls
// back to bearer-only HTTPS or trusts a caller-supplied backend or measurement.
package maple

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	Model         = "deepseek-v4-1-flash-1017-uncensored"
	requestLimit  = 16 * 1024 * 1024
	responseLimit = 64 * 1024 * 1024
	lineLimit     = 1024 * 1024
	concurrency   = 32
	childUID      = 65200
)

var slots = make(chan uint32, concurrency)

func init() {
	for i := range uint32(concurrency) {
		slots <- childUID + i
	}
}

type process struct {
	stdout io.ReadCloser
	wait   func() error
}

type processStarter func(context.Context, []byte, uint32) (process, error)

// Start accepts a server-authorized opaque workspace scope, never a request
// field. Empty scopes get fresh roots and cannot share a provider prompt cache.
// The caller must close the body, including on cancellation or translation error.
func Start(ctx context.Context, key, scope string, body []byte) (int, io.ReadCloser, error) {
	return start(ctx, key, scope, body, startProcess)
}

func start(ctx context.Context, key, scope string, body []byte, launch processStarter) (int, io.ReadCloser, error) {
	input, err := encodeInput(key, scope, body)
	if err != nil {
		return 0, nil, err
	}
	defer clear(input)
	var uid uint32
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case uid = <-slots:
	default:
		return 0, nil, errors.New("maple: encrypted adapter capacity exhausted")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	p, err := launch(ctx, input, uid)
	if err != nil {
		cancel()
		slots <- uid
		return 0, nil, errors.New("maple: encrypted adapter unavailable")
	}
	var once sync.Once
	var waitErr error
	wait := func() error {
		once.Do(func() {
			waitErr = p.wait()
			cancel()
			_ = p.stdout.Close()
			slots <- uid
		})
		return waitErr
	}
	// Start-time budget includes attestation and encrypted response headers.
	startTimer := time.AfterFunc(125*time.Second, cancel)
	reader := bufio.NewReaderSize(p.stdout, lineLimit)
	statusLine, err := reader.ReadSlice('\n')
	startTimer.Stop()
	var header struct {
		Status int `json:"status"`
	}
	if err != nil || len(statusLine) > 64 || json.Unmarshal(statusLine, &header) != nil ||
		(header.Status != 200 && (header.Status < 400 || header.Status > 599)) {
		cancel()
		_ = wait()
		return 0, nil, errors.New("maple: invalid encrypted adapter status")
	}
	if header.Status != 200 {
		if err := finishProcess(reader, wait); err != nil {
			cancel()
			_ = wait()
			return 0, nil, err
		}
		return header.Status, io.NopCloser(strings.NewReader("")), nil
	}
	r, w := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := relay(reader, w, wait)
		cancel()
		_ = wait()
		_ = w.CloseWithError(err)
	}()
	return 200, &responseBody{PipeReader: r, cancel: cancel, done: done}, nil
}

func encodeInput(key, scope string, body []byte) ([]byte, error) {
	if strings.TrimSpace(key) == "" || len(key) > 8192 || len(body) > requestLimit {
		return nil, errors.New("maple: invalid managed request")
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return nil, errors.New("maple: invalid request body")
	}
	var model string
	var stream bool
	if json.Unmarshal(request["model"], &model) != nil || model != Model ||
		json.Unmarshal(request["stream"], &stream) != nil || !stream {
		return nil, errors.New("maple: model or transport is not release-pinned")
	}
	var root [32]byte
	if scope = strings.TrimSpace(scope); scope != "" {
		root = sha256.Sum256([]byte("maple-cache-v1\x00" + scope))
	} else if _, err := rand.Read(root[:]); err != nil {
		return nil, errors.New("maple: cannot isolate prompt cache")
	}
	defer clear(root[:])
	encoded, err := json.Marshal(struct {
		Key  string          `json:"api_key"`
		Root string          `json:"cache_root"`
		Body json.RawMessage `json:"body"`
	}{key, base64.StdEncoding.EncodeToString(root[:]), body})
	if err != nil || len(encoded) > requestLimit {
		clear(encoded)
		return nil, errors.New("maple: request exceeds adapter limit")
	}
	return encoded, nil
}

type responseBody struct {
	*io.PipeReader
	cancel context.CancelFunc
	done   <-chan struct{}
}

func (b *responseBody) Close() error {
	b.cancel()
	err := b.PipeReader.Close()
	<-b.done
	return err
}

// The Rust helper only emits DONE after authenticated encrypted EOF. Hold it
// again until successful helper exit so a crash cannot become a successful bill.
func relay(reader *bufio.Reader, out io.Writer, wait func() error) error {
	total := 0
	for {
		line, err := reader.ReadSlice('\n')
		total += len(line)
		if err != nil || total > responseLimit || len(line) > lineLimit {
			return errors.New("maple: encrypted stream incomplete or exceeds limit")
		}
		if bytes.Equal(line, []byte("data: [DONE]\n")) {
			if err := finishProcess(reader, wait); err != nil {
				return err
			}
			_, err := io.WriteString(out, "data: [DONE]\n\n")
			return err
		}
		if _, err := out.Write(line); err != nil {
			return errors.New("maple: consumer closed")
		}
	}
}

func finishProcess(reader io.Reader, wait func() error) error {
	tail, err := io.ReadAll(io.LimitReader(reader, 65))
	if err != nil || len(tail) > 64 || len(bytes.TrimSpace(tail)) != 0 {
		return errors.New("maple: unexpected adapter response tail")
	}
	if wait() != nil {
		return errors.New("maple: encrypted adapter failed")
	}
	return nil
}
