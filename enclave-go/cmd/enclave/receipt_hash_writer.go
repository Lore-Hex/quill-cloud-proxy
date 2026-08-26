package main

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"
)

const maxReceiptSSEEventBytes = 16 << 20

type receiptHashWriter struct {
	w       io.Writer
	domain  string
	hash    hash.Hash
	pending []byte
	events  int
	sealed  bool
	valid   bool
	err     error
}

func newReceiptHashWriter(w io.Writer, domain string) *receiptHashWriter {
	return &receiptHashWriter{w: w, domain: domain, hash: sha256.New(), valid: true}
}

func (w *receiptHashWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.sealed {
		return w.w.Write(p)
	}
	w.pending = append(w.pending, p...)
	if len(w.pending) > maxReceiptSSEEventBytes {
		w.valid = false
		n, err := w.w.Write(w.pending)
		w.pending = nil
		if err != nil {
			w.err = err
			return 0, err
		}
		if n == 0 && len(p) > 0 {
			w.err = io.ErrShortWrite
			return 0, w.err
		}
		w.sealed = true
		return len(p), nil
	}
	for {
		event, rest, ok := nextSSEEvent(w.pending)
		if !ok {
			break
		}
		w.pending = rest
		w.observeEvent(event)
		if _, err := w.w.Write(event); err != nil {
			w.err = err
			return 0, err
		}
	}
	return len(p), nil
}

func (w *receiptHashWriter) observeEvent(raw []byte) {
	name, payload, done, ok := receiptSSEEvent(raw)
	if !ok {
		w.valid = false
		return
	}
	if done {
		return
	}
	switch w.domain {
	case "sse-data-v1":
		if len(name) != 0 {
			w.valid = false
			return
		}
	case "sse-events-v1":
		_, _ = w.hash.Write(name)
		_, _ = w.hash.Write([]byte{'\n'})
	default:
		w.valid = false
		return
	}
	_, _ = w.hash.Write(payload)
	_, _ = w.hash.Write([]byte{'\n'})
	w.events++
}

func receiptSSEEvent(raw []byte) (name, payload []byte, done, ok bool) {
	body := bytes.TrimSuffix(raw, []byte("\n\n"))
	body = bytes.TrimSuffix(body, []byte("\r\n\r\n"))
	lines := bytes.Split(body, []byte{'\n'})
	dataSeen := false
	eventSeen := false
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		switch {
		case bytes.HasPrefix(line, []byte("data:")):
			if dataSeen {
				return nil, nil, false, false
			}
			dataSeen = true
			payload = line[len("data:"):]
			if len(payload) > 0 && payload[0] == ' ' {
				payload = payload[1:]
			}
		case bytes.HasPrefix(line, []byte("event:")):
			if eventSeen {
				return nil, nil, false, false
			}
			eventSeen = true
			name = line[len("event:"):]
			if len(name) > 0 && name[0] == ' ' {
				name = name[1:]
			}
		default:
			return nil, nil, false, false
		}
	}
	if !dataSeen || bytes.IndexByte(payload, '\n') >= 0 || bytes.IndexByte(name, '\n') >= 0 {
		return nil, nil, false, false
	}
	return name, payload, bytes.Equal(payload, []byte("[DONE]")), true
}

func (w *receiptHashWriter) Seal() ([32]byte, int) {
	if !w.sealed {
		w.sealed = true
		if len(w.pending) > 0 {
			w.valid = false
			if _, err := w.w.Write(w.pending); err != nil {
				w.err = err
			}
			w.pending = nil
		}
	}
	var digest [32]byte
	copy(digest[:], w.hash.Sum(nil))
	return digest, w.events
}

func (w *receiptHashWriter) Valid() bool {
	return w.valid && w.err == nil && w.sealed
}
