package llm

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"
)

type nativeCustomStreamCall struct {
	id, name, itemID string
	digest           hash.Hash
	inputDone        bool
	truncated        bool
}

func newNativeCustomStreamCall(id, name, itemID string) *nativeCustomStreamCall {
	return &nativeCustomStreamCall{id: id, name: name, itemID: itemID, digest: sha256.New()}
}

func (c *nativeCustomStreamCall) writeDelta(w io.Writer, index int, delta string) error {
	_, _ = io.WriteString(c.digest, delta)
	return writeAnthropicToolDelta(w, index+1, delta)
}

// Compare the two terminal snapshots without buffering a second copy of
// the tool input or releasing a mismatched snapshot as a successful call.
func (c *nativeCustomStreamCall) matches(input *string) bool {
	if input == nil {
		return false
	}
	h := sha256.Sum256([]byte(*input))
	return bytes.Equal(c.digest.Sum(nil), h[:])
}
