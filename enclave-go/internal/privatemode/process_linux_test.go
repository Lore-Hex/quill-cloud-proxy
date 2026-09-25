//go:build linux

package privatemode

import (
	"io"
	"testing"
)

func TestTLSPrivateKeyMemfdCannotBeMutated(t *testing.T) {
	f, err := sealedFile([]byte("synthetic-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("replacement"), 0); err == nil {
		t.Fatal("memfd is writable")
	}
	if err := f.Truncate(0); err == nil {
		t.Fatal("memfd can be truncated")
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "synthetic-private-key" {
		t.Fatal("sealed bytes changed")
	}
}
