package upstreamerror

import (
	"strings"
	"testing"
)

func TestSplitErrorStatePreservesScalarFragmentsAndSignificantTail(t *testing.T) {
	for _, scalar := range []string{`"error"`, `123`, `true`, `false`, `null`} {
		t.Run(scalar, func(t *testing.T) {
			tail := "{"
			if err := CheckLine(scalar, &tail); err != nil || !strings.Contains(tail, "{") || !strings.HasSuffix(tail, scalar) {
				t.Fatalf("scalar fragment lost: tail=%q err=%v", tail, err)
			}
		})
	}
	tail := ""
	if err := CheckLine(`{"error"`+strings.Repeat(" ", 100), &tail); err != nil {
		t.Fatal(err)
	}
	if err := CheckLine(`:{"message":"refused"}}`, &tail); err == nil {
		t.Fatal("whitespace erased split error key")
	}
	for _, chunk := range []string{`{}`, `[]`} {
		tail = `{"error"`
		if err := CheckLine(chunk, &tail); err != nil || tail != "" {
			t.Fatalf("complete container did not reset state: %q %v", tail, err)
		}
		if err := CheckLine(`:{"message":"refused"}}`, &tail); err != nil {
			t.Fatalf("healthy container bridged malformed fragments: %v", err)
		}
	}
}
