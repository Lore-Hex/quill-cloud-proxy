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
	// Leading padding in a later fragment must not evict the key either.
	for name, fragments := range map[string][]string{
		"padded colon after type key":   {`{"type"`, strings.Repeat(" ", 80) + `:`, `"error","message":"refused"}`},
		"padded colon after error key":  {`{"error"`, strings.Repeat(" ", 80) + `:`, `{"message":"refused"}}`},
		"padded value after type colon": {`{"type":`, strings.Repeat("\t", 80), strings.Repeat(" ", 80) + `"error"}`},
	} {
		tail = ""
		var err error
		for _, fragment := range fragments {
			if err = CheckLine(fragment, &tail); err != nil {
				break
			}
		}
		if err == nil {
			t.Fatalf("%s: split error report missed", name)
		}
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
