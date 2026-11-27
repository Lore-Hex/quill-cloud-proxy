package llm

import (
	"errors"
	"net/http"
	"testing"
)

func TestTinfoilBYOKUsesVerifiedTransportWithoutOrdinaryFallback(t *testing.T) {
	want := &http.Client{}
	got, err := byokTransport("tinfoil", func() (*http.Client, error) { return want, nil })
	if err != nil || got != want {
		t.Fatal("verified client not used")
	}
	refuse := errors.New("verification refused")
	got, err = byokTransport("tinfoil", func() (*http.Client, error) { return nil, refuse })
	if got != nil || !errors.Is(err, refuse) {
		t.Fatal("failed verification did not fail closed")
	}
}
