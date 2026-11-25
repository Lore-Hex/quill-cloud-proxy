package privatemode

import (
	"net/http"
	"testing"
)

func TestRerankTransportUnsupported(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://"+proxyAuthority+"/v1/rerank", nil)
	if _, err := (restrictedTransport{}).RoundTrip(request); err == nil {
		t.Fatal("rerank must remain outside encrypted transport")
	}
}
