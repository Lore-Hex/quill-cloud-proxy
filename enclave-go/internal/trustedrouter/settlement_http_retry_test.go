package trustedrouter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSettleRetriesTransientHTTPFailuresOnOriginalAuthority(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var bodies []string
			client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "trustedrouter.com" || r.URL.Path != "/internal/gateway/settle" {
					t.Fatalf("settlement moved authority: %s", r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, string(body))
				if len(bodies) == 1 {
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
				}
				return settlementResponse(http.StatusOK), nil
			})})
			client.baseURLs = append(client.baseURLs, "https://other-billing.example")
			auth := &Authorization{AuthorizationID: "auth_once", Model: "model"}
			auth.pinControlPlaneEndpoint(0)
			result, err := client.Settle(context.Background(), auth, Usage{RequestID: "request_once", InputTokens: 3, OutputTokens: 4})
			if err != nil || result == nil || result.GenerationID != "gen_once" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if len(bodies) != 2 || bodies[0] != bodies[1] {
				t.Fatalf("settlement changed: %v", bodies)
			}
		})
	}
}

func TestSettleHTTPRetryAfterCommitDoesNotChargeTwice(t *testing.T) {
	var requests, commits atomic.Int32
	var originalBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if requests.Add(1) == 1 {
			originalBody = string(body)
			commits.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if string(body) != originalBody {
			commits.Add(1)
			t.Error("replay changed the committed settlement body")
		}
		_, _ = io.WriteString(w, `{"data":{"already_settled":true,"settled":true,"finalization_outcome":"settled","generation_id":"gen_once","cost_microdollars":7}}`)
	}))
	t.Cleanup(server.Close)
	result, err := New(server.URL, "internal", server.Client()).Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{InputTokens: 3, OutputTokens: 4})
	if err != nil || result == nil || !result.AlreadySettled || result.CostMicrodollars != 7 || requests.Load() != 2 || commits.Load() != 1 {
		t.Fatalf("result=%+v err=%v requests=%d commits=%d", result, err, requests.Load(), commits.Load())
	}
}

func TestSettleHTTPFailureWithoutPinnedAuthorityIsNotReplayed(t *testing.T) {
	var attempts int
	client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(*http.Request) (*http.Response, error) {
		attempts++
		return settlementResponse(http.StatusInternalServerError), nil
	})})
	client.baseURLs = append(client.baseURLs, "https://other-billing.example")
	_, err := client.Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{})
	if err == nil || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}
