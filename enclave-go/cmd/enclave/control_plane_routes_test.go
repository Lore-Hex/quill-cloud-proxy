package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeOneControlPlaneDiscovery(t *testing.T) {
	for _, origin := range []struct{ name, host, sni string }{
		{"ordinary", "api.trustedrouter.com", ""},
		{"confidential host", "api.confidential.trustedrouter.com", ""},
		{"confidential SNI", "api.trustedrouter.com", "api.confidential.trustedrouter.com"},
	} {
		for _, root := range []string{"keys", "credits", "activity", "workspaces", "organization", "billing", "byok", "custom-models", "broadcast", "auth", "signup", "generation"} {
			for _, target := range []struct{ method, suffix string }{
				{"GET", ""},
				{"POST", "/"},
				{"PATCH", "/private-path-id?api_key=private-query-key"},
				{"DELETE", "/private-path-id/nested"},
			} {
				for _, bearer := range []string{"", "private-bearer"} {
					t.Run(fmt.Sprintf("%s/%s/%s/bearer=%t", origin.name, root, target.method, bearer != ""), func(t *testing.T) {
						header := ""
						if bearer != "" {
							header = "Authorization: Bearer " + bearer + "\r\n"
						}
						raw := fmt.Sprintf("%s /v1/%s%s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", target.method, root, target.suffix, origin.host, header)
						conn := &confidentialSNIConn{newScriptedConn(raw, nil), origin.sni}
						gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
							// Preserve the existing post-error audit lookup, but no
							// control-plane work may precede the discovery response.
							if r.URL.Path != "/internal/gateway/validate" || !strings.Contains(conn.writes.String(), "404 Not Found") {
								t.Fatalf("unexpected control-plane call: %s", r.URL.Path)
							}
							return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{}}`))}, nil
						})})
						serveOne(t.Context(), conn, auth.New(nil), nil, nil, nil, gateway, nil)
						response, body := readHTTPResponseBody(t, bufio.NewReader(strings.NewReader(conn.writes.String())))
						if response.StatusCode != http.StatusNotFound || response.Header.Get("Location") != "" || response.Header.Get("Content-Type") != "application/json" {
							t.Fatalf("expected JSON 404 without redirect: %s", conn.writes.String())
						}
						var envelope map[string]map[string]any
						if err := json.Unmarshal([]byte(body), &envelope); err != nil {
							t.Fatal(err)
						}
						subject := "Account management"
						if root == "keys" {
							subject = "Key management"
						}
						want := subject + " is served at https://trustedrouter.com/v1/" + root + ", not api.trustedrouter.com"
						errBody := envelope["error"]
						if len(envelope) != 1 || len(errBody) != 3 || errBody["status"] != float64(404) || errBody["source"] != "router" || errBody["message"] != want {
							t.Fatalf("error envelope changed: %s", body)
						}
						if strings.Contains(conn.writes.String(), "private-") {
							t.Fatal("response echoed private request data")
						}
					})
				}
			}
		}
	}
}

func TestControlPlaneDiscoveryLeavesGatewayRoutes(t *testing.T) {
	for _, path := range []string{
		"/health", "/attestation", "/receipt-key", "/receipt-attestation",
		"/v1/key", "/v1/key/", "/v1/models", "/v1/models/openai/gpt-5.5",
		"/v1/chat/completions", "/v1/responses", "/v1/responses/input_tokens", "/v1/messages",
		"/v1/embeddings", "/v1/images/generations", "/v1/videos", "/v1/files", "/v1/batches",
		"/v1/keys-extra", "/v1/creditsXYZ", "/v1/workspaces-extra", "/v1/authorization", "/v1/unknown", "/other/v1/keys",
	} {
		t.Run(path, func(t *testing.T) {
			if message := controlPlaneRouteMessage(path); message != "" {
				t.Fatalf("gateway/unknown route captured: %s", message)
			}
		})
	}
}

func TestServeOneControlPlaneDiscoveryLeavesInferenceAuth(t *testing.T) {
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com"} {
		for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/responses/input_tokens"} {
			for _, bearer := range []string{"", "test-key"} {
				t.Run(fmt.Sprintf("%s%s/bearer=%t", host, path, bearer != ""), func(t *testing.T) {
					// Valid privacy policy passes the confidential guard; the
					// unknown field is rejected by the ordinary inference parser.
					body := `{"provider":{"min_privacy":"confidential"},"unknown_field":true}`
					header := ""
					want := http.StatusUnauthorized
					if bearer != "" {
						header = "Authorization: Bearer " + bearer + "\r\n"
						want = http.StatusBadRequest
					}
					gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						if r.URL.Path != "/internal/gateway/validate" {
							t.Fatalf("unexpected control-plane call: %s", r.URL.Path)
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{}}`))}, nil
					})})
					raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, host, header, len(body), body)
					conn := newScriptedConn(raw, nil)
					serveOne(t.Context(), conn, auth.New(nil), nil, nil, nil, gateway, nil)
					response, responseBody := readHTTPResponseBody(t, bufio.NewReader(strings.NewReader(conn.writes.String())))
					if response.StatusCode != want || strings.Contains(responseBody, "is served at") {
						t.Fatalf("inference handling changed: %d %s", response.StatusCode, responseBody)
					}
				})
			}
		}
	}
}

func TestServeOneControlPlaneDiscoveryLeavesKeyRelay(t *testing.T) {
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com"} {
		for _, bearer := range []string{"", "test-key"} {
			t.Run(fmt.Sprintf("%s/bearer=%t", host, bearer != ""), func(t *testing.T) {
				calls := 0
				const keyInfo = `{"data":{"label":"test","limit_remaining":10}}`
				gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.Path != "/internal/gateway/key" {
						t.Fatalf("key relay changed: %s", r.URL.Path)
					}
					var payload map[string]string
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if len(payload) != 1 || payload["api_key_lookup_hash"] != trustedrouter.LookupHash(bearer) || strings.Contains(r.Header.Get("Authorization"), bearer) {
						t.Fatal("key relay credential handling changed")
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(keyInfo))}, nil
				})})
				header := ""
				if bearer != "" {
					header = "Authorization: Bearer " + bearer + "\r\n"
				}
				conn := newScriptedConn("GET /v1/key HTTP/1.1\r\nHost: "+host+"\r\n"+header+"Connection: close\r\n\r\n", nil)
				serveOne(t.Context(), conn, auth.New(nil), nil, nil, nil, gateway, nil)
				response, body := readHTTPResponseBody(t, bufio.NewReader(strings.NewReader(conn.writes.String())))
				if bearer == "" {
					if response.StatusCode != 401 || calls != 0 {
						t.Fatalf("anonymous key introspection changed: %d calls=%d", response.StatusCode, calls)
					}
				} else if response.StatusCode != 200 || body != keyInfo || calls != 1 {
					t.Fatalf("key introspection changed: %d calls=%d body=%s", response.StatusCode, calls, body)
				}
			})
		}
	}
}
