package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// throughDispatch sends one real HTTP request down the same path a customer's
// does (serveOne: parsing, authentication, routing), not to serveDecide
// directly, because which PATHS reach serveDecide is what is under test.
func throughDispatch(t *testing.T, method, path, body string, log *controlPlaneLog) (int, map[string]any) {
	t.Helper()
	controlPlane := fakeDecideControlPlane(t, log, "cerebras")
	return throughDispatchTo(t, controlPlane.URL, controlPlane.Client(), method, path, body)
}

func throughDispatchTo(t *testing.T, controlPlaneURL string, client *http.Client, method, path, body string) (int, map[string]any) {
	t.Helper()
	gateway := trustedrouter.New(controlPlaneURL, "internal-token", client)
	server, peer := net.Pipe()
	defer peer.Close()
	go serveOne(context.Background(), server, auth.New(nil), &scriptedLLM{replies: []string{goodNative}}, nil, nil, gateway, nil)
	if _, err := fmt.Fprintf(peer,
		"%s %s HTTP/1.1\r\nAuthorization: Bearer sk-tr-test-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		method, path, len(body), body); err != nil {
		t.Fatalf("%s %s: write: %v", method, path, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("%s %s: read: %v", method, path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	return resp.StatusCode, payload
}

func aliasBody(booleanSpelling string) string {
	return fmt.Sprintf(`{"model":%q,"state":%q,"questions":{
	  "refund":{"type":%q,"instructions":"Is a refund requested?"},
	  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`,
		decide.TrevModelID, privateState, booleanSpelling)
}

func TestDecideIsServedUnderItsNameAndEveryAlias(t *testing.T) {
	for _, path := range []string{"/api/alpha/decide", "/api/decide", "/v1/decide", "/v1/evaluate", "/api/alpha/decisions", "/api/decisions"} {
		log := &controlPlaneLog{}
		status, payload := throughDispatch(t, "POST", path, aliasBody("boolean"), log)
		answers, _ := payload["answers"].(map[string]any)
		if status != 200 || len(answers) != 2 || payload["model"] != decide.TrevModelID {
			t.Errorf("POST %s: status %d, payload %v", path, status, payload)
			continue
		}
		// The same route, not a look-alike: one decide authorization, one settle.
		if len(log.authorize) != 1 || log.authorize[0]["route_type"] != decideRouteType || len(log.settle) != 1 {
			t.Errorf("POST %s: authorize=%v settle=%d", path, log.authorize, len(log.settle))
		}
	}
}

func TestOnlyTheListedPathsAreTheDecideRoute(t *testing.T) {
	// A near miss must not reach a billed route. Whatever else the gateway does
	// with a path it does not know (it may ask the control plane about the key),
	// it never AUTHORIZES anything for it.
	var mu sync.Mutex
	var asked []string
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		asked = append(asked, request.URL.Path)
		mu.Unlock()
		http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
	}))
	defer controlPlane.Close()
	for _, path := range []string{
		"/v1/decisions", "/api/beta/decide", "/api/beta/decisions", "/api/alpha/decision", "/api/alpha/decisions/",
		"/api/alpha/decide/", "/api/alpha/evaluate", "/api/v1/decide", "/decide",
	} {
		status, payload := throughDispatchTo(t, controlPlane.URL, controlPlane.Client(), "POST", path, aliasBody("boolean"))
		if status == 200 || payload["answers"] != nil {
			t.Errorf("POST %s: status %d payload %v; only the listed paths are the route", path, status, payload)
		}
	}
	// And every path is POST-only. The body is a VALID decision request on
	// purpose: with an empty one, serveDecide itself answers 400 "invalid JSON"
	// before it authorizes anything, so the check passed with the method guard
	// deleted. 404 is the guard's answer and nobody else's.
	for _, path := range []string{"/api/alpha/decide", "/api/decide", "/v1/decide", "/v1/evaluate", "/api/alpha/decisions", "/api/decisions"} {
		for _, method := range []string{"GET", "PUT", "DELETE"} {
			status, payload := throughDispatchTo(t, controlPlane.URL, controlPlane.Client(), method, path, aliasBody("boolean"))
			if status != 404 || payload["answers"] != nil {
				t.Errorf("%s %s: status %d payload %v, want 404", method, path, status, payload)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range asked {
		if strings.Contains(path, "authorize") || strings.Contains(path, "settle") {
			t.Errorf("a request that is not the decide route reached %s", path)
		}
	}
	if isDecidePath("") || isDecidePath("/") {
		t.Error("an empty path is not the decide route")
	}
}

func TestANoulQuestionIsAnsweredAsNoulOnTheNativePath(t *testing.T) {
	// What an OpenRouter or TypeSafe client sends to /api/alpha/decisions.
	backend := &scriptedLLM{replies: []string{goodNative}}
	log := &controlPlaneLog{}
	controlPlane := fakeDecideControlPlane(t, log, "cerebras")
	gateway := trustedrouter.New(controlPlane.URL, "internal-token", controlPlane.Client())
	var out strings.Builder
	serveDecide(context.Background(), &out, backend, []byte(aliasBody("noul")), gateway, true, "sk-tr-test-bearer", nil, "idem-1", requestAttributionHeaders{}, "log-1")
	raw := out.String()
	if !strings.HasPrefix(raw, "HTTP/1.1 200") {
		t.Fatalf("response: %s", raw)
	}
	body := strings.SplitN(raw, "\r\n\r\n", 2)[1]
	var payload struct {
		Answers map[string]json.RawMessage `json:"answers"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	// Exactly TypeSafe's shape, with no "probability" beside it.
	if got := string(payload.Answers["refund"]); got != `{"type":"noul","noul":0.97}` {
		t.Errorf("refund = %s", got)
	}
	if got := string(payload.Answers["route"]); !strings.Contains(got, `"type":"choice"`) {
		t.Errorf("route = %s", got)
	}
	// The MODEL is never shown the word: it is a spelling at this gateway's edge.
	prompt, _ := json.Marshal(backend.requests[0].Messages)
	if strings.Contains(strings.ToLower(string(prompt)), "noul") {
		t.Errorf("the prompt carries the noul spelling: %s", prompt)
	}
}

func TestABooleanQuestionIsStillAnsweredAsBoolean(t *testing.T) {
	backend := &scriptedLLM{replies: []string{goodNative}}
	status, payload := runNativeDecide(t, decide.TrevModelID, "", backend, &controlPlaneLog{})
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	refund, _ := payload["answers"].(map[string]any)["refund"].(map[string]any)
	if refund["type"] != "boolean" || refund["probability"] != 0.97 || refund["noul"] != nil {
		t.Errorf("refund = %v", refund)
	}
}

func TestANoulQuestionReachesAHostedModelAsBooleanAndIsAnsweredAsNoul(t *testing.T) {
	// The hosted backends each have their own spelling (Vercel "boolean",
	// TypeSafe "noul") and translate from the canonical one; a caller's "noul"
	// passed through as-is would be a 400 at Vercel.
	p, choice := 0.93, "billing"
	backend := &fakeDecider{answers: map[string]decide.Answer{
		"refund": {Type: decide.TypeBoolean, Probability: &p},
		"route":  {Type: decide.TypeChoice, Choice: &choice, Probabilities: map[string]float64{"billing": 0.8, "shipping": 0.2}},
	}}
	body := strings.Replace(decideBody, `"type":"boolean"`, `"type":"noul"`, 1)
	if body == decideBody {
		t.Fatal("fixture: decideBody has no boolean question to re-spell")
	}
	status, raw := runDecide(t, backend, body)
	if status != 200 {
		t.Fatalf("status %d: %s", status, raw)
	}
	if backend.seen == nil || backend.seen.Questions["refund"].Type != decide.TypeBoolean {
		t.Fatalf("the hosted backend was sent %+v, want the canonical boolean", backend.seen)
	}
	var payload struct {
		Answers map[string]json.RawMessage `json:"answers"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if got := string(payload.Answers["refund"]); got != `{"type":"noul","noul":0.93}` {
		t.Errorf("refund = %s", got)
	}
}
