package llm

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
)

func TestProviderEgressCoversCompiledEndpoints(t *testing.T) {
	for _, spec := range directproviders.All() {
		u, _ := url.Parse(spec.BaseURL)
		want := spec.Provider != "privatemode" && spec.Provider != "maple"
		if approvedProviderURL(u) != want {
			t.Errorf("provider %s: allowed=%v, want %v", spec.Provider, !want, want)
		}
	}
	// Every literal returned by the legacy endpoint switch must be reviewed in
	// the policy. New adapters cannot silently ship an unreachable destination.
	f, err := parser.ParseFile(token.NewFileSet(), "byok.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "directBaseURL" {
			continue
		}
		ast.Inspect(fn, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, _ := strconv.Unquote(lit.Value)
			if strings.HasPrefix(value, "https://") {
				u, _ := url.Parse(value)
				if !approvedProviderURL(u) {
					t.Errorf("compiled endpoint is missing from allowlist: %s", value)
				}
				count++
			}
			return true
		})
	}
	if count < 40 {
		t.Fatalf("endpoint coverage unexpectedly small: %d", count)
	}
	for host := range providerEgressHosts {
		if host != strings.ToLower(host) || strings.ContainsAny(host, "*:/@ ") || net.ParseIP(host) != nil {
			t.Errorf("non-exact hostname in policy: %q", host)
		}
	}
}

func TestDefaultProviderClientAlwaysEnforcesPolicy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client := NewProviderHTTPClient()
	defer client.CloseIdleConnections()
	if _, ok := client.Transport.(*providerEgressTransport); !ok {
		t.Fatalf("production client has unguarded transport %T", client.Transport)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://unreviewed.example/v1", strings.NewReader("prompt"))
	if _, err := client.Do(req); !errors.Is(err, errProviderEgress) {
		t.Fatalf("production client did not refuse before I/O: %v", err)
	}
}

func TestProviderEgressRejectsBeforeTransport(t *testing.T) {
	for _, raw := range []string{
		"https://attacker.example/v1?secret=do-not-log", "http://api.openai.com/v1",
		"https://api.openai.com.attacker.example/v1", "https://attacker.api.openai.com/v1",
		"https://api.openai.com:8443/v1", "https://api.openai.com./v1",
		"https://api.openai.com:/v1", "https://user:pass@api.openai.com/v1",
		"https://127.0.0.1/v1", "https://169.254.169.254/computeMetadata/v1/",
		"https://[::1]/v1", "https://other.cloud.databricks.com/serving-endpoints",
		"https://unreviewed-aiplatform.googleapis.com/v1", "https://api.privatemode.ai/v1",
		"https://enclave.trymaple.ai/v1", "https://api.openai.com/v1#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			called := false
			guard := &providerEgressTransport{base: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
				called = true
				return nil, errors.New("unexpected dial")
			})}
			req, err := http.NewRequest(http.MethodPost, raw, strings.NewReader("private prompt"))
			if err != nil {
				t.Fatal(err)
			}
			// NewRequest canonicalizes an empty port. Exercise the transport's
			// own validation too, including requests built by adapters manually.
			req.URL, err = url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = guard.RoundTrip(req)
			if !errors.Is(err, errProviderEgress) || called || strings.Contains(err.Error(), "secret") {
				t.Fatalf("called=%v error=%v", called, err)
			}
		})
	}
}

func TestProviderEgressAllowsReviewedHTTPSAndRejectsHostOverride(t *testing.T) {
	called := 0
	guard := &providerEgressTransport{base: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called++
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}
	for host := range providerEgressHosts {
		req, _ := http.NewRequest(http.MethodPost, "https://"+host+"/v1", strings.NewReader("prompt"))
		req.Header.Set("Authorization", "Bearer test")
		resp, err := guard.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
	}
	if called != len(providerEgressHosts) {
		t.Fatal("not all approved endpoints reached transport")
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1", nil)
	req.Host = "attacker.example"
	if _, err := guard.RoundTrip(req); !errors.Is(err, errProviderEgress) {
		t.Fatalf("Host override accepted: %v", err)
	}
}

func TestProviderEgressRefusesRedirectEvenToApprovedHost(t *testing.T) {
	for _, override := range []bool{false, true} {
		calls := 0
		client := lockProviderHTTPClient(&http.Client{Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://api.anthropic.com/receive"}}, Body: http.NoBody, Request: req}, nil
		})})
		if override {
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
		}
		req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1", strings.NewReader("prompt"))
		req.Header.Set("X-Api-Key", "test")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if calls != 1 || (override && !errors.Is(err, errProviderEgress)) || (!override && err != nil) {
			t.Fatalf("override=%v calls=%d err=%v", override, calls, err)
		}
	}
}

func TestProviderEgressMetadataExceptionIsNarrow(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodPost },
		func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("prompt")) },
		func(r *http.Request) { r.URL.Path = "/computeMetadata/v1/instance/attributes/" },
		func(r *http.Request) { r.URL.RawQuery = "x=prompt" },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") },
		func(r *http.Request) { r.Header.Set("X-Prompt", "secret") },
		func(r *http.Request) { r.Header.Del("Metadata-Flavor") },
	} {
		r, _ := http.NewRequest(http.MethodGet, providerMetadataTokenURL, nil)
		r.Header.Set("Metadata-Flavor", "Google")
		if !approvedMetadataRequest(r) {
			t.Fatal("legitimate token request rejected")
		}
		mutate(r)
		if approvedMetadataRequest(r) {
			t.Fatal("overbroad metadata exception")
		}
	}
}

type providerResolver struct {
	ips   []netip.Addr
	calls int
}

func (r *providerResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return r.ips, nil
}

func TestProviderDialRejectsDNSRebindingAndUnknownHosts(t *testing.T) {
	for _, bad := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "100.100.100.200", "168.63.129.16", "::1", "::ffff:127.0.0.1", "2001:db8::1"} {
		resolver := &providerResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(bad)}}
		calls := 0
		_, err := providerDialWith(context.Background(), "tcp", "api.openai.com:443", resolver, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil })
		if !errors.Is(err, errProviderEgress) || calls != 0 {
			t.Fatalf("%s: calls=%d err=%v", bad, calls, err)
		}
	}
	for _, address := range []string{"attacker.example:443", "api.openai.com:80", "api.openai.com:8443", "127.0.0.1:443", "metadata.google.internal:443"} {
		resolver := &providerResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
		_, err := providerDialWith(context.Background(), "tcp", address, resolver, func(context.Context, string, string) (net.Conn, error) { t.Fatal("unexpected dial"); return nil, nil })
		if !errors.Is(err, errProviderEgress) || resolver.calls != 0 {
			t.Fatalf("%s: resolved=%d err=%v", address, resolver.calls, err)
		}
	}
}

func TestProviderDialPinsVettedIP(t *testing.T) {
	resolver := &providerResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	_, err := providerDialWith(context.Background(), "tcp", "api.openai.com:443", resolver, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Fatalf("unvetted dial %s %s", network, address)
		}
		return nil, nil
	})
	if err != nil || resolver.calls != 1 {
		t.Fatalf("resolve count=%d error=%v", resolver.calls, err)
	}
}

func TestPinnedProviderRequestCannotDowngradeOrChangeDestination(t *testing.T) {
	for _, raw := range []string{"http://inference.tinfoil.sh/v1", "https://inference.tinfoil.sh:8443/v1", "https://api.openai.com/v1"} {
		req, _ := http.NewRequest(http.MethodPost, raw, nil)
		if approvedPinnedProviderRequest(req, "inference.tinfoil.sh") {
			t.Fatalf("accepted %s", raw)
		}
		// The real attested transport must reject before even asking its
		// verifier for evidence, not just at a helper validation call.
		if _, err := (&attestedRoundTripper{}).RoundTrip(req); !errors.Is(err, errProviderEgress) {
			t.Fatalf("attested transport accepted %s: %v", raw, err)
		}
	}
}

func TestArtifactTransportCannotSendPromptsOrCredentials(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodPost },
		func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("prompt")) },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") },
		func(r *http.Request) { r.Header.Set("X-Api-Key", "secret") },
		func(r *http.Request) { r.Header.Set("Cookie", "session") },
		func(r *http.Request) { r.URL.Host = "other.example" },
		func(r *http.Request) { r.URL.Scheme = "http" },
	} {
		calls := 0
		guard := &artifactReadOnlyTransport{host: "cdn.example", base: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		})}
		req, _ := http.NewRequest(http.MethodGet, "https://cdn.example/result.mp4?signature=test", nil)
		resp, err := guard.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		mutate(req)
		if _, err := guard.RoundTrip(req); !errors.Is(err, errProviderEgress) || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	}
}
