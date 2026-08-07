package enclavetls

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestProvider(t *testing.T, handler http.HandlerFunc) (*CloudDNSProvider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &CloudDNSProvider{
		Project:     "quill-cloud-proxy",
		ManagedZone: "trustedrouter-com",
		HTTPClient:  srv.Client(),
		AccessToken: func(context.Context) (string, error) { return "test-token", nil },
	}, srv
}

// The provider posts to the real Cloud DNS URL shape; point it at the test
// server by overriding the base through the client's transport.
func redirect(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		u := *r.URL
		u.Scheme, u.Host = "http", strings.TrimPrefix(srv.URL, "http://")
		r2 := r.Clone(r.Context())
		r2.URL = &u
		return srv.Client().Transport.RoundTrip(r2)
	})}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChallengeRecordIsQuotedAndFullyQualified(t *testing.T) {
	// TWO failures that both look like "propagation is slow" and never
	// converge:
	//
	//   unquoted rrdata — Cloud DNS accepts the write and serves the value
	//   with quotes ADDED, so the resolver returns something the CA cannot
	//   match against the challenge token.
	//
	//   no trailing dot — the API treats the name as RELATIVE and appends the
	//   zone suffix, so the TXT lands at a name the CA never queries.
	var got cloudDNSChange
	p, srv := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	p.HTTPClient = redirect(t, srv)

	if _, err := p.AddTXT(context.Background(),
		"_acme-challenge.api-azure.trustedrouter.com", "tok3n-value"); err != nil {
		t.Fatalf("AddTXT: %v", err)
	}

	if len(got.Additions) != 1 {
		t.Fatalf("expected one addition, got %+v", got)
	}
	add := got.Additions[0]
	if !strings.HasSuffix(add.Name, ".") {
		t.Errorf("name is not fully qualified: %q", add.Name)
	}
	if add.Type != "TXT" {
		t.Errorf("type = %q", add.Type)
	}
	if len(add.Rrdatas) != 1 || add.Rrdatas[0] != `"tok3n-value"` {
		t.Errorf("rrdata must be a QUOTED string, got %q", add.Rrdatas)
	}
}

func TestCleanupDeletesTheExactRecordThatWasCreated(t *testing.T) {
	// Cloud DNS deletes by VALUE, not by id: the deletion body must reproduce
	// the record set exactly. A cleanup that misses leaves a stale TXT, and a
	// stale TXT is the documented cause of the CA refusing the NEXT order for
	// the same name — i.e. the failure lands on a future renewal, far from
	// this code.
	var changes []cloudDNSChange
	p, srv := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		var c cloudDNSChange
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &c)
		changes = append(changes, c)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	p.HTTPClient = redirect(t, srv)
	ctx := context.Background()

	handle, err := p.AddTXT(ctx, "_acme-challenge.api.trustedrouter.com", "abc")
	if err != nil {
		t.Fatalf("AddTXT: %v", err)
	}
	if err := p.RemoveTXT(ctx, handle); err != nil {
		t.Fatalf("RemoveTXT: %v", err)
	}

	if len(changes) != 2 {
		t.Fatalf("expected add then delete, got %d calls", len(changes))
	}
	added, deleted := changes[0].Additions, changes[1].Deletions
	if len(deleted) != 1 {
		t.Fatalf("delete carried no record set: %+v", changes[1])
	}
	if deleted[0].Name != added[0].Name ||
		deleted[0].Rrdatas[0] != added[0].Rrdatas[0] ||
		deleted[0].TTL != added[0].TTL {
		t.Fatalf("deletion does not reproduce the addition:\n add=%+v\n del=%+v", added[0], deleted[0])
	}
}

func TestAnAPIRejectionIsSurfacedWithItsBody(t *testing.T) {
	// A 403 here means the service account lacks dns.admin on the zone, and
	// that is the single most likely misconfiguration. Swallowing the body
	// would leave an operator with "renewal failed" and nothing to act on.
	p, srv := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"Forbidden: dns.changes.create"}}`))
	})
	p.HTTPClient = redirect(t, srv)

	_, err := p.AddTXT(context.Background(), "_acme-challenge.x.trustedrouter.com", "v")
	if err == nil {
		t.Fatal("a 403 was treated as success")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "dns.changes.create") {
		t.Errorf("error should carry status and body: %v", err)
	}
}

func TestMissingConfigurationIsRefusedBeforeAnyCall(t *testing.T) {
	called := false
	p, srv := newTestProvider(t, func(http.ResponseWriter, *http.Request) { called = true })
	p.HTTPClient = redirect(t, srv)
	p.ManagedZone = ""

	if _, err := p.AddTXT(context.Background(), "_acme-challenge.x.trustedrouter.com", "v"); err == nil {
		t.Fatal("empty managed zone accepted")
	}
	if called {
		t.Error("made an API call despite incomplete configuration")
	}
}

// --------------------------------------------------------------------------
// The wildcard rule, and the provider seam
// --------------------------------------------------------------------------

func TestWildcardChallengeStripsTheAsteriskLabel(t *testing.T) {
	// For "*.example.com" the CA looks at _acme-challenge.EXAMPLE.COM. Publishing
	// _acme-challenge.*.example.com creates a record with a literal asterisk
	// label that is never queried, so validation times out while the record sits
	// in the zone looking correct — the worst kind of wrong.
	got := challengeRecordName("*.trustedrouter.com")
	if got != "_acme-challenge.trustedrouter.com" {
		t.Fatalf("wildcard challenge name = %q", got)
	}
}

func TestNonWildcardChallengeKeepsTheFullName(t *testing.T) {
	got := challengeRecordName("api-azure.trustedrouter.com")
	if got != "_acme-challenge.api-azure.trustedrouter.com" {
		t.Fatalf("challenge name = %q", got)
	}
}

func TestConfigWithoutAProviderStillUsesCloudflare(t *testing.T) {
	// Every deployment that predates this seam passes no Provider, and must keep
	// behaving exactly as it did.
	if name := (DNS01Config{}).provider().Name(); name != "cloudflare" {
		t.Fatalf("default provider = %q, want cloudflare", name)
	}
}

func TestAConfiguredProviderIsUsed(t *testing.T) {
	p := &CloudDNSProvider{}
	if name := (DNS01Config{Provider: p}).provider().Name(); name != "clouddns" {
		t.Fatalf("provider = %q, want clouddns", name)
	}
}

func TestCloudDNSProviderRequestsTheDNSScopeNotStorage(t *testing.T) {
	// A token minted for the storage scope fails against the DNS API with a 403
	// that names neither the scope nor the caller.
	p := NewCloudDNSProvider("proj", "zone", nil)
	if p.AccessToken == nil {
		t.Fatal("no token source wired")
	}
	if cloudDNSScope == gcsScope {
		t.Fatal("DNS and storage scopes must differ")
	}
	if cloudDNSScope != "https://www.googleapis.com/auth/ndev.clouddns.readwrite" {
		t.Fatalf("unexpected DNS scope %q", cloudDNSScope)
	}
}

func TestTokenSourceDefaultsToStorageScope(t *testing.T) {
	// The GCS cache constructs its source without a scope and must keep getting
	// the storage one.
	if (&gcpTokenSource{}).requestedScope() != gcsScope {
		t.Fatal("default scope changed")
	}
	if (&gcpTokenSource{scope: cloudDNSScope}).requestedScope() != cloudDNSScope {
		t.Fatal("explicit scope ignored")
	}
}
