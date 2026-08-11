package enclavetls

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

// The wire path (runDNS01Order) is production-exercised; the new logic is
// the CA iteration. These tests pin its contract through the orderCA seam:
// order, short-circuit, account-key isolation, and error aggregation.

func withStubOrder(
	t *testing.T,
	stub func(ctx context.Context, cfg DNS01Config, ca DNS01CA) error,
) {
	t.Helper()
	previous := orderCA
	orderCA = stub
	t.Cleanup(func() { orderCA = previous })
}

func TestFallbackCATriedInOrderAfterPrimaryFails(t *testing.T) {
	var tried []string
	withStubOrder(t, func(_ context.Context, _ DNS01Config, ca DNS01CA) error {
		tried = append(tried, ca.DirectoryURL)
		if ca.DirectoryURL == "" {
			return errors.New("LE is down")
		}
		return nil // fallback issues
	})

	cfg := DNS01Config{
		DNSName: "api.trustedrouter.com",
		FallbackCAs: []DNS01CA{{
			DirectoryURL:       "https://dv.acme-v02.api.pki.goog/directory",
			EAB:                &acme.ExternalAccountBinding{KID: "kid", Key: []byte("k")},
			AccountKeyCacheKey: AccountKeyCacheKeyForDirectory("https://dv.acme-v02.api.pki.goog/directory"),
		}},
	}
	if err := runDNS01Orders(context.Background(), cfg); err != nil {
		t.Fatalf("expected fallback to succeed, got %v", err)
	}
	if len(tried) != 2 || tried[0] != "" || tried[1] != "https://dv.acme-v02.api.pki.goog/directory" {
		t.Fatalf("wrong CA order: %v", tried)
	}
}

func TestPrimarySuccessNeverTouchesFallback(t *testing.T) {
	var tried []string
	withStubOrder(t, func(_ context.Context, _ DNS01Config, ca DNS01CA) error {
		tried = append(tried, ca.DirectoryURL)
		return nil
	})

	cfg := DNS01Config{
		DNSName:     "api.trustedrouter.com",
		FallbackCAs: []DNS01CA{{DirectoryURL: "https://fallback.example/directory"}},
	}
	if err := runDNS01Orders(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The fallback CA stays COLD in the normal world — that is the design.
	if len(tried) != 1 {
		t.Fatalf("fallback touched on primary success: %v", tried)
	}
}

func TestAllCAsFailingJoinsEveryError(t *testing.T) {
	withStubOrder(t, func(_ context.Context, _ DNS01Config, ca DNS01CA) error {
		return errors.New("boom:" + ca.DirectoryURL)
	})

	cfg := DNS01Config{
		DNSName:     "api.trustedrouter.com",
		FallbackCAs: []DNS01CA{{DirectoryURL: "https://fallback.example/directory"}},
	}
	err := runDNS01Orders(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when every CA fails")
	}
	// Both failures must be visible: an operator debugging a dual outage
	// needs to see BOTH directories' errors, not just the last one.
	for _, needle := range []string{"letsencrypt-default", "fallback.example"} {
		if !strings.Contains(err.Error(), needle) {
			t.Fatalf("joined error missing %q: %v", needle, err)
		}
	}
}

func TestPrimaryCAUsesLegacySharedAccountKey(t *testing.T) {
	var keys []string
	withStubOrder(t, func(_ context.Context, _ DNS01Config, ca DNS01CA) error {
		key := ca.AccountKeyCacheKey
		if key == "" {
			key = "acme_account+key"
		}
		keys = append(keys, key)
		return errors.New("force iteration")
	})

	cfg := DNS01Config{
		DNSName: "api.trustedrouter.com",
		FallbackCAs: []DNS01CA{{
			DirectoryURL:       "https://dv.acme-v02.api.pki.goog/directory",
			AccountKeyCacheKey: AccountKeyCacheKeyForDirectory("https://dv.acme-v02.api.pki.goog/directory"),
		}},
	}
	_ = runDNS01Orders(context.Background(), cfg)
	if keys[0] != "acme_account+key" {
		t.Fatalf("primary must keep autocert's shared account key, got %q", keys[0])
	}
	if keys[1] != "acme_account+key+dv.acme-v02.api.pki.goog" {
		t.Fatalf("fallback must isolate its account key per directory host, got %q", keys[1])
	}
}

func TestAccountKeyCacheKeyForDirectoryIsHostScoped(t *testing.T) {
	got := AccountKeyCacheKeyForDirectory("https://ACME.ZeroSSL.com/v2/DV90")
	if got != "acme_account+key+acme.zerossl.com" {
		t.Fatalf("unexpected cache key: %q", got)
	}
}

func TestPreRegisterRetriesUntilSuccessThenStops(t *testing.T) {
	var calls int
	previous := registerCA
	registerCA = func(_ context.Context, _ DNS01Config, _ DNS01CA) error {
		calls++
		if calls == 1 {
			return errors.New("directory unreachable")
		}
		return nil
	}
	t.Cleanup(func() { registerCA = previous })

	cfg := DNS01Config{
		DNSName:     "api.trustedrouter.com",
		FallbackCAs: []DNS01CA{{DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory"}},
	}
	if preRegisterFallbackCAs(context.Background(), cfg, false) {
		t.Fatal("first attempt failed; must report not-done so the tick retries")
	}
	if !preRegisterFallbackCAs(context.Background(), cfg, false) {
		t.Fatal("second attempt succeeded; must report done")
	}
	if !preRegisterFallbackCAs(context.Background(), cfg, true) {
		t.Fatal("alreadyDone must short-circuit")
	}
	if calls != 2 {
		t.Fatalf("expected 2 register calls (fail, succeed, then stop), got %d", calls)
	}
}

func TestPreRegisterNoFallbacksIsDone(t *testing.T) {
	if !preRegisterFallbackCAs(context.Background(), DNS01Config{}, false) {
		t.Fatal("no fallback CAs must report done immediately")
	}
}
