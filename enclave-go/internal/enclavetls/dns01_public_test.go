package enclavetls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPublicTXTAnswers(t *testing.T) {
	owner := dnsmessage.MustNewName("_acme-challenge.alias.example.")
	dest := dnsmessage.MustNewName("_acme-challenge.target.example.")
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"direct", true}, {"delegated", true}, {"stale", false}, {"no-link", false}, {"different-link", false}, {"other-owner", false}, {"wrong-question", false}, {"nxdomain", false}, {"truncated", false}, {"not-dns", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := dest
			if tc.name == "direct" {
				target = owner
			}
			client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected resolver request")
				}
				wire, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var m dnsmessage.Message
				if err = m.Unpack(wire); err != nil || len(m.Questions) != 1 || m.Questions[0].Name != owner || m.Questions[0].Type != dnsmessage.TypeTXT || bytes.Contains(wire, []byte("challenge-value")) {
					t.Fatal("wrong public question")
				}
				m.Response = true
				if tc.name == "wrong-question" {
					m.Questions[0].Name = dest
				}
				if tc.name == "nxdomain" {
					m.RCode = dnsmessage.RCodeNameError
				}
				m.Truncated = tc.name == "truncated"
				if tc.name != "direct" && tc.name != "no-link" {
					to := dest
					if tc.name == "different-link" {
						to = owner
					}
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: to}})
				}
				text := "challenge-value"
				if tc.name == "stale" {
					text = "old-value"
				}
				n := target
				if tc.name == "other-owner" {
					n = owner
				}
				m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{text}}})
				out, err := m.Pack()
				if err != nil {
					t.Fatal(err)
				}
				ct := "application/dns-message"
				if tc.name == "not-dns" {
					ct = "text/plain"
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{ct}}, Body: io.NopCloser(bytes.NewReader(out))}, nil
			})}
			if got := publicTXTMatches(context.Background(), client, "https://resolver.example/query", owner.String(), target.String(), "challenge-value"); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestPublicTXTWaitHonorsCacheWindowAndOrderDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		n := 0
		err := waitPublicTXT(t.Context(), start, func(context.Context) bool {
			if time.Since(start) < 5*time.Minute {
				t.Fatal("premature public check")
			}
			n++
			return n == 2
		})
		if err != nil || n != 2 || time.Since(start) != 5*time.Minute+5*time.Second {
			t.Fatal("incorrect cache wait or polling")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		err = waitPublicTXT(ctx, time.Now(), func(context.Context) bool { t.Fatal("lookup after deadline"); return true })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}

func TestPreissuePublicFailureNeverAcceptsChallenge(t *testing.T) {
	var accepts atomic.Int32
	ca := fakeACMEWith(t, func(_ http.ResponseWriter, r *http.Request, _ string) bool {
		if r.URL.Path == "/chal/1" {
			accepts.Add(1)
		}
		return false
	})
	p := &recordingProvider{}
	missing := errors.New("test: public views disagree")
	old := preissuePublicTXT
	t.Cleanup(func() { preissuePublicTXT = old })
	const target = "_acme-challenge.mirror.example"
	preissuePublicTXT = func(_ context.Context, published time.Time, owner, destination, token string) error {
		if published.IsZero() || owner != "_acme-challenge.api-aws.trustedrouter.com" || destination != target || token == "" {
			t.Fatal("wrong challenge identity")
		}
		return missing
	}
	err := PreissueDNS01(t.Context(), DNS01Config{DNSName: "api-aws.trustedrouter.com", ChallengeRecord: target, Provider: p, Cache: autocert.DirCache(t.TempDir()), DirectoryURL: ca.URL + "/directory", HTTPClient: ca.Client()}, false)
	if !errors.Is(err, missing) || accepts.Load() != 0 || len(p.added) != 1 || len(p.waited) != 1 || len(p.removed) != 1 {
		t.Fatalf("public gate or TXT cleanup failed: %v", err)
	}
}
