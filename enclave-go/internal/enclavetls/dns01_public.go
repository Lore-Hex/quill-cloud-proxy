package enclavetls

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These public challenge zones have an observed negative TTL of 300 seconds.
// Don't prime recursive caches with absent names or equate Cloud DNS "done"
// with visibility at the CA. Query the actual validation owner, not only the
// record to which it delegates. No credentials or challenge values are sent.
const preissueCacheWindow = 5 * time.Minute

var preissuePublicTXT = func(ctx context.Context, published time.Time, owner, target, token string) error {
	client := NewDNS01HTTPClient()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return waitPublicTXT(ctx, published, func(ctx context.Context) bool {
		return publicTXTMatches(ctx, client, "https://dns.google/dns-query", owner, target, token) &&
			publicTXTMatches(ctx, client, "https://cloudflare-dns.com/dns-query", owner, target, token)
	})
}

func waitPublicTXT(ctx context.Context, published time.Time, visible func(context.Context) bool) error {
	// The existing whole-order deadline still applies. Time already spent in
	// the provider wait counts toward the negative-cache window.
	for delay := time.Until(published.Add(preissueCacheWindow)); ; delay = 5 * time.Second {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if visible(ctx) {
			return nil
		}
	}
}

func publicTXTMatches(ctx context.Context, client *http.Client, endpoint, owner, target, token string) bool {
	qname, err := dnsmessage.NewName(dnsFQDN(owner))
	if err != nil {
		return false
	}
	q := dnsmessage.Question{Name: qname, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	wire, err := query.Pack()
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || mt != "application/dns-message" {
		return false
	}
	const maxDNS = 65535
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDNS+1))
	var answer dnsmessage.Message
	if err != nil || len(b) > maxDNS || answer.Unpack(b) != nil || !answer.Response || answer.ID != query.ID || answer.OpCode != 0 || answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 {
		return false
	}
	got := answer.Questions[0]
	if got.Type != q.Type || got.Class != q.Class || !strings.EqualFold(got.Name.String(), q.Name.String()) {
		return false
	}
	destination := dnsFQDN(target)
	direct := strings.EqualFold(qname.String(), destination)
	linked, matched := direct, false
	for _, rr := range answer.Answers {
		if rr.Header.Class != dnsmessage.ClassINET {
			continue
		}
		switch v := rr.Body.(type) {
		case *dnsmessage.CNAMEResource:
			if strings.EqualFold(rr.Header.Name.String(), qname.String()) {
				if direct || !strings.EqualFold(v.CNAME.String(), destination) {
					return false
				}
				linked = true
			}
		case *dnsmessage.TXTResource:
			if strings.EqualFold(rr.Header.Name.String(), destination) && strings.Join(v.TXT, "") == token {
				matched = true
			}
		}
	}
	return linked && matched
}
