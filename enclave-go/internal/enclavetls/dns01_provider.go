// DNS-01 challenge providers.
//
// WHY THIS SEAM EXISTS. The DNS-01 renewer was written against Cloudflare, and
// that is the wrong shape for this fleet: trustedrouter.com is served by Google
// Cloud DNS (ns-cloud-b*.googledomains.com), so the renewer could not touch the
// zone that matters. The practical consequence was invisible — DNS-01 is
// defense-in-depth behind TLS-ALPN-01, so nothing failed loudly; the fallback
// simply was not there when TLS-ALPN-01 hit a wall.
//
// It matters now because DNS-01 is the ONLY way to obtain a WILDCARD, and a
// wildcard is what takes certificate issuance off the availability path
// entirely: one *.trustedrouter.com in the shared cache serves every region and
// every future machine, so bringing up a region costs zero issuances and the
// per-identifier rate limit stops being reachable at all.
package enclavetls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DNS01Provider publishes and withdraws the _acme-challenge TXT record.
//
// AddTXT returns an opaque handle that RemoveTXT understands, so a provider
// that needs a record id (Cloudflare) and one that needs the full prior record
// (Cloud DNS, whose change API deletes by exact value) can both be expressed
// without the caller knowing which it is talking to.
type DNS01Provider interface {
	AddTXT(ctx context.Context, name, value string) (handle string, err error)
	RemoveTXT(ctx context.Context, handle string) error
	// Name identifies the provider in logs. An operator staring at a failed
	// renewal needs to know WHICH zone API was refusing them.
	Name() string
}

// ---------------------------------------------------------------------------
// Google Cloud DNS
// ---------------------------------------------------------------------------

const cloudDNSAPIBase = "https://dns.googleapis.com/dns/v1"

// CloudDNSProvider publishes challenge records through Google Cloud DNS.
//
// Auth is the ambient service-account credential the enclave already holds
// (GOOGLE_APPLICATION_CREDENTIALS, wired from the sealed bundle). The token is
// fetched through the same HTTP client as everything else so it inherits the
// vsock tunnel on AWS.
type CloudDNSProvider struct {
	Project     string
	ManagedZone string
	HTTPClient  *http.Client
	// AccessToken returns a bearer token for the DNS API. Injected rather than
	// hardcoded so tests never need a credential and so the AWS build can route
	// the metadata call through its own transport.
	AccessToken func(ctx context.Context) (string, error)
	// TTL on the challenge record. Deliberately short: a stale TXT that
	// outlives its order is the documented cause of LE refusing the NEXT
	// order for the same name.
	TTL int
}

func (p *CloudDNSProvider) Name() string { return "clouddns" }

type cloudDNSRecordSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Rrdatas []string `json:"rrdatas"`
}

type cloudDNSChange struct {
	Additions []cloudDNSRecordSet `json:"additions,omitempty"`
	Deletions []cloudDNSRecordSet `json:"deletions,omitempty"`
}

// AddTXT creates the record and returns the exact record set as the handle.
//
// Cloud DNS deletes by VALUE, not by id: the deletion body must reproduce the
// record set byte-for-byte. Returning the marshalled set is what makes cleanup
// possible at all, and it is why this interface hands back an opaque string
// instead of an id.
func (p *CloudDNSProvider) AddTXT(ctx context.Context, name, value string) (string, error) {
	rs := cloudDNSRecordSet{
		Name: dnsFQDN(name),
		Type: "TXT",
		TTL:  p.ttl(),
		// Cloud DNS requires TXT rrdata to be a QUOTED string. Sending it bare
		// is accepted by the API and then served with the quotes ADDED, so the
		// resolver returns a value the CA cannot match — a failure that looks
		// like slow propagation and never converges.
		Rrdatas: []string{strconv.Quote(value)},
	}
	if err := p.change(ctx, cloudDNSChange{Additions: []cloudDNSRecordSet{rs}}); err != nil {
		return "", err
	}
	handle, err := json.Marshal(rs)
	if err != nil {
		return "", fmt.Errorf("clouddns: marshal handle: %w", err)
	}
	return string(handle), nil
}

func (p *CloudDNSProvider) RemoveTXT(ctx context.Context, handle string) error {
	var rs cloudDNSRecordSet
	if err := json.Unmarshal([]byte(handle), &rs); err != nil {
		return fmt.Errorf("clouddns: bad handle: %w", err)
	}
	return p.change(ctx, cloudDNSChange{Deletions: []cloudDNSRecordSet{rs}})
}

func (p *CloudDNSProvider) ttl() int {
	if p.TTL > 0 {
		return p.TTL
	}
	return 60
}

func (p *CloudDNSProvider) change(ctx context.Context, body cloudDNSChange) error {
	if p.Project == "" || p.ManagedZone == "" {
		return errors.New("clouddns: project and managed zone are required")
	}
	if p.AccessToken == nil {
		return errors.New("clouddns: no access token source")
	}
	token, err := p.AccessToken(ctx)
	if err != nil {
		return fmt.Errorf("clouddns: access token: %w", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("clouddns: marshal change: %w", err)
	}
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes",
		cloudDNSAPIBase, p.Project, p.ManagedZone)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("clouddns: change status %d body=%s", resp.StatusCode, snippet)
	}
	return nil
}

// dnsFQDN normalises a name to the trailing-dot form Cloud DNS requires.
//
// Without the dot the API accepts the write and stores a record under a
// DIFFERENT name (it appends the zone's suffix to what it treats as a relative
// name), so the challenge TXT lands somewhere the CA never looks.
func dnsFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
