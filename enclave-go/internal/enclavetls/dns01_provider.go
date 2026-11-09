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
	"bytes"
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

// DNS01PropagationWaiter is implemented by a provider that can confirm, from
// its own API, that the record behind an AddTXT handle is being served by the
// zone's authoritative nameservers, which are what the CA's resolver asks.
//
// It exists because the generic check polls a public resolver over UDP, and a
// Nitro enclave has no network interface: only vsock tunnels to named HTTPS
// hosts. On AWS that lookup cannot succeed, so every DNS-01 order timed out
// after publishing its TXT and before asking the CA to validate it. The
// api-aws certificate came within 12 days of expiry before anyone noticed.
type DNS01PropagationWaiter interface {
	WaitTXT(ctx context.Context, handle string) error
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

// cloudDNSChangeStatus is the part of the API's Change resource that says
// whether a change has reached the authoritative servers ("done") or not
// ("pending").
type cloudDNSChangeStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// cloudDNSHandle is what AddTXT hands back: the exact record set, which
// RemoveTXT needs, plus the id of the change that created it, which WaitTXT
// needs. The record set is embedded so its fields stay at the top level.
type cloudDNSHandle struct {
	cloudDNSRecordSet
	ChangeID string `json:"changeId,omitempty"`
}

// How often WaitTXT re-reads a pending change. A variable so tests do not
// sleep.
var cloudDNSChangePollInterval = 2 * time.Second

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
	created, err := p.change(ctx, cloudDNSChange{Additions: []cloudDNSRecordSet{rs}})
	if errors.Is(err, errCloudDNSUndecodable) {
		// The record exists, so return a handle the caller will clean up.
		// Without a change id WaitTXT fails and the resolver is used.
		created, err = cloudDNSChangeStatus{}, nil
	}
	if err != nil {
		return "", err
	}
	handle, err := json.Marshal(cloudDNSHandle{cloudDNSRecordSet: rs, ChangeID: created.ID})
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
	_, err := p.change(ctx, cloudDNSChange{Deletions: []cloudDNSRecordSet{rs}})
	return err
}

// WaitTXT polls the change that created the record until Cloud DNS reports it
// "done", meaning every authoritative nameserver serves it. That is the
// question the CA's validation actually depends on, and it is answered over
// dns.googleapis.com, which the AWS enclave already tunnels.
func (p *CloudDNSProvider) WaitTXT(ctx context.Context, handle string) error {
	var h cloudDNSHandle
	if err := json.Unmarshal([]byte(handle), &h); err != nil {
		return fmt.Errorf("clouddns: bad handle: %w", err)
	}
	if h.ChangeID == "" {
		return errors.New("clouddns: change id missing from handle")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes/%s",
		cloudDNSAPIBase, p.Project, p.ManagedZone, h.ChangeID)
	last := errors.New("no response yet")
	for {
		var status cloudDNSChangeStatus
		err := p.do(ctx, http.MethodGet, url, nil, &status)
		switch {
		case err == nil && status.Status == "done":
			return nil
		case err == nil:
			last = fmt.Errorf("change %s still %q", h.ChangeID, status.Status)
		case isPermanentCloudDNSError(err):
			// A refusal (403 without dns.changes.get, 404) will not change on
			// retry; return it so the caller can fall back at once.
			return err
		default:
			// A 5xx, 429 or transport error is worth retrying here: on AWS
			// the resolver fallback cannot succeed, so leaving this loop
			// early would spend the order for nothing.
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("clouddns: %w (%v)", ctx.Err(), last)
		case <-time.After(cloudDNSChangePollInterval):
		}
	}
}

// cloudDNSStatusError is a non-2xx answer from the DNS API.
type cloudDNSStatusError struct {
	Method string
	Code   int
	Body   []byte
}

func (e *cloudDNSStatusError) Error() string {
	return fmt.Sprintf("clouddns: %s status %d body=%s", strings.ToLower(e.Method), e.Code, e.Body)
}

// isPermanentCloudDNSError reports a 4xx other than 429: a refusal or a
// malformed request, which no amount of waiting will change.
func isPermanentCloudDNSError(err error) bool {
	var status *cloudDNSStatusError
	return errors.As(err, &status) &&
		status.Code/100 == 4 && status.Code != http.StatusTooManyRequests
}

func (p *CloudDNSProvider) ttl() int {
	if p.TTL > 0 {
		return p.TTL
	}
	return 60
}

func (p *CloudDNSProvider) change(ctx context.Context, body cloudDNSChange) (cloudDNSChangeStatus, error) {
	var created cloudDNSChangeStatus
	payload, err := json.Marshal(body)
	if err != nil {
		return created, fmt.Errorf("clouddns: marshal change: %w", err)
	}
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes",
		cloudDNSAPIBase, p.Project, p.ManagedZone)
	err = p.do(ctx, http.MethodPost, url, payload, &created)
	return created, err
}

// do sends one authenticated request to the DNS API and decodes the JSON
// response into out.
func (p *CloudDNSProvider) do(ctx context.Context, method, url string, payload []byte, out any) error {
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
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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
		return &cloudDNSStatusError{Method: method, Code: resp.StatusCode, Body: snippet}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("%w: %v", errCloudDNSUndecodable, err)
	}
	return nil
}

// errCloudDNSUndecodable marks a 2xx whose body could not be read: the
// request took effect, only its answer is unknown.
var errCloudDNSUndecodable = errors.New("clouddns: undecodable response")

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

// NewCloudDNSProvider builds a Cloud DNS provider that authenticates with the
// same credential the shared ACME cache already uses — GCE metadata on GCP, or
// the cross-cloud service-account key elsewhere — minted for the Cloud DNS
// scope rather than the storage one.
func NewCloudDNSProvider(project, managedZone string, httpClient *http.Client) *CloudDNSProvider {
	tokens := &gcpTokenSource{httpClient: newTokenHTTPClient(), scope: cloudDNSScope}
	return &CloudDNSProvider{
		Project:     project,
		ManagedZone: managedZone,
		HTTPClient:  httpClient,
		AccessToken: tokens.Token,
	}
}
