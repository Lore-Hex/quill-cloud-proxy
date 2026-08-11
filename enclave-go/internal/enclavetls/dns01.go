// DNS-01 ACME renewer — defense-in-depth path for issuing the public
// LE certificate when TLS-ALPN-01 can't (e.g., the AWS Nitro enclave
// during a sustained GCP outage where the shared GCS cache + cross-
// cloud routing can't deliver the TLS-ALPN-01 challenge token).
//
// Architecture:
//
//	periodic renewer goroutine
//	  └─ load existing cert from autocert.Cache (GCS, shared)
//	  └─ if cert expires within --dns01-renew-window-days (default 30):
//	       ├─ acme.Client.AuthorizeOrder()  → DNS-01 challenge token
//	       ├─ Cloudflare API: TXT _acme-challenge.<domain> = <token>
//	       ├─ poll public resolvers until TXT is visible
//	       ├─ acme.Client.Accept(challenge)  → LE validates
//	       ├─ acme.Client.CreateOrderCert()  → cert returned
//	       ├─ write cert+privkey to autocert.Cache (GCS, CMEK-encrypted)
//	       └─ Cloudflare API: TXT _acme-challenge.<domain> delete
//
// The renewer runs ALONGSIDE the autocert.Manager that already handles
// TLS-ALPN-01. autocert serves certs from the same Cache. So:
//   - GCP enclaves keep TLS-ALPN-01 (works via shared cache)
//   - AWS enclaves can fall back to DNS-01 when CF routing can't
//     deliver TLS-ALPN-01 validation to them
//   - Once the renewer writes a new cert, every enclave on the next
//     handshake reads it from Cache and serves it — no restart needed
//
// On startup the renewer does a one-shot check: if cert is already
// within the renew window, run DNS-01 immediately. This lets a deploy
// of the AWS enclave during an active TLS-ALPN-01 outage recover by
// itself rather than waiting up to one renewer-tick.
package enclavetls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// DNS01Config carries everything the renewer needs at construction
// time. All fields are required unless noted. Created in cmd/enclave/
// main.go from BootstrapData + the env-baked ACME config.
type DNS01Config struct {
	DNSName            string         // e.g. "api.quillrouter.com"
	Email              string         // ACME account email
	DirectoryURL       string         // empty → LE prod
	Cache              autocert.Cache // shared GCS cache (same one autocert uses)
	CloudflareAPIToken string         // Zone:DNS:Edit on the zone
	CloudflareZoneID   string         // the zone of DNSName (e.g. quillrouter.com's zone id)
	HTTPClient         *http.Client   // vsock-tunneled on AWS, stdlib on GCP
	// AllowBootstrap lets DNS-01 obtain the FIRST certificate for this name,
	// rather than only renewing one TLS-ALPN-01 already produced.
	//
	// Off by default, and that default is right for a region's PRIMARY name:
	// DNS points at it, so TLS-ALPN-01 works, and letting both paths issue at
	// once would race and burn two of five weekly issuances for one name.
	//
	// It must be ON for a SHARED name — one this region serves but DNS does not
	// point at. TLS-ALPN-01 validation lands on whichever region DNS resolves
	// to, so from here it can never succeed, and without bootstrap the name is
	// simply never obtained. That is the case multi-region failover depends on.
	AllowBootstrap bool
	// Provider publishes the challenge TXT. nil selects Cloudflare, which is
	// what every existing deployment used before this seam existed.
	Provider DNS01Provider
	// EAB binds this ACME account to an account the CA already knows about.
	// nil for Let's Encrypt; REQUIRED by the CAs this path exists to fail
	// over to. Without it, pointing DirectoryURL at one of them fails at
	// registration during an outage — the worst moment to learn the fallback
	// was never wired.
	ExternalAccountBinding *acme.ExternalAccountBinding
	// FallbackCAs are tried IN ORDER when the primary CA (DirectoryURL
	// above) fails an order. This is the CA half of defense-in-depth that
	// the DNS-01 transport half always promised: a sustained Let's Encrypt
	// outage flips issuance to the next CA automatically on the next
	// renewer tick, instead of being a total TLS outage with a 30-day fuse.
	// Order is preference: LE-first keeps the fallback CA cold (zero spend,
	// zero rate-limit history) in the normal world.
	FallbackCAs         []DNS01CA
	RenewWithinDuration time.Duration // renew when cert has <= this much life left (default 30d)
	CheckEvery          time.Duration // poll cadence (default 6h)
}

// DNS01CA is one certificate authority the renewer can order from.
type DNS01CA struct {
	DirectoryURL string // empty → LE prod (only sensible for the primary)
	// EAB for THIS CA. Google Trust Services and ZeroSSL refuse
	// registration without it; Let's Encrypt ignores it.
	EAB *acme.ExternalAccountBinding
	// AccountKeyCacheKey isolates ACME account state per CA. Every CA sees
	// a registration signed by the key at this cache key; sharing one key
	// across CAs would entangle their account state and rate-limit
	// histories. Empty → the legacy shared key ("acme_account+key"), which
	// stays correct for the primary CA (it IS that account).
	AccountKeyCacheKey string
}

// AccountKeyCacheKeyForDirectory derives a stable per-CA account key cache
// key from the directory URL, so the same fallback CA reuses its account
// across restarts and replicas (registration is idempotent per key).
func AccountKeyCacheKeyForDirectory(directoryURL string) string {
	host := directoryURL
	if u, err := neturl.Parse(directoryURL); err == nil && u.Host != "" {
		host = u.Host
	}
	return "acme_account+key+" + strings.ToLower(host)
}

// StartDNS01Renewer spawns a goroutine that periodically checks the
// cert in `Cache` and, if it's within `RenewWithinDuration` of expiry
// (or missing entirely), runs a DNS-01 renewal against ACME via the
// Cloudflare DNS API.
//
// The goroutine exits when ctx is cancelled. Errors are logged to
// stderr but do not stop the loop — autocert's TLS-ALPN-01 path
// remains the primary, and the renewer is a defense-in-depth fallback.
func StartDNS01Renewer(ctx context.Context, cfg DNS01Config) {
	if cfg.RenewWithinDuration == 0 {
		cfg.RenewWithinDuration = 30 * 24 * time.Hour
	}
	if cfg.CheckEvery == 0 {
		cfg.CheckEvery = 6 * time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}

	go func() {
		// Fallback-CA accounts register EAGERLY, not at first outage: GTS
		// EAB keys expire ~7 days after minting if unused, and the fallback
		// only orders when LE is already down — which would mean discovering
		// an expired EAB at the exact moment it was needed. Registering now
		// converts the short-fuse EAB into a durable CA account (shared via
		// the account-key cache, so one success covers the whole fleet).
		// Retried each tick until it succeeds; never blocks renewal.
		registered := preRegisterFallbackCAs(ctx, cfg, false)

		// One-shot check on startup so a deploy during an active
		// outage doesn't have to wait one tick.
		if err := maybeRenewDNS01(ctx, cfg); err != nil {
			fmt.Fprintf(maybeStderr, "dns01_renewer.startup_check_failed err=%v\n", err)
		}
		tick := time.NewTicker(cfg.CheckEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				registered = preRegisterFallbackCAs(ctx, cfg, registered)
				if err := maybeRenewDNS01(ctx, cfg); err != nil {
					fmt.Fprintf(maybeStderr, "dns01_renewer.check_failed err=%v\n", err)
				}
			}
		}
	}()
}

// maybeRenewDNS01 inspects the cert currently in Cache and runs a
// DNS-01 renewal if its NotAfter is within RenewWithinDuration.
// Returns nil on "cert is fine, nothing to do."
func maybeRenewDNS01(ctx context.Context, cfg DNS01Config) error {
	if cfg.Cache == nil {
		return errors.New("dns01: nil cache")
	}
	raw, err := cfg.Cache.Get(ctx, cfg.DNSName)
	if errors.Is(err, autocert.ErrCacheMiss) {
		if !cfg.AllowBootstrap {
			// Primary name: DNS points here, so autocert's TLS-ALPN-01 will
			// obtain it on the first handshake. Issuing from both paths at once
			// would race and spend two of five weekly issuances on one name.
			return nil
		}
		fmt.Fprintf(maybeStderr, "dns01_renewer.bootstrapping dns_name=%s\n", cfg.DNSName)
		return runDNS01Orders(ctx, cfg)
	}
	if err != nil {
		// Cache read errored. Don't treat as "needs renewal" — that
		// could mask a misconfiguration. Surface for the operator.
		return fmt.Errorf("cache get: %w", err)
	}
	leaf, err := leafFromAutocertEntry(raw)
	if err != nil {
		return err
	}
	timeLeft := time.Until(leaf.NotAfter)
	if timeLeft > cfg.RenewWithinDuration {
		// Plenty of life; the TLS-ALPN-01 path handles natural renewal.
		// DNS-01 only fires when ALPN can't.
		return nil
	}
	fmt.Fprintf(maybeStderr,
		"dns01_renewer.renewing dns_name=%s expires_in_hours=%.1f\n",
		cfg.DNSName, timeLeft.Hours(),
	)
	return runDNS01Orders(ctx, cfg)
}

// registerCA registers (or confirms) the ACME account for one CA. Indirect
// for the same reason as orderCA below.
var registerCA = registerFallbackAccount

func registerFallbackAccount(ctx context.Context, cfg DNS01Config, ca DNS01CA) error {
	accountCacheKey := ca.AccountKeyCacheKey
	if accountCacheKey == "" {
		accountCacheKey = "acme_account+key"
	}
	accountKey, err := loadOrCreateACMEAccountKey(ctx, cfg.Cache, accountCacheKey)
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}
	client := &acme.Client{Key: accountKey, HTTPClient: cfg.HTTPClient}
	if ca.DirectoryURL != "" {
		client.DirectoryURL = ca.DirectoryURL
	}
	_, err = client.Register(ctx, &acme.Account{
		Contact:                []string{"mailto:" + cfg.Email},
		ExternalAccountBinding: ca.EAB,
	}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return err
	}
	return nil
}

// preRegisterFallbackCAs registers every fallback CA account once. Returns
// true when all succeeded (callers stop retrying); a failure is logged and
// retried on the next renewer tick. Success is fleet-wide durable: the
// account key lives in the shared cache, so replicas and other clouds that
// register the same key get ErrAccountAlreadyExists, EAB no longer needed.
func preRegisterFallbackCAs(ctx context.Context, cfg DNS01Config, alreadyDone bool) bool {
	if alreadyDone || len(cfg.FallbackCAs) == 0 {
		return true
	}
	done := true
	for _, ca := range cfg.FallbackCAs {
		if err := registerCA(ctx, cfg, ca); err != nil {
			fmt.Fprintf(maybeStderr,
				"dns01_renewer.fallback_preregister_failed directory=%s err=%v\n",
				ca.DirectoryURL, err,
			)
			done = false
			continue
		}
		fmt.Fprintf(maybeStderr,
			"dns01_renewer.fallback_preregistered directory=%s\n", ca.DirectoryURL,
		)
	}
	return done
}

// orderCA is the per-CA order function, indirect so tests can exercise the
// fallback ORDERING logic without standing up a fake ACME directory (the
// wire path below is the one production has been running since DNS-01
// shipped; the new, untested-in-prod logic is the iteration).
var orderCA = runDNS01Order

// runDNS01Orders tries the primary CA, then each FallbackCA in order. The
// first success wins; every failure is logged with the directory it came
// from so an operator can tell "LE is down, GTS carried it" from the log
// line alone. All CAs failing returns the joined error.
func runDNS01Orders(ctx context.Context, cfg DNS01Config) error {
	cas := make([]DNS01CA, 0, 1+len(cfg.FallbackCAs))
	cas = append(cas, DNS01CA{
		DirectoryURL: cfg.DirectoryURL,
		EAB:          cfg.ExternalAccountBinding,
		// Legacy shared key: this IS the account autocert shares.
		AccountKeyCacheKey: "acme_account+key",
	})
	cas = append(cas, cfg.FallbackCAs...)
	var errs []error
	for index, ca := range cas {
		err := orderCA(ctx, cfg, ca)
		if err == nil {
			if index > 0 {
				fmt.Fprintf(maybeStderr,
					"dns01_renewer.fallback_ca_issued dns_name=%s directory=%s\n",
					cfg.DNSName, ca.DirectoryURL,
				)
			}
			return nil
		}
		directory := ca.DirectoryURL
		if directory == "" {
			directory = "letsencrypt-default"
		}
		fmt.Fprintf(maybeStderr,
			"dns01_renewer.ca_failed dns_name=%s directory=%s err=%v\n",
			cfg.DNSName, directory, err,
		)
		errs = append(errs, fmt.Errorf("%s: %w", directory, err))
	}
	return errors.Join(errs...)
}

// runDNS01Order executes one full DNS-01 ACME order against ONE CA, leaving
// the cert in Cache when successful. All on-the-wire pieces (ACME directory,
// Cloudflare API) go through cfg.HTTPClient so the same vsock-tunneled
// transport works on AWS Nitro.
func runDNS01Order(ctx context.Context, cfg DNS01Config, ca DNS01CA) error {
	// 1. Build or load the ACME account key for THIS CA. The primary CA
	// shares autocert's key ("acme_account+key") so DNS-01 and TLS-ALPN-01
	// renewals come from one LE account (same rate limits + history);
	// fallback CAs get their own key so account state never crosses CAs.
	accountCacheKey := ca.AccountKeyCacheKey
	if accountCacheKey == "" {
		accountCacheKey = "acme_account+key"
	}
	accountKey, err := loadOrCreateACMEAccountKey(ctx, cfg.Cache, accountCacheKey)
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}
	client := &acme.Client{
		Key:        accountKey,
		HTTPClient: cfg.HTTPClient,
	}
	if ca.DirectoryURL != "" {
		client.DirectoryURL = ca.DirectoryURL
	}

	// 2. Register / get account.
	_, err = client.Register(ctx, &acme.Account{
		Contact:                []string{"mailto:" + cfg.Email},
		ExternalAccountBinding: ca.EAB,
	}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		// Account-exists is fine; LE returns it on idempotent register.
		return fmt.Errorf("acme register: %w", err)
	}

	// 3. Authorize order for DNSName via DNS-01 challenge.
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: cfg.DNSName},
	})
	if err != nil {
		return fmt.Errorf("acme authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("acme get authorization: %w", err)
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return errors.New("acme: no dns-01 challenge offered")
		}

		token, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("acme dns-01 token: %w", err)
		}

		provider := cfg.provider()
		recordName := challengeRecordName(cfg.DNSName)
		recordID, err := provider.AddTXT(ctx, recordName, token)
		if err != nil {
			return fmt.Errorf("%s TXT add: %w", provider.Name(), err)
		}
		// Best-effort cleanup of the TXT record whether the challenge
		// passes or fails. LE rate-limits the same TXT being seen
		// across consecutive orders, so leaving stale records around
		// is operationally bad.
		defer func() {
			if delErr := provider.RemoveTXT(ctx, recordID); delErr != nil {
				fmt.Fprintf(maybeStderr,
					"dns01_renewer.txt_cleanup_failed record_id=%s err=%v\n",
					recordID, delErr,
				)
			}
		}()

		// Wait for the TXT to be visible from a public resolver so LE's
		// validation doesn't race the propagation. Cloudflare's edge
		// usually converges in 5-30s; we poll up to 5 minutes.
		if err := waitForTXTPropagation(ctx, recordName, token); err != nil {
			return fmt.Errorf("dns propagation: %w", err)
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("acme accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return fmt.Errorf("acme wait authorization: %w", err)
		}
	}

	// 4. Generate cert key + CSR. The cert private key is freshly
	// generated for every issuance — autocert does the same. The key
	// only lives outside the enclave inside the CMEK-encrypted Cache
	// entry (the trust property we already accept for TLS-ALPN-01
	// renewals).
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("gen cert key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{cfg.DNSName},
	}, certKey)
	if err != nil {
		return fmt.Errorf("csr: %w", err)
	}

	// 5. Finalize: LE returns the issued cert chain.
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("acme finalize: %w", err)
	}

	// 6. Persist the combined key+cert to the cache in autocert's format.
	blob, err := encodeAutocertEntry(certKey, der)
	if err != nil {
		return err
	}
	if err := cfg.Cache.Put(ctx, cfg.DNSName, blob); err != nil {
		return fmt.Errorf("cache put: %w", err)
	}
	fmt.Fprintf(maybeStderr, "dns01_renewer.cert_renewed dns_name=%s\n", cfg.DNSName)
	return nil
}

// loadOrCreateACMEAccountKey reads (or creates) the persisted account key
// under the given cache key. The primary CA uses autocert's shared key
// ("acme_account+key"); fallback CAs use a per-directory key so account
// state and rate-limit history never cross CAs.
func loadOrCreateACMEAccountKey(
	ctx context.Context, cache autocert.Cache, cacheKey string,
) (*ecdsa.PrivateKey, error) {
	raw, err := cache.Get(ctx, cacheKey)
	if errors.Is(err, autocert.ErrCacheMiss) {
		key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate account key: %w", gerr)
		}
		der, merr := x509.MarshalECPrivateKey(key)
		if merr != nil {
			return nil, fmt.Errorf("marshal account key: %w", merr)
		}
		var buf bytes.Buffer
		if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
			return nil, fmt.Errorf("pem encode account key: %w", err)
		}
		if perr := cache.Put(ctx, cacheKey, buf.Bytes()); perr != nil {
			return nil, fmt.Errorf("persist account key: %w", perr)
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("account key cache: no PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// -----------------------------------------------------------------------------
// Cloudflare DNS API helpers.
// -----------------------------------------------------------------------------

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

type cloudflareTXTRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// cloudflareAddTXTRecord creates a TXT record under the given zone.
// Returns the record id (needed for delete).
func cloudflareAddTXTRecord(ctx context.Context, cfg DNS01Config, name, value string) (string, error) {
	body, _ := json.Marshal(cloudflareTXTRecord{
		Type:    "TXT",
		Name:    name,
		Content: value,
		TTL:     60,
	})
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, cfg.CloudflareZoneID),
		bytes.NewReader(body),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.CloudflareAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("cloudflare TXT add status %d body=%s", resp.StatusCode, bodyBytes)
	}
	var out struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("cloudflare TXT add decode: %w", err)
	}
	if !out.Success || out.Result.ID == "" {
		return "", errors.New("cloudflare TXT add: unexpected response shape")
	}
	return out.Result.ID, nil
}

// cloudflareDeleteTXTRecord removes the TXT record by id.
func cloudflareDeleteTXTRecord(ctx context.Context, cfg DNS01Config, recordID string) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, cfg.CloudflareZoneID, recordID),
		nil,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.CloudflareAPIToken)
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("cloudflare TXT delete status %d body=%s", resp.StatusCode, bodyBytes)
	}
	return nil
}

// waitForTXTPropagation polls 1.1.1.1 (Cloudflare's own resolver, so
// propagation is fastest) for the expected TXT value. Times out
// after 5 minutes.
func waitForTXTPropagation(ctx context.Context, name, expected string) error {
	deadline := time.Now().Add(5 * time.Minute)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		records, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, r := range records {
				if strings.TrimSpace(r) == expected {
					return nil
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	return errors.New("dns01: TXT propagation timed out (5min)")
}

// Stderr writer that's a no-op when not configured. Pluggable so tests
// can assert log output. Wired to os.Stderr in cmd/enclave/main.go via
// SetDNS01Stderr.
var maybeStderr io.Writer = io.Discard

// SetDNS01Stderr wires a writer (typically os.Stderr) so the renewer's
// log lines actually appear. cmd/enclave/main.go calls this on startup.
func SetDNS01Stderr(w io.Writer) {
	if w != nil {
		maybeStderr = w
	}
}

// provider returns the configured challenge publisher, defaulting to
// Cloudflare so existing deployments behave exactly as before.
func (c DNS01Config) provider() DNS01Provider {
	if c.Provider != nil {
		return c.Provider
	}
	return cloudflareProvider{cfg: c}
}

// challengeRecordName is where the CA looks for the DNS-01 token.
//
// THE WILDCARD RULE. For "*.example.com" the challenge record is
// _acme-challenge.EXAMPLE.COM — the label is stripped, not kept. Publishing
// _acme-challenge.*.example.com creates a record with a literal asterisk label
// that the CA never queries, so validation times out with the record sitting
// right there in the zone looking correct.
//
// This matters because a wildcard is the whole reason DNS-01 exists here: one
// *.trustedrouter.com in the shared cache serves every region and every future
// machine, and takes certificate issuance off the availability path.
func challengeRecordName(dnsName string) string {
	return "_acme-challenge." + strings.TrimPrefix(strings.TrimSpace(dnsName), "*.")
}

// cloudflareProvider adapts the pre-existing Cloudflare helpers to the
// DNS01Provider interface. Its handle is the record id, which is what the
// Cloudflare API deletes by.
type cloudflareProvider struct{ cfg DNS01Config }

func (p cloudflareProvider) Name() string { return "cloudflare" }

func (p cloudflareProvider) AddTXT(ctx context.Context, name, value string) (string, error) {
	return cloudflareAddTXTRecord(ctx, p.cfg, name, value)
}

func (p cloudflareProvider) RemoveTXT(ctx context.Context, handle string) error {
	return cloudflareDeleteTXTRecord(ctx, p.cfg, handle)
}

// encodeAutocertEntry serialises a certificate for autocert's cache.
//
// THE PRIVATE KEY MUST COME FIRST. autocert's cacheGet does a single
// pem.Decode and rejects the entry outright unless that first block is the
// key:
//
//	priv, pub := pem.Decode(data)
//	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
//	    return nil, ErrCacheMiss
//	}
//
// This renewer wrote the chain first and the key last, under a comment
// claiming it was "autocert's format". Every certificate it produced was
// therefore returned as a cache MISS — no error, no log, just a cache that
// never hit. Combined with the renewer only speaking to Cloudflare while
// trustedrouter.com is served by Cloud DNS, the DNS-01 fallback had two
// independent reasons it could not work, and neither was visible because
// DNS-01 only runs behind TLS-ALPN-01.
//
// Getting this wrong is invisible in exactly the way that matters: the write
// succeeds, the object appears in the bucket, and the certificate is silently
// never used.
func encodeAutocertEntry(key *ecdsa.PrivateKey, chain [][]byte) ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, fmt.Errorf("pem key: %w", err)
	}
	for _, b := range chain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return nil, fmt.Errorf("pem cert: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// leafFromAutocertEntry extracts the leaf certificate from a cache entry.
//
// autocert's format is PRIVATE KEY FIRST, then the chain. This read path took
// the first PEM block and parsed it as a certificate, which is the mirror of
// the write bug: against a real autocert-written entry it reads the private key
// and reports
//
//	parse leaf: x509: malformed tbs certificate
//
// Observed live on southeastasia. The consequence is worse than a confusing
// message: maybeRenewDNS01 returns that error and gives up, so the renewer
// never evaluates expiry and never renews. The DNS-01 fallback stays dark for
// exactly the certificates it is supposed to protect.
//
// Skipping to the first CERTIFICATE block also keeps this tolerant of an entry
// written the old way, so a cache still holding a legacy blob is readable
// rather than fatal.
func leafFromAutocertEntry(raw []byte) (*x509.Certificate, error) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("cache entry has no CERTIFICATE block")
		}
		if block.Type != "CERTIFICATE" {
			continue // the private key, which autocert stores first
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse leaf: %w", err)
		}
		return leaf, nil
	}
}
