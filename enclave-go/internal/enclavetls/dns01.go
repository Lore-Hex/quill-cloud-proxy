// DNS-01 ACME renewer — defense-in-depth path for issuing the public
// LE certificate when TLS-ALPN-01 can't (e.g., the AWS Nitro enclave
// during a sustained GCP outage where the shared GCS cache + cross-
// cloud routing can't deliver the TLS-ALPN-01 challenge token).
//
// Architecture:
//
//   periodic renewer goroutine
//     └─ load existing cert from autocert.Cache (GCS, shared)
//     └─ if cert expires within --dns01-renew-window-days (default 30):
//          ├─ acme.Client.AuthorizeOrder()  → DNS-01 challenge token
//          ├─ Cloudflare API: TXT _acme-challenge.<domain> = <token>
//          ├─ poll public resolvers until TXT is visible
//          ├─ acme.Client.Accept(challenge)  → LE validates
//          ├─ acme.Client.CreateOrderCert()  → cert returned
//          ├─ write cert+privkey to autocert.Cache (GCS, CMEK-encrypted)
//          └─ Cloudflare API: TXT _acme-challenge.<domain> delete
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
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// DNS01Config carries everything the renewer needs at construction
// time. All fields are required unless noted. Created in cmd/enclave/
// main.go from BootstrapData + the env-baked ACME config.
type DNS01Config struct {
	DNSName             string         // e.g. "api.quillrouter.com"
	Email               string         // ACME account email
	DirectoryURL        string         // empty → LE prod
	Cache               autocert.Cache // shared GCS cache (same one autocert uses)
	CloudflareAPIToken  string         // Zone:DNS:Edit on the zone
	CloudflareZoneID    string         // the zone of DNSName (e.g. quillrouter.com's zone id)
	HTTPClient          *http.Client   // vsock-tunneled on AWS, stdlib on GCP
	RenewWithinDuration time.Duration  // renew when cert has <= this much life left (default 30d)
	CheckEvery          time.Duration  // poll cadence (default 6h)
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
		// No cert yet; let autocert handle the first-issuance via
		// TLS-ALPN-01 on the first TLS handshake. DNS-01 is the
		// renewal fallback, not the bootstrap path.
		return nil
	}
	if err != nil {
		// Cache read errored. Don't treat as "needs renewal" — that
		// could mask a misconfiguration. Surface for the operator.
		return fmt.Errorf("cache get: %w", err)
	}
	leafBlock, _ := pem.Decode(raw)
	if leafBlock == nil {
		return errors.New("cache returned bytes that don't PEM-decode")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
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
	return runDNS01Order(ctx, cfg)
}

// runDNS01Order executes one full DNS-01 ACME order, leaving the cert
// in Cache when successful. All on-the-wire pieces (ACME directory,
// Cloudflare API) go through cfg.HTTPClient so the same vsock-tunneled
// transport works on AWS Nitro.
func runDNS01Order(ctx context.Context, cfg DNS01Config) error {
	// 1. Build or load the ACME account key. We share the same account
	// key autocert stores in Cache under "acme_account+key" so DNS-01
	// renewals and TLS-ALPN-01 renewals come from the same LE account
	// (and share the per-account rate limits + history).
	accountKey, err := loadOrCreateACMEAccountKey(ctx, cfg.Cache)
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}
	client := &acme.Client{
		Key:        accountKey,
		HTTPClient: cfg.HTTPClient,
	}
	if cfg.DirectoryURL != "" {
		client.DirectoryURL = cfg.DirectoryURL
	}

	// 2. Register / get account.
	_, err = client.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + cfg.Email},
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

		recordName := "_acme-challenge." + cfg.DNSName
		recordID, err := cloudflareAddTXTRecord(ctx, cfg, recordName, token)
		if err != nil {
			return fmt.Errorf("cloudflare TXT add: %w", err)
		}
		// Best-effort cleanup of the TXT record whether the challenge
		// passes or fails. LE rate-limits the same TXT being seen
		// across consecutive orders, so leaving stale records around
		// is operationally bad.
		defer func() {
			if delErr := cloudflareDeleteTXTRecord(ctx, cfg, recordID); delErr != nil {
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

	// 6. Persist the combined cert+key to Cache in autocert's format
	// (cert chain PEM concatenated with the EC private key PEM). The
	// next autocert.GetCertificate call returns this on cache hit.
	var buf bytes.Buffer
	for _, b := range der {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return fmt.Errorf("pem cert: %w", err)
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("pem key: %w", err)
	}
	if err := cfg.Cache.Put(ctx, cfg.DNSName, buf.Bytes()); err != nil {
		return fmt.Errorf("cache put: %w", err)
	}
	fmt.Fprintf(maybeStderr, "dns01_renewer.cert_renewed dns_name=%s\n", cfg.DNSName)
	return nil
}

// loadOrCreateACMEAccountKey reads (or creates) the persisted account
// key under the same cache key autocert uses ("acme_account+key").
// Sharing the key means DNS-01 and TLS-ALPN-01 renewals come from a
// single ACME account.
func loadOrCreateACMEAccountKey(ctx context.Context, cache autocert.Cache) (*ecdsa.PrivateKey, error) {
	raw, err := cache.Get(ctx, "acme_account+key")
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
		if perr := cache.Put(ctx, "acme_account+key", buf.Bytes()); perr != nil {
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
