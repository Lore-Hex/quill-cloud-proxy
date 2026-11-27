//go:build cloud_aws

package enclavetls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const NitroGatewayHost = "api-aws.trustedrouter.com"
const firstOrderPrefix = "release-control/v1/" + NitroGatewayHost + "/"

// The operator arms one hostname after rehearsal. Losing a response to the
// conditional create must not allow a replacement order from another boot.
func claimNitroOrder(ctx context.Context, store *gcsCache, pin string) error {
	permit, err := store.Get(ctx, firstOrderPrefix+"permit")
	prefix := "first-order-v1 " + NitroGatewayHost + " " + pin + " "
	expiry, match := strings.CutPrefix(strings.TrimSuffix(string(permit), "\n"), prefix)
	until, parseErr := time.Parse(time.RFC3339, expiry)
	remaining := time.Until(until)
	if err != nil || !match || parseErr != nil || remaining <= 9*time.Minute || remaining > 30*time.Minute {
		return errors.New("Nitro first certificate order is not armed")
	}
	token, err := store.tokens.Token(ctx)
	if err != nil {
		return errors.New("Nitro first order claim authentication failed")
	}
	q := url.Values{"name": {firstOrderPrefix + "claimed"}, "uploadType": {"media"}, "ifGenerationMatch": {"0"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gcsUploadBase+"/b/"+AWSSealedBucket+"/o?"+q.Encode(), strings.NewReader("first-order-v1\n"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := store.httpClient.Do(req)
	if err != nil {
		return errors.New("Nitro first order claim indeterminate; reconcile before issuing")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Nitro first order not acquired (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func verifiedNitroLeaf(ctx context.Context, cache autocert.Cache, roots *x509.CertPool) error {
	entry, err := cache.Get(ctx, NitroGatewayHost)
	if err != nil {
		return err
	}
	defer clear(entry)
	pair, err := tls.X509KeyPair(entry, entry)
	if err != nil {
		return errors.New("invalid Nitro TLS cache key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid Nitro TLS leaf")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("invalid Nitro TLS intermediate")
		}
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: NitroGatewayHost, Roots: roots, Intermediates: intermediates})
	return err
}

func ensureNitroLeaf(ctx context.Context, read, claim, issue func(context.Context) error) error {
	if err := read(ctx); !errors.Is(err, autocert.ErrCacheMiss) {
		return err
	}
	if err := claim(ctx); err != nil {
		return err
	}
	if err := issue(ctx); err != nil {
		return errors.New("Nitro first certificate order failed; claim retained")
	}
	return read(ctx)
}

func ReadyNitroACMECache(ctx context.Context, root []byte, pin string) (autocert.Cache, error) {
	cache, store, err := nitroACMEStorage(root, pin)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
	defer cancel()
	err = ensureNitroLeaf(ctx,
		func(ctx context.Context) error { return verifiedNitroLeaf(ctx, cache, nil) },
		func(ctx context.Context) error { return claimNitroOrder(ctx, store, pin) },
		func(ctx context.Context) error {
			client := NewDNS01HTTPClient()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			return PreissueDNS01(ctx, DNS01Config{nitroFirstOrder: true, DNSName: NitroGatewayHost, Email: "acme@trustedrouter.com",
				Provider:     NewCloudDNSProvider("quill-cloud-proxy", "trustedrouter-com", client),
				DirectoryURL: acme.LetsEncryptURL, Cache: cache, HTTPClient: client}, false)
		})
	if err != nil {
		return nil, err
	}
	return cache, nil
}
