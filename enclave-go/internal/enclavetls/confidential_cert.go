package enclavetls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/apihosts"
	"golang.org/x/crypto/acme/autocert"
)

// Confidential origins cannot pass TLS-ALPN validation before DNS publication,
// and DNS publication requires their certificates. Only DNS-01 may issue them.
// Cache successful reads briefly inside the enclave; never cache bootstrap misses.
func confidentialCertificateGetter(names []string, cache autocert.Cache, next func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	type entry struct {
		cert  *tls.Certificate
		until time.Time
	}
	var mu sync.Mutex
	certificates := make(map[string]entry)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
		if !apihosts.Confidential(name) {
			return next(hello)
		}
		if !allowed[name] {
			return nil, fmt.Errorf("enclavetls: confidential hostname is not configured")
		}
		mu.Lock()
		cached, ok := certificates[name]
		mu.Unlock()
		now := time.Now()
		if ok && now.Before(cached.until) && now.Before(cached.cert.Leaf.NotAfter) {
			return cached.cert, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		raw, err := cache.Get(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("enclavetls: confidential DNS-01 certificate unavailable: %w", err)
		}
		cert, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			return nil, fmt.Errorf("enclavetls: invalid confidential certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("enclavetls: invalid confidential certificate: %w", err)
		}
		if err := leaf.VerifyHostname(name); err != nil {
			return nil, fmt.Errorf("enclavetls: confidential certificate hostname: %w", err)
		}
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return nil, fmt.Errorf("enclavetls: confidential certificate outside validity period")
		}
		cert.Leaf = leaf
		mu.Lock()
		certificates[name] = entry{cert: &cert, until: now.Add(time.Minute)}
		mu.Unlock()
		return &cert, nil
	}
}
