// Package privatemode supervises the vendor's attestation/encryption proxy
// inside the enclave. No provider inference request uses ordinary HTTPS.
package privatemode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"time"
)

const (
	BaseURL        = "https://privatemode.internal:18489/v1"
	proxyAddress   = "127.0.0.1:18489"
	proxyAuthority = "privatemode.internal:18489"
	proxyBinary    = "/privatemode-proxy"
)

// The expected manifest is part of our attested image, never downloaded at runtime.
//
//go:embed manifest.json
var manifest []byte

// AllowedModel deliberately excludes rolling and deprecated upstream aliases.
func AllowedModel(model string) bool {
	switch model {
	case "glm-5.3", "glm-5.3-flash", "gpt-oss-120b":
		return true
	}
	return false
}

func localIdentity(now time.Time) (certPEM, keyPEM []byte, cert *x509.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "privatemode.internal"},
		DNSNames:  []string{"privatemode.internal"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), cert, err
}

// A rogue loopback listener cannot receive a key or prompt: it cannot present
// the ephemeral certificate handed only to our child through sealed memfds.
func localClient(cert *x509.Certificate) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != proxyAuthority {
				return nil, errors.New("privatemode: unexpected local authority")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 180 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   64,
	}
	return &http.Client{
		Transport: restrictedTransport{transport}, Timeout: 15 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("privatemode: redirect refused") },
	}
}

type restrictedTransport struct{ base *http.Transport }

func (t restrictedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != proxyAuthority || r.URL.User != nil || r.URL.RawQuery != "" ||
		!((r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions") ||
			(r.Method == http.MethodGet && r.URL.Path == "/readyz")) {
		return nil, errors.New("privatemode: request outside encrypted chat interface")
	}
	return t.base.RoundTrip(r)
}
