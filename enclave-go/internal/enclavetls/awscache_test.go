//go:build cloud_aws

package enclavetls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestNitroCacheCannotReadClearOrSubstitutedEntry(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewNitroACMECache(key, "test-pin")
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*sealedACMECache)
	s.store = newMemoryACMECache()
	data := []byte("synthetic tls private material")
	if err := s.Put(ctx, "a", data); err != nil {
		t.Fatal(err)
	}
	blob, err := s.store.Get(ctx, "a")
	if err != nil || bytes.Contains(blob, data) {
		t.Fatal("unprotected storage")
	}
	reader, err := NewNitroACMECache(bytes.Clone(key), "test-pin")
	if err != nil {
		t.Fatal(err)
	}
	r := reader.(*sealedACMECache)
	r.store = s.store
	got, err := r.Get(ctx, "a")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("independent reader", err)
	}
	for _, x := range [][]byte{blob, data} {
		if err = s.store.Put(ctx, "b", x); err != nil {
			t.Fatal(err)
		}
		if out, err := r.Get(ctx, "b"); err == nil || out != nil {
			t.Fatal("substituted/clear object accepted")
		}
	}
	if _, err := NewACMECache("", "quill-acme-cache"); err == nil {
		t.Fatal("legacy GCS cache still selectable")
	}
}

func TestNitroSealedCacheColdReplicaAndRotation(t *testing.T) {
	const host = "tls.gateway.test"
	ctx := t.Context()
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	backing := newMemoryACMECache()
	replica := func() *sealedACMECache {
		c, err := NewNitroACMECache(bytes.Clone(root), "fixture-identity")
		if err != nil {
			t.Fatal(err)
		}
		s := c.(*sealedACMECache)
		s.store = backing
		return s
	}
	writer := replica()
	var last []byte
	for range 2 {
		issued, err := NewSelfSigned(host)
		if err != nil {
			t.Fatal(err)
		}
		cert := issued.Certificate
		entry, err := encodeAutocertEntry(cert.PrivateKey.(*ecdsa.PrivateKey), cert.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.Put(ctx, host, entry); err != nil {
			t.Fatal(err)
		}
		raw, err := backing.Get(ctx, host)
		if err != nil || !bytes.HasPrefix(raw, []byte(sealedCacheV1)) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Fatal("cache did not store a sealed envelope", err)
		}
		if bytes.Equal(last, cert.Leaf.RawSubjectPublicKeyInfo) {
			t.Fatal("fixture failed to rotate")
		}
		last = bytes.Clone(cert.Leaf.RawSubjectPublicKeyInfo)
		roots := x509.NewCertPool()
		roots.AddCert(cert.Leaf)
		for range 2 {
			// An unreachable ACME directory: a cold replica must use only its sealed entry.
			srv, err := NewACMEWithCache(host, "", "https://127.0.0.1:1/directory", replica(), nil)
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			deadline := time.Now().Add(5 * time.Second)
			_ = a.SetDeadline(deadline)
			_ = b.SetDeadline(deadline)
			done := make(chan error, 1)
			go func() { defer a.Close(); done <- tls.Server(a, srv.tlsConfig).HandshakeContext(ctx) }()
			c := tls.Client(b, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13})
			err = c.HandshakeContext(ctx)
			_ = b.Close()
			if other := <-done; err != nil || other != nil {
				t.Fatal("replica failed TLS handshake", err, other)
			}
			if !bytes.Equal(c.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo, last) {
				t.Fatal("cold replica served the wrong public key")
			}
		}
	}
}
