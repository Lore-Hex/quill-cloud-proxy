package awssealed

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

func TestTLSCacheRecipientCommitment(t *testing.T) {
	seed, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&seed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(public)
	raw, err := x509.MarshalPKCS8PrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for range 2 {
		rec, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		cms := wrapForTest(t, raw, &rec.PublicKey)
		got, err := openTLSCacheKey(cms, rec, pin[:])
		if err != nil || len(got) != 32 || (previous != nil && !bytes.Equal(previous, got)) {
			t.Fatal("replicas did not derive the same pinned root", err)
		}
		if bytes.Contains(raw, got) {
			t.Fatal("raw scalar used as wrapping key")
		}
		previous = got
		if _, err := UnwrapCMS(cms, rec); err == nil {
			t.Fatal("bootstrap accepted TLS envelope")
		}
		wrong := sha256.Sum256([]byte("other public identity"))
		for _, test := range []struct{ msg, pin []byte }{{cms, wrong[:]}, {cms[:len(cms)-1], pin[:]}, {wrapForTest(t, got, &rec.PublicKey), pin[:]}} {
			if out, err := openTLSCacheKey(test.msg, rec, test.pin); err == nil || out != nil {
				t.Fatal("accepted wrong identity, malformed or cross-protocol envelope")
			}
		}
	}
}
func TestUnprovisionedTLSIdentityRefusesTransport(t *testing.T) {
	if key, err := FetchTLSCacheKey(context.Background(), nil, nil, ""); key != nil || err != errTLSKey {
		t.Fatal("missing pin did not fail closed before transport")
	}
}

func TestTLSCacheFramedExchange(t *testing.T) {
	seed, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&seed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	var recipient *rsa.PublicKey
	document := []byte("synthetic-bound-document")
	attest := func(_ context.Context, pk, nonce []byte) ([]byte, error) {
		pub, err := x509.ParsePKIXPublicKey(pk)
		if err != nil || len(nonce) != 32 {
			return nil, errors.New("bad synthetic challenge")
		}
		recipient = pub.(*rsa.PublicKey)
		return document, nil
	}
	done := make(chan error, 1)
	dial := func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		wire, err := json.Marshal(map[string][]byte{"ciphertext_for_recipient": wrapForTest(t, raw, recipient)})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer s.Close()
			frame, err := readFrame(s, MaxRequestBytes)
			var req Request
			if err == nil {
				err = canonicalDecode(frame, MaxRequestBytes, &req)
			}
			if err == nil && (req.Protocol != TLSCacheProtocol || !bytes.Equal(req.AttestationDocument, document)) {
				err = errors.New("unexpected recipient request")
			}
			if err == nil {
				err = writeFrame(s, wire)
			}
			done <- err
		}()
		return c, nil
	}
	got, err := FetchTLSCacheKey(context.Background(), dial, attest, hex.EncodeToString(pin[:]))
	if err != nil || len(got) != 32 {
		t.Fatal("framed TLS seed exchange failed", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
