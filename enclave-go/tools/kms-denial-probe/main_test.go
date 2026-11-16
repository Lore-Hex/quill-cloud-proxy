//go:build cloud_aws

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestPublicEvidenceBindsChallengeAndFreshRSAKey(t *testing.T) {
	var previous []byte
	for range 2 {
		client, server := net.Pipe()
		challenge := bytes.Repeat([]byte{42}, 32)
		result := make(chan error, 1)
		go func() {
			defer server.Close()
			result <- handle(server, func(publicKey, nonce []byte) ([]byte, error) {
				if !bytes.Equal(challenge, nonce) {
					return nil, errors.New("wrong nonce")
				}
				return []byte("test public evidence"), nil
			})
		}()
		if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(challenge); err != nil {
			t.Fatal(err)
		}
		var size uint32
		if err := binary.Read(client, binary.BigEndian, &size); err != nil || size == 0 || size > 32<<10 {
			t.Fatalf("invalid response frame: %d %v", size, err)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(client, body); err != nil {
			t.Fatal(err)
		}
		var got evidence
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		public, err := x509.ParsePKIXPublicKey(got.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := public.(*rsa.PublicKey)
		if !ok || key.N.BitLen() != 2048 || key.E != 65537 {
			t.Fatal("not a 2048-bit RSA recipient")
		}
		if !bytes.Equal(got.Nonce, challenge) || got.Protocol != protocol || string(got.Document) != "test public evidence" {
			t.Fatal("public evidence mismatch")
		}
		if bytes.Equal(got.PublicKey, previous) {
			t.Fatal("recipient key reused")
		}
		previous = got.PublicKey
		client.Close()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidAttestationProducesNoEvidence(t *testing.T) {
	for _, document := range [][]byte{nil, make([]byte, (16<<10)+1)} {
		client, server := net.Pipe()
		result := make(chan error, 1)
		go func() {
			defer server.Close()
			result <- handle(server, func(_, _ []byte) ([]byte, error) { return document, nil })
		}()
		if _, err := client.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(client)
		client.Close()
		if err != nil || len(body) != 0 || <-result == nil {
			t.Fatal("invalid attestation emitted evidence")
		}
	}
}

func TestIncompleteChallengeDoesNotAttest(t *testing.T) {
	client, server := net.Pipe()
	client.Close()
	defer server.Close()
	called := false
	err := handle(server, func(_, _ []byte) ([]byte, error) { called = true; return []byte("bad"), nil })
	if err == nil || called {
		t.Fatal("incomplete challenge reached NSM")
	}
}
