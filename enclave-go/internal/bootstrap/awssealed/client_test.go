package awssealed

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func wrapForTest(t *testing.T, dataKey []byte, recipient *rsa.PublicKey) []byte {
	t.Helper()
	n := fixtureNode(t)
	contentKey := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipient, contentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(contentKey)
	pad := aes.BlockSize - len(dataKey)%aes.BlockSize
	plaintext := append(bytes.Clone(dataKey), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	envelope := &n.children[1].children[0]
	envelope.children[1].children[0].children[3].body = wrapped
	envelope.children[2].children[1].children[1].body = iv
	envelope.children[2].children[2] = cmsNode{tag: 128, body: ciphertext}
	return encodeNode(n)
}

func TestFreshRecipientNativeProtocol(t *testing.T) {
	response, signer, key := fixture(t, "eu-west-1", 4)
	var previousPublic []byte
	for i := 0; i < 2; i++ {
		var public *rsa.PublicKey
		attest := func(ctx context.Context, der, nonce []byte) ([]byte, error) {
			if len(nonce) != 32 || bytes.Equal(der, previousPublic) {
				t.Fatal("recipient or nonce was not fresh")
			}
			previousPublic = bytes.Clone(der)
			parsed, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			public = parsed.(*rsa.PublicKey)
			return []byte("fake NSM document bound to captured public key"), nil
		}
		serverDone := make(chan error, 1)
		dial := func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			response.CiphertextForRecipient = wrapForTest(t, key, public)
			wire, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer server.Close()
				request, err := readFrame(server, MaxRequestBytes)
				if err == nil {
					var r Request
					err = canonicalDecode(request, MaxRequestBytes, &r)
					if err == nil && (r.Protocol != Protocol || len(r.AttestationDocument) == 0) {
						err = errors.New("invalid request")
					}
				}
				if err == nil {
					err = writeFrame(server, wire)
				}
				serverDone <- err
			}()
			return client, nil
		}
		plaintext, _, err := Fetch(context.Background(), dial, attest, &signer.PublicKey, 4)
		if err != nil || !bytes.Contains(plaintext, []byte(`"test":true`)) {
			t.Fatalf("attested exchange failed: %v", err)
		}
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnresponsiveParentHasBoundedDeadline(t *testing.T) {
	_, signer, _ := fixture(t, "eu-west-1", 4)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var peer net.Conn
	dial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		peer = server
		return client, nil
	}
	start := time.Now()
	_, _, err := Fetch(ctx, dial, func(context.Context, []byte, []byte) ([]byte, error) { return []byte("fake"), nil }, &signer.PublicKey, 4)
	if peer != nil {
		_ = peer.Close()
	}
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("unresponsive parent was not bounded")
	}
}

func TestRequestAttestationFailureDoesNotDial(t *testing.T) {
	_, signer, _ := fixture(t, "eu-west-1", 4)
	for _, size := range []int{0, MaxDocumentBytes + 1} {
		_, _, err := Fetch(context.Background(), func(context.Context) (net.Conn, error) {
			t.Fatal("invalid hardware attestation reached parent")
			return nil, nil
		}, func(context.Context, []byte, []byte) ([]byte, error) { return make([]byte, size), nil }, &signer.PublicKey, 4)
		if err == nil {
			t.Fatal("invalid document accepted")
		}
	}
}

func TestOversizedFrameRejectedBeforeAllocation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], ^uint32(0))
		_, _ = server.Write(length[:])
	}()
	if _, err := readFrame(client, MaxResponseBytes); err == nil {
		t.Fatal("unbounded response accepted")
	}
	<-done
}
