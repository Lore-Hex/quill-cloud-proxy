package main

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	rekorpgp "github.com/sigstore/rekor/pkg/pki/pgp"
)

// Rekor's generic key factory is used only by upstream signing fixtures.
func TestOfflineDependencyPGPAdapter(t *testing.T) {
	entity, err := openpgp.NewEntity("fixture", "", "fixture@example.test", &packet.Config{RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	key, err := rekorpgp.NewPublicKey(bytes.NewReader(public.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("offline verification fixture")
	for _, armored := range []bool{false, true} {
		name, sign := "binary", openpgp.DetachSign
		if armored {
			name, sign = "armored", openpgp.ArmoredDetachSign
		}
		t.Run(name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := sign(&encoded, entity, bytes.NewReader(message), nil); err != nil {
				t.Fatal(err)
			}
			sig, err := rekorpgp.NewSignature(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(bytes.NewReader(message), key); err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(bytes.NewReader([]byte("tampered")), key); err == nil {
				t.Fatal("accepted a tampered message")
			}
		})
	}
	if _, err := rekorpgp.NewSignature(bytes.NewReader([]byte("not a signature"))); err == nil {
		t.Fatal("accepted malformed signature")
	}
}
