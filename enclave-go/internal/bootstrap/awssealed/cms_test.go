package awssealed

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

func kmsFixture(t testing.TB) ([]byte, *rsa.PrivateKey, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/upstream-kms.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PrivateKey string `json:"private_key_pem"`
		Ciphertext string `json:"ciphertext_for_recipient"`
		Plaintext  string `json:"plaintext_key_hex"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(fixture.PrivateKey))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid public test key fixture")
		return nil, nil, nil
	}
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(fixture.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := hex.DecodeString(fixture.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, private, plaintext
}

func TestPublishedKMSRecipientInteroperability(t *testing.T) {
	ciphertext, private, expected := kmsFixture(t)
	got, err := UnwrapCMS(ciphertext, private)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("published KMS fixture failed: %v", err)
	}
}

// Re-encode the parsed fixture as definite DER, independently of the production
// BER reader, so profile mutations cannot be dismissed as truncated BER.
func encodeNode(n cmsNode) []byte {
	body := bytes.Clone(n.body)
	if n.tag&32 != 0 {
		body = nil
		for _, child := range n.children {
			body = append(body, encodeNode(child)...)
		}
	}
	out := []byte{n.tag}
	switch {
	case len(body) < 128:
		out = append(out, byte(len(body)))
	case len(body) < 256:
		out = append(out, 129, byte(len(body)))
	default:
		out = append(out, 130, byte(len(body)>>8), byte(len(body)))
	}
	return append(out, body...)
}

func fixtureNode(t testing.TB) cmsNode {
	t.Helper()
	data, _, _ := kmsFixture(t)
	remaining := 128
	n, used, err := readCMSNode(data, 0, &remaining)
	if err != nil || used != len(data) {
		t.Fatal("cannot parse published fixture")
	}
	return n
}

func TestCMSDefiniteAndPrimitiveContent(t *testing.T) {
	_, private, expected := kmsFixture(t)
	for _, primitive := range []bool{false, true} {
		n := fixtureNode(t)
		if primitive {
			content := &n.children[1].children[0].children[2].children[2]
			value, err := appendCMSOctets(nil, *content)
			if err != nil {
				t.Fatal(err)
			}
			*content = cmsNode{tag: 128, body: value}
		}
		got, err := UnwrapCMS(encodeNode(n), private)
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("definite/primitive interoperability: %v", err)
		}
	}
}

func TestCMSRejectsOtherProfiles(t *testing.T) {
	_, private, _ := kmsFixture(t)
	mutations := map[string]func(*cmsNode){
		"envelope version": func(n *cmsNode) { n.children[0].body = []byte{0} },
		"multiple recipients": func(n *cmsNode) {
			n.children[1].children = append(n.children[1].children, n.children[1].children[0])
		},
		"recipient version": func(n *cmsNode) { n.children[1].children[0].children[0].body = []byte{0} },
		"wrapped key size":  func(n *cmsNode) { n.children[1].children[0].children[3].body = []byte{1} },
		"PKCS1v15": func(n *cmsNode) {
			oid := &n.children[1].children[0].children[2].children[0]
			oid.body[len(oid.body)-1] = 1
		},
		"OAEP defaults": func(n *cmsNode) { n.children[1].children[0].children[2].children[1].children = nil },
		"OAEP hash": func(n *cmsNode) {
			oid := &n.children[1].children[0].children[2].children[1].children[0].children[0].children[0]
			oid.body[len(oid.body)-1] = 2
		},
		"MGF hash": func(n *cmsNode) {
			oid := &n.children[1].children[0].children[2].children[1].children[1].children[0].children[1].children[0]
			oid.body[len(oid.body)-1] = 2
		},
		"extra parameter": func(n *cmsNode) {
			p := &n.children[1].children[0].children[2].children[1]
			p.children = append(p.children, p.children[0])
		},
		"AES128": func(n *cmsNode) {
			oid := &n.children[2].children[1].children[0]
			oid.body[len(oid.body)-1] = 2
		},
		"bad IV":               func(n *cmsNode) { n.children[2].children[1].children[1].body = make([]byte, 15) },
		"short ciphertext":     func(n *cmsNode) { n.children[2].children[2] = cmsNode{tag: 128, body: make([]byte, 16)} },
		"extra envelope field": func(n *cmsNode) { n.children = append(n.children, cmsNode{tag: 5}) },
		"nested wrong tag": func(n *cmsNode) {
			n.children[2].children[2] = cmsNode{tag: 160, children: []cmsNode{{tag: 2, body: []byte{0}}}}
		},
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			n := fixtureNode(t)
			change(&n.children[1].children[0])
			if _, _, _, err := parseCMS(encodeNode(n)); err == nil {
				t.Fatal("invalid profile reached crypto")
			}
			if plain, err := UnwrapCMS(encodeNode(n), private); err == nil || len(plain) != 0 {
				t.Fatal("invalid CMS accepted")
			}
		})
	}
}

func TestCMSRejectsMalformedBERAndCiphertext(t *testing.T) {
	valid, private, _ := kmsFixture(t)
	inputs := [][]byte{
		nil, {48}, {48, 128}, {48, 130, 255, 255}, {4, 128, 0, 0},
		{0, 0}, {31, 0}, {48, 2, 0, 0}, {48, 129, 0},
		append(bytes.Clone(valid), 0, 0), bytes.Repeat([]byte{48, 128}, 40),
		bytes.Repeat([]byte{1}, MaxCMSBytes+1),
	}
	for i := 0; i < len(valid); i++ {
		inputs = append(inputs, valid[:i])
	}
	for _, data := range inputs {
		if plain, err := UnwrapCMS(data, private); err == nil || len(plain) != 0 {
			t.Fatal("malformed BER accepted")
		}
	}
	n := fixtureNode(t)
	// Change the second CBC block so the final padding block is invalid.
	content := &n.children[1].children[0].children[2].children[2]
	value, _ := appendCMSOctets(nil, *content)
	value[31] ^= 1
	*content = cmsNode{tag: 128, body: value}
	if _, err := UnwrapCMS(encodeNode(n), private); err == nil {
		t.Fatal("bad CBC padding accepted")
	}
	if _, err := UnwrapCMS(valid, nil); err == nil {
		t.Fatal("missing recipient key accepted")
	}
}

func FuzzCMSParser(f *testing.F) {
	fixture, _, _ := kmsFixture(f)
	f.Add(fixture)
	f.Add([]byte{48, 128, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parseCMS(data)
	})
}
