package awssealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
)

var errCMS = errors.New("aws sealed bootstrap: invalid recipient envelope")

// KMS uses BER EnvelopedData, including indefinite constructed lengths. Accept
// only the small RSA-OAEP-SHA256 / AES-256-CBC profile needed for a 32-byte key.
// Parsing never invokes cryptography until structure, algorithms and sizes pass.
type cmsNode struct {
	tag      byte
	body     []byte
	children []cmsNode
}

func readCMSNode(data []byte, depth int, remaining *int) (cmsNode, int, error) {
	if len(data) < 2 || depth > 16 || *remaining <= 0 || data[0] == 0 || data[0]&31 == 31 {
		return cmsNode{}, 0, errCMS
	}
	*remaining--
	node := cmsNode{tag: data[0]}
	start, size := 2, int(data[1])
	indefinite := size == 128
	if indefinite && node.tag&32 == 0 {
		return cmsNode{}, 0, errCMS
	}
	if size > 128 {
		count := size & 127
		if count > 2 || len(data) < 2+count || data[2] == 0 {
			return cmsNode{}, 0, errCMS
		}
		size = 0
		for _, b := range data[2 : 2+count] {
			size = size*256 + int(b)
		}
		start += count
	}
	end := len(data)
	if !indefinite {
		if size > len(data)-start {
			return cmsNode{}, 0, errCMS
		}
		end = start + size
	}
	if node.tag&32 == 0 {
		node.body = data[start:end]
		return node, end, nil
	}
	for offset := start; ; {
		if !indefinite && offset == end {
			return node, end, nil
		}
		if indefinite && end-offset >= 2 && data[offset] == 0 && data[offset+1] == 0 {
			return node, offset + 2, nil
		}
		child, used, err := readCMSNode(data[offset:end], depth+1, remaining)
		if err != nil {
			return cmsNode{}, 0, errCMS
		}
		node.children = append(node.children, child)
		offset += used
	}
}

func (n cmsNode) shape(tag byte, count int) bool {
	return n.tag == tag && len(n.children) == count
}

func (n cmsNode) oid(value asn1.ObjectIdentifier) bool {
	encoded, err := asn1.Marshal(value)
	return err == nil && n.tag == 6 && bytes.Equal(n.body, encoded[2:])
}

func (n cmsNode) version2() bool {
	return n.tag == 2 && bytes.Equal(n.body, []byte{2})
}

var (
	oidEnveloped  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidOAEP       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

func sha256Algorithm(n cmsNode) bool {
	if n.tag != 48 || len(n.children) < 1 || len(n.children) > 2 || !n.children[0].oid(oidSHA256) {
		return false
	}
	return len(n.children) == 1 || n.children[1].tag == 5 && len(n.children[1].body) == 0
}

func oaepAlgorithm(n cmsNode) bool {
	if !n.shape(48, 2) || !n.children[0].oid(oidOAEP) {
		return false
	}
	p := n.children[1]
	if p.tag != 48 || len(p.children) < 2 || len(p.children) > 3 {
		return false
	}
	hash, mgf := p.children[0], p.children[1]
	if !hash.shape(160, 1) || !sha256Algorithm(hash.children[0]) || !mgf.shape(161, 1) {
		return false
	}
	m := mgf.children[0]
	if !m.shape(48, 2) || !m.children[0].oid(oidMGF1) || !sha256Algorithm(m.children[1]) {
		return false
	}
	if len(p.children) == 3 {
		label := p.children[2]
		if !label.shape(162, 1) || !label.children[0].shape(48, 2) {
			return false
		}
		algorithm := label.children[0].children
		if !algorithm[0].oid(oidPSpecified) || algorithm[1].tag != 4 || len(algorithm[1].body) != 0 {
			return false
		}
	}
	return true
}

func appendCMSOctets(dst []byte, n cmsNode) ([]byte, error) {
	return appendBoundedOctets(dst, n, 48)
}

func appendBoundedOctets(dst []byte, n cmsNode, max int) ([]byte, error) {
	if n.tag == 4 || n.tag == 128 {
		if len(n.body) > max-len(dst) {
			return nil, errCMS
		}
		return append(dst, n.body...), nil
	}
	if n.tag != 36 && n.tag != 160 {
		return nil, errCMS
	}
	for _, child := range n.children {
		if child.tag != 4 && child.tag != 36 {
			return nil, errCMS
		}
		var err error
		dst, err = appendBoundedOctets(dst, child, max)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func parseCMS(data []byte) (wrapped, iv, ciphertext []byte, err error) {
	return parseBoundedCMS(data, 48, 48)
}

func parseBoundedCMS(data []byte, minLen, maxLen int) (wrapped, iv, ciphertext []byte, err error) {
	if len(data) == 0 || len(data) > MaxCMSBytes {
		return nil, nil, nil, errCMS
	}
	remaining := 128
	root, used, err := readCMSNode(data, 0, &remaining)
	if err != nil || used != len(data) || !root.shape(48, 2) || !root.children[0].oid(oidEnveloped) || !root.children[1].shape(160, 1) {
		return nil, nil, nil, errCMS
	}
	envelope := root.children[1].children[0]
	if !envelope.shape(48, 3) || !envelope.children[0].version2() || !envelope.children[1].shape(49, 1) {
		return nil, nil, nil, errCMS
	}
	r := envelope.children[1].children[0]
	if !r.shape(48, 4) || !r.children[0].version2() || r.children[1].tag != 128 || len(r.children[1].body) == 0 || len(r.children[1].body) > 64 ||
		!oaepAlgorithm(r.children[2]) || r.children[3].tag != 4 || len(r.children[3].body) != 256 {
		return nil, nil, nil, errCMS
	}
	content := envelope.children[2]
	if !content.shape(48, 3) || !content.children[0].oid(oidData) {
		return nil, nil, nil, errCMS
	}
	algorithm := content.children[1]
	if !algorithm.shape(48, 2) || !algorithm.children[0].oid(oidAES256CBC) || algorithm.children[1].tag != 4 || len(algorithm.children[1].body) != aes.BlockSize ||
		(content.children[2].tag != 128 && content.children[2].tag != 160) {
		return nil, nil, nil, errCMS
	}
	ciphertext, err = appendBoundedOctets(nil, content.children[2], maxLen)
	if err != nil || len(ciphertext) < minLen || len(ciphertext)%aes.BlockSize != 0 {
		return nil, nil, nil, errCMS
	}
	return r.children[3].body, algorithm.children[1].body, ciphertext, nil
}

// UnwrapCMS returns only a 32-byte AES key, never arbitrary KMS plaintext. The
// caller must verify the signed outer bundle first; CMS is not a KMS signature.
func UnwrapCMS(data []byte, private *rsa.PrivateKey) ([]byte, error) {
	wrapped, iv, ciphertext, err := parseCMS(data)
	if err != nil {
		return nil, errCMS
	}
	plain, err := decryptCMSBlocks(wrapped, iv, ciphertext, private)
	if err != nil {
		return nil, errCMS
	}
	defer clear(plain)
	valid := 1
	for _, b := range plain[32:] {
		valid &= subtle.ConstantTimeByteEq(b, 16)
	}
	if valid != 1 {
		return nil, errCMS
	}
	return bytes.Clone(plain[:32]), nil
}

func decryptCMSBlocks(wrapped, iv, ciphertext []byte, private *rsa.PrivateKey) ([]byte, error) {
	if private == nil || private.N == nil || private.N.BitLen() != 2048 || private.E != 65537 {
		return nil, errCMS
	}
	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, wrapped, nil)
	defer clear(contentKey)
	if err != nil || len(contentKey) != 32 {
		return nil, errCMS
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, errCMS
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return plain, nil
}
