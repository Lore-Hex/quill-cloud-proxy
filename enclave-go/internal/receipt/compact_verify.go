package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// VerifyCompactJWS authenticates against caller-configured keys, never an
// embedded key. Its restricted JSON/base64 wire rules match detached_jws.py;
// callers own claim bindings and the purpose-specific type/keyring.
func VerifyCompactJWS(token string, keys map[string]ed25519.PublicKey, typ string) ([]byte, error) {
	if len(token) > 65536 || strings.Count(token, ".") != 2 {
		return nil, errors.New("compact")
	}
	for _, part := range strings.Split(token, ".") {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || part == "" || base64.RawURLEncoding.EncodeToString(raw) != part {
			return nil, errors.New("base64")
		}
	}
	parts, err := ParseJWS([]byte(token))
	if err != nil {
		return nil, err
	}
	header, err := strictJWSObject(parts.ProtectedJSON)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, parts.ProtectedJSON) {
		return nil, errors.New("canonical_header")
	}
	kid, ok := header["kid"].(string)
	if len(header) != 3 || header["alg"] != "EdDSA" || header["typ"] != typ || !ok || kid == "" || strings.ContainsAny(kid, `<>&`) {
		return nil, errors.New("header")
	}
	key := keys[kid]
	if len(key) != ed25519.PublicKeySize || len(parts.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, parts.SigningInput, parts.Signature) {
		return nil, errors.New("signature")
	}
	if _, err := strictJWSObject(parts.PayloadJSON); err != nil {
		return nil, err
	}
	return parts.PayloadJSON, nil
}

// Reject duplicate members, escapes/non-ASCII, floats, out-of-domain integers,
// non-object claims, and excessive nesting before typed claim decoding.
func strictJWSObject(raw []byte) (map[string]any, error) {
	for _, b := range raw {
		if b < 0x20 || b > 0x7e || b == '\\' {
			return nil, errors.New("json")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictJWSValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("json")
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("fields")
	}
	return result, nil
}
func strictJWSValue(d *json.Decoder, depth int) (any, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Number:
		digits := strings.TrimPrefix(string(v), "-")
		if len(digits) > 19 || strings.ContainsAny(string(v), ".eE") {
			return nil, errors.New("integer")
		}
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < 0 {
			return nil, errors.New("integer")
		}
		return n, nil
	case json.Delim:
		if depth >= 16 {
			return nil, errors.New("json")
		}
		switch v {
		case '{':
			result := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("json")
				}
				if _, exists := result[name]; exists {
					return nil, errors.New("duplicate_key")
				}
				value, err := strictJWSValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				result[name] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("json")
			}
			return result, nil
		case '[':
			result := []any{}
			for d.More() {
				value, err := strictJWSValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("json")
			}
			return result, nil
		default:
			return nil, errors.New("json")
		}
	default:
		return token, nil
	}
}
