package llm

import (
	"bytes"
	"compress/gzip"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	chutesMLKEMCiphertextSize = 1088
	chutesNonceSize           = chacha20poly1305.NonceSize
	chutesTagSize             = 16

	chutesRequestKDFInfo  = "e2e-req-v1"
	chutesResponseKDFInfo = "e2e-resp-v1"
	chutesStreamKDFInfo   = "e2e-stream-v1"
)

type chutesEncryptedRequest struct {
	blob       []byte
	responseSK *mlkem.DecapsulationKey768
}

func deriveChutesKey(sharedSecret, mlkemCiphertext []byte, info string) ([]byte, error) {
	if len(mlkemCiphertext) < 16 {
		return nil, fmt.Errorf("chutes e2ee: ML-KEM ciphertext too short: %d", len(mlkemCiphertext))
	}
	reader := hkdf.New(sha256.New, sharedSecret, mlkemCiphertext[:16], []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("chutes e2ee: derive key: %w", err)
	}
	return key, nil
}

func buildChutesEncryptedRequest(e2ePubkey string, payload any) (*chutesEncryptedRequest, error) {
	pubkeyBytes, err := base64.StdEncoding.DecodeString(e2ePubkey)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decode instance public key: %w", err)
	}
	instanceKey, err := mlkem.NewEncapsulationKey768(pubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: invalid instance ML-KEM-768 key: %w", err)
	}
	sharedSecret, mlkemCiphertext := instanceKey.Encapsulate()
	if len(mlkemCiphertext) != chutesMLKEMCiphertextSize {
		return nil, fmt.Errorf("chutes e2ee: unexpected ML-KEM ciphertext size %d", len(mlkemCiphertext))
	}
	requestKey, err := deriveChutesKey(sharedSecret, mlkemCiphertext, chutesRequestKDFInfo)
	if err != nil {
		return nil, err
	}

	responseSK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: generate response key: %w", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: marshal payload: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &object); err != nil {
		return nil, fmt.Errorf("chutes e2ee: request payload must be a JSON object: %w", err)
	}
	responsePK, err := json.Marshal(base64.StdEncoding.EncodeToString(responseSK.EncapsulationKey().Bytes()))
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: marshal response key: %w", err)
	}
	object["e2e_response_pk"] = responsePK
	payloadBytes, err = json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: marshal encrypted payload: %w", err)
	}

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payloadBytes); err != nil {
		return nil, fmt.Errorf("chutes e2ee: gzip request: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("chutes e2ee: finish gzip request: %w", err)
	}

	aead, err := chacha20poly1305.New(requestKey)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: initialize request cipher: %w", err)
	}
	nonce := make([]byte, chutesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("chutes e2ee: generate request nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, compressed.Bytes(), nil)
	blob := make([]byte, 0, len(mlkemCiphertext)+len(nonce)+len(sealed))
	blob = append(blob, mlkemCiphertext...)
	blob = append(blob, nonce...)
	blob = append(blob, sealed...)
	return &chutesEncryptedRequest{blob: blob, responseSK: responseSK}, nil
}

func decryptChutesResponse(blob []byte, responseSK *mlkem.DecapsulationKey768) ([]byte, error) {
	minimum := chutesMLKEMCiphertextSize + chutesNonceSize + chutesTagSize
	if len(blob) < minimum {
		return nil, fmt.Errorf("chutes e2ee: encrypted response too short: %d", len(blob))
	}
	mlkemCiphertext := blob[:chutesMLKEMCiphertextSize]
	nonce := blob[chutesMLKEMCiphertextSize : chutesMLKEMCiphertextSize+chutesNonceSize]
	sealed := blob[chutesMLKEMCiphertextSize+chutesNonceSize:]
	sharedSecret, err := responseSK.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decapsulate response key: %w", err)
	}
	key, err := deriveChutesKey(sharedSecret, mlkemCiphertext, chutesResponseKDFInfo)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: initialize response cipher: %w", err)
	}
	compressed, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: authenticate response: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: open response gzip: %w", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(zr, 32<<20))
	closeErr := zr.Close()
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decompress response: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("chutes e2ee: close response gzip: %w", closeErr)
	}
	return decompressed, nil
}

func decryptChutesStreamInit(encoded string, responseSK *mlkem.DecapsulationKey768) ([]byte, error) {
	mlkemCiphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decode stream key: %w", err)
	}
	if len(mlkemCiphertext) != chutesMLKEMCiphertextSize {
		return nil, fmt.Errorf("chutes e2ee: invalid stream ML-KEM ciphertext size %d", len(mlkemCiphertext))
	}
	sharedSecret, err := responseSK.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decapsulate stream key: %w", err)
	}
	return deriveChutesKey(sharedSecret, mlkemCiphertext, chutesStreamKDFInfo)
}

func decryptChutesStreamChunk(encoded string, streamKey []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: decode stream chunk: %w", err)
	}
	if len(raw) < chutesNonceSize+chutesTagSize {
		return nil, fmt.Errorf("chutes e2ee: encrypted stream chunk too short: %d", len(raw))
	}
	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: initialize stream cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, raw[:chutesNonceSize], raw[chutesNonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: authenticate stream chunk: %w", err)
	}
	return plaintext, nil
}
