package main

import (
	"encoding/hex"
	"errors"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/phalaaci"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

type phalaCustody struct {
	Provider string `json:"provider"`
	Keys     []struct {
		Role      string   `json:"role"`
		Path      string   `json:"path"`
		Purpose   string   `json:"purpose"`
		Algo      string   `json:"algo"`
		Public    string   `json:"public_key"`
		KMSPublic string   `json:"kms_public_key"`
		Chain     []string `json:"signature_chain"`
	} `json:"keys"`
}

func recoverPhalaKMS(message []byte, signature string) ([]byte, error) {
	raw, err := hex.DecodeString(signature)
	if err != nil || len(raw) != 65 {
		return nil, errors.New("Phala KMS signature malformed")
	}
	recovery := raw[64]
	if recovery >= 27 && recovery <= 30 {
		recovery -= 27
	}
	if recovery > 3 {
		return nil, errors.New("Phala KMS recovery id invalid")
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write(message)
	compact := append([]byte{27 + 4 + recovery}, raw[:64]...)
	key, _, err := ecdsa.RecoverCompact(compact, hash.Sum(nil))
	if err != nil {
		return nil, errors.New("Phala KMS signature verification failed")
	}
	return key.SerializeCompressed(), nil
}

func verifyPhalaCustody(custody phalaCustody, keys *phalaaci.Keyset, appID, root string) error {
	if custody.Provider != "dstack-kms" || len(custody.Keys) > 16 {
		return errors.New("Phala KMS custody missing")
	}
	appBytes, err := hex.DecodeString(appID)
	if err != nil || len(appBytes) != 20 {
		return errors.New("Phala KMS measured app identity invalid")
	}
	// Both the receipt key and selected encryption key must have a custody
	// chain anchored to the reviewed KMS. The curve conversion is guaranteed
	// by the measured release code, not by a self-reported public-key label.
	wanted := append([]phalaaci.Key{}, keys.ReceiptKeys...)
	for _, key := range keys.EncryptionKeys {
		if key.Algo == phalaaci.Suite {
			wanted = append(wanted, key)
		}
	}
	if len(keys.ReceiptKeys) == 0 || len(wanted) <= len(keys.ReceiptKeys) {
		return errors.New("Phala attested keys missing")
	}
	for _, key := range wanted {
		matches := 0
		for _, proof := range custody.Keys {
			if proof.Public != key.PublicKey || proof.Algo != key.Algo {
				continue
			}
			matches++
			purpose, path, role := "aci.receipt.ed25519.v1", "aci/receipt-ed25519/v1", "receipt"
			if key.Algo == phalaaci.Suite {
				purpose, path, role = "aci.e2ee.x25519.v1", "aci/e2ee-x25519/v1", "e2ee-x25519"
			}
			if (key.Algo != "ed25519" && key.Algo != phalaaci.Suite) || proof.Purpose != purpose || proof.Path != path || proof.Role != role || len(proof.Chain) != 2 {
				return errors.New("Phala KMS custody role/path mismatch")
			}
			raw, err := hex.DecodeString(proof.KMSPublic)
			if err != nil {
				return errors.New("Phala KMS public key malformed")
			}
			public, err := secp256k1.ParsePubKey(raw)
			if err != nil {
				return errors.New("Phala KMS public key invalid")
			}
			appKey, err := recoverPhalaKMS([]byte(purpose+":"+hex.EncodeToString(public.SerializeCompressed())), proof.Chain[0])
			if err != nil {
				return err
			}
			message := append([]byte("dstack-kms-issued:"), appBytes...)
			message = append(message, appKey...)
			rootKey, err := recoverPhalaKMS(message, proof.Chain[1])
			if err != nil {
				return err
			}
			if hex.EncodeToString(rootKey) != root {
				return errors.New("Phala KMS root is outside reviewed policy")
			}
		}
		if matches != 1 {
			return errors.New("Phala key custody missing or ambiguous")
		}
	}
	return nil
}
