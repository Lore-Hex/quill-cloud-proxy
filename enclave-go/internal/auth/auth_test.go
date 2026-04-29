package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRegistry(t *testing.T) {
	key1 := "quill_key_1"
	hash1 := sha256.Sum256([]byte(key1))
	hex1 := hex.EncodeToString(hash1[:])

	key2 := "quill_key_2"
	hash2 := sha256.Sum256([]byte(key2))
	hex2 := hex.EncodeToString(hash2[:])

	devices := []types.DeviceConfig{
		{DeviceID: "d1", KeyHash: hex1},
		{DeviceID: "d2", KeyHash: hex2},
	}

	reg := New(devices)

	t.Run("successful lookup", func(t *testing.T) {
		d := reg.Lookup(key1)
		if d == nil || d.DeviceID != "d1" {
			t.Errorf("expected d1, got %v", d)
		}
		
		d = reg.Lookup(key2)
		if d == nil || d.DeviceID != "d2" {
			t.Errorf("expected d2, got %v", d)
		}
	})

	t.Run("failed lookup", func(t *testing.T) {
		d := reg.Lookup("wrong_key")
		if d != nil {
			t.Errorf("expected nil for wrong key, got %v", d)
		}
	})

	t.Run("replace registry", func(t *testing.T) {
		key3 := "quill_key_3"
		hash3 := sha256.Sum256([]byte(key3))
		hex3 := hex.EncodeToString(hash3[:])

		reg.Replace([]types.DeviceConfig{
			{DeviceID: "d3", KeyHash: hex3},
		})

		if reg.Lookup(key1) != nil {
			t.Error("expected key1 to be gone after replace")
		}
		d := reg.Lookup(key3)
		if d == nil || d.DeviceID != "d3" {
			t.Errorf("expected d3, got %v", d)
		}
	})
}
