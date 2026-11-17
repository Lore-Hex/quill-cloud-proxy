//go:build cloud_aws

// Package bootstrap loads startup configuration using a cloud-specific adapter.
// AWS's measured bootstrap mode selects legacy, transitional, or strict release.
// Transitional mode is NOT confidential: any v2 failure permits the parent to
// supply V1 plaintext. Only strict images, with V1 images removed from every
// accepted measurement set and legacy IAM revoked, close that downgrade path.
package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap/awssealed"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const (
	ParentCID           uint32 = 3
	BootstrapPort       uint32 = 9100
	SealedBootstrapPort uint32 = 9101
)

// These values are linked into the measured binary, never read from parent
// configuration or runtime environment. Production refuses the legacy
// plaintext path. Changing this policy or signer changes the measurement.
var (
	AWSBootstrapMode        = "strict"
	AWSBundleSignerDER      = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEMlctJbn0WQ7D5J+XBOtI2SW9alu4DXzUwBi60xO0ULnh5KmCMPzd1NDwUbZzorPGnqgUPqpMz/Hqfcp8XjtYnwxaR25F92wQ4veNNzNK4OpZzk+CNmmtCBVwHI+mmmLx"
	AWSMinimumBundleVersion = "1"
)

type bootstrapNSMSession interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

func attestBootstrap(ctx context.Context, publicDER, nonce []byte) ([]byte, error) {
	return attestBootstrapWith(ctx, publicDER, nonce, func() (bootstrapNSMSession, error) {
		return nsm.OpenDefaultSession()
	})
}

func attestBootstrapWith(ctx context.Context, publicDER, nonce []byte, open func() (bootstrapNSMSession, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := open()
	if err != nil {
		return nil, errors.New("bootstrap: NSM unavailable")
	}
	defer session.Close()
	result, err := session.Send(&request.Attestation{
		Nonce: nonce, PublicKey: publicDER, UserData: []byte(awssealed.Protocol),
	})
	if err != nil || result.Error != "" || result.Attestation == nil ||
		len(result.Attestation.Document) == 0 || len(result.Attestation.Document) > awssealed.MaxDocumentBytes {
		return nil, errors.New("bootstrap: NSM document unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result.Attestation.Document, nil
}

func measuredAWSConfig(mode, encoded, minimumText string) (*ecdsa.PublicKey, uint64, error) {
	if mode == "legacy" {
		return nil, 0, nil
	}
	if mode != "transition" && mode != "strict" {
		return nil, 0, errors.New("bootstrap: invalid measured mode")
	}
	minimum, err := strconv.ParseUint(minimumText, 10, 64)
	if err != nil || minimum == 0 || minimum > 1<<53-1 {
		return nil, 0, errors.New("bootstrap: invalid measured minimum")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(der) > 256 {
		return nil, 0, errors.New("bootstrap: invalid measured signer")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, 0, errors.New("bootstrap: invalid measured signer")
	}
	key, ok := public.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, 0, errors.New("bootstrap: signer must be P-384")
	}
	return key, minimum, nil
}

type sealedFetch func(context.Context) ([]byte, awssealed.Manifest, error)
type legacyFetch func(context.Context) (*types.BootstrapData, error)

// Fetch bounds the complete boot sequence, including connect and retry waits.
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	signer, minimum, err := measuredAWSConfig(AWSBootstrapMode, AWSBundleSignerDER, AWSMinimumBundleVersion)
	if err != nil {
		return nil, err
	}
	return fetchAWS(ctx, AWSBootstrapMode, func(ctx context.Context) ([]byte, awssealed.Manifest, error) {
		return awssealed.Fetch(ctx, func(ctx context.Context) (net.Conn, error) {
			return dialBootstrap(ctx, SealedBootstrapPort)
		}, attestBootstrap, signer, minimum)
	}, fetchAWSLegacy, 30*time.Second, 2*time.Second)
}

func fetchAWS(ctx context.Context, mode string, sealed sealedFetch, legacy legacyFetch, budget, pause time.Duration) (*types.BootstrapData, error) {
	if mode != "legacy" && mode != "transition" && mode != "strict" {
		return nil, errors.New("bootstrap: invalid mode")
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for ctx.Err() == nil {
		if mode != "legacy" {
			attempt, stop := context.WithTimeout(ctx, 8*time.Second)
			body, manifest, err := sealed(attempt)
			stop()
			if err == nil {
				data, decodeErr := decodeAWSBootstrap(body)
				if decodeErr == nil && data.Region == manifest.Region && ctx.Err() == nil {
					data.AWSBootstrap = &types.AWSBootstrapEvidence{Policy: mode, Mode: "attested", BundleVersion: manifest.Version}
					clear(body)
					log.Printf("bootstrap.aws mode=attested region=%s version=%d", manifest.Region, manifest.Version)
					return data, nil
				}
				err = errors.New("bootstrap: signed payload rejected")
			}
			clear(body)
			if mode == "transition" {
				log.Printf("bootstrap.aws mode=legacy_fallback reason=%s", awsFallbackReason(err))
			} else {
				log.Printf("bootstrap.aws mode=strict_retry reason=%s", awsFallbackReason(err))
			}
		}
		if mode == "legacy" || mode == "transition" {
			attempt, stop := context.WithTimeout(ctx, 10*time.Second)
			data, err := legacy(attempt)
			stop()
			if err == nil && data != nil && ctx.Err() == nil {
				data.AWSBootstrap = &types.AWSBootstrapEvidence{Policy: mode, Mode: "legacy"}
				log.Printf("bootstrap.aws mode=legacy")
				return data, nil
			}
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil, errors.New("bootstrap: parent unavailable within boot deadline")
}

func awsFallbackReason(err error) string {
	if err == nil {
		return "empty_result"
	}
	switch err.Error() {
	case "aws sealed bootstrap: parent unavailable":
		return "parent_unavailable"
	case "aws sealed bootstrap: response read failed":
		return "response_unavailable"
	case "aws sealed bootstrap: signature rejected":
		return "signature_rejected"
	case "aws sealed bootstrap: bundle version":
		return "version_rejected"
	case "aws sealed bootstrap: hardware attestation unavailable":
		return "hardware_unavailable"
	case "bootstrap: signed payload rejected":
		return "payload_rejected"
	default:
		return "v2_exchange_failed"
	}
}

func decodeAWSBootstrap(body []byte) (*types.BootstrapData, error) {
	var data *types.BootstrapData
	if err := json.Unmarshal(body, &data); err != nil || data == nil {
		return nil, errors.New("bootstrap: payload JSON rejected")
	}
	return data, nil
}

func fetchAWSLegacy(ctx context.Context) (*types.BootstrapData, error) {
	conn, err := dialBootstrap(ctx, BootstrapPort)
	if err != nil {
		return nil, errors.New("bootstrap: legacy parent unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, errors.New("bootstrap: legacy deadline")
		}
	}
	const maximum = 1 << 20
	body, err := io.ReadAll(io.LimitReader(conn, maximum+1))
	defer clear(body)
	if err != nil || len(body) > maximum {
		return nil, errors.New("bootstrap: legacy payload unavailable")
	}
	return decodeAWSBootstrap(body)
}
