//go:build cloud_aws

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap/awssealed"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

func TestAWSBootstrapMixedPairings(t *testing.T) {
	for _, pair := range []struct{ mode, parent, expected string }{
		{"legacy", "v1", "legacy"}, {"legacy", "v2", "legacy"},
		{"transition", "v1", "legacy"}, {"transition", "v2", "attested"},
		{"strict", "v2", "attested"},
	} {
		t.Run(pair.mode+"-"+pair.parent, func(t *testing.T) {
			sealedCalls, legacyCalls := 0, 0
			sealed := func(context.Context) ([]byte, awssealed.Manifest, error) {
				sealedCalls++
				if pair.parent == "v1" {
					return nil, awssealed.Manifest{}, errors.New("aws sealed bootstrap: parent unavailable")
				}
				return []byte("{\"region\":\"eu-west-1\"}"), awssealed.Manifest{Region: "eu-west-1", Version: 1}, nil
			}
			legacy := func(context.Context) (*types.BootstrapData, error) {
				legacyCalls++
				return &types.BootstrapData{Region: "eu-west-1"}, nil
			}
			data, err := fetchAWS(t.Context(), pair.mode, sealed, legacy, time.Second, time.Millisecond)
			if err != nil || data.Region != "eu-west-1" {
				t.Fatalf("fetch: %v", err)
			}
			if pair.mode == "legacy" && sealedCalls != 0 {
				t.Fatal("V1 attempted V2")
			}
			if pair.expected == "attested" && legacyCalls != 0 {
				t.Fatal("attested boot touched V1")
			}
			if pair.expected == "legacy" && legacyCalls != 1 {
				t.Fatal("legacy boot not used")
			}
		})
	}
}

func TestAWSTransitionFallbackForEveryV2Failure(t *testing.T) {
	for _, reason := range []string{
		"connection refused", "KMS AccessDenied", "bundle absent",
		"aws sealed bootstrap: signature rejected", "aws sealed bootstrap: bundle version",
		"aws sealed bootstrap: ciphertext rejected", "invalid CMS", "NSM unavailable",
	} {
		t.Run(reason, func(t *testing.T) {
			calls := 0
			data, err := fetchAWS(t.Context(), "transition",
				func(context.Context) ([]byte, awssealed.Manifest, error) {
					return nil, awssealed.Manifest{}, errors.New(reason)
				},
				func(context.Context) (*types.BootstrapData, error) {
					calls++
					return &types.BootstrapData{Region: "eu-west-3"}, nil
				}, time.Second, time.Millisecond)
			if err != nil || data.Region != "eu-west-3" || calls != 1 {
				t.Fatal("fallback failed")
			}
		})
	}
}

func TestAWSStrictRetriesAndNeverTouchesLegacy(t *testing.T) {
	calls := 0
	_, err := fetchAWS(t.Context(), "strict",
		func(context.Context) ([]byte, awssealed.Manifest, error) {
			calls++
			return nil, awssealed.Manifest{}, errors.New("KMS denied")
		},
		func(context.Context) (*types.BootstrapData, error) {
			t.Fatal("strict boot dialed V1")
			return nil, nil
		}, 30*time.Millisecond, time.Millisecond)
	if err == nil || calls < 2 {
		t.Fatal("strict mode did not retry then fail closed")
	}
}

func TestAWSBootCancellationStopsWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	start := time.Now()
	_, err := fetchAWS(ctx, "strict",
		func(context.Context) ([]byte, awssealed.Manifest, error) {
			cancel()
			return nil, awssealed.Manifest{}, errors.New("unavailable")
		}, nil, time.Minute, time.Minute)
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("boot ignored cancellation")
	}
}

func TestAWSSignedPayloadRegionAndJSONRejected(t *testing.T) {
	for _, body := range []string{"null", "{", "{\"region\":\"eu-west-3\"}"} {
		calls := 0
		_, err := fetchAWS(t.Context(), "transition",
			func(context.Context) ([]byte, awssealed.Manifest, error) {
				return []byte(body), awssealed.Manifest{Region: "eu-west-1", Version: 1}, nil
			},
			func(context.Context) (*types.BootstrapData, error) {
				calls++
				return &types.BootstrapData{}, nil
			}, time.Second, time.Millisecond)
		if err != nil || calls != 1 {
			t.Fatal("invalid signed payload was accepted")
		}
	}
}

func TestAWSMeasuredTrustConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	for _, mode := range []string{"transition", "strict"} {
		public, minimum, err := measuredAWSConfig(mode, encoded, "7")
		if err != nil || public.Curve != elliptic.P384() || minimum != 7 {
			t.Fatal("valid measured config rejected")
		}
	}
	for _, test := range []struct{ mode, key, minimum string }{
		{"unknown", encoded, "1"}, {"strict", "", "1"}, {"transition", "invalid", "1"},
		{"strict", encoded, "0"}, {"strict", encoded, "-1"},
		{"strict", encoded, "9007199254740992"},
	} {
		if _, _, err := measuredAWSConfig(test.mode, test.key, test.minimum); err == nil {
			t.Fatalf("accepted invalid measured configuration: %s/%s", test.mode, test.minimum)
		}
	}
}

type fakeBootstrapNSM struct {
	t             *testing.T
	public, nonce []byte
	closed        bool
}

func (s *fakeBootstrapNSM) Close() error { s.closed = true; return nil }
func (s *fakeBootstrapNSM) Send(req request.Request) (response.Response, error) {
	a, ok := req.(*request.Attestation)
	if !ok || !bytes.Equal(a.PublicKey, s.public) || !bytes.Equal(a.Nonce, s.nonce) ||
		string(a.UserData) != awssealed.Protocol {
		s.t.Fatal("recipient not bound to NSM request")
	}
	return response.Response{Attestation: &response.Attestation{Document: []byte("signed-document")}}, nil
}
func TestAWSBootstrapNSMBindsRecipientAndNonce(t *testing.T) {
	session := &fakeBootstrapNSM{t: t, public: []byte("ephemeral-spki"), nonce: bytes.Repeat([]byte{7}, 32)}
	doc, err := attestBootstrapWith(t.Context(), session.public, session.nonce,
		func() (bootstrapNSMSession, error) { return session, nil })
	if err != nil || string(doc) != "signed-document" || !session.closed {
		t.Fatal("NSM adapter failed")
	}
}

func TestAWSFallbackLogReasonNeverIncludesPayload(t *testing.T) {
	if got := awsFallbackReason(errors.New("secret=do-not-log")); got != "v2_exchange_failed" {
		t.Fatal("unexpected error detail leaked")
	}
}
