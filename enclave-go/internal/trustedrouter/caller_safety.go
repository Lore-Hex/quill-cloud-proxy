package trustedrouter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const callerSafetyTag = "safety_identifier"

type callerSafetyKey struct{}
type callerSafety struct{ workspace, activity, openAI string }

func callerSafetyHash(domain, workspace, inputDigest string) string {
	sum := sha256.Sum256([]byte("trustedrouter/caller-safety/" + domain + "/v1\x00" + workspace + "\x00" + inputDigest))
	return hex.EncodeToString(sum[:])
}

// BindCallerSafety uses the authenticated workspace, not the bearer or the
// key creator: rotating keys preserves an app's pseudonyms. Only opted-in
// requests need the metadata lookup; it does not create a billing hold.
func (c *Client) BindCallerSafety(ctx context.Context, bearer, route, inputDigest string, req *qtypes.OpenAIChatRequest) (context.Context, error) {
	if _, exists := req.Tags.Values()[callerSafetyTag]; exists {
		return ctx, &qtypes.TagValidationError{Message: "do not supply both safety_identifier and tags.safety_identifier"}
	}
	identity, err := c.ValidateKeyInfo(ctx, bearer, route)
	if err != nil {
		return ctx, err
	}
	if identity == nil || identity.WorkspaceID == "" {
		return ctx, &ControlPlaneError{StatusCode: 503, Type: "attribution_unavailable", Message: "workspace attribution unavailable"}
	}
	ws := identity.WorkspaceID
	s := &callerSafety{ws, callerSafetyHash("activity", ws, inputDigest), callerSafetyHash("openai", ws, inputDigest)}
	if err := s.attach(req); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, callerSafetyKey{}, s), nil
}

func (s *callerSafety) attach(req *qtypes.OpenAIChatRequest) error {
	m := req.Tags.Values()
	if value, ok := m[callerSafetyTag]; ok && value == s.activity {
		return nil
	}
	if m == nil {
		m = qtypes.TagMap{}
	}
	m[callerSafetyTag] = s.activity
	tags, err := qtypes.ValidateTags(m)
	if err == nil {
		req.Tags = qtypes.NewRequestTags(tags)
	}
	return err
}

// CallerOpenAISafety returns a caller digest only for the matching, tagged
// authorization. A caller-provided tag alone can never select a provider ID.
func CallerOpenAISafety(ctx context.Context, a *Authorization) (string, error) {
	s, _ := ctx.Value(callerSafetyKey{}).(*callerSafety)
	if s == nil {
		return "", nil
	}
	if a == nil || a.WorkspaceID != s.workspace || a.RequestMetadataVersion < 1 || a.Tags[callerSafetyTag] != s.activity {
		return "", errors.New("caller safety attribution did not match authorization")
	}
	return s.openAI, nil
}
