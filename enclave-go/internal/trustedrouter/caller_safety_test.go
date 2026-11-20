package trustedrouter

import (
	"context"
	"fmt"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestCallerSafetyRequiresWorkspaceAndFrozenTag(t *testing.T) {
	s := &callerSafety{workspace: "workspace-A", activity: "activity-digest", openAI: "provider-digest"}
	ctx := context.WithValue(context.Background(), callerSafetyKey{}, s)
	a := &Authorization{WorkspaceID: s.workspace, RequestMetadataVersion: 1, Tags: qtypes.TagMap{callerSafetyTag: s.activity}}
	if got, err := CallerOpenAISafety(context.Background(), a); got != "" || err != nil {
		t.Fatal("a caller-supplied tag alone changed the provider subject")
	}
	if got, err := CallerOpenAISafety(ctx, a); got != s.openAI || err != nil {
		t.Fatal("matching subject was not bound")
	}
	for _, invalid := range []*Authorization{nil, {WorkspaceID: "workspace-B", RequestMetadataVersion: 1, Tags: a.Tags}, {WorkspaceID: s.workspace, Tags: a.Tags}, {WorkspaceID: s.workspace, RequestMetadataVersion: 1}} {
		if got, err := CallerOpenAISafety(ctx, invalid); got != "" || err == nil {
			t.Fatal("unverified subject was accepted")
		}
	}
}

func TestCallerSafetyTagConflictsAndLimits(t *testing.T) {
	ctx := context.Background()
	r := &qtypes.OpenAIChatRequest{Tags: qtypes.NewRequestTags(qtypes.TagMap{callerSafetyTag: "manual"})}
	if _, err := (*Client)(nil).BindCallerSafety(ctx, "", "", "hash", r); err == nil || r.Tags.Values()[callerSafetyTag] != "manual" {
		t.Fatal("top-level ID and explicit tag must conflict before authorization")
	}
	s := &callerSafety{activity: "generated"}
	tags := qtypes.TagMap{}
	for i := 0; i < qtypes.MaxTags; i++ {
		tags[fmt.Sprint(i)] = "x"
	}
	r.Tags = qtypes.NewRequestTags(tags)
	if err := s.attach(r); err == nil || len(r.Tags.Values()) != qtypes.MaxTags {
		t.Fatal("did not enforce tag capacity")
	}
	child := &qtypes.OpenAIChatRequest{}
	if err := s.attach(child); err != nil || child.Tags.Values()[callerSafetyTag] != s.activity {
		t.Fatal("child call lost attribution")
	}
}
