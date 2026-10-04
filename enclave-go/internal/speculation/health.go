package speculation

// ScopeHealth is a trusted local snapshot, not a token claim. Known and Healthy
// must both be affirmative. An absent map entry or zero value cannot reopen a
// scope after denial, expiry of Retry-After, or a delayed grant delivery.
type ScopeHealth struct {
	Known, Healthy, Latched bool
	Epoch                   int64
}

// LocalHealth belongs to the named workspace/key and provider on this boot.
// Snapshot acquisition and atomic resource reservation belong to later PRs.
type LocalHealth struct {
	WorkspaceID, KeyID, Provider                          string
	Workspace, Key                                        ScopeHealth
	ProviderKnown, ProviderHealthy, InfrastructureHealthy bool
}

func healthReason(c map[string]any, h LocalHealth) Reason {
	if !h.Workspace.Known || !h.Key.Known || !h.ProviderKnown ||
		h.WorkspaceID != c["workspace_id"] || h.KeyID != c["key_id"] || h.Provider != c["route"].(map[string]any)["provider"] {
		return ReasonHealthMissing
	}
	if h.Workspace.Latched {
		return ReasonWorkspaceLatch
	}
	if h.Key.Latched {
		return ReasonKeyLatch
	}
	if !h.Workspace.Healthy || !h.Key.Healthy || !h.ProviderHealthy || !h.InfrastructureHealthy {
		return ReasonHealth
	}
	if h.Workspace.Epoch != number(c, "workspace_epoch") {
		return ReasonWorkspaceEpoch
	}
	if h.Key.Epoch != number(c, "key_epoch") {
		return ReasonKeyEpoch
	}
	return ReasonEligible
}
