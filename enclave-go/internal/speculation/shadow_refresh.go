package speculation

// VerifyShadowRefreshGrant keeps deployment bindings pinned while allowing the
// signed authority to advance health epochs. VerifyGrant itself retains its exact
// binding contract for all existing callers and wire fixtures.
func VerifyShadowRefreshGrant(token string, keys []TrustedKey, context map[string]any, now int64) (VerifiedGrant, error) {
	claims, _, _, err := shadowRefreshClaims(token, keys)
	if err != nil {
		return VerifiedGrant{}, err
	}
	bindings := make(map[string]any, len(context))
	for k, v := range context {
		bindings[k] = v
	}
	bindings["workspace_epoch"] = claims["workspace_epoch"]
	bindings["key_epoch"] = claims["key_epoch"]
	return VerifyGrant(token, keys, bindings, now, true)
}

func shadowRefreshClaims(token string, keys []TrustedKey) (claims map[string]any, key TrustedKey, payload []byte, err error) {
	defer refusal(&err)
	claims, key, payload = verify(token, keys, ShadowTyp, "shadow-grant")
	return
}
