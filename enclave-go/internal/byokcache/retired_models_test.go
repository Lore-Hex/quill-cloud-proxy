package byokcache

import "testing"

func TestRetiredOwnerCredentialsNeverUnwrapOrReadCache(t *testing.T) {
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})
	envelope := sealWith(t, AlgorithmV2, mustAADv2(t, namespaceUserModel, "owner-ws", "user_model_signing"), "owner-secret")
	for range 2 {
		secret, cached, err := cache.ResolveUserModel(t.Context(), "owner-ws", "user_model_signing", envelope)
		if secret != "" || cached || err == nil {
			t.Fatal("retired credential resolved")
		}
	}
	if unwrapper.calls != 0 || cache.Size() != 0 {
		t.Fatal("retired credential reached key unwrapping or cache")
	}
	if _, _, err := cache.Resolve(t.Context(), "owner-ws", "user_model_signing", "", envelope); err == nil {
		t.Fatal("retired credential opened through ordinary BYOK")
	}
}
