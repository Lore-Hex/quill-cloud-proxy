package transcription

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestPrivatemodeTranscriptionNeverUsesOrdinaryHTTP(t *testing.T) {
	ordinary := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("audio escaped encrypted proxy")
		return nil, errors.New("unexpected request")
	})}
	for _, model := range []string{"openai/whisper-large-v3", "mistralai/voxtral-mini-3b-2507"} {
		for _, get := range []func() (*http.Client, error){nil, func() (*http.Client, error) { return nil, nil }, func() (*http.Client, error) { return nil, errors.New("verification failed") }} {
			client := New(ordinary, map[string]string{"privatemode": "test-key"}, func() (*http.Client, error) { t.Fatal("wrong provider verifier"); return nil, nil }).WithPrivatemodeAttestation(get)
			if _, err := client.Transcribe(context.Background(), &Request{Model: model, Audio: []byte("synthetic")}); err == nil {
				t.Fatal("unverified audio accepted")
			}
		}
	}
}
