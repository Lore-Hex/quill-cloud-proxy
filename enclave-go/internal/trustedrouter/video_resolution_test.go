package trustedrouter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizeVideoResolutionContract(t *testing.T) {
	for _, resolution := range []string{"480p", "720p", "1080p", "768p", "2K", "4k"} {
		t.Run(resolution, func(t *testing.T) {
			want := resolution
			if resolution == "768p" || resolution == "2K" || resolution == "4k" {
				want = ""
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				got, present := body["video_resolution"]
				if body["route_type"] != "videos" || (want != "" && got != want) || (want == "" && present) {
					t.Errorf("wrong resolution contract: %#v", body)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"authorization_id": "auth", "additional_cost_reservation_microdollars": 100,
					"video_tariff_resolution": want,
				}})
			}))
			defer server.Close()
			client := New(server.URL, "internal", server.Client())
			auth, _, err := client.AuthorizeVideo(t.Context(), "key", "model", resolution, "idem", "", nil, 100, 1_500_000)
			if err != nil {
				t.Fatal(err)
			}
			if auth.VideoTariffResolution != want {
				t.Fatalf("echo = %q, want %q", auth.VideoTariffResolution, want)
			}
		})
	}
}

func TestAuthorizeNonVideoOmitsVideoResolution(t *testing.T) {
	for _, route := range []string{"chat", "images", "embeddings"} {
		t.Run(route, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if _, exists := body["video_resolution"]; exists {
					t.Errorf("non-video resolution leaked: %#v", body)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"authorization_id": "auth"}})
			}))
			defer server.Close()
			client := New(server.URL, "internal", server.Client())
			// Even an accidentally populated internal field cannot alter other routes.
			_, err := client.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{Model: "model", VideoResolution: "1080p"}, route)
			if err != nil {
				t.Fatal(err)
			}
			if route == "embeddings" {
				_, err = client.AuthorizeEmbeddings(t.Context(), "key", &qtypes.EmbeddingRequest{Model: "model"}, 10)
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	raw, err := json.Marshal(&qtypes.OpenAIChatRequest{Model: "model"})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["video_resolution"]; exists {
		t.Fatalf("empty field changed request serialization: %s", raw)
	}
}
