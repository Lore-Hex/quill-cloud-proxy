package video

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func resolvedVideoRequest(t *testing.T, request CreateRequest) *ResolvedRequest {
	t.Helper()
	resolved, err := ResolveRequest(&request)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestXAIProviderQuoteQueuePollAndDownload(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "x-ai/grok-imagine-video", Prompt: "private prompt", Duration: 5,
		Resolution: "720p", AspectRatio: "16:9",
	})
	var queuedPayload map[string]any
	client := NewXAIClient("xai-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "media.x.ai" {
			if req.Header.Get("Authorization") != "" {
				t.Fatal("xAI key leaked to the signed media URL")
			}
			return response(200, "video/mp4", "xai-video"), nil
		}
		if req.Header.Get("Authorization") != "Bearer xai-secret" {
			t.Fatal("missing xAI authorization")
		}
		switch req.URL.Path {
		case "/v1/videos/generations":
			if err := json.NewDecoder(req.Body).Decode(&queuedPayload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"request_id":"xai-job"}`), nil
		case "/v1/videos/xai-job":
			return response(200, "application/json", `{"status":"done","video":{"url":"https://media.x.ai/result.mp4"}}`), nil
		default:
			t.Fatalf("unexpected xAI path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 420_000 {
		t.Fatalf("quote=%d err=%v, want 420000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "xai-job" || queued.ProviderModel != "grok-imagine-video" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if queuedPayload["prompt"] != "private prompt" || queuedPayload["duration"] != float64(5) {
		t.Fatalf("bad xAI payload: %#v", queuedPayload)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(download.Body)
	download.Body.Close()
	if string(body) != "xai-video" {
		t.Fatalf("download body=%q", body)
	}
}

func TestMiniMaxProviderUsesH3MultimodalContractAndExactQuote(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 4,
		FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: "https://assets.example/frame.png"}},
	})
	var payload map[string]any
	client := NewMiniMaxClient("minimax-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer minimax-secret" {
			t.Fatal("missing MiniMax authorization")
		}
		switch req.URL.Path {
		case "/v2/video_generation":
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"task_id":"minimax-job"}`), nil
		case "/v2/query/video_generation/minimax-job":
			return response(200, "application/json", `{"task":{"status":"succeeded","content":{"url":"https://cdn.minimax.io/result.mp4"}}}`), nil
		default:
			t.Fatalf("unexpected MiniMax path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 624_000 {
		t.Fatalf("quote=%d err=%v, want 624000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "minimax-job" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["model"] != "MiniMax-H3" || payload["resolution"] != "2K" {
		t.Fatalf("bad MiniMax payload: %#v", payload)
	}
	encoded, _ := json.Marshal(payload["content"])
	if !strings.Contains(string(encoded), `"role":"first_frame"`) {
		t.Fatalf("first-frame role missing: %s", encoded)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
}

func TestMiniMaxProviderChargesCurrentExtraImagePrice(t *testing.T) {
	references := make([]InputReference, 0, 6)
	for index := 0; index < 6; index++ {
		references = append(references, InputReference{
			Type: "image",
			URL:  fmt.Sprintf("https://assets.example/reference-%d.png", index),
		})
	}
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 4,
		InputReferences: references,
	})
	quoted, err := NewMiniMaxClient("minimax-secret", nil).QuoteResolved(context.Background(), request)
	if err != nil || quoted != 672_000 {
		t.Fatalf("quote=%d err=%v, want 672000", quoted, err)
	}
}

func TestGoogleVeoProviderUsesLongRunningOperationAndKeyedDownload(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "google/veo-3.1-fast", Prompt: "move", Duration: 8,
		Resolution: "720p", AspectRatio: "9:16",
	})
	var payload map[string]any
	client := NewGoogleVeoClient("google-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("x-goog-api-key") != "google-secret" {
			t.Fatal("Google video request is missing its API key")
		}
		switch req.URL.Path {
		case "/v1beta/models/veo-3.1-fast-generate-preview:predictLongRunning":
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"name":"operations/veo-job"}`), nil
		case "/v1beta/operations/veo-job":
			return response(200, "application/json", `{"done":true,"response":{"generateVideoResponse":{"generatedSamples":[{"video":{"uri":"https://generativelanguage.googleapis.com/v1beta/files/video:download"}}]}}}`), nil
		case "/v1beta/files/video:download":
			return response(200, "video/mp4", "veo-video"), nil
		default:
			t.Fatalf("unexpected Google path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 960_000 {
		t.Fatalf("quote=%d err=%v, want 960000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "operations/veo-job" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	parameters := payload["parameters"].(map[string]any)
	if parameters["durationSeconds"] != float64(8) || parameters["aspectRatio"] != "9:16" {
		t.Fatalf("bad Veo parameters: %#v", parameters)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	download.Body.Close()
}

func TestVideoDownloadStripsProviderCredentialsOnCrossHostRedirect(t *testing.T) {
	headers := make(http.Header)
	headers.Set("x-goog-api-key", "google-secret")
	calls := 0
	httpc := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		switch req.URL.Host {
		case "generativelanguage.googleapis.com":
			if req.Header.Get("x-goog-api-key") != "google-secret" {
				t.Fatal("provider download credential missing from original host")
			}
			redirect := response(http.StatusFound, "text/plain", "")
			redirect.Header.Set("Location", "https://cdn.example/result.mp4")
			return redirect, nil
		case "cdn.example":
			if req.Header.Get("x-goog-api-key") != "" {
				t.Fatal("provider download credential leaked across hosts")
			}
			return response(http.StatusOK, "video/mp4", "video"), nil
		default:
			t.Fatalf("unexpected video download host %q", req.URL.Host)
			return nil, nil
		}
	})}
	result, err := downloadVideo(
		context.Background(), httpc,
		"https://generativelanguage.googleapis.com/v1beta/files/video:download",
		"google-ai-studio", headers,
	)
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if calls != 2 {
		t.Fatalf("download calls = %d, want 2", calls)
	}
}

func TestAlibabaProviderUsesWan27AsyncContractAndExactQuote(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "alibaba/wan-2.7", Prompt: "move", NegativePrompt: "blur",
		Duration: 5, Resolution: "720p", AspectRatio: "4:3",
	})
	var payload map[string]any
	client := NewAlibabaClientAt("alibaba-secret", "https://workspace.eu-central-1.maas.aliyuncs.com", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer alibaba-secret" {
			t.Fatal("missing Alibaba authorization")
		}
		switch req.URL.Path {
		case "/api/v1/services/aigc/video-generation/video-synthesis":
			if req.Header.Get("X-DashScope-Async") != "enable" {
				t.Fatal("missing Alibaba async header")
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"output":{"task_status":"PENDING","task_id":"wan-job"}}`), nil
		case "/api/v1/tasks/wan-job":
			return response(200, "application/json", `{"output":{"task_status":"SUCCEEDED","video_url":"https://media.aliyuncs.com/result.mp4"}}`), nil
		default:
			t.Fatalf("unexpected Alibaba path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 600_000 {
		t.Fatalf("quote=%d err=%v, want 600000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "wan-job" || queued.ProviderModel != "wan2.7-t2v" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["model"] != "wan2.7-t2v" {
		t.Fatalf("bad Wan model: %#v", payload)
	}
	parameters := payload["parameters"].(map[string]any)
	if parameters["resolution"] != "720P" || parameters["ratio"] != "4:3" {
		t.Fatalf("bad Wan parameters: %#v", parameters)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
}

func TestLTXProviderUsesNativeImageQueueAndExactQuote(t *testing.T) {
	generateAudio := true
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "lightricks/ltx-2.3-fast", Prompt: "move", Duration: 6,
		Resolution: "1080p", AspectRatio: "9:16", GenerateAudio: &generateAudio,
		FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: "https://assets.example/frame.png"}},
	})
	var payload map[string]any
	client := NewLTXClient("ltx-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "media.ltx.io" {
			if req.Header.Get("Authorization") != "" {
				t.Fatal("LTX key leaked to signed media URL")
			}
			return response(200, "video/mp4", "ltx-video"), nil
		}
		if req.Header.Get("Authorization") != "Bearer ltx-secret" {
			t.Fatal("missing LTX authorization")
		}
		switch req.URL.Path {
		case "/v2/image-to-video":
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"id":"ltx-job"}`), nil
		case "/v2/image-to-video/ltx-job":
			return response(200, "application/json", `{"status":"completed","result":{"video_url":"https://media.ltx.io/result.mp4"}}`), nil
		default:
			t.Fatalf("unexpected LTX path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 432_000 {
		t.Fatalf("quote=%d err=%v, want 432000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "ltx-job" || queued.ProviderModel != "ltx-2-3-fast|image-to-video" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["model"] != "ltx-2-3-fast" || payload["image_uri"] != "https://assets.example/frame.png" ||
		payload["resolution"] != "1080x1920" || payload["generate_audio"] != true {
		t.Fatalf("bad LTX payload: %#v", payload)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	download.Body.Close()
}

func TestRunwayProviderUsesVersionedNativeContractAndExactQuote(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "runway/gen-4.5", Prompt: "move", Duration: 5, AspectRatio: "16:9",
	})
	var payload map[string]any
	client := NewRunwayClient("runway-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer runway-secret" ||
			req.Header.Get("X-Runway-Version") != "2024-11-06" {
			t.Fatal("missing Runway authentication or version header")
		}
		switch req.URL.Path {
		case "/v1/text_to_video":
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"id":"runway-job"}`), nil
		case "/v1/tasks/runway-job":
			return response(200, "application/json", `{"status":"SUCCEEDED","output":["https://media.runwayml.com/result.mp4"]}`), nil
		default:
			t.Fatalf("unexpected Runway path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 720_000 {
		t.Fatalf("quote=%d err=%v, want 720000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "runway-job" || queued.ProviderModel != "gen4.5" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["model"] != "gen4.5" || payload["ratio"] != "1280:720" || payload["duration"] != float64(5) {
		t.Fatalf("bad Runway payload: %#v", payload)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
}

func TestOpenAIVideoProviderUsesMultipartContentAndDeletesAsset(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "openai/sora-2", Prompt: "move", Duration: 4,
		Resolution: "720p", AspectRatio: "9:16",
	})
	deleted := false
	client := NewOpenAIVideoClient("openai-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer openai-secret" {
			t.Fatal("missing OpenAI authorization")
		}
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/v1/videos":
			if err := req.ParseMultipartForm(1 << 20); err != nil {
				t.Fatal(err)
			}
			if req.FormValue("model") != "sora-2" || req.FormValue("prompt") != "move" ||
				req.FormValue("seconds") != "4" || req.FormValue("size") != "720x1280" {
				t.Fatalf("bad OpenAI multipart form: %#v", req.MultipartForm.Value)
			}
			return response(200, "application/json", `{"id":"video-openai"}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v1/videos/video-openai":
			return response(200, "application/json", `{"status":"completed"}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v1/videos/video-openai/content":
			return response(200, "video/mp4", "sora-video"), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/v1/videos/video-openai":
			deleted = true
			return response(200, "application/json", `{"deleted":true}`), nil
		default:
			t.Fatalf("unexpected OpenAI request %s %q", req.Method, req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 480_000 {
		t.Fatalf("quote=%d err=%v, want 480000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "video-openai" || queued.ProviderModel != "sora-2" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL != "openai-video:video-openai" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	download.Body.Close()
	if err := client.Complete(context.Background(), queued.ProviderModel, queued.QueueID); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("OpenAI generated asset was not deleted after relay")
	}
}

func TestKlingProviderUsesCurrentV3ContractAndExactQuote(t *testing.T) {
	generateAudio := true
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "kling/v3-pro", Prompt: "move", Duration: 5,
		Resolution: "1080p", AspectRatio: "16:9", GenerateAudio: &generateAudio,
		FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: "https://assets.example/frame.png"}},
	})
	var payload map[string]any
	client := NewKlingClient("kling-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "media.klingai.com" {
			if req.Header.Get("Authorization") != "" {
				t.Fatal("Kling key leaked to signed media URL")
			}
			return response(200, "video/mp4", "kling-video"), nil
		}
		if req.Header.Get("Authorization") != "Bearer kling-secret" {
			t.Fatal("missing Kling authorization")
		}
		switch req.URL.Path {
		case "/image-to-video/kling-3.0":
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"code":0,"data":{"id":"kling-job","status":"submitted"}}`), nil
		case "/tasks":
			if req.URL.Query().Get("task_ids") != "kling-job" {
				t.Fatalf("bad Kling task query: %s", req.URL.RawQuery)
			}
			return response(200, "application/json", `{"code":0,"data":[{"id":"kling-job","status":"succeeded","outputs":[{"type":"video","url":"https://media.klingai.com/result.mp4"}]}]}`), nil
		default:
			t.Fatalf("unexpected Kling path %q", req.URL.Path)
			return nil, nil
		}
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 1_090_914 {
		t.Fatalf("quote=%d err=%v, want 1090914", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "kling-job" || queued.ProviderModel != "kling-3.0|image" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	settings := payload["settings"].(map[string]any)
	if settings["resolution"] != "1080p" || settings["audio"] != "native" || settings["duration"] != float64(5) {
		t.Fatalf("bad Kling settings: %#v", settings)
	}
	contents := payload["contents"].([]any)
	if len(contents) != 2 {
		t.Fatalf("bad Kling contents: %#v", contents)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	download.Body.Close()
}

func TestKlingOmniAliasUsesCurrentOmniEndpoint(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "kling/o3-pro", Prompt: "move", Duration: 3,
		Resolution: "720p", AspectRatio: "1:1",
	})
	client := NewKlingClient("kling-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/omni-video/kling-3.0-omni" {
			t.Fatalf("unexpected Kling Omni path %q", req.URL.Path)
		}
		return response(200, "application/json", `{"code":0,"data":{"id":"omni-job"}}`), nil
	})})
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.ProviderModel != "kling-3.0-omni|omni" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
}
