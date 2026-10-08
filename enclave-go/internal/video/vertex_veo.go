package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg" // decode first-frame dimensions
	_ "image/png"  // decode first-frame dimensions
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VertexVeoProviderID is the control-plane provider slug for Veo served from
// Vertex AI with GCP billing (as opposed to the AI Studio Gemini API key).
const VertexVeoProviderID = "google-vertex"

// gcpMetadataTokenURL is the same GCE/Confidential Space metadata endpoint
// internal/llm/gcp.go uses for Vertex text traffic.
const gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.

// maxVertexVeoBytes bounds the decoded MP4 returned inline as
// bytesBase64Encoded (no storageUri is sent, so no bucket is involved).
var maxVertexVeoBytes = 96 * 1024 * 1024

// vertexVeoInlineSlots bounds how many inline results are held in memory at
// once (decoded JSON + base64 string). A slot is held until the returned
// body is closed.
var vertexVeoInlineSlots = make(chan struct{}, 2)

func vertexVeoPermanentResultError() error {
	return &HTTPError{Provider: VertexVeoProviderID, Status: http.StatusBadGateway, Retryable: false}
}

type slotReleasingBody struct {
	io.Reader
	once sync.Once
}

func (b *slotReleasingBody) Close() error {
	b.once.Do(func() { <-vertexVeoInlineSlots })
	return nil
}

// vertexVeoUpstreamModels is the only set of Vertex publisher model ids this
// adapter will put into a URL, keyed by TrustedRouter model id. The control
// plane's authorized upstream_model must match; empty selects the GA id.
var vertexVeoUpstreamModels = map[string]string{
	"google/veo-3.1":      "veo-3.1-generate-001",
	"google/veo-3.1-fast": "veo-3.1-fast-generate-001",
}

type TokenSource func(context.Context) (string, error)

type VertexVeoClient struct {
	projectID string
	location  string
	baseURL   string
	token     TokenSource
	httpc     *http.Client
}

func NewVertexVeoClient(projectID, location string, httpc *http.Client) *VertexVeoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	location = strings.TrimSpace(location)
	if location == "" {
		location = "us-central1"
	}
	return NewVertexVeoClientAt(projectID, location, "https://"+vertexHost(location), newMetadataTokenSource(httpc), httpc)
}

func NewVertexVeoClientAt(projectID, location, baseURL string, token TokenSource, httpc *http.Client) *VertexVeoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &VertexVeoClient{
		projectID: strings.TrimSpace(projectID), location: strings.TrimSpace(location),
		baseURL: strings.TrimRight(baseURL, "/"), token: token, httpc: httpc,
	}
}

// vertexHost mirrors gcpClient.vertexHost in internal/llm/gcp.go.
func vertexHost(location string) string {
	switch location {
	case "", "global":
		return "aiplatform.googleapis.com"
	case "us", "eu":
		return fmt.Sprintf("aiplatform.%s.rep.googleapis.com", location)
	default:
		return fmt.Sprintf("%s-aiplatform.googleapis.com", location)
	}
}

func newMetadataTokenSource(httpc *http.Client) TokenSource {
	var (
		mu     sync.Mutex
		token  string
		expiry time.Time
	)
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if token != "" && time.Now().Before(expiry.Add(-30*time.Second)) {
			return token, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcpMetadataTokenURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := httpc.Do(req)
		if err != nil {
			return "", fmt.Errorf("vertex veo metadata token: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("vertex veo metadata token http %d", resp.StatusCode)
		}
		var body struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil || body.AccessToken == "" {
			return "", fmt.Errorf("vertex veo metadata token: invalid response")
		}
		token = body.AccessToken
		expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
		return token, nil
	}
}

func (c *VertexVeoClient) ID() string { return VertexVeoProviderID }
func (c *VertexVeoClient) Enabled() bool {
	return c != nil && c.projectID != "" && c.location != "" && c.token != nil
}

func (c *VertexVeoClient) Supports(request *ResolvedRequest) bool {
	if request == nil {
		return false
	}
	if _, ok := vertexVeoUpstreamModels[request.Model.ID]; !ok {
		return false
	}
	if len(request.ReferenceImages) > 0 || request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	// Vertex accepts JPEG/PNG frames only, and lastFrame requires image.
	if request.FirstFrame != "" && !vertexFrameSupported(request.FirstFrame) {
		return false
	}
	if request.LastFrame != "" && (request.FirstFrame == "" || !vertexFrameSupported(request.LastFrame)) {
		return false
	}
	// The quote below is the with-audio price; never run a request whose
	// billing basis differs from what was reserved.
	return request.GenerateAudio
}

// QuoteResolved uses the same per-second rates as the AI Studio adapter: the
// Vertex GA list price for Veo 3.1 / 3.1 Fast with audio is identical.
func (c *VertexVeoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("vertex veo provider does not support this request")
	}
	return veoCustomerQuote(request)
}

func (c *VertexVeoClient) nativeModel(request *ResolvedRequest) (string, error) {
	expected := vertexVeoUpstreamModels[request.Model.ID]
	upstream := strings.TrimSpace(request.UpstreamModel)
	if upstream == "" || upstream == expected {
		return expected, nil
	}
	return "", fmt.Errorf("vertex veo: unsupported upstream model")
}

func (c *VertexVeoClient) modelPath(model string) string {
	return "/v1/projects/" + c.projectID + "/locations/" + c.location + "/publishers/google/models/" + model
}

func (c *VertexVeoClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("vertex veo provider does not support this request")
	}
	model, err := c.nativeModel(request)
	if err != nil {
		return nil, err
	}
	instance := map[string]any{"prompt": request.Prompt}
	if request.FirstFrame != "" {
		image, err := vertexInlineImage(request.FirstFrame)
		if err != nil {
			return nil, err
		}
		instance["image"] = image
	}
	if request.LastFrame != "" {
		image, err := vertexInlineImage(request.LastFrame)
		if err != nil {
			return nil, err
		}
		instance["lastFrame"] = image
	}
	parameters := map[string]any{
		"durationSeconds": request.DurationSeconds,
		"resolution":      strings.ToLower(request.Resolution),
		"generateAudio":   request.GenerateAudio,
		"sampleCount":     1,
	}
	// Image requests resolve to "source" aspect. Vertex has no such value and
	// defaults to 16:9, so derive the supported ratio from the first frame.
	switch {
	case request.AspectRatio != "" && request.AspectRatio != "source":
		parameters["aspectRatio"] = request.AspectRatio
	case request.FirstFrame != "":
		parameters["aspectRatio"] = sourceAspectRatio(request.FirstFrame)
	}
	if request.NegativePrompt != "" {
		parameters["negativePrompt"] = request.NegativePrompt
	}
	if request.Seed != nil {
		parameters["seed"] = *request.Seed
	}
	payload := map[string]any{"instances": []map[string]any{instance}, "parameters": parameters}
	resp, err := c.request(ctx, c.modelPath(model)+":predictLongRunning", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("vertex veo queue: invalid response")
	}
	name := strings.TrimSpace(body.Name)
	if _, ok := c.operationModel(name); !ok {
		return nil, fmt.Errorf("vertex veo queue: invalid operation name")
	}
	return &QueueResult{ProviderModel: model, QueueID: name}, nil
}

// operationModel validates that an operation name belongs to this project,
// location and an allowed Veo model, and returns that model.
func (c *VertexVeoClient) operationModel(name string) (string, bool) {
	prefix := "projects/" + c.projectID + "/locations/" + c.location + "/publishers/google/models/"
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return "", false
	}
	model, operationID, ok := strings.Cut(rest, "/operations/")
	if !ok || operationID == "" || strings.ContainsAny(operationID, "/?#") {
		return "", false
	}
	for _, allowed := range vertexVeoUpstreamModels {
		if model == allowed {
			return model, true
		}
	}
	return "", false
}

func vertexFrameSupported(dataURL string) bool {
	prefix := strings.ToLower(strings.SplitN(dataURL, ",", 2)[0])
	return prefix == "data:image/png;base64" || prefix == "data:image/jpeg;base64"
}

// sourceAspectRatio maps the first frame's orientation to the closest Veo
// ratio; undecodable images fall back to Vertex's 16:9 default.
func sourceAspectRatio(dataURL string) string {
	_, encoded, _ := strings.Cut(dataURL, ",")
	config, _, err := image.DecodeConfig(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded)))
	if err == nil && config.Height > config.Width {
		return "9:16"
	}
	return "16:9"
}

func vertexInlineImage(raw string) (map[string]any, error) {
	image, err := googleInlineData(raw)
	if err != nil {
		return nil, err
	}
	inline := image["inlineData"].(map[string]any)
	return map[string]any{"bytesBase64Encoded": inline["data"], "mimeType": inline["mimeType"]}, nil
}

func (c *VertexVeoClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	name := strings.TrimSpace(queueID)
	model, ok := c.operationModel(name)
	if !ok {
		return nil, fmt.Errorf("vertex veo retrieve: invalid operation name")
	}
	select {
	case vertexVeoInlineSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	result, err := c.retrieve(ctx, model, name)
	if result == nil || result.Body == nil {
		<-vertexVeoInlineSlots
	}
	return result, err
}

func (c *VertexVeoClient) retrieve(ctx context.Context, model, name string) (*PollResult, error) {
	resp, err := c.request(ctx, c.modelPath(model)+":fetchPredictOperation", map[string]any{"operationName": name})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Done  bool `json:"done"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
		Response struct {
			RAIMediaFilteredCount int `json:"raiMediaFilteredCount"`
			Videos                []struct {
				BytesBase64Encoded string `json:"bytesBase64Encoded"`
				GCSURI             string `json:"gcsUri"`
				MimeType           string `json:"mimeType"`
			} `json:"videos"`
		} `json:"response"`
	}
	maxJSONBytes := int64(maxVertexVeoBytes)*4/3 + 1024*1024
	limited := &io.LimitedReader{R: resp.Body, N: maxJSONBytes + 1}
	if err := json.NewDecoder(limited).Decode(&body); err != nil {
		if limited.N <= 0 {
			// The completed result can never fit; stop polling it.
			return nil, vertexVeoPermanentResultError()
		}
		return nil, fmt.Errorf("vertex veo retrieve: invalid response")
	}
	if !body.Done {
		return &PollResult{State: PollProcessing, ProviderStatus: "RUNNING"}, nil
	}
	if body.Error != nil {
		return &PollResult{State: PollFailed, ProviderStatus: "FAILED"}, nil
	}
	if len(body.Response.Videos) == 0 {
		if body.Response.RAIMediaFilteredCount > 0 {
			return &PollResult{State: PollFailed, ProviderStatus: "FILTERED"}, nil
		}
		return nil, vertexVeoPermanentResultError()
	}
	video := body.Response.Videos[0]
	encoded := strings.TrimSpace(video.BytesBase64Encoded)
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxVertexVeoBytes) {
		return nil, vertexVeoPermanentResultError()
	}
	if _, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))); err != nil {
		return nil, vertexVeoPermanentResultError()
	}
	contentType := strings.TrimSpace(video.MimeType)
	if !strings.HasPrefix(strings.ToLower(contentType), "video/") {
		contentType = "video/mp4"
	}
	return &PollResult{
		State: PollCompleted, ProviderStatus: "SUCCEEDED",
		Body:        &slotReleasingBody{Reader: base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))},
		ContentType: contentType,
	}, nil
}

func (c *VertexVeoClient) Download(context.Context, string) (*PollResult, error) {
	return nil, fmt.Errorf("vertex veo download: inline result required")
}

func (c *VertexVeoClient) Complete(context.Context, string, string) error { return nil }

func (c *VertexVeoClient) request(ctx context.Context, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("vertex veo provider is not configured")
	}
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vertex veo request failed: %w", err)
	}
	return resp, nil
}
