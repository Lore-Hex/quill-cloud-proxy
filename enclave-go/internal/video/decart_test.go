package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecartVideoQuoteQueuePollAndDownload(t *testing.T) {
	videoBytes := testMP4(5_000, 1_000, false)
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "decart/lucy-2.5", Prompt: "turn the car red", Duration: 5,
		InputReferences: []InputReference{{
			Type: "video", URL: "data:video/mp4;base64," + base64.StdEncoding.EncodeToString(videoBytes),
		}},
	})
	var fields map[string]string
	var uploaded []byte
	retrieveCalls := 0
	client := NewDecartVideoClient("decart-secret", &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-API-KEY") != "decart-secret" {
				t.Fatal("missing Decart API key")
			}
			switch req.URL.Path {
			case "/v1/jobs/lucy-2.5":
				if req.Method != http.MethodPost {
					t.Fatalf("queue method = %s", req.Method)
				}
				fields = make(map[string]string)
				reader, err := req.MultipartReader()
				if err != nil {
					t.Fatal(err)
				}
				for {
					part, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(part)
					if err != nil {
						t.Fatal(err)
					}
					if part.FormName() == "data" {
						uploaded = body
					} else {
						fields[part.FormName()] = string(body)
					}
				}
				return response(http.StatusOK, "application/json", `{"job_id":"decart-job"}`), nil
			case "/v1/jobs/decart-job":
				retrieveCalls++
				if retrieveCalls == 1 {
					return response(http.StatusOK, "application/json", `{"status":"processing"}`), nil
				}
				return response(http.StatusOK, "application/json", `{"status":"completed"}`), nil
			case "/v1/jobs/decart-job/content":
				return response(http.StatusOK, "video/mp4", "edited-video"), nil
			default:
				t.Fatalf("unexpected Decart path %q", req.URL.Path)
				return nil, nil
			}
		}),
	})

	quote, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quote != 240_000 {
		t.Fatalf("quote=%d err=%v, want 240000", quote, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "decart-job" || queued.ProviderModel != "lucy-2.5" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if !bytes.Equal(uploaded, videoBytes) {
		t.Fatal("Decart upload did not preserve the source MP4")
	}
	if fields["prompt"] != "turn the car red" || fields["resolution"] != "720p" {
		t.Fatalf("multipart fields=%#v", fields)
	}
	if _, found := fields["duration"]; found {
		t.Fatalf("Decart does not accept a duration field: %#v", fields)
	}
	processing, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || processing.State != PollProcessing {
		t.Fatalf("processing=%#v err=%v", processing, err)
	}
	completed, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || completed.State != PollCompleted || completed.DownloadURL != "decart-video:decart-job" {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	download, err := client.Download(context.Background(), completed.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(download.Body)
	download.Body.Close()
	if string(body) != "edited-video" {
		t.Fatalf("download body=%q", body)
	}
	if QueueTimeout(client) != 3*time.Minute {
		t.Fatalf("queue timeout = %s", QueueTimeout(client))
	}
}

func TestDecartVideoModelsRequireExplicitMatchingSourceDuration(t *testing.T) {
	models := []string{
		"decart/lucy-2.5", "decart/lucy-vton-3.5", "decart/lucy-restyle-2",
	}
	for _, modelID := range models {
		t.Run(modelID, func(t *testing.T) {
			base := CreateRequest{Model: modelID, Prompt: "edit"}
			if _, err := ResolveRequest(&base); err == nil || !strings.Contains(err.Error(), "duration is required") {
				t.Fatalf("missing duration error = %v", err)
			}
			base.Duration = 5
			if _, err := ResolveRequest(&base); err == nil || !strings.Contains(err.Error(), "requires one video") {
				t.Fatalf("missing video error = %v", err)
			}
			base.InputReferences = []InputReference{{
				Type: "video", URL: "data:video/mp4;base64,AAAA",
			}}
			resolved, err := ResolveRequest(&base)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.AspectRatio != "source" || resolved.Resolution != "720p" {
				t.Fatalf("resolved source geometry = %#v", resolved)
			}
			withAspect := base
			withAspect.AspectRatio = "16:9"
			if _, err := ResolveRequest(&withAspect); err == nil || !strings.Contains(err.Error(), "derived from the source") {
				t.Fatalf("explicit source aspect error = %v", err)
			}
		})
	}

	videoBytes := testMP4(5_001, 1_000, false)
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "decart/lucy-2.5", Prompt: "edit", Duration: 5,
		InputReferences: []InputReference{{
			Type: "video", URL: "data:video/mp4;base64," + base64.StdEncoding.EncodeToString(videoBytes),
		}},
	})
	client := NewDecartVideoClient("decart-secret", &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("duration mismatch must fail before provider submission")
			return nil, nil
		}),
	})
	if _, err := client.QueueResolved(context.Background(), request); err == nil || !strings.Contains(err.Error(), "source 6") {
		t.Fatalf("duration mismatch error = %v", err)
	}
}

func TestDecartMP4DurationParserSupportsVersionZeroAndOne(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		seconds int
	}{
		{name: "version zero exact", payload: testMP4(5_000, 1_000, false), seconds: 5},
		{name: "version zero rounds up", payload: testMP4(5_001, 1_000, false), seconds: 6},
		{name: "version one", payload: testMP4(65_000, 1_000, true), seconds: 65},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seconds, err := mp4DurationSeconds(bytes.NewReader(tt.payload), int64(len(tt.payload)))
			if err != nil || seconds != tt.seconds {
				t.Fatalf("seconds=%d err=%v, want %d", seconds, err, tt.seconds)
			}
		})
	}
	if _, err := mp4DurationSeconds(strings.NewReader("not an mp4"), 10); err == nil {
		t.Fatal("malformed input must be rejected")
	}
}

func TestDecartMP4DurationRejectsHeaderAndSampleTableManipulation(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "movie header understates samples",
			payload: testMP4WithTimings(5_000, 65_000, 65_000, 1_000, false),
		},
		{
			name:    "media header understates samples",
			payload: testMP4WithTimings(65_000, 5_000, 65_000, 1_000, false),
		},
		{
			name: "fragmented movie",
			payload: append(
				testMP4(5_000, 1_000, false),
				testMP4Box("moof", []byte("fragment"))...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := mp4DurationSeconds(bytes.NewReader(tt.payload), int64(len(tt.payload))); err == nil {
				t.Fatal("manipulated MP4 timing must be rejected")
			}
		})
	}
}

func TestDecartMalformedInputIsNotRetryableProviderFailure(t *testing.T) {
	payload := testMP4WithTimings(5_000, 65_000, 65_000, 1_000, false)
	_, _, err := spoolDecartVideo(
		io.NopCloser(bytes.NewReader(payload)),
		5,
		maxDecartDataVideoBytes,
	)
	if err == nil {
		t.Fatal("manipulated input must fail")
	}
	var inputErr *InputError
	if !AsInputError(err, &inputErr) || IsRetryableProviderError(err) {
		t.Fatalf("error=%T %v must be a non-retryable input error", err, err)
	}
}

func TestDecartUnknownStatusIsTerminalProviderFailure(t *testing.T) {
	client := NewDecartVideoClient("decart", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"status":"mystery"}`), nil
	})})
	_, err := client.Retrieve(t.Context(), "lucy-2.5", "job-one")
	if err == nil {
		t.Fatal("unknown status must fail")
	}
	var httpErr *HTTPError
	if !AsHTTPError(err, &httpErr) || httpErr.Retryable || httpErr.Status != http.StatusBadGateway {
		t.Fatalf("error=%T %v must be a terminal provider error", err, err)
	}
}

func TestDecartMP4ParserBoundsBoxesAndSampleTableEntries(t *testing.T) {
	entries := make([]byte, 8+(maxMP4STTSEntries+1)*8)
	binary.BigEndian.PutUint32(entries[4:8], maxMP4STTSEntries+1)
	if _, err := parseTimeToSample(bytes.NewReader(entries), 0, int64(len(entries))); err == nil {
		t.Fatal("oversized stts table must be rejected")
	}

	boxes := bytes.Repeat(testMP4Box("free", nil), maxMP4BoxesPerContainer+1)
	if _, err := parseTrackDuration(bytes.NewReader(boxes), 0, int64(len(boxes))); err == nil {
		t.Fatal("excessive MP4 box count must be rejected")
	}
}

func TestDecartInputReadFailureIsNotRetryableProviderFailure(t *testing.T) {
	_, _, err := spoolDecartVideo(failingReadCloser{}, 5, maxDecartDataVideoBytes)
	if err == nil {
		t.Fatal("read failure must fail")
	}
	var inputErr *InputError
	if !AsInputError(err, &inputErr) || IsRetryableProviderError(err) {
		t.Fatalf("error=%T %v must be a non-retryable input error", err, err)
	}
}

func TestDecartRegistryKeepsVideoModelsDirectOnly(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "decart/lucy-restyle-2", Prompt: "painted", Duration: 5,
		InputReferences: []InputReference{{
			Type: "video", URL: "data:video/mp4;base64,AAAA",
		}},
	})
	registry := NewRegistry(ProviderKeys{Decart: "decart", Venice: "venice"}, nil)
	providers := registry.Supporting(request)
	got := make([]string, 0, len(providers))
	for _, provider := range providers {
		got = append(got, provider.ID())
	}
	if !reflect.DeepEqual(got, []string{"decart"}) {
		t.Fatalf("providers=%v, want direct Decart only", got)
	}
}

func testMP4(duration, timescale uint32, versionOne bool) []byte {
	return testMP4WithTimings(duration, duration, duration, timescale, versionOne)
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingReadCloser) Close() error             { return nil }

func testMP4WithTimings(
	movieDuration, mediaDuration, sampleDuration, timescale uint32,
	versionOne bool,
) []byte {
	movieHeader := testDurationHeader(movieDuration, timescale, versionOne)
	mediaHeader := testDurationHeader(mediaDuration, timescale, versionOne)
	stts := make([]byte, 16)
	binary.BigEndian.PutUint32(stts[4:8], 1)
	binary.BigEndian.PutUint32(stts[8:12], 1)
	binary.BigEndian.PutUint32(stts[12:16], sampleDuration)
	stbl := testMP4Box("stbl", testMP4Box("stts", stts))
	minf := testMP4Box("minf", stbl)
	mdiaPayload := append(testMP4Box("mdhd", mediaHeader), minf...)
	trak := testMP4Box("trak", testMP4Box("mdia", mdiaPayload))
	ftyp := testMP4Box("ftyp", []byte("isom\x00\x00\x02\x00isom"))
	moovPayload := append(testMP4Box("mvhd", movieHeader), trak...)
	moov := testMP4Box("moov", moovPayload)
	mdat := testMP4Box("mdat", []byte("fake-video-payload"))
	return append(append(ftyp, mdat...), moov...)
}

func testDurationHeader(duration, timescale uint32, versionOne bool) []byte {
	var movieHeader []byte
	if versionOne {
		movieHeader = make([]byte, 32)
		movieHeader[0] = 1
		binary.BigEndian.PutUint32(movieHeader[20:24], timescale)
		binary.BigEndian.PutUint64(movieHeader[24:32], uint64(duration))
	} else {
		movieHeader = make([]byte, 20)
		binary.BigEndian.PutUint32(movieHeader[12:16], timescale)
		binary.BigEndian.PutUint32(movieHeader[16:20], duration)
	}
	return movieHeader
}

func testMP4Box(kind string, payload []byte) []byte {
	box := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(box[:4], checkedTestUint32(len(box)))
	copy(box[4:8], kind)
	copy(box[8:], payload)
	return box
}

func checkedTestUint32(value int) uint32 {
	if value < 0 || int64(value) > int64(^uint32(0)) {
		panic("test value does not fit uint32")
	}
	return uint32(value) // #nosec G115 -- the explicit bounds check above proves this conversion.
}
