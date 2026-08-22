package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

const (
	defaultDecartVideoBaseURL = "https://api.decart.ai"
	maxDecartInputVideoBytes  = 200 << 20
	// A data URL expands by 4/3 inside the 32 MiB API request envelope. URL
	// inputs retain Decart's larger upload allowance without pretending an
	// impossible 200 MiB inline body can reach this adapter.
	maxDecartDataVideoBytes = 23 << 20
	maxDecartResponseBytes  = 64 << 10
	maxMP4BoxesPerContainer = 4096
	maxMP4STTSEntries       = 131072
)

var decartUploadSlots = make(chan struct{}, 2)

var decartVideoRates = map[string]int{
	"decart/lucy-2.5":       40_000,
	"decart/lucy-vton-3.5":  40_000,
	"decart/lucy-restyle-2": 10_000,
}

type DecartVideoClient struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

func NewDecartVideoClient(apiKey string, httpc *http.Client) *DecartVideoClient {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &DecartVideoClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: defaultDecartVideoBaseURL, http: httpc,
	}
}

func (c *DecartVideoClient) ID() string                  { return "decart" }
func (c *DecartVideoClient) Enabled() bool               { return c != nil && c.apiKey != "" }
func (c *DecartVideoClient) QueueTimeout() time.Duration { return 3 * time.Minute }

func (c *DecartVideoClient) Supports(request *ResolvedRequest) bool {
	if request == nil || !c.Enabled() || decartVideoRates[request.Model.ID] == 0 {
		return false
	}
	return request.VideoReference != "" && request.FirstFrame == "" && request.LastFrame == "" &&
		request.AudioReference == "" && len(request.ReferenceImages) <= 1 &&
		strings.EqualFold(request.Resolution, "720p")
}

func (c *DecartVideoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("decart video provider does not support this request")
	}
	return staticCustomerQuote(decartVideoRates[request.Model.ID], request.DurationSeconds, 0)
}

func (c *DecartVideoClient) QueueResolved(
	ctx context.Context,
	request *ResolvedRequest,
) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("decart video provider does not support this request")
	}
	select {
	case decartUploadSlots <- struct{}{}:
		defer func() { <-decartUploadSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var referenceType string
	var referenceBytes []byte
	if len(request.ReferenceImages) == 1 {
		var err error
		referenceType, referenceBytes, err = llm.LoadNormalizedImage(ctx, request.ReferenceImages[0])
		if err != nil {
			return nil, fmt.Errorf("decart video reference image: %w", err)
		}
	}
	videoBody, videoType, err := c.openInputVideo(
		ctx, request.VideoReference, request.DurationSeconds,
	)
	if err != nil {
		return nil, err
	}

	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	go writeDecartVideoMultipart(
		writer, multipartWriter, videoBody, videoType, request, referenceType, referenceBytes,
	)
	endpoint := c.baseURL + "/v1/jobs/" + url.PathEscape(request.Model.ReferenceProviderModel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reader)
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("decart video queue: invalid request")
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	_ = reader.Close()
	if err != nil {
		return nil, fmt.Errorf("decart video request failed: %w", err)
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		JobID string `json:"job_id"`
	}
	if err := decodeDecartJSON(resp.Body, &body); err != nil || strings.TrimSpace(body.JobID) == "" {
		return nil, decartProtocolError()
	}
	return &QueueResult{
		ProviderModel: request.Model.ReferenceProviderModel,
		QueueID:       strings.TrimSpace(body.JobID),
	}, nil
}

func writeDecartVideoMultipart(
	pipe *io.PipeWriter,
	writer *multipart.Writer,
	video io.ReadCloser,
	videoType string,
	request *ResolvedRequest,
	referenceType string,
	referenceBytes []byte,
) {
	fail := func(err error) {
		_ = video.Close()
		_ = pipe.CloseWithError(err)
	}
	if err := writer.WriteField("prompt", request.Prompt); err != nil {
		fail(err)
		return
	}
	if err := writer.WriteField("resolution", "720p"); err != nil {
		fail(err)
		return
	}
	if request.Seed != nil {
		if err := writer.WriteField("seed", fmt.Sprint(*request.Seed)); err != nil {
			fail(err)
			return
		}
	}
	if len(referenceBytes) > 0 {
		extension := map[string]string{
			"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
		}[referenceType]
		part, err := writer.CreateFormFile("reference_image", "reference"+extension)
		if err != nil {
			fail(err)
			return
		}
		if _, err := part.Write(referenceBytes); err != nil {
			fail(err)
			return
		}
	}
	part, err := writer.CreateFormFile("data", "input.mp4")
	if err != nil {
		fail(err)
		return
	}
	if videoType != "video/mp4" {
		fail(&InputError{Message: "video input must be MP4"})
		return
	}
	written, err := io.Copy(part, io.LimitReader(video, maxDecartInputVideoBytes+1))
	_ = video.Close()
	if err != nil {
		_ = pipe.CloseWithError(&InputError{Message: "video input could not be read"})
		return
	}
	if written > maxDecartInputVideoBytes {
		_ = pipe.CloseWithError(&InputError{Message: "video input exceeds the size limit"})
		return
	}
	if err := writer.Close(); err != nil {
		_ = pipe.CloseWithError(err)
		return
	}
	_ = pipe.Close()
}

func (c *DecartVideoClient) openInputVideo(
	ctx context.Context,
	rawURL string,
	declaredDurationSeconds int,
) (io.ReadCloser, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if strings.HasPrefix(rawURL, "data:") {
		prefix, encoded, ok := strings.Cut(rawURL, ",")
		if !ok || !strings.EqualFold(prefix, "data:video/mp4;base64") || encoded == "" ||
			base64.StdEncoding.DecodedLen(len(encoded)) > maxDecartDataVideoBytes {
			return nil, "", &InputError{Message: "video input must be an MP4 data URL under 23 MiB"}
		}
		return spoolDecartVideo(
			io.NopCloser(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))),
			declaredDurationSeconds,
			maxDecartDataVideoBytes,
		)
	}
	return c.openRemoteVideo(ctx, rawURL, declaredDurationSeconds)
}

func spoolDecartVideo(
	source io.ReadCloser,
	declaredDurationSeconds int,
	maxBytes int64,
) (io.ReadCloser, string, error) {
	defer source.Close()
	file, err := os.CreateTemp("", "trustedrouter-decart-video-*")
	if err != nil {
		return nil, "", fmt.Errorf("decart video input could not be staged")
	}
	// Keep the staged customer video accessible only by this file descriptor.
	// An enclave process crash therefore cannot leave named content behind.
	if err := os.Remove(file.Name()); err != nil {
		file.Close()
		return nil, "", fmt.Errorf("decart video input could not be staged")
	}
	closeWithError := func(err error) (io.ReadCloser, string, error) {
		file.Close()
		return nil, "", err
	}
	written, err := io.Copy(file, io.LimitReader(source, maxBytes+1))
	if err != nil {
		return closeWithError(&InputError{Message: "video input could not be read"})
	}
	if written > maxBytes {
		return closeWithError(&InputError{Message: "video input exceeds the size limit"})
	}
	actualDurationSeconds, err := mp4DurationSeconds(file, written)
	if err != nil {
		return closeWithError(&InputError{Message: "video input is not a supported MP4"})
	}
	if actualDurationSeconds != declaredDurationSeconds {
		return closeWithError(&InputError{Message: fmt.Sprintf(
			"duration must equal the source video duration rounded up to a whole second (got %d, source %d)",
			declaredDurationSeconds, actualDurationSeconds,
		)})
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return closeWithError(fmt.Errorf("decart video input could not be staged"))
	}
	return file, "video/mp4", nil
}

type mp4Box struct {
	kind         string
	payloadStart int64
	end          int64
}

func mp4DurationSeconds(reader io.ReaderAt, size int64) (int, error) {
	if size < 16 {
		return 0, fmt.Errorf("invalid MP4")
	}
	var foundFTYP bool
	var movieBox *mp4Box
	boxCount := 0
	for offset := int64(0); offset < size; {
		box, err := readNextMP4Box(reader, offset, size, &boxCount)
		if err != nil {
			return 0, fmt.Errorf("invalid MP4")
		}
		switch box.kind {
		case "ftyp":
			foundFTYP = true
		case "moov":
			copy := box
			movieBox = &copy
		case "moof":
			return 0, fmt.Errorf("fragmented MP4 is not supported")
		}
		offset = box.end
	}
	if !foundFTYP || movieBox == nil {
		return 0, fmt.Errorf("MP4 movie duration is unavailable")
	}
	return validatedMovieDurationSeconds(reader, movieBox.payloadStart, movieBox.end)
}

type mediaDuration struct {
	units     uint64
	timescale uint32
}

func (d mediaDuration) roundedSeconds() (int, error) {
	if d.timescale == 0 || d.units == 0 || d.units == ^uint64(0) {
		return 0, fmt.Errorf("invalid MP4 duration")
	}
	seconds := d.units / uint64(d.timescale)
	if d.units%uint64(d.timescale) != 0 {
		seconds++
	}
	maxInt := uint64(^uint(0) >> 1)
	if seconds == 0 || seconds > maxInt {
		return 0, fmt.Errorf("invalid MP4 duration")
	}
	return int(seconds), nil
}

func validatedMovieDurationSeconds(reader io.ReaderAt, start, end int64) (int, error) {
	var movie mediaDuration
	tracks := make([]mediaDuration, 0, 2)
	boxCount := 0
	for offset := start; offset < end; {
		box, err := readNextMP4Box(reader, offset, end, &boxCount)
		if err != nil {
			return 0, err
		}
		switch box.kind {
		case "mvhd":
			movie, err = parseDurationHeader(reader, box.payloadStart, box.end)
			if err != nil {
				return 0, err
			}
		case "trak":
			track, trackErr := parseTrackDuration(reader, box.payloadStart, box.end)
			if trackErr != nil {
				return 0, trackErr
			}
			tracks = append(tracks, track)
		case "mvex":
			return 0, fmt.Errorf("fragmented MP4 is not supported")
		}
		offset = box.end
	}
	movieSeconds, err := movie.roundedSeconds()
	if err != nil || len(tracks) == 0 {
		return 0, fmt.Errorf("MP4 timing metadata is unavailable")
	}
	actualSeconds := 0
	for _, track := range tracks {
		seconds, trackErr := track.roundedSeconds()
		if trackErr != nil {
			return 0, trackErr
		}
		if seconds > actualSeconds {
			actualSeconds = seconds
		}
	}
	difference := movieSeconds - actualSeconds
	if difference < 0 {
		difference = -difference
	}
	if difference > 1 {
		return 0, fmt.Errorf("MP4 movie and sample durations disagree")
	}
	return actualSeconds, nil
}

func parseTrackDuration(reader io.ReaderAt, start, end int64) (mediaDuration, error) {
	boxCount := 0
	for offset := start; offset < end; {
		box, err := readNextMP4Box(reader, offset, end, &boxCount)
		if err != nil {
			return mediaDuration{}, err
		}
		if box.kind == "mdia" {
			return parseMediaDuration(reader, box.payloadStart, box.end)
		}
		offset = box.end
	}
	return mediaDuration{}, fmt.Errorf("MP4 track has no media timing")
}

func parseMediaDuration(reader io.ReaderAt, start, end int64) (mediaDuration, error) {
	var header mediaDuration
	var samples uint64
	boxCount := 0
	for offset := start; offset < end; {
		box, err := readNextMP4Box(reader, offset, end, &boxCount)
		if err != nil {
			return mediaDuration{}, err
		}
		switch box.kind {
		case "mdhd":
			header, err = parseDurationHeader(reader, box.payloadStart, box.end)
			if err != nil {
				return mediaDuration{}, err
			}
		case "minf":
			samples, err = parseSampleTiming(reader, box.payloadStart, box.end)
			if err != nil {
				return mediaDuration{}, err
			}
		}
		offset = box.end
	}
	if header.timescale == 0 || samples == 0 {
		return mediaDuration{}, fmt.Errorf("MP4 track timing is unavailable")
	}
	difference := header.units
	if samples > difference {
		difference = samples - difference
	} else {
		difference -= samples
	}
	if difference > uint64(header.timescale) {
		return mediaDuration{}, fmt.Errorf("MP4 media and sample durations disagree")
	}
	return mediaDuration{units: samples, timescale: header.timescale}, nil
}

func parseSampleTiming(reader io.ReaderAt, start, end int64) (uint64, error) {
	boxCount := 0
	for offset := start; offset < end; {
		box, err := readNextMP4Box(reader, offset, end, &boxCount)
		if err != nil {
			return 0, err
		}
		if box.kind == "stbl" {
			childCount := 0
			for child := box.payloadStart; child < box.end; {
				entry, childErr := readNextMP4Box(reader, child, box.end, &childCount)
				if childErr != nil {
					return 0, childErr
				}
				if entry.kind == "stts" {
					return parseTimeToSample(reader, entry.payloadStart, entry.end)
				}
				child = entry.end
			}
		}
		offset = box.end
	}
	return 0, fmt.Errorf("MP4 sample timing is unavailable")
}

func parseTimeToSample(reader io.ReaderAt, start, end int64) (uint64, error) {
	if end-start < 8 {
		return 0, fmt.Errorf("truncated stts box")
	}
	var header [8]byte
	if _, err := reader.ReadAt(header[:], start); err != nil {
		return 0, err
	}
	if header[0] != 0 {
		return 0, fmt.Errorf("unsupported stts version")
	}
	count := binary.BigEndian.Uint32(header[4:8])
	if count == 0 || count > maxMP4STTSEntries || int64(count) > (end-start-8)/8 {
		return 0, fmt.Errorf("invalid stts entries")
	}
	entries := make([]byte, int64(count)*8)
	if _, err := reader.ReadAt(entries, start+8); err != nil {
		return 0, err
	}
	var total uint64
	for index := uint32(0); index < count; index++ {
		entry := entries[index*8 : index*8+8]
		sampleCount := uint64(binary.BigEndian.Uint32(entry[:4]))
		sampleDelta := uint64(binary.BigEndian.Uint32(entry[4:]))
		if sampleCount == 0 || sampleDelta == 0 || sampleCount > (^uint64(0)-total)/sampleDelta {
			return 0, fmt.Errorf("invalid stts duration")
		}
		total += sampleCount * sampleDelta
	}
	return total, nil
}

func readNextMP4Box(reader io.ReaderAt, offset, limit int64, count *int) (mp4Box, error) {
	(*count)++
	if *count > maxMP4BoxesPerContainer {
		return mp4Box{}, fmt.Errorf("too many MP4 boxes")
	}
	return readMP4Box(reader, offset, limit)
}

func readMP4Box(reader io.ReaderAt, offset, limit int64) (mp4Box, error) {
	if offset < 0 || limit-offset < 8 {
		return mp4Box{}, fmt.Errorf("truncated box")
	}
	var header [16]byte
	if _, err := reader.ReadAt(header[:8], offset); err != nil {
		return mp4Box{}, err
	}
	headerSize := int64(8)
	boxSize := int64(binary.BigEndian.Uint32(header[:4]))
	if boxSize == 1 {
		if limit-offset < 16 {
			return mp4Box{}, fmt.Errorf("truncated extended box")
		}
		if _, err := reader.ReadAt(header[8:16], offset+8); err != nil {
			return mp4Box{}, err
		}
		headerSize = 16
		extended := binary.BigEndian.Uint64(header[8:16])
		if extended > uint64(^uint64(0)>>1) {
			return mp4Box{}, fmt.Errorf("oversized box")
		}
		boxSize = int64(extended)
	} else if boxSize == 0 {
		boxSize = limit - offset
	}
	if boxSize < headerSize || boxSize > limit-offset {
		return mp4Box{}, fmt.Errorf("invalid box size")
	}
	return mp4Box{
		kind: string(header[4:8]), payloadStart: offset + headerSize, end: offset + boxSize,
	}, nil
}

func parseDurationHeader(reader io.ReaderAt, start, end int64) (mediaDuration, error) {
	var payload [32]byte
	available := end - start
	if available < 20 {
		return mediaDuration{}, fmt.Errorf("truncated duration box")
	}
	readSize := int64(len(payload))
	if available < readSize {
		readSize = available
	}
	if _, err := reader.ReadAt(payload[:readSize], start); err != nil {
		return mediaDuration{}, err
	}
	var timescale uint32
	var duration uint64
	switch payload[0] {
	case 0:
		timescale = binary.BigEndian.Uint32(payload[12:16])
		duration = uint64(binary.BigEndian.Uint32(payload[16:20]))
	case 1:
		if available < 32 {
			return mediaDuration{}, fmt.Errorf("truncated version 1 duration box")
		}
		timescale = binary.BigEndian.Uint32(payload[20:24])
		duration = binary.BigEndian.Uint64(payload[24:32])
	default:
		return mediaDuration{}, fmt.Errorf("unsupported duration version")
	}
	if timescale == 0 || duration == 0 || duration == ^uint64(0) {
		return mediaDuration{}, fmt.Errorf("invalid MP4 duration")
	}
	return mediaDuration{units: duration, timescale: timescale}, nil
}

func (c *DecartVideoClient) Retrieve(
	ctx context.Context,
	_ string,
	queueID string,
) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(strings.TrimSpace(queueID)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeDecartJSON(resp.Body, &body); err != nil {
		return nil, decartProtocolError()
	}
	status := strings.ToLower(strings.TrimSpace(body.Status))
	switch status {
	case "pending", "queued", "processing", "running", "in_progress":
		return &PollResult{State: PollProcessing, ProviderStatus: strings.ToUpper(status)}, nil
	case "completed", "complete", "succeeded", "success", "done":
		return &PollResult{
			State: PollCompleted, ProviderStatus: strings.ToUpper(status),
			DownloadURL: "decart-video:" + strings.TrimSpace(queueID),
		}, nil
	case "failed", "error", "cancelled", "canceled":
		return &PollResult{State: PollFailed, ProviderStatus: strings.ToUpper(status)}, nil
	default:
		return nil, decartProtocolError()
	}
}

func decartProtocolError() error {
	return &HTTPError{Provider: "decart", Status: http.StatusBadGateway, Retryable: false}
}

func (c *DecartVideoClient) Download(ctx context.Context, reference string) (*PollResult, error) {
	queueID := strings.TrimPrefix(strings.TrimSpace(reference), "decart-video:")
	if queueID == "" || queueID == strings.TrimSpace(reference) {
		return nil, fmt.Errorf("decart video download: invalid reference")
	}
	headers := make(http.Header)
	headers.Set("X-API-KEY", c.apiKey)
	return downloadVideo(
		ctx, c.http,
		c.baseURL+"/v1/jobs/"+url.PathEscape(queueID)+"/content",
		c.ID(), headers,
	)
}

func (c *DecartVideoClient) Complete(context.Context, string, string) error {
	// Decart exposes no delete endpoint for completed jobs.
	return nil
}

func (c *DecartVideoClient) request(
	ctx context.Context,
	method string,
	path string,
) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("decart video provider is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("decart video request is invalid")
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("decart video request failed: %w", err)
	}
	return resp, nil
}

func decodeDecartJSON(body io.Reader, target any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxDecartResponseBytes+1))
	if err != nil || len(raw) > maxDecartResponseBytes {
		return fmt.Errorf("invalid response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
