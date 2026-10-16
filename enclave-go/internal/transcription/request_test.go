package transcription

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"mime/multipart"
	"strings"
	"testing"
)

// Generated silence, no customer content: ffmpeg lavfi anullsrc, 16 kHz mono,
// one second, libmp3lame 32k. MPEG encoder padding adds a few frames.
//
//go:embed testdata/silence.mp3
var silenceMP3 []byte

func TestMP3Duration(t *testing.T) {
	r := &Request{Audio: silenceMP3, AudioFormat: "mp3"}
	if err := Measure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if r.DurationMS < 1000 || r.DurationMS > 1250 {
		t.Fatalf("invalid MP3 duration %d", r.DurationMS)
	}
	measured, err := wavDuration(r.Audio)
	if err != nil || measured != r.DurationMS || r.AudioFormat != "wav" {
		t.Fatal("decoded upload duration differs from billed duration")
	}
}

func wavFixture() []byte {
	b := make([]byte, 44+16000*2)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)-8))
	copy(b[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(b[16:20], 16)
	binary.LittleEndian.PutUint16(b[20:22], 1)
	binary.LittleEndian.PutUint16(b[22:24], 1)
	binary.LittleEndian.PutUint32(b[24:28], 16000)
	binary.LittleEndian.PutUint32(b[28:32], 32000)
	binary.LittleEndian.PutUint16(b[32:34], 2)
	binary.LittleEndian.PutUint16(b[34:36], 16)
	copy(b[36:], "data")
	binary.LittleEndian.PutUint32(b[40:44], uint32(len(b)-44))
	return b
}

func TestJSONAndMultipart(t *testing.T) {
	for _, multipartBody := range []bool{false, true} {
		var body []byte
		contentType := "application/json"
		if multipartBody {
			var b bytes.Buffer
			w := multipart.NewWriter(&b)
			_ = w.WriteField("model", "openai/whisper-1")
			_ = w.WriteField("response_format", "verbose_json")
			_ = w.WriteField("timestamp_granularities[]", "word")
			_ = w.WriteField("provider[only][]", "openai")
			_ = w.WriteField("provider[allow_fallbacks]", "false")
			part, _ := w.CreateFormFile("file", "do-not-store-this-filename.wav")
			_, _ = part.Write(wavFixture())
			_ = w.Close()
			body, contentType = b.Bytes(), w.FormDataContentType()
		} else {
			body, _ = json.Marshal(map[string]any{"model": "openai/whisper-1", "input_audio": map[string]string{"data": base64.StdEncoding.EncodeToString(wavFixture()), "format": "wav"}, "response_format": "verbose_json", "timestamp_granularities": []string{"word"}})
		}
		r, err := Parse(body, contentType)
		if err != nil {
			t.Fatal(err)
		}
		if multipartBody && (r.Provider == nil || len(r.Provider.Only) != 1 || r.Provider.Only[0] != "openai" || r.Provider.AllowFallbacks == nil || *r.Provider.AllowFallbacks) {
			t.Fatal("SDK provider settings lost")
		}
		if err := Measure(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if r.DurationMS != 1000 || r.AudioFormat != "wav" || r.InputAudio != nil {
			t.Fatalf("wrong measured metadata: %d %s", r.DurationMS, r.AudioFormat)
		}
		metadata, _ := json.Marshal(r)
		if bytes.Contains(metadata, []byte("do-not-store")) || bytes.Contains(metadata, []byte(base64.StdEncoding.EncodeToString(wavFixture()))) {
			t.Fatal("raw audio retained in request metadata")
		}
	}
}

func TestRejectInvalidRequests(t *testing.T) {
	for _, fields := range []string{
		`"unknown":"private"`, `"response_format":"srt"`, `"temperature":2`,
		`"language":"english"`, `"diarize":true`, `"keyterms":["x"]`,
		`"timestamp_granularities":["word"]`, `"stream":true`, `"input_audio":{"url":"http://169.254.169.254"}`,
		`"model":"mistralai/voxtral-mini-2602"`,
	} {
		raw := []byte(`{"model":"openai/whisper-1","input_audio":{"data":"UklGRg==","format":"wav"},` + fields + `}`)
		if _, err := Parse(raw, "application/json"); err == nil {
			t.Fatalf("accepted %s", fields)
		}
	}
	if _, err := Parse([]byte(`{} {}`), "application/json"); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if _, err := Parse([]byte("body"), "text/plain"); err == nil {
		t.Fatal("accepted wrong content type")
	}
}

func FuzzMeasure(f *testing.F) {
	f.Add(wavFixture())
	f.Add(silenceMP3)
	f.Add([]byte("ID3\x04\x00\x00\x7f\x7f\x7f\x7f"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}
		_ = Measure(context.Background(), &Request{Audio: data})
	})
}

func TestRejectMaliciousAudio(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[4] = 0; return b },
		func(b []byte) []byte { b[20] = 3; return b },
		func(b []byte) []byte { b[32] = 1; return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[40:44], 0xffffffff); return b },
		func(b []byte) []byte { return b[:43] },
	} {
		if err := Measure(context.Background(), &Request{Audio: mutate(wavFixture())}); err == nil {
			t.Fatal("accepted malformed WAV")
		}
	}
	for _, audio := range [][]byte{[]byte("ID3"), []byte("ID3\x04\x00\x00\xff\xff\xff\xff"), []byte("ID3\x04\x00\x00\x7f\x7f\x7f\x7f"), []byte("not audio")} {
		if err := Measure(context.Background(), &Request{Audio: audio}); err == nil {
			t.Fatal("accepted invalid MP3")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Measure(ctx, &Request{Audio: wavFixture()}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestMultipartRejectsDuplicateFile(t *testing.T) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("model", "openai/whisper-1")
	for i := 0; i < 2; i++ {
		part, _ := w.CreateFormFile("file", "audio.wav")
		_, _ = part.Write(wavFixture())
	}
	_ = w.Close()
	if _, err := Parse(b.Bytes(), w.FormDataContentType()); err == nil || !strings.Contains(err.Error(), "one audio") {
		t.Fatalf("duplicate file: %v", err)
	}
}
