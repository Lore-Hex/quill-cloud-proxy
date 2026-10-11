package speech

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"mime"
)

func decodeGeminiAudio(raw []byte, spec Spec, format string) (*Result, error) {
	var response struct {
		Status      string `json:"status"`
		Model       string `json:"model"`
		ServiceTier string `json:"service_tier"`
		Usage       struct {
			Input   int `json:"total_input_tokens"`
			Output  int `json:"total_output_tokens"`
			Cached  int `json:"total_cached_tokens"`
			Thought int `json:"total_thought_tokens"`
			Tools   int `json:"total_tool_use_tokens"`
		} `json:"usage"`
		Steps []struct {
			Type    string `json:"type"`
			Content []struct {
				Type       string `json:"type"`
				Data       string `json:"data"`
				Mime       string `json:"mime_type"`
				SampleRate int    `json:"sample_rate"`
				Channels   int    `json:"channels"`
			} `json:"content"`
		} `json:"steps"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Status != "completed" || response.Model != spec.Upstream || response.ServiceTier != "standard" {
		return nil, errors.New("invalid Gemini speech completion")
	}
	usage := response.Usage
	if usage.Input <= 0 || usage.Input > GeminiInputLimit || usage.Output <= 0 || usage.Output > GeminiOutputLimit || usage.Cached != 0 || usage.Thought != 0 || usage.Tools != 0 {
		return nil, errors.New("invalid Gemini speech usage")
	}
	if len(response.Steps) != 1 || response.Steps[0].Type != "model_output" || len(response.Steps[0].Content) != 1 {
		return nil, errors.New("invalid Gemini speech output")
	}
	part := response.Steps[0].Content[0]
	wantMime := "audio/l16"
	if format == "wav" {
		wantMime = "audio/wav"
	}
	mediaType, _, err := mime.ParseMediaType(part.Mime)
	if err != nil || mediaType != wantMime || part.Type != "audio" {
		return nil, errors.New("invalid Gemini speech format")
	}
	// WAV carries its format in the validated RIFF header. The API omits
	// redundant sample_rate/channels there, but supplies both for raw PCM.
	if (format == "pcm" && (part.SampleRate != 24000 || part.Channels != 1)) ||
		(format == "wav" && ((part.SampleRate != 0 && part.SampleRate != 24000) || (part.Channels != 0 && part.Channels != 1))) {
		return nil, errors.New("invalid Gemini speech layout")
	}
	audio, err := base64.StdEncoding.Strict().DecodeString(part.Data)
	if err != nil || len(audio) == 0 || len(audio) > MaxAudioBytes {
		return nil, errors.New("invalid Gemini speech encoding")
	}
	if format == "wav" {
		if !validWAV(audio) {
			return nil, errors.New("invalid Gemini WAV")
		}
	} else if len(audio)%2 != 0 {
		return nil, errors.New("invalid Gemini PCM")
	}
	contentType := "audio/pcm;rate=24000;channels=1"
	if format == "wav" {
		contentType = "audio/wav"
	}
	return &Result{Audio: audio, ContentType: contentType, InputTokens: usage.Input, OutputTokens: usage.Output}, nil
}

// Validate chunk boundaries and PCM layout before charging for buffered audio.
func validWAV(b []byte) bool {
	if len(b) < 44 || len(b) > MaxAudioBytes || !bytes.Equal(b[:4], []byte("RIFF")) || !bytes.Equal(b[8:12], []byte("WAVE")) || uint64(binary.LittleEndian.Uint32(b[4:8]))+8 != uint64(len(b)) {
		return false
	}
	fmtOK, dataOK := false, false
	for offset := 12; offset < len(b); {
		if len(b)-offset < 8 {
			return false
		}
		size := binary.LittleEndian.Uint32(b[offset+4 : offset+8])
		if size > MaxAudioBytes {
			return false
		}
		// Both offsets and chunk sizes are bounded by 64 MiB, including on
		// 32-bit builds; do not convert an unchecked provider-sized integer.
		chunkSize := int(size)
		end := offset + 8 + chunkSize
		if end > len(b) {
			return false
		}
		switch string(b[offset : offset+4]) {
		case "fmt ":
			if fmtOK || size < 16 {
				return false
			}
			p := b[offset+8 : end]
			fmtOK = binary.LittleEndian.Uint16(p[:2]) == 1 && binary.LittleEndian.Uint16(p[2:4]) == 1 && binary.LittleEndian.Uint32(p[4:8]) == 24000 && binary.LittleEndian.Uint32(p[8:12]) == 48000 && binary.LittleEndian.Uint16(p[12:14]) == 2 && binary.LittleEndian.Uint16(p[14:16]) == 16
			if !fmtOK {
				return false
			}
		case "data":
			if dataOK || size == 0 || size%2 != 0 {
				return false
			}
			dataOK = true
		}
		offset = end + chunkSize%2
		if offset > len(b) {
			return false
		}
	}
	return fmtOK && dataOK
}
