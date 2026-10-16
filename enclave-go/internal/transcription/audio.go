package transcription

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/hajimehoshi/go-mp3"
)

// Measure bounds decoded work as well as compressed bytes. Duration supplied by
// a caller, filename, or ID3 tag is never used for billing admission.
func Measure(ctx context.Context, req *Request) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(req.Audio) == 0 || len(req.Audio) > MaxAudioBytes {
		return invalid("file", "Audio exceeds the upload limit")
	}
	if bytes.HasPrefix(req.Audio, []byte("RIFF")) {
		if req.AudioFormat != "" && req.AudioFormat != "wav" {
			return invalid("input_audio.format", "Audio format does not match its contents")
		}
		req.AudioFormat = "wav"
		ms, err := wavDuration(req.Audio)
		if err != nil {
			return err
		}
		req.DurationMS = ms
		return nil
	}
	if req.AudioFormat != "" && req.AudioFormat != "mp3" {
		return invalid("input_audio.format", "This release supports PCM WAV and MP3 uploads")
	}
	// A non-seekable reader avoids an initial scan for an untrusted length.
	// The decoder allocates ID3 tag size before reading it. Validate that
	// untrusted length against actual input first, including synchsafe bits.
	if bytes.HasPrefix(req.Audio, []byte("ID3")) {
		if len(req.Audio) < 10 {
			return invalid("file", "Invalid ID3 header")
		}
		var size uint32
		for _, value := range req.Audio[6:10] {
			if value > 127 {
				return invalid("file", "Invalid ID3 tag size")
			}
			size = size<<7 | uint32(value)
		}
		if int64(size) > int64(len(req.Audio))-10 {
			return invalid("file", "Truncated ID3 tag")
		}
	}
	decoder, err := mp3.NewDecoder(bytes.NewBuffer(req.Audio))
	if err != nil {
		return invalid("file", "Invalid MP3 or unsupported audio format")
	}
	sampleRate := decoder.SampleRate()
	if sampleRate < 8000 || sampleRate > 48000 {
		return invalid("file", "Unsupported MP3 sample rate")
	}
	rate := uint32(sampleRate)
	deadline := time.Now().Add(15 * time.Second)
	limit := int64(sampleRate) * 4 * MaxDurationMS / 1000
	var total int64
	var pcm bytes.Buffer
	buffer := make([]byte, 16384)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return invalid("file", "Audio validation exceeded its processing limit")
		}
		n, err := decoder.Read(buffer)
		total += int64(n)
		if total > limit {
			return invalid("file", "Audio exceeds ten minutes")
		}
		// Canonical mono PCM makes the charged duration exactly match what the
		// provider receives, even for MPEG files with inconsistent frame rates.
		if n%4 != 0 {
			return invalid("file", "Invalid MP3 sample alignment")
		}
		for i := 0; i < n; i += 4 {
			left := signedPCM16(buffer[i : i+2])
			right := signedPCM16(buffer[i+2 : i+4])
			sample := (left + right) / 2
			_ = pcm.WriteByte(byte(sample & 0xff))
			_ = pcm.WriteByte(byte((sample >> 8) & 0xff))
		}
		if pcm.Len() > 24_000_000 {
			return invalid("file", "Decoded audio exceeds 24 MB; use a shorter clip or lower sample rate")
		}
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return invalid("file", "Invalid MP3 audio")
		}
	}
	if total == 0 {
		return invalid("file", "Audio is empty")
	}
	req.DurationMS = int((total*1000 + int64(sampleRate)*4 - 1) / (int64(sampleRate) * 4))
	pcmSize := pcm.Len()
	if pcmSize <= 0 || pcmSize > 24_000_000 {
		return invalid("file", "Decoded audio exceeds 24 MB")
	}
	data := make([]byte, 44+pcmSize)
	copy(data, "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], uint32(pcmSize)+36)
	copy(data[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(data[16:20], 16)
	binary.LittleEndian.PutUint16(data[20:22], 1)
	binary.LittleEndian.PutUint16(data[22:24], 1)
	binary.LittleEndian.PutUint32(data[24:28], rate)
	binary.LittleEndian.PutUint32(data[28:32], rate*2)
	binary.LittleEndian.PutUint16(data[32:34], 2)
	binary.LittleEndian.PutUint16(data[34:36], 16)
	copy(data[36:], "data")
	binary.LittleEndian.PutUint32(data[40:44], uint32(pcmSize))
	copy(data[44:], pcm.Bytes())
	req.Audio, req.AudioFormat = data, "wav"
	return nil
}

func signedPCM16(data []byte) int32 {
	value := int32(binary.LittleEndian.Uint16(data))
	if value >= 32768 {
		value -= 65536
	}
	return value
}

func wavDuration(data []byte) (int, error) {
	bad := func() (int, error) { return 0, invalid("file", "Use a valid PCM WAV file of at most ten minutes") }
	if len(data) < 44 || string(data[8:12]) != "WAVE" || uint64(binary.LittleEndian.Uint32(data[4:8]))+8 != uint64(len(data)) {
		return bad()
	}
	var rate, align, size uint64
	fmtSeen, dataSeen := false, false
	for offset := uint64(12); offset < uint64(len(data)); {
		if uint64(len(data))-offset < 8 {
			return bad()
		}
		n := uint64(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		start := offset + 8
		end := start + n
		if end > uint64(len(data)) {
			return bad()
		}
		switch string(data[offset : offset+4]) {
		case "fmt ":
			if fmtSeen || n != 16 {
				return bad()
			}
			fmtSeen = true
			p := data[start:end]
			codec, channels, bits := binary.LittleEndian.Uint16(p[:2]), binary.LittleEndian.Uint16(p[2:4]), binary.LittleEndian.Uint16(p[14:16])
			rate, align = uint64(binary.LittleEndian.Uint32(p[4:8])), uint64(binary.LittleEndian.Uint16(p[12:14]))
			if codec != 1 || channels < 1 || channels > 2 || bits != 16 || rate < 8000 || rate > 48000 || align != uint64(channels)*2 || uint64(binary.LittleEndian.Uint32(p[8:12])) != rate*align {
				return bad()
			}
		case "data":
			if dataSeen {
				return bad()
			}
			dataSeen, size = true, n
		}
		offset = end + n%2
		if offset > uint64(len(data)) {
			return bad()
		}
	}
	if !fmtSeen || !dataSeen || size == 0 || size%align != 0 {
		return bad()
	}
	ms := (size*1000 + rate*align - 1) / (rate * align)
	if ms > MaxDurationMS {
		return bad()
	}
	return int(ms), nil
}
