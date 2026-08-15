package llm

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const chutesMaxEncryptedSSELine = 16 << 20

type chutesEncryptedSSEEvent struct {
	Init  string          `json:"e2e_init"`
	Chunk string          `json:"e2e"`
	Usage json.RawMessage `json:"usage"`
	Error json.RawMessage `json:"e2e_error"`
}

// decryptChutesStream turns Chutes' encrypted outer SSE stream back into the
// ordinary OpenAI SSE stream produced inside the attested GPU workload. It is
// deliberately strict: malformed, reordered, unauthenticated, or truncated
// streams fail instead of being translated into a successful empty response.
func decryptChutesStream(
	r io.Reader,
	w io.Writer,
	responseSK *mlkem.DecapsulationKey768,
) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), chutesMaxEncryptedSSELine)
	var streamKey []byte
	initSeen := false
	chunkSeen := false
	innerDoneSeen := false
	doneSeen := false

	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "event:") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			return fmt.Errorf("chutes e2ee: unexpected encrypted SSE field")
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "[DONE]" {
			if !initSeen || !chunkSeen || !innerDoneSeen {
				return fmt.Errorf("chutes e2ee: stream ended before authenticated terminal marker")
			}
			if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
				return err
			}
			doneSeen = true
			break
		}
		if raw == "" {
			continue
		}

		var event chutesEncryptedSSEEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return fmt.Errorf("chutes e2ee: malformed encrypted SSE event: %w", err)
		}
		fields := 0
		if event.Init != "" {
			fields++
		}
		if event.Chunk != "" {
			fields++
		}
		if len(event.Usage) > 0 {
			fields++
		}
		if len(event.Error) > 0 {
			fields++
		}
		if fields != 1 {
			return fmt.Errorf("chutes e2ee: encrypted SSE event has %d recognized fields", fields)
		}

		switch {
		case event.Init != "":
			if initSeen {
				return fmt.Errorf("chutes e2ee: duplicate stream initialization")
			}
			key, err := decryptChutesStreamInit(event.Init, responseSK)
			if err != nil {
				return err
			}
			streamKey = key
			initSeen = true
		case event.Chunk != "":
			if !initSeen {
				return fmt.Errorf("chutes e2ee: encrypted chunk arrived before stream initialization")
			}
			plaintext, err := decryptChutesStreamChunk(event.Chunk, streamKey)
			if err != nil {
				return err
			}
			framed, terminal, err := frameChutesDecryptedChunk(plaintext)
			if err != nil {
				return err
			}
			if innerDoneSeen && len(framed) > 0 {
				return fmt.Errorf("chutes e2ee: encrypted content arrived after terminal marker")
			}
			innerDoneSeen = innerDoneSeen || terminal
			if len(framed) > 0 {
				if _, err := w.Write(framed); err != nil {
					return err
				}
				chunkSeen = true
			}
		case len(event.Usage) > 0:
			if !json.Valid(event.Usage) {
				return fmt.Errorf("chutes e2ee: invalid plaintext usage event")
			}
			if _, err := fmt.Fprintf(w, "data: {\"usage\":%s}\n\n", event.Usage); err != nil {
				return err
			}
		case len(event.Error) > 0:
			return fmt.Errorf("chutes e2ee: attested instance returned an encrypted-stream error")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("chutes e2ee: read encrypted stream: %w", err)
	}
	if !doneSeen && innerDoneSeen && initSeen && chunkSeen {
		if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
			return err
		}
		doneSeen = true
	}
	if !doneSeen {
		return fmt.Errorf("chutes e2ee: encrypted stream ended without [DONE]")
	}
	return nil
}

func frameChutesDecryptedChunk(plaintext []byte) ([]byte, bool, error) {
	plaintext = bytes.TrimSpace(plaintext)
	if bytes.HasPrefix(plaintext, []byte("data:")) {
		payload := bytes.TrimSpace(bytes.TrimPrefix(plaintext, []byte("data:")))
		if len(payload) == 0 {
			return nil, false, nil
		}
		if bytes.Equal(payload, []byte("[DONE]")) {
			return nil, true, nil
		}
		if !json.Valid(payload) {
			return nil, false, fmt.Errorf("chutes e2ee: decrypted SSE chunk has invalid JSON")
		}
		return append(append([]byte(nil), plaintext...), '\n', '\n'), false, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &object); err != nil || len(object) == 0 {
		// Chutes' reference client treats authenticated non-JSON chunks as
		// token text. Normalize that provider variant into the OpenAI delta
		// shape consumed by the rest of the enclave. Never echo the text in
		// an error or log.
		if len(plaintext) == 0 {
			return nil, false, nil
		}
		if bytes.Equal(plaintext, []byte("[DONE]")) {
			return nil, true, nil
		}
		if !utf8.Valid(plaintext) {
			return nil, false, fmt.Errorf("chutes e2ee: decrypted stream chunk has invalid text framing")
		}
		normalized, marshalErr := json.Marshal(map[string]any{
			"choices": []any{map[string]any{
				"delta": map[string]string{"content": string(plaintext)},
			}},
		})
		if marshalErr != nil {
			return nil, false, fmt.Errorf("chutes e2ee: normalize authenticated text chunk: %w", marshalErr)
		}
		plaintext = normalized
		object = map[string]json.RawMessage{"choices": json.RawMessage("[]")}
	}
	if _, choices := object["choices"]; !choices {
		if _, usage := object["usage"]; !usage {
			if _, providerError := object["error"]; !providerError {
				return nil, false, fmt.Errorf("chutes e2ee: decrypted stream chunk has no OpenAI event field")
			}
		}
	}
	framed := make([]byte, 0, len(plaintext)+8)
	framed = append(framed, "data: "...)
	framed = append(framed, plaintext...)
	framed = append(framed, '\n', '\n')
	return framed, false, nil
}

func translateChutesEncryptedStream(
	r io.Reader,
	out io.Writer,
	responseSK *mlkem.DecapsulationKey768,
) error {
	reader, writer := io.Pipe()
	go func() {
		err := decryptChutesStream(r, writer, responseSK)
		_ = writer.CloseWithError(err)
	}()
	return translateOpenAIStreamToAnthropic(reader, out)
}
