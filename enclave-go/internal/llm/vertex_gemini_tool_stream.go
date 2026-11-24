//go:build llm_multi

package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Vertex sends one named start, then anonymous continuations, even for two
// parallel calls to the same function. Only advance the index at the call end.
type geminiToolStream struct {
	index           int
	name, signature string
	args            *geminiArgumentStream
}

func (s *geminiToolStream) write(w io.Writer, call geminiFunctionCall) error {
	if s.args == nil {
		if call.Name == "" {
			return errors.New("llm/vertex-gemini-stream: unnamed function call")
		}
		id := fmt.Sprintf("call_%d", s.index)
		if call.Signature != "" {
			id += geminiSignatureDelimiter + call.Signature
		}
		if err := writeAnthropicToolStart(w, s.index, id, call.Name); err != nil {
			return err
		}
		s.name, s.signature = call.Name, call.Signature
	} else if (call.Name != "" && call.Name != s.name) || (call.Signature != "" && call.Signature != s.signature) {
		return errors.New("llm/vertex-gemini-stream: function identity changed during call")
	}

	var delta strings.Builder
	if call.Args != nil || (s.args == nil && !call.WillContinue && call.PartialArgs == nil) {
		if s.args != nil || call.PartialArgs != nil || call.WillContinue {
			return errors.New("llm/vertex-gemini-stream: mixed complete and partial arguments")
		}
		if call.Args == nil {
			delta.WriteString("{}")
		} else {
			b, err := json.Marshal(call.Args)
			if err != nil {
				return err
			}
			delta.Write(b)
		}
	} else {
		if s.args == nil {
			s.args = &geminiArgumentStream{frames: []geminiArgFrame{{}}}
			delta.WriteByte('{')
		}
		for _, arg := range call.PartialArgs {
			if err := s.args.appendArg(&delta, arg); err != nil {
				return err
			}
		}
		if !call.WillContinue {
			if s.args.stringPath != "" {
				return errGeminiArg
			}
			s.args.closeTo(&delta, 0)
		}
	}
	if delta.Len() != 0 {
		if err := writeAnthropicToolDelta(w, s.index, delta.String()); err != nil {
			return err
		}
	}
	if call.WillContinue {
		return nil
	}
	if err := writeAnthropicToolStop(w, s.index); err != nil {
		return err
	}
	s.args = nil
	s.index++
	return nil
}

type geminiPartialArg struct {
	JSONPath     string
	StringValue  *string
	NumberValue  *json.Number
	BoolValue    *bool
	NullValue    json.RawMessage
	WillContinue bool
}

// Argument deltas are append-only. Keep the open containers, not the generated
// argument text. Reject a path that would require rewriting already sent bytes.
type geminiArgumentStream struct {
	frames     []geminiArgFrame
	stringPath string
}

type geminiPathStep struct {
	key   string
	index int
	array bool
}

type geminiArgFrame struct {
	at    geminiPathStep
	array bool
	count int
	keys  map[string]struct{}
}

var errGeminiArg = errors.New("llm/vertex-gemini-stream: invalid partial argument sequence")

func (s *geminiArgumentStream) closeTo(out *strings.Builder, depth int) {
	for len(s.frames) > depth {
		i := len(s.frames) - 1
		if s.frames[i].array {
			out.WriteByte(']')
		} else {
			out.WriteByte('}')
		}
		s.frames[i] = geminiArgFrame{}
		s.frames = s.frames[:i]
	}
}

func (s *geminiArgumentStream) appendArg(out *strings.Builder, arg geminiPartialArg) error {
	continued := s.stringPath != ""
	if continued {
		if arg.JSONPath != s.stringPath {
			return errGeminiArg
		}
	} else {
		path, err := geminiArgPath(arg.JSONPath)
		if err != nil {
			return err
		}
		// Frame zero is the root object. Reuse the shared container prefix.
		depth := 1
		for depth < len(path) && depth < len(s.frames) && path[depth-1] == s.frames[depth].at {
			depth++
		}
		s.closeTo(out, depth)
		for i := depth - 1; i < len(path); i++ {
			step := path[i]
			frame := &s.frames[i]
			if frame.array != step.array {
				return errGeminiArg
			}
			if frame.count > 0 {
				out.WriteByte(',')
			}
			if step.array {
				if step.index != frame.count {
					return errGeminiArg
				}
			} else {
				if frame.keys == nil {
					frame.keys = make(map[string]struct{})
				}
				if _, exists := frame.keys[step.key]; exists {
					return errGeminiArg
				}
				frame.keys[step.key] = struct{}{}
				key, _ := json.Marshal(step.key)
				out.Write(key)
				out.WriteByte(':')
			}
			frame.count++
			if i+1 < len(path) {
				array := path[i+1].array
				if array {
					out.WriteByte('[')
				} else {
					out.WriteByte('{')
				}
				s.frames = append(s.frames, geminiArgFrame{at: step, array: array})
			}
		}
	}

	types := 0
	for _, set := range []bool{arg.StringValue != nil, arg.NumberValue != nil, arg.BoolValue != nil, arg.NullValue != nil} {
		if set {
			types++
		}
	}
	// Vertex may omit the empty stringValue on the closing chunk of a string.
	if types == 0 && continued && !arg.WillContinue {
		out.WriteByte('"')
		s.stringPath = ""
		return nil
	}
	if types != 1 || ((continued || arg.WillContinue) && arg.StringValue == nil) {
		return errGeminiArg
	}
	switch {
	case arg.StringValue != nil:
		b, _ := json.Marshal(*arg.StringValue)
		if !continued {
			out.WriteByte('"')
		}
		out.Write(b[1 : len(b)-1])
		if arg.WillContinue {
			s.stringPath = arg.JSONPath
		} else {
			out.WriteByte('"')
			s.stringPath = ""
		}
	case arg.BoolValue != nil:
		out.WriteString(strconv.FormatBool(*arg.BoolValue))
	case arg.NumberValue != nil:
		out.WriteString(arg.NumberValue.String())
	default:
		switch string(arg.NullValue) {
		case "null", "0", "\"NULL_VALUE\"":
			out.WriteString("null")
		default:
			return errGeminiArg
		}
	}
	return nil
}

// Only concrete RFC 9535 member names and nonnegative element indices can
// identify one argument. Wildcards, slices, filters and recursive descent cannot.
var geminiPathToken = regexp.MustCompile(`^(?:\.([A-Za-z_\x{80}-\x{10ffff}][A-Za-z0-9_\x{80}-\x{10ffff}]*)|\[(0|[1-9][0-9]*)\]|\[("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\])`)

func geminiArgPath(path string) ([]geminiPathStep, error) {
	if !strings.HasPrefix(path, "$") || len(path) < 2 || len(path) > 16384 {
		return nil, errGeminiArg
	}
	var steps []geminiPathStep
	for tail := path[1:]; tail != ""; {
		m := geminiPathToken.FindStringSubmatch(tail)
		if m == nil || len(steps) >= 128 {
			return nil, errGeminiArg
		}
		step := geminiPathStep{key: m[1]}
		if m[2] != "" {
			i, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, errGeminiArg
			}
			step.array, step.index = true, i
		} else if m[3] != "" {
			quoted := m[3]
			if quoted[0] == '\'' {
				// Convert single-quoted JSONPath to a JSON string before decoding.
				var b strings.Builder
				b.WriteByte('"')
				for i := 1; i < len(quoted)-1; i++ {
					switch quoted[i] {
					case '\\':
						i++
						if quoted[i] != '\'' {
							b.WriteByte('\\')
						}
					case '"':
						b.WriteByte('\\')
					}
					b.WriteByte(quoted[i])
				}
				b.WriteByte('"')
				quoted = b.String()
			}
			if err := json.Unmarshal([]byte(quoted), &step.key); err != nil {
				return nil, errGeminiArg
			}
		}
		steps = append(steps, step)
		tail = tail[len(m[0]):]
	}
	return steps, nil
}
