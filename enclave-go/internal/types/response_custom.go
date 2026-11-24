package types

import "strings"

// NativeCustomTools describes Responses wire semantics lost in the shared chat
// projection. History maps hold IDs only: input and output must come from the
// normalized messages that actually passed the gateway's request processing.
type NativeCustomTools struct {
	Definitions map[string]map[string]any
	CallIDs     map[string]bool
	OutputIDs   map[string]bool
	Choice      string
}

func NativeCustomModel(model string) bool {
	switch strings.TrimPrefix(model, "openai/") {
	case "gpt-5.5", "gpt-6.2-astra":
		return true
	}
	return false
}

func (m *ResponseRequestMeta) CustomTool(name string) bool {
	return m != nil && m.NativeCustom != nil && m.NativeCustom.Definitions[name] != nil
}
