package shadowcoord

// MaxInputDepth bounds the second JSON decode and recursive payload preparation.
// Strings (including escaped quotes/brackets) do not affect container depth.
const MaxInputDepth = 32

func InputDepthOK(raw []byte) bool {
	depth := 0
	quoted, escaped := false, false
	for _, b := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > MaxInputDepth {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}
