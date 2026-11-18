package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

// MaxLenientDrops bounds how many parameters one lenient request may shed.
// Each drop re-runs validation, so the bound also caps the work per request.
const MaxLenientDrops = 64

// MaxLenientWorkBytes bounds the body bytes one lenient request may re-parse
// across all of its drops.
const MaxLenientWorkBytes = 32 << 20

// lenientContentRoots name the conversation itself. Lenient mode drops
// request parameters only; it never edits what the user or model said, so an
// unsupported content part is still refused.
var lenientContentRoots = map[string]struct{}{
	"input": {}, "message": {}, "messages": {}, "prompt": {}, "instructions": {},
	// These carry earlier turns by reference. Dropping one would answer
	// without the history the client asked for.
	"previous_response_id": {}, "conversation": {},
}

// LenientDropPath reports the request path a lenient request may drop to
// get past err. Only "unknown request parameter" 400s and 501 not-supported
// errors qualify. A malformed value of a supported field stays an error.
func LenientDropPath(err error) (string, bool) {
	var aerr *AdapterError
	if !errors.As(err, &aerr) || aerr == nil {
		return "", false
	}
	unknown := aerr.Status == 400 && aerr.Message == "unknown request parameter"
	if !unknown && aerr.Status != 501 {
		return "", false
	}
	// An unknown parameter's context is the client's literal key, kept exact.
	// A few 501 contexts also name the refused value ("store=true"); there
	// the field is the part before it.
	path := aerr.Context
	if aerr.Status == 501 {
		if field, _, named := strings.Cut(path, "="); named {
			path = field
		}
	}
	if strings.TrimSpace(path) == "" || strings.HasPrefix(path, "/") {
		return "", false
	}
	root, _ := splitPathSegment(strings.SplitN(path, ".", 2)[0])
	if _, content := lenientContentRoots[root]; content {
		return "", false
	}
	return path, true
}

// DropRequestPath removes the parameter named by path from a decoded request
// body. Paths use the error-context grammar: dot-separated keys and an
// optional [index] on a key. A client may name a key that itself contains "."
// or "[", so at each level the longest run of segments that is literally a key
// is taken before any of it is read as path syntax. Inside an array of
// objects, a segment either names elements by their "id" (plugins.<id>) or,
// failing that, the path applies to every element that holds it
// (tools.parameters.engine). A path ending in .type inside an indexed array
// element drops the whole element, since an element without its type is not a
// smaller valid request. It reports whether anything was removed.
func DropRequestPath(raw map[string]json.RawMessage, path string) bool {
	if path == "" {
		return false
	}
	return dropFromObject(raw, strings.Split(path, "."))
}

func dropFromObject(object map[string]json.RawMessage, segments []string) bool {
	for n := len(segments); n >= 1; n-- {
		literal := strings.Join(segments[:n], ".")
		if _, ok := object[literal]; ok {
			return dropAt(object, literal, -1, segments[n:])
		}
	}
	key, index := splitPathSegment(segments[0])
	if index < 0 {
		return false
	}
	if _, ok := object[key]; !ok {
		return false
	}
	return dropAt(object, key, index, segments[1:])
}

func dropAt(object map[string]json.RawMessage, key string, index int, rest []string) bool {
	value := object[key]
	if index < 0 {
		if len(rest) == 0 {
			delete(object, key)
			return true
		}
		updated, dropped := dropFromValue(key, value, rest)
		if !dropped {
			return false
		}
		object[key] = updated
		return true
	}
	var items []json.RawMessage
	if err := json.Unmarshal(value, &items); err != nil || index >= len(items) {
		return false
	}
	if len(rest) == 0 || (len(rest) == 1 && rest[0] == "type") {
		items = append(items[:index], items[index+1:]...)
	} else {
		updated, dropped := dropFromValue(key, items[index], rest)
		if !dropped {
			return false
		}
		items[index] = updated
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return false
	}
	object[key] = encoded
	return true
}

// dropFromValue applies the remaining path to a nested object or array. key
// is the field the value is held under.
func dropFromValue(key string, value json.RawMessage, segments []string) (json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err == nil && object != nil {
		if !dropFromObject(object, segments) {
			return nil, false
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, false
		}
		return encoded, true
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(value, &items); err != nil {
		return nil, false
	}
	// Only plugin contexts name an element by its id; an id may itself hold
	// dots (plugins.vendor.search), so the longest run of segments that is a
	// complete id wins. Any other array (tools) never matches by id, so a
	// field name cannot select an unrelated element that has that id.
	byID := false
	for n := len(segments); key == "plugins" && n >= 1 && !byID; n-- {
		id := strings.ToLower(strings.Join(segments[:n], "."))
		for _, item := range items {
			if elementID(item) == id {
				byID = true
				segments = append([]string{id}, segments[n:]...)
				break
			}
		}
	}
	if !byID {
		// The context names no element, so it is safe only when exactly one
		// element holds the path. Dropping it from several could strip a
		// supported sibling (a function tool's parameters schema).
		holder := -1
		for index, item := range items {
			probe := cloneObject(item)
			if probe != nil && dropFromObject(probe, segments) {
				if holder >= 0 {
					return nil, false
				}
				holder = index
			}
		}
		if holder < 0 || !dropFromObject(items[holder], segments) {
			return nil, false
		}
		encoded, err := json.Marshal(items)
		if err != nil {
			return nil, false
		}
		return encoded, true
	}
	dropped := false
	kept := make([]map[string]json.RawMessage, 0, len(items))
	for _, item := range items {
		if elementID(item) == strings.ToLower(segments[0]) {
			if len(segments) == 1 {
				dropped = true
				continue
			}
			if dropFromObject(item, segments[1:]) {
				dropped = true
			}
		}
		kept = append(kept, item)
	}
	if !dropped {
		return nil, false
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func cloneObject(item map[string]json.RawMessage) map[string]json.RawMessage {
	if item == nil {
		return nil
	}
	clone := make(map[string]json.RawMessage, len(item))
	for key, value := range item {
		clone[key] = value
	}
	return clone
}

func elementID(item map[string]json.RawMessage) string {
	var id string
	_ = json.Unmarshal(item["id"], &id)
	return strings.ToLower(strings.TrimSpace(id))
}

func splitPathSegment(segment string) (string, int) {
	open := strings.IndexByte(segment, '[')
	if open < 0 || !strings.HasSuffix(segment, "]") {
		return segment, -1
	}
	index, err := strconv.Atoi(segment[open+1 : len(segment)-1])
	if err != nil || index < 0 {
		return segment, -1
	}
	return segment[:open], index
}

// LenientParse runs parse on body. When lenient is set and parse fails on a
// droppable parameter, the parameter is removed and parse runs again, until it
// succeeds, fails on something that cannot be dropped, or MaxLenientDrops is
// reached. It returns the dropped paths in the order they were removed and the
// body that parsed, which later stages must use in place of the original. The
// caller's body is never modified.
func LenientParse[T any](body []byte, lenient bool, parse func([]byte) (T, error)) (T, []string, []byte, error) {
	result, err := parse(body)
	if err == nil || !lenient {
		return result, nil, body, err
	}
	// A repeated key is merged by the struct parse but kept only once by the
	// re-serialization below, which could drop a supported control (a first
	// provider object's zdr). Such a request keeps the strict answer.
	if hasDuplicateKeys(body) {
		return result, nil, body, err
	}
	var dropped []string
	current := body
	positions := arrayPositions{}
	work := 0
	for len(dropped) < MaxLenientDrops {
		// Each drop re-reads the whole body; bound the total so a large body
		// with many droppable fields cannot cost many parses.
		if work += len(current); work > MaxLenientWorkBytes {
			return result, nil, body, err
		}
		path, ok := LenientDropPath(err)
		if !ok {
			return result, nil, body, positions.remapError(current, err)
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(current, &raw) != nil {
			return result, nil, body, err
		}
		reported, recordRemoval := positions.original(raw, path)
		if !DropRequestPath(raw, path) {
			return result, nil, body, err
		}
		recordRemoval()
		encoded, marshalErr := json.Marshal(raw)
		if marshalErr != nil {
			return result, nil, body, err
		}
		current = encoded
		dropped = append(dropped, reported)
		result, err = parse(current)
		if err == nil {
			return result, dropped, current, nil
		}
	}
	return result, nil, body, err
}

// arrayPositions remembers, for every array a lenient parse removed elements
// from, the client-request indexes it removed. Arrays are keyed by their path
// in the client's request, so a path reported after earlier removals, at any
// depth, still names the element the client sent.
type arrayPositions map[string][]int

// original rewrites path's indexes to the client's request and returns a
// function that records the removal path makes, if it removes an element.
func (p arrayPositions) original(raw map[string]json.RawMessage, path string) (string, func()) {
	if _, literal := raw[path]; literal {
		return path, func() {}
	}
	if id, ok := strings.CutPrefix(path, "plugins."); ok && !strings.Contains(id, "[") {
		return path, p.pluginRemoval(raw, id)
	}
	segments := strings.Split(path, ".")
	reported := make([]string, len(segments))
	lastArray, lastIndex, lastPosition := "", -1, -1
	for position, segment := range segments {
		key, index := splitPathSegment(segment)
		if index < 0 {
			reported[position] = segment
			continue
		}
		arrayPath := strings.Join(append(append([]string{}, reported[:position]...), key), ".")
		original := index
		for _, removed := range p[arrayPath] {
			if removed <= original {
				original++
			}
		}
		reported[position] = key + "[" + strconv.Itoa(original) + "]"
		lastArray, lastIndex, lastPosition = arrayPath, original, position
	}
	record := func() {}
	tail := segments[lastPosition+1:]
	if lastPosition >= 0 && (len(tail) == 0 || (len(tail) == 1 && tail[0] == "type")) {
		record = func() {
			removed := append(p[lastArray], lastIndex)
			sort.Ints(removed)
			p[lastArray] = removed
		}
	}
	return strings.Join(reported, "."), record
}

// remapError rewrites the context of a refusal that follows earlier drops so
// it names the element in the client's request, which the caller's preview
// of the original body then reads.
func (p arrayPositions) remapError(current []byte, err error) error {
	var aerr *AdapterError
	if len(p) == 0 || !errors.As(err, &aerr) || aerr == nil || aerr.Context == "" {
		return err
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(current, &raw) != nil {
		return err
	}
	context, _ := p.original(raw, aerr.Context)
	if context == aerr.Context {
		return err
	}
	remapped := *aerr
	remapped.Context = context
	return &remapped
}

// hasDuplicateKeys reports whether any JSON object in body repeats a key. A
// body it cannot scan to the end counts as having one: rewriting what was not
// checked is not safe.
func hasDuplicateKeys(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	type frame struct {
		object    bool
		keys      map[string]struct{}
		expectKey bool
	}
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			// The end of a whole document, not one cut off inside an object.
			return len(stack) != 0
		}
		if err != nil {
			return true
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				if top != nil && top.object {
					top.expectKey = true
				}
				stack = append(stack, &frame{object: value == '{', keys: map[string]struct{}{}, expectKey: value == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		case string:
			if top != nil && top.object && top.expectKey {
				if _, seen := top.keys[value]; seen {
					return true
				}
				top.keys[value] = struct{}{}
				top.expectKey = false
				continue
			}
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
}

// pluginRemoval records the client-request indexes of the plugins a
// plugins.<id> path removes, when it names whole plugins by id.
func (p arrayPositions) pluginRemoval(raw map[string]json.RawMessage, id string) func() {
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw["plugins"], &items) != nil {
		return func() {}
	}
	id = strings.ToLower(id)
	var current []int
	for index, item := range items {
		if elementID(item) == id {
			current = append(current, index)
		}
	}
	if len(current) == 0 {
		return func() {}
	}
	return func() {
		removed := p["plugins"]
		var originals []int
		for _, index := range current {
			original := index
			for _, earlier := range removed {
				if earlier <= original {
					original++
				}
			}
			originals = append(originals, original)
		}
		removed = append(removed, originals...)
		sort.Ints(removed)
		p["plugins"] = removed
	}
}
