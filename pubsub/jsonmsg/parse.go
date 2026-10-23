// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// member is one member of a JSON object, in document order.
type member struct {
	key string
	val json.RawMessage
}

func errorf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{ErrDecode}, args...)...)
}

// kind returns the first significant byte of a JSON value.
func kind(raw json.RawMessage) byte {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return c
	}
	return 0
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// objectMembers splits a JSON object into its members, keeping their order.
// Duplicate keys are an error. limit bounds the number of members.
func objectMembers(raw json.RawMessage, limit int) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errorf("%v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errorf("expected a JSON object")
	}
	var out []member
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errorf("%v", err)
		}
		k, ok := tok.(string)
		if !ok {
			return nil, errorf("expected an object key")
		}
		if _, dup := seen[k]; dup {
			return nil, errorf("duplicate member %q", k)
		}
		seen[k] = struct{}{}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errorf("member %q: %v", k, err)
		}
		if len(out) >= limit {
			return nil, errorf("more than %d members", limit)
		}
		out = append(out, member{key: k, val: v})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, errorf("%v", err)
	}
	if err := trailing(dec); err != nil {
		return nil, err
	}
	return out, nil
}

// arrayElements splits a JSON array into its elements.
func arrayElements(raw json.RawMessage, limit int) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errorf("%v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, errorf("expected a JSON array")
	}
	var out []json.RawMessage
	for dec.More() {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errorf("%v", err)
		}
		if len(out) >= limit {
			return nil, errorf("more than %d elements", limit)
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, errorf("%v", err)
	}
	if err := trailing(dec); err != nil {
		return nil, err
	}
	return out, nil
}

func trailing(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		return errorf("data after the JSON value")
	}
	return nil
}

func lookup(ms []member, key string) (json.RawMessage, bool) {
	for _, m := range ms {
		if m.key == key {
			return m.val, true
		}
	}
	return nil, false
}

// stringValue decodes a JSON string; null is the empty string.
func stringValue(raw json.RawMessage, name string) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errorf("%s: expected a string", name)
	}
	return s, nil
}

// uintValue decodes a JSON number (or a string holding one, the form of
// 64-bit integers) that fits in max.
func uintValue(raw json.RawMessage, name string, max uint64) (uint64, error) {
	s := strings.TrimSpace(string(raw))
	if len(s) >= 2 && s[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, errorf("%s: %v", name, err)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		// Accept integral numbers written with a fraction or exponent.
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil || f < 0 || f != math.Trunc(f) || f > float64(max) {
			return 0, errorf("%s: expected an unsigned integer, got %.40s", name, s)
		}
		n = uint64(f)
	}
	if n > max {
		return 0, errorf("%s: %d out of range", name, n)
	}
	return n, nil
}

func timeValue(raw json.RawMessage, name string, co []ua.CodecOption) (time.Time, error) {
	var t time.Time
	if err := ua.DecodeJSON(raw, &t, co...); err != nil {
		return time.Time{}, errorf("%s: %v", name, err)
	}
	return t, nil
}

// statusValue decodes a StatusCode: the {"Code":..,"Symbol":..} object of
// OPC UA 1.05 or the bare number of 1.04 and of open62541's decoder.
func statusValue(raw json.RawMessage, name string) (ua.StatusCode, error) {
	var sc ua.StatusCode
	if err := ua.DecodeJSON(raw, &sc); err != nil {
		return 0, errorf("%s: %v", name, err)
	}
	return sc, nil
}
