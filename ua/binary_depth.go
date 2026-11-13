// SPDX-License-Identifier: MIT

package ua

import "fmt"

// MaxBinaryNestingDepth bounds how deeply Variant, DataValue,
// DiagnosticInfo and ExtensionObject values may be nested inside each other
// in the UA Binary encoding. Each of these types counts as one level,
// whatever the path between them (a Variant holding a DataValue holding a
// Variant is three levels). Decoding or encoding a deeper value fails with
// [StatusBadEncodingLimitsExceeded] (OPC UA Part 6 §5.2.2 lets a stack
// enforce encoding limits and report them with that status). The value
// matches [DefaultCodecMaxDepth] of the JSON and XML codecs.
const MaxBinaryNestingDepth = DefaultCodecMaxDepth

// depthDecoder is implemented by the types that may nest; decodeDepth
// decodes with depth enclosing nesting levels already open.
type depthDecoder interface {
	decodeDepth(b []byte, depth int) (int, error)
}

// depthEncoder is the encoding counterpart of depthDecoder.
type depthEncoder interface {
	encodeDepth(depth int) ([]byte, error)
}

// nestedBuffer opens one nesting level below depth and returns the buffer
// that carries it, or an error once MaxBinaryNestingDepth is reached.
func nestedBuffer(b []byte, depth int) (*Buffer, error) {
	if depth >= MaxBinaryNestingDepth {
		return nil, fmt.Errorf("ua: binary: nesting exceeds %d levels: %w", MaxBinaryNestingDepth, StatusBadEncodingLimitsExceeded)
	}
	buf := NewBuffer(b)
	buf.depth = depth + 1
	return buf, nil
}
