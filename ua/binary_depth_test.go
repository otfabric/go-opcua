// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// nestedDiagnosticInfo returns the encoding of n DiagnosticInfo values,
// each the inner one of the previous.
func nestedDiagnosticInfo(n int) []byte {
	return append(bytes.Repeat([]byte{DiagnosticInfoInnerDiagnosticInfo}, n-1), 0)
}

// nestedVariant returns the encoding of n Variants, each holding the next;
// the innermost one is null.
func nestedVariant(n int) []byte {
	return append(bytes.Repeat([]byte{byte(TypeIDVariant)}, n-1), 0)
}

func TestBinaryNestingDepthDiagnosticInfo(t *testing.T) {
	d := new(DiagnosticInfo)
	_, err := d.Decode(nestedDiagnosticInfo(MaxBinaryNestingDepth))
	require.NoError(t, err)

	_, err = new(DiagnosticInfo).Decode(nestedDiagnosticInfo(MaxBinaryNestingDepth + 1))
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)

	// The decoded value encodes again; one more level does not.
	_, err = d.Encode()
	require.NoError(t, err)
	_, err = (&DiagnosticInfo{EncodingMask: DiagnosticInfoInnerDiagnosticInfo, InnerDiagnosticInfo: d}).Encode()
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
}

func TestBinaryNestingDepthVariant(t *testing.T) {
	v := new(Variant)
	_, err := v.Decode(nestedVariant(MaxBinaryNestingDepth))
	require.NoError(t, err)

	_, err = new(Variant).Decode(nestedVariant(MaxBinaryNestingDepth + 1))
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)

	_, err = v.Encode()
	require.NoError(t, err)
	_, err = MustVariant(v).Encode()
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
}

func TestBinaryNestingDepthMixed(t *testing.T) {
	// Variant -> ExtensionObject(WriteValue) -> DataValue -> Variant -> ...
	// counts every Variant, ExtensionObject and DataValue as one level.
	v := MustVariant(int32(1))
	levels := 1
	for levels+3 <= MaxBinaryNestingDepth {
		wv := &WriteValue{NodeID: NewNumericNodeID(0, 1), AttributeID: AttributeIDValue, Value: &DataValue{EncodingMask: DataValueValue, Value: v}}
		v = MustVariant(NewExtensionObject(wv))
		levels += 3
	}
	b, err := v.Encode()
	require.NoError(t, err)

	got := new(Variant)
	_, err = got.Decode(b)
	require.NoError(t, err)

	// Wrapping the encoding in enough Variants exceeds the limit.
	deeper := append(bytes.Repeat([]byte{byte(TypeIDVariant)}, MaxBinaryNestingDepth-levels+1), b...)
	_, err = new(Variant).Decode(deeper)
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)

	// So does decoding through the reflection decoder (a service body).
	req := &WriteRequest{RequestHeader: &RequestHeader{AuthenticationToken: NewTwoByteNodeID(0)}, NodesToWrite: []*WriteValue{{
		NodeID: NewNumericNodeID(0, 1), AttributeID: AttributeIDValue,
		Value: &DataValue{EncodingMask: DataValueValue, Value: v},
	}}}
	_, err = Encode(req)
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
}

func TestBinaryNestingDepthLargeInput(t *testing.T) {
	// A message-sized run of nesting markers fails at the limit instead
	// of recursing once per byte.
	b := bytes.Repeat([]byte{DiagnosticInfoInnerDiagnosticInfo}, 2<<20)
	_, err := new(DiagnosticInfo).Decode(b)
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)

	b = bytes.Repeat([]byte{byte(TypeIDDataValue), DataValueValue}, 1<<20)
	_, err = new(Variant).Decode(b)
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
}
