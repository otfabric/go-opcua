// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

// TestHistoryReadRequest_Encode_NilDataEncoding ensures encoding a HistoryReadRequest
// with HistoryReadValueID that has nil DataEncoding does not panic (see QualifiedName.Encode
// and encode.go handling of nil pointer BinaryEncoder).
func TestHistoryReadRequest_Encode_NilDataEncoding(t *testing.T) {
	req := &HistoryReadRequest{
		RequestHeader: &RequestHeader{},
		HistoryReadDetails: &ExtensionObject{
			TypeID:       NewFourByteExpandedNodeID(0, 644), // ReadEventDetails_Encoding_DefaultBinary
			EncodingMask: ExtensionObjectBinary,
			Value:        &ReadEventDetails{},
		},
		TimestampsToReturn:        TimestampsToReturnSource,
		ReleaseContinuationPoints: false,
		NodesToRead: []*HistoryReadValueID{
			{
				NodeID:       NewNumericNodeID(0, 2256),
				IndexRange:   "",
				DataEncoding: nil, // optional; was causing nil pointer dereference in QualifiedName.Encode
			},
		},
	}
	_, err := Encode(req)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
}
