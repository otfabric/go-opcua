// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/stretchr/testify/require"
)

// roundTripIdempotent verifies that encoding is symmetric with decoding:
// encode(v) -> b1, decode(b1) -> v2, encode(v2) -> b2, and b1 == b2.
//
// This is the property that guarantees a message survives the wire. It is
// stronger than a single encode/decode because nil pointers are normalized
// to their zero value on decode; the second encode must reproduce the first.
func roundTripIdempotent(t *testing.T, v interface{}) {
	t.Helper()

	b1, err := Encode(v)
	require.NoError(t, err, "first encode failed")

	// Decode via the service registry so we exercise the same path the
	// secure channel uses for requests/responses.
	tid := ServiceTypeID(v)
	require.NotZero(t, tid, "type not registered as a service: %T", v)
	full := append(mustEncode(t, NewFourByteNodeID(0, tid)), b1...)

	_, decoded, err := DecodeService(full)
	require.NoError(t, err, "DecodeService failed for %T", v)

	b2, err := Encode(decoded)
	require.NoError(t, err, "second encode failed")

	require.Equal(t, b1, b2, "re-encoded bytes differ for %T", v)
}

func mustEncode(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := Encode(v)
	require.NoError(t, err)
	return b
}

// header returns a fully-populated RequestHeader like a client would send.
func testRequestHeader() *RequestHeader {
	return &RequestHeader{
		AuthenticationToken: NewTwoByteNodeID(0),
		AdditionalHeader:    NewExtensionObject(nil),
	}
}

func TestNilPointerCodec_QueryFirst(t *testing.T) {
	cases := []struct {
		name string
		req  *QueryFirstRequest
	}{
		{
			name: "empty",
			req:  &QueryFirstRequest{RequestHeader: testRequestHeader()},
		},
		{
			name: "with node types and no filter",
			req: &QueryFirstRequest{
				RequestHeader: testRequestHeader(),
				NodeTypes: []*NodeTypeDescription{
					{
						TypeDefinitionNode: NewNumericExpandedNodeID(0, id.BaseObjectType),
						IncludeSubTypes:    true,
						DataToReturn: []*QueryDataDescription{
							{AttributeID: AttributeIDValue},
						},
					},
				},
			},
		},
		{
			name: "with literal filter",
			req: &QueryFirstRequest{
				RequestHeader: testRequestHeader(),
				NodeTypes: []*NodeTypeDescription{
					{TypeDefinitionNode: NewNumericExpandedNodeID(0, id.BaseObjectType)},
				},
				Filter: &ContentFilter{
					Elements: []*ContentFilterElement{
						{
							FilterOperator: FilterOperatorEquals,
							FilterOperands: []*ExtensionObject{
								litOperand(MustVariant(int32(1))),
								litOperand(MustVariant(int32(1))),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roundTripIdempotent(t, tc.req)
		})
	}
}

func TestNilPointerCodec_QueryNext(t *testing.T) {
	roundTripIdempotent(t, &QueryNextRequest{
		RequestHeader:     testRequestHeader(),
		ContinuationPoint: []byte{0x01, 0x02, 0x03},
	})
}

func TestNilPointerCodec_ContentFilterOperands(t *testing.T) {
	req := &QueryFirstRequest{
		RequestHeader: testRequestHeader(),
		NodeTypes: []*NodeTypeDescription{
			{TypeDefinitionNode: NewNumericExpandedNodeID(0, id.BaseObjectType)},
		},
		Filter: &ContentFilter{
			Elements: []*ContentFilterElement{
				{
					FilterOperator: FilterOperatorAnd,
					FilterOperands: []*ExtensionObject{
						elemOperand(1),
						elemOperand(2),
					},
				},
				{
					FilterOperator: FilterOperatorEquals,
					FilterOperands: []*ExtensionObject{
						attrOperand(),
						litOperand(MustVariant("x")),
					},
				},
				{
					FilterOperator: FilterOperatorIsNull,
					FilterOperands: []*ExtensionObject{
						simpleAttrOperand(),
					},
				},
			},
		},
	}
	roundTripIdempotent(t, req)
}

func litOperand(v *Variant) *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID:       NewNumericExpandedNodeID(0, id.LiteralOperandEncodingDefaultBinary),
		Value:        LiteralOperand{Value: v},
	}
}

func elemOperand(i uint32) *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID:       NewNumericExpandedNodeID(0, id.ElementOperandEncodingDefaultBinary),
		Value:        ElementOperand{Index: i},
	}
}

func attrOperand() *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID:       NewNumericExpandedNodeID(0, id.AttributeOperandEncodingDefaultBinary),
		Value: AttributeOperand{
			NodeID:      NewTwoByteNodeID(0),
			AttributeID: AttributeIDValue,
		},
	}
}

func simpleAttrOperand() *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID:       NewNumericExpandedNodeID(0, id.SimpleAttributeOperandEncodingDefaultBinary),
		Value: SimpleAttributeOperand{
			TypeDefinitionID: NewNumericNodeID(0, id.BaseEventType),
			AttributeID:      AttributeIDValue,
		},
	}
}

// TestNilPointerCodec_NullNodeID verifies a nil *NodeID inside a struct now
// round-trips as a null NodeID instead of corrupting the stream.
func TestNilPointerCodec_NullNodeID(t *testing.T) {
	// ReadValueID has a *NodeID field; leave it nil.
	rvid := &ReadValueID{AttributeID: AttributeIDValue}
	b, err := Encode(rvid)
	require.NoError(t, err)

	var got ReadValueID
	_, err = Decode(b, &got)
	require.NoError(t, err)
	require.NotNil(t, got.NodeID)
	require.Equal(t, NewTwoByteNodeID(0), got.NodeID)
}
