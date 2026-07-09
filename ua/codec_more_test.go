// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestCodecRoundTrip_DiscoveryAndViewRequests(t *testing.T) {
	cases := []interface{}{
		&FindServersRequest{RequestHeader: testRequestHeader()},
		&FindServersOnNetworkRequest{RequestHeader: testRequestHeader()},
		&GetEndpointsRequest{RequestHeader: testRequestHeader(), EndpointURL: "opc.tcp://127.0.0.1:4840"},
		&RegisterNodesRequest{
			RequestHeader:   testRequestHeader(),
			NodesToRegister: []*NodeID{NewStringNodeID(2, "x")},
		},
		&UnregisterNodesRequest{
			RequestHeader:     testRequestHeader(),
			NodesToUnregister: []*NodeID{NewStringNodeID(2, "x")},
		},
		&SetPublishingModeRequest{
			RequestHeader:     testRequestHeader(),
			PublishingEnabled: true,
			SubscriptionIDs:   []uint32{1, 2},
		},
		&BrowseNextRequest{
			RequestHeader:             testRequestHeader(),
			ContinuationPoints:        [][]byte{{1, 2}},
			ReleaseContinuationPoints: false,
		},
		&ReadRequest{
			RequestHeader: testRequestHeader(),
			NodesToRead: []*ReadValueID{
				{NodeID: NewNumericNodeID(0, 85), AttributeID: AttributeIDValue},
			},
			MaxAge:             0,
			TimestampsToReturn: TimestampsToReturnBoth,
		},
		&WriteRequest{
			RequestHeader: testRequestHeader(),
			NodesToWrite: []*WriteValue{
				{
					NodeID:      NewNumericNodeID(0, 85),
					AttributeID: AttributeIDValue,
					Value:       &DataValue{EncodingMask: DataValueValue, Value: MustVariant(int32(1))},
				},
			},
		},
		&CallRequest{
			RequestHeader: testRequestHeader(),
			MethodsToCall: []*CallMethodRequest{
				{
					ObjectID: NewNumericNodeID(0, 85),
					MethodID: NewNumericNodeID(0, 86),
					InputArguments: []*Variant{
						MustVariant(int32(7)),
					},
				},
			},
		},
		&CreateSubscriptionRequest{
			RequestHeader:               testRequestHeader(),
			RequestedPublishingInterval: 1000,
			RequestedLifetimeCount:      10000,
			RequestedMaxKeepAliveCount:  3000,
			MaxNotificationsPerPublish:  0,
			PublishingEnabled:           true,
			Priority:                    0,
		},
		&ModifySubscriptionRequest{
			RequestHeader:               testRequestHeader(),
			SubscriptionID:              1,
			RequestedPublishingInterval: 500,
			RequestedLifetimeCount:      10000,
			RequestedMaxKeepAliveCount:  3000,
			MaxNotificationsPerPublish:  0,
			Priority:                    0,
		},
		&TranslateBrowsePathsToNodeIDsRequest{
			RequestHeader: testRequestHeader(),
			BrowsePaths: []*BrowsePath{
				{
					StartingNode: NewNumericNodeID(0, 85),
					RelativePath: &RelativePath{
						Elements: []*RelativePathElement{{
							IncludeSubtypes: true,
							TargetName:      &QualifiedName{Name: "Server"},
						}},
					},
				},
			},
		},
	}
	for _, req := range cases {
		roundTripIdempotent(t, req)
	}
}

func TestExpandedNodeIDString(t *testing.T) {
	exp := NewExpandedNodeID(NewNumericNodeID(0, 42), "http://example.com", 2)
	if exp.String() == "" {
		t.Fatal("expected non-empty string")
	}
	encoded, err := exp.Encode()
	if err != nil || len(encoded) == 0 {
		t.Fatalf("encode: %v len=%d", err, len(encoded))
	}
}
