// SPDX-License-Identifier: MIT

package message

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPublisherID(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want PublisherID
		str  string
	}{
		{byte(7), NewPublisherID(PublisherIDByte, 7), "7"},
		{uint16(2234), NewPublisherID(PublisherIDUInt16, 2234), "2234"},
		{uint32(70000), NewPublisherID(PublisherIDUInt32, 70000), "70000"},
		{uint64(1 << 40), NewPublisherID(PublisherIDUInt64, 1<<40), "1099511627776"},
		{"urn:pub", StringPublisherID("urn:pub"), "urn:pub"},
	} {
		got, err := PublisherIDFromVariant(ua.MustVariant(tc.v))
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
		require.True(t, got.Equal(tc.want))
		require.Equal(t, tc.str, got.String())
		// Variant round trip keeps the type.
		require.Equal(t, tc.v, got.Variant().Value())
	}

	_, err := PublisherIDFromVariant(nil)
	require.Error(t, err)
	_, err = PublisherIDFromVariant(&ua.Variant{})
	require.Error(t, err)
	_, err = PublisherIDFromVariant(ua.MustVariant(int32(1)))
	require.ErrorContains(t, err, "not allowed")

	require.False(t, NewPublisherID(PublisherIDUInt16, 1).Equal(NewPublisherID(PublisherIDUInt32, 1)), "type matters")
	require.False(t, StringPublisherID("a").Equal(StringPublisherID("b")))
	require.False(t, NewPublisherID(PublisherIDByte, 1).Equal(NewPublisherID(PublisherIDByte, 2)))
}

func TestStrings(t *testing.T) {
	for typ, want := range map[PublisherIDType]string{
		PublisherIDByte: "Byte", PublisherIDUInt16: "UInt16", PublisherIDUInt32: "UInt32",
		PublisherIDUInt64: "UInt64", PublisherIDString: "String", 9: "PublisherIDType(9)",
	} {
		require.Equal(t, want, typ.String())
	}
	for e, want := range map[FieldEncoding]string{
		FieldEncodingVariant: "Variant", FieldEncodingRawData: "RawData", FieldEncodingDataValue: "DataValue", 5: "FieldEncoding(5)",
	} {
		require.Equal(t, want, e.String())
	}
	for m, want := range map[DataSetMessageType]string{
		DataSetMessageKeyFrame: "KeyFrame", DataSetMessageDeltaFrame: "DeltaFrame", DataSetMessageEvent: "Event",
		DataSetMessageKeepAlive: "KeepAlive", 8: "DataSetMessageType(8)",
	} {
		require.Equal(t, want, m.String())
	}
}

func TestDiscoveryStrings(t *testing.T) {
	for typ, want := range map[DiscoveryType]string{
		DiscoveryPublisherEndpoints: "PublisherEndpoints", DiscoveryDataSetMetaData: "DataSetMetaData",
		DiscoveryDataSetWriterConfig: "DataSetWriterConfiguration", DiscoveryPubSubConnection: "PubSubConnection",
		DiscoveryApplicationInformation: "ApplicationInformation", 9: "DiscoveryType(9)",
	} {
		require.Equal(t, want, typ.String())
	}
	for typ, want := range map[InformationType]string{
		InformationPublisherEndpoints: "PublisherEndpoints", InformationDataSetMetaData: "DataSetMetaData",
		InformationDataSetWriterConfig: "DataSetWriterConfiguration", InformationWriterGroupConfig: "WriterGroupConfiguration",
		InformationPubSubConnections: "PubSubConnections", 9: "InformationType(9)",
	} {
		require.Equal(t, want, typ.String())
	}
	for typ, want := range map[DataSetMessageType]string{
		DataSetMessageActionRequest: "ActionRequest", DataSetMessageActionResponse: "ActionResponse",
	} {
		require.Equal(t, want, typ.String())
	}
	for typ, want := range map[ActionMessageType]string{
		ActionRequest: "ActionRequest", ActionResponse: "ActionResponse", 9: "ActionMessageType(9)",
	} {
		require.Equal(t, want, typ.String())
	}
}
