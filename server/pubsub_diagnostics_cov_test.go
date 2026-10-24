// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPubSubCov_DiagValue(t *testing.T) {
	s := newTestServer()
	s.cfg.pubsub = &pubsubConfig{}
	require.NotNil(t, s.PubSub())
	t.Cleanup(s.closePubSub)
	require.NoError(t, s.buildPubSubModel())
	m := s.ps.model

	for _, path := range []string{
		"Nope", "DiagnosticsLevel/x", "SubError/x", "TotalError/a/b", "TotalError/Nope", "Counters", "Counters/Nope",
		"Counters/StateError/Nope", "Counters/a/b/c", "LiveValues", "LiveValues/Nope", "LiveValues/ResolvedAddress/Nope", "LiveValues/a/b/c",
	} {
		_, ok := m.diagValue(pubsub.Root, path)
		require.False(t, ok, path)
	}
	// The root has no SentNetworkMessages counter; a removed component no
	// diagnostics.
	val, ok := m.diagValue(pubsub.Root, "Counters/SentNetworkMessages")
	require.True(t, ok)
	require.Equal(t, ua.StatusBadNodeIDUnknown, val().Status)
	val, ok = m.diagValue(9999, "DiagnosticsLevel")
	require.True(t, ok)
	require.Equal(t, ua.StatusBadNodeIDUnknown, val().Status)
	val, ok = m.diagValue(pubsub.Root, "TotalInformation/Classification")
	require.True(t, ok)
	require.Equal(t, int32(ua.PubSubDiagnosticsCounterClassificationInformation), val().Value.Value())

	for k, want := range map[pubsub.ComponentKind]uint32{
		pubsub.KindPubSub: id.PubSubDiagnosticsRootType, pubsub.KindConnection: id.PubSubDiagnosticsConnectionType,
		pubsub.KindWriterGroup: id.PubSubDiagnosticsWriterGroupType, pubsub.KindReaderGroup: id.PubSubDiagnosticsReaderGroupType,
		pubsub.KindDataSetWriter: id.PubSubDiagnosticsDataSetWriterType, pubsub.KindDataSetReader: id.PubSubDiagnosticsDataSetReaderType,
		pubsub.KindPublishedDataSet: id.PubSubDiagnosticsRootType,
	} {
		require.Equal(t, want, diagTypeOf(k))
	}
}
