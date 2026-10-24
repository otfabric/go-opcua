// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func readDV(t *testing.T, c *opcua.Client, n *ua.NodeID) *ua.DataValue {
	t.Helper()
	res, err := c.Read(context.Background(), &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: n, AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	require.Len(t, res.Results, 1)
	return res.Results[0]
}

func readValue(t *testing.T, c *opcua.Client, n *ua.NodeID) any {
	t.Helper()
	dv := readDV(t, c, n)
	require.Equal(t, ua.StatusOK, dv.Status, "read %v", n)
	return dv.Value.Value()
}

// typeDefOf returns the target of the HasTypeDefinition reference of n.
func typeDefOf(t *testing.T, c *opcua.Client, n *ua.NodeID) uint32 {
	t.Helper()
	refs, err := c.Node(n).References(context.Background(), id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, refs, 1)
	return refs[0].NodeID.NodeID.IntID()
}

// child browses a path of BrowseNames below n.
func child(t *testing.T, c *opcua.Client, n *ua.NodeID, path ...string) *ua.NodeID {
	t.Helper()
	for _, name := range path {
		refs := browseNames(t, c, n)
		r, ok := refs[name]
		require.True(t, ok, "%v has no %q", n, name)
		n = r.NodeID.NodeID
	}
	return n
}

func TestPubSubDiagnosticsRoot(t *testing.T) {
	t.Parallel()
	_, surl := testutil.NewTestServer(t, server.WithPubSub(nil))
	c := testutil.NewTestClient(t, surl)
	d := nid(id.PublishSubscribeDiagnostics)
	refs := browseNames(t, c, nid(id.PublishSubscribe))
	require.Equal(t, uint32(id.PubSubDiagnosticsRootType), refs["Diagnostics"].TypeDefinition.NodeID.IntID())
	names := browseNames(t, c, d)
	for _, name := range []string{"DiagnosticsLevel", "TotalInformation", "TotalError", "Reset", "SubError", "Counters", "LiveValues"} {
		require.Contains(t, names, name)
	}
	require.Equal(t, int32(ua.DiagnosticsLevelBasic), readValue(t, c, nid(id.PublishSubscribeDiagnosticsDiagnosticsLevel)))
	require.Equal(t, false, readValue(t, c, nid(id.PublishSubscribeDiagnosticsSubError)))
	// Paused at New, Operational at Start.
	require.Equal(t, uint32(2), readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalInformation)))
	require.Equal(t, uint32(0), readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalError)))
	require.Equal(t, true, readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalErrorActive)))
	require.Equal(t, int32(ua.PubSubDiagnosticsCounterClassificationError), readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalErrorClassification)))
	require.Equal(t, int32(ua.DiagnosticsLevelBasic), readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalErrorDiagnosticsLevel)))
	require.Equal(t, uint32(1), readValue(t, c, nid(id.PublishSubscribeDiagnosticsCountersStateOperationalByParent)))
	require.Equal(t, true, readValue(t, c, nid(id.PublishSubscribeDiagnosticsCountersStateOperationalByParentActive)))
	require.Equal(t, int32(ua.DiagnosticsLevelBasic), readValue(t, c, nid(id.PublishSubscribeDiagnosticsCountersStateErrorDiagnosticsLevel)))
	require.Equal(t, uint16(0), readValue(t, c, nid(id.PublishSubscribeDiagnosticsLiveValuesConfiguredDataSetWriters)))
	require.Equal(t, int32(ua.DiagnosticsLevelBasic), readValue(t, c, nid(id.PublishSubscribeDiagnosticsLiveValuesConfiguredDataSetWritersDiagnosticsLevel)))

	// The optional TimeFirstChange properties are added with their
	// standard NodeIds.
	tfc := readValue(t, c, nid(id.PublishSubscribeDiagnosticsCountersStateOperationalByParentTimeFirstChange)).(time.Time)
	require.False(t, tfc.IsZero())
	require.True(t, readValue(t, c, nid(id.PublishSubscribeDiagnosticsCountersStateErrorTimeFirstChange)).(time.Time).IsZero())
	require.False(t, readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalInformationTimeFirstChange)).(time.Time).IsZero())
	require.Contains(t, browseNames(t, c, nid(id.PublishSubscribeDiagnosticsTotalError)), "TimeFirstChange")

	// Reset.
	res := psCall(t, c, d, nid(id.PublishSubscribeDiagnosticsReset))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, uint32(0), readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalInformation)))
	require.True(t, readValue(t, c, nid(id.PublishSubscribeDiagnosticsTotalInformationTimeFirstChange)).(time.Time).IsZero())
}

func TestPubSubDiagnosticsComponents(t *testing.T) {
	t.Parallel()
	url := pubsubUDPURL(t)
	pds := pubsub.PublishedDataItems("pds", pubsub.Var("time", nid(id.ServerServerStatusCurrentTime), ua.TypeIDDateTime))
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachReaderGroups(pubsub.AttachWriterGroups(pubsub.UDPConnection("conn", url, uint16(4)),
			pubsub.WriterGroup("wg", 2, time.Hour, pubsub.DataSetWriter("w", 3, "pds"))),
			pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(4), 2, 3, nil))))
	var denied atomic.Bool
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(cfg), server.WithPubSubAuthorizer(func(_ context.Context, _ *server.MethodCaller, m string) ua.StatusCode {
		if m == "Reset" && denied.Load() {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}))
	c := testutil.NewTestClient(t, surl)
	rt := srv.PubSub()

	conn := child(t, c, nid(id.PublishSubscribe), "conn")
	wg := child(t, c, conn, "wg")
	w := child(t, c, wg, "w")
	rg := child(t, c, conn, "rg")
	r := child(t, c, rg, "r")
	for n, typ := range map[*ua.NodeID]uint32{
		conn: id.PubSubDiagnosticsConnectionType, wg: id.PubSubDiagnosticsWriterGroupType, w: id.PubSubDiagnosticsDataSetWriterType,
		rg: id.PubSubDiagnosticsReaderGroupType, r: id.PubSubDiagnosticsDataSetReaderType,
	} {
		ref := browseNames(t, c, n)["Diagnostics"]
		require.NotNil(t, ref, "%v has no Diagnostics", n)
		require.Equal(t, typ, ref.TypeDefinition.NodeID.IntID())
		names := browseNames(t, c, ref.NodeID.NodeID)
		for _, name := range []string{"DiagnosticsLevel", "TotalInformation", "TotalError", "Reset", "SubError", "Counters", "LiveValues"} {
			require.Contains(t, names, name)
		}
		ctrs := browseNames(t, c, names["Counters"].NodeID.NodeID)
		for _, name := range []string{"StateError", "StateOperationalByMethod", "StateOperationalByParent", "StateOperationalFromError", "StatePausedByParent", "StateDisabledByMethod"} {
			require.Contains(t, ctrs, name)
			require.Equal(t, uint32(id.PubSubDiagnosticsCounterType), typeDefOf(t, c, ctrs[name].NodeID.NodeID))
		}
	}
	wgCtrs := browseNames(t, c, child(t, c, wg, "Diagnostics", "Counters"))
	for _, name := range []string{"SentNetworkMessages", "FailedTransmissions", "EncryptionErrors"} {
		require.Contains(t, wgCtrs, name)
	}
	require.Contains(t, browseNames(t, c, child(t, c, rg, "Diagnostics", "Counters")), "ReceivedNetworkMessages")
	require.Contains(t, browseNames(t, c, child(t, c, w, "Diagnostics", "Counters")), "FailedDataSetMessages")
	rlv := browseNames(t, c, child(t, c, r, "Diagnostics", "LiveValues"))
	for _, name := range []string{"MessageSequenceNumber", "StatusCode", "MajorVersion", "MinorVersion", "SecurityTokenID", "TimeToNextTokenID"} {
		require.Contains(t, rlv, name)
	}

	// The writer group sends once (the interval is an hour), the reader
	// group of the same connection receives it.
	sent := child(t, c, wg, "Diagnostics", "Counters", "SentNetworkMessages")
	require.Eventually(t, func() bool { return readValue(t, c, sent) == uint32(1) }, 5*time.Second, 5*time.Millisecond)
	recv := child(t, c, rg, "Diagnostics", "Counters", "ReceivedNetworkMessages")
	require.Eventually(t, func() bool { return readValue(t, c, recv) == uint32(1) }, 5*time.Second, 5*time.Millisecond)
	require.Equal(t, int32(ua.PubSubDiagnosticsCounterClassificationInformation), readValue(t, c, child(t, c, wg, "Diagnostics", "Counters", "SentNetworkMessages", "Classification")))
	require.Equal(t, int32(ua.PubSubDiagnosticsCounterClassificationError), readValue(t, c, child(t, c, wg, "Diagnostics", "Counters", "FailedTransmissions", "Classification")))
	require.False(t, readValue(t, c, child(t, c, wg, "Diagnostics", "Counters", "SentNetworkMessages", "TimeFirstChange")).(time.Time).IsZero())
	require.Equal(t, url, readValue(t, c, child(t, c, conn, "Diagnostics", "LiveValues", "ResolvedAddress")))
	require.Equal(t, uint16(1), readValue(t, c, child(t, c, wg, "Diagnostics", "LiveValues", "ConfiguredDataSetWriters")))
	require.Equal(t, uint16(1), readValue(t, c, child(t, c, wg, "Diagnostics", "LiveValues", "OperationalDataSetWriters")))
	require.Equal(t, uint16(1), readValue(t, c, child(t, c, rg, "Diagnostics", "LiveValues", "ConfiguredDataSetReaders")))
	require.Equal(t, uint16(1), readValue(t, c, nid(id.PublishSubscribeDiagnosticsLiveValuesConfiguredDataSetReaders)))

	// Counters and LiveValues above the DiagnosticsLevel are out of
	// service.
	enc := child(t, c, wg, "Diagnostics", "Counters", "EncryptionErrors")
	require.Equal(t, ua.StatusBadOutOfService, readDV(t, c, enc).Status)
	require.Equal(t, false, readValue(t, c, child(t, c, wg, "Diagnostics", "Counters", "EncryptionErrors", "Active")))
	require.Equal(t, int32(ua.DiagnosticsLevelAdvanced), readValue(t, c, child(t, c, wg, "Diagnostics", "Counters", "EncryptionErrors", "DiagnosticsLevel")))
	seq := child(t, c, w, "Diagnostics", "LiveValues", "MessageSequenceNumber")
	require.Equal(t, ua.StatusBadOutOfService, readDV(t, c, seq).Status)
	require.Equal(t, int32(ua.DiagnosticsLevelInfo), readValue(t, c, child(t, c, w, "Diagnostics", "LiveValues", "MessageSequenceNumber", "DiagnosticsLevel")))
	wid, ok := srv.PubSubComponentID(w)
	require.True(t, ok)
	wgid, ok := srv.PubSubComponentID(wg)
	require.True(t, ok)
	require.NoError(t, rt.SetDiagnosticsLevel(wid, ua.DiagnosticsLevelInfo))
	require.NoError(t, rt.SetDiagnosticsLevel(wgid, ua.DiagnosticsLevelInfo))
	require.Equal(t, int32(ua.DiagnosticsLevelInfo), readValue(t, c, child(t, c, w, "Diagnostics", "DiagnosticsLevel")))
	require.Equal(t, uint16(1), readValue(t, c, seq))
	require.Equal(t, ua.StatusGood, readValue(t, c, child(t, c, w, "Diagnostics", "LiveValues", "StatusCode")))
	require.Equal(t, uint32(0), readValue(t, c, enc))
	require.Equal(t, uint32(0), readValue(t, c, child(t, c, wg, "Diagnostics", "LiveValues", "SecurityTokenID")))
	require.Equal(t, 0.0, readValue(t, c, child(t, c, wg, "Diagnostics", "LiveValues", "TimeToNextTokenID")))

	// Reset, through the method of the type, and its authorisation.
	wgDiag := child(t, c, wg, "Diagnostics")
	denied.Store(true)
	require.Equal(t, ua.StatusBadUserAccessDenied, psCall(t, c, wgDiag, nid(id.PubSubDiagnosticsTypeReset)).StatusCode)
	denied.Store(false)
	require.Equal(t, ua.StatusOK, psCall(t, c, wgDiag, nid(id.PubSubDiagnosticsTypeReset)).StatusCode)
	require.Equal(t, uint32(0), readValue(t, c, sent))
	require.Equal(t, uint32(0), readValue(t, c, child(t, c, wg, "Diagnostics", "TotalInformation")))
	require.Equal(t, uint32(1), readValue(t, c, recv), "Reset does not reach other objects")

	// The diagnostics of a removed component go with it; those of an
	// added one come with it.
	require.Equal(t, ua.StatusOK, psCall(t, c, conn, nid(id.PubSubConnectionTypeRemoveGroup), ua.MustVariant(wg)).StatusCode)
	require.Equal(t, ua.StatusBadNodeIDUnknown, readDV(t, c, sent).Status)
	require.Equal(t, ua.StatusBadNodeIDUnknown, psCall(t, c, wgDiag, nid(id.PubSubDiagnosticsTypeReset)).StatusCode)
	res := psCall(t, c, conn, nid(id.PubSubConnectionTypeAddWriterGroup), eoArg(pubsub.WriterGroup("wg2", 7, time.Hour)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	wg2 := res.OutputArguments[0].Value().(*ua.NodeID)
	require.Equal(t, uint16(0), readValue(t, c, child(t, c, wg2, "Diagnostics", "LiveValues", "ConfiguredDataSetWriters")))
}

func TestPubSubDiagnosticsStateCounters(t *testing.T) {
	t.Parallel()
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil))
	c := testutil.NewTestClient(t, surl)
	res := psCall(t, c, nid(id.PublishSubscribe), nid(id.PublishSubscribeAddConnection), eoArg(pubsub.UDPConnection("c", pubsubUDPURL(t), uint16(1))))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	conn := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg")))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	rg := res.OutputArguments[0].Value().(*ua.NodeID)
	cid, _ := srv.PubSubComponentID(conn)
	require.Eventually(t, func() bool {
		st, err := srv.PubSub().State(cid)
		return err == nil && st == ua.PubSubStateOperational
	}, 5*time.Second, 5*time.Millisecond)

	st := child(t, c, rg, "Status")
	require.Equal(t, ua.StatusOK, psCall(t, c, st, nid(id.PubSubStatusTypeDisable)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, st, nid(id.PubSubStatusTypeEnable)).StatusCode)
	require.Equal(t, uint32(1), readValue(t, c, child(t, c, rg, "Diagnostics", "Counters", "StateDisabledByMethod")))
	require.Equal(t, uint32(1), readValue(t, c, child(t, c, rg, "Diagnostics", "Counters", "StateOperationalByMethod")))
	require.Equal(t, false, readValue(t, c, child(t, c, conn, "Diagnostics", "SubError")))
	require.Equal(t, uint32(0), readValue(t, c, child(t, c, rg, "Diagnostics", "TotalError")))
}
