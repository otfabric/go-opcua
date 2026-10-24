// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	refAdd    = ua.PubSubConfigurationRefMaskElementAdd
	refMatch  = ua.PubSubConfigurationRefMaskElementMatch
	refModify = ua.PubSubConfigurationRefMaskElementModify
	refRemove = ua.PubSubConfigurationRefMaskElementRemove
	refConn   = ua.PubSubConfigurationRefMaskReferenceConnection
	refWG     = ua.PubSubConfigurationRefMaskReferenceWriterGroup
	refRG     = ua.PubSubConfigurationRefMaskReferenceReaderGroup
	refWriter = ua.PubSubConfigurationRefMaskReferenceWriter
	refReader = ua.PubSubConfigurationRefMaskReferenceReader
	refPDS    = ua.PubSubConfigurationRefMaskReferencePubDataset
)

func cfgFileCall(t *testing.T, c *opcua.Client, method uint32, args ...*ua.Variant) *ua.CallMethodResult {
	t.Helper()
	return psCall(t, c, nid(id.PublishSubscribePubSubConfiguration), nid(method), args...)
}

func openCfg(t *testing.T, c *opcua.Client, mode byte) (uint32, ua.StatusCode) {
	t.Helper()
	res := cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationOpen, ua.MustVariant(mode))
	if res.StatusCode != ua.StatusOK {
		return 0, res.StatusCode
	}
	return res.OutputArguments[0].Value().(uint32), ua.StatusOK
}

func closeCfg(t *testing.T, c *opcua.Client, h uint32) ua.StatusCode {
	t.Helper()
	return cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationClose, ua.MustVariant(h)).StatusCode
}

func calcAction() *ua.PublishedDataSetDataType {
	return pubsub.PublishedActions("Calc", []pubsub.Field{{Name: "A", Type: ua.TypeIDInt32}}, []pubsub.Field{{Name: "R", Type: ua.TypeIDInt32}}, pubsub.ActionTargetOf(1, "Run"))
}

// TestPubSubConfigurationFile: the FileType methods of the PubSubConfiguration
// object (Part 14 §9.1.3.7.1): the modes, shared reads and exclusive
// writes, handles of a session, positions.
func TestPubSubConfigurationFile(t *testing.T) {
	t.Parallel()
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{calcAction()},
		pubsub.AttachWriterGroups(pubsub.UDPConnection("conn", pubsubUDPURL(t), uint16(4)),
			pubsub.WriterGroup("wg", 2, time.Second, pubsub.DataSetWriter("w", 3, "Calc"))))
	_, surl := testutil.NewTestServer(t, server.WithPubSub(cfg))
	c := testutil.NewTestClient(t, surl)
	c2 := testutil.NewTestClient(t, surl)
	ctx := context.Background()

	got, err := remote.New(c).ReadConfiguration(ctx)
	require.NoError(t, err)
	require.Len(t, got.Connections, 1)
	require.Equal(t, "conn", got.Connections[0].Name)
	require.Equal(t, uint16(2), got.Connections[0].WriterGroups[0].WriterGroupID)
	require.Equal(t, "Calc", got.PublishedDataSets[0].Name)

	for _, mode := range []byte{0, 0x02, 0x04, 0x08, 0x07, 0x09} {
		_, sc := openCfg(t, c, mode)
		require.Equal(t, ua.StatusBadInvalidArgument, sc, "mode %#x", mode)
	}

	// Reads are shared, writes exclusive.
	r1, sc := openCfg(t, c, 0x01)
	require.Equal(t, ua.StatusOK, sc)
	r2, sc := openCfg(t, c2, 0x01)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = openCfg(t, c, 0x06)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	open, err := c.Node(nid(id.PublishSubscribePubSubConfigurationOpenCount)).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, uint16(2), open.Value())

	// A handle belongs to its session.
	require.Equal(t, ua.StatusBadInvalidArgument, closeCfg(t, c2, r1))
	res := cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationRead, ua.MustVariant(r2), ua.MustVariant(int32(10)))
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)

	// Positions.
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationRead, ua.MustVariant(r1), ua.MustVariant(int32(10)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Len(t, res.OutputArguments[0].Value(), 10)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationGetPosition, ua.MustVariant(r1))
	require.Equal(t, uint64(10), res.OutputArguments[0].Value())
	size, err := c.Node(nid(id.PublishSubscribePubSubConfigurationSize)).Value(ctx)
	require.NoError(t, err)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationSetPosition, ua.MustVariant(r1), ua.MustVariant(uint64(1<<40)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationGetPosition, ua.MustVariant(r1))
	require.Equal(t, size.Value(), res.OutputArguments[0].Value())
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationRead, ua.MustVariant(r1), ua.MustVariant(int32(10)))
	require.Empty(t, res.OutputArguments[0].Value())
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationRead, ua.MustVariant(r1), ua.MustVariant(int32(-1)))
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationWrite, ua.MustVariant(r1), ua.MustVariant([]byte{1}))
	require.Equal(t, ua.StatusBadInvalidState, res.StatusCode)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(r1), ua.MustVariant(false), ua.MustVariant([]*ua.ExtensionObject{}))
	require.Equal(t, ua.StatusBadInvalidState, res.StatusCode)
	require.Equal(t, ua.StatusOK, closeCfg(t, c, r1))
	require.Equal(t, ua.StatusBadInvalidArgument, closeCfg(t, c, r1))

	// A writer excludes readers. Closing its session releases the handle.
	_, sc = openCfg(t, c2, 0x06)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	require.Equal(t, ua.StatusOK, closeCfg(t, c2, r2))
	w, sc := openCfg(t, c2, 0x06)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = openCfg(t, c, 0x01)
	require.Equal(t, ua.StatusBadNotReadable, sc)
	res = cfgFileCall(t, c2, id.PublishSubscribePubSubConfigurationRead, ua.MustVariant(w), ua.MustVariant(int32(10)))
	require.Equal(t, ua.StatusBadInvalidState, res.StatusCode)
	require.NoError(t, c2.Close(ctx))
	_, sc = openCfg(t, c, 0x03)
	require.Equal(t, ua.StatusOK, sc)
}

// TestPubSubConfigurationReserveIDs: ReserveIds returns unused ids of the
// range 0x8000-0xFFFF, unique among the sessions (Part 14 §9.1.3.7.5).
func TestPubSubConfigurationReserveIDs(t *testing.T) {
	t.Parallel()
	cfg := pubsub.NewConfiguration(nil, pubsub.AttachWriterGroups(pubsub.UDPConnection("conn", pubsubUDPURL(t), uint16(4)),
		pubsub.WriterGroup("wg", 0x8000, time.Second)))
	_, surl := testutil.NewTestServer(t, server.WithPubSub(cfg))
	ctx := context.Background()
	r1 := remote.New(testutil.NewTestClient(t, surl))
	r2 := remote.New(testutil.NewTestClient(t, surl))

	a, err := r1.ReserveIDs(ctx, transport.ProfileUDPUADP, 2, 3)
	require.NoError(t, err)
	require.Equal(t, uint16(4), a.DefaultPublisherID.Value())
	require.Equal(t, []uint16{0x8001, 0x8002}, a.WriterGroupIDs)
	require.Equal(t, []uint16{0x8000, 0x8001, 0x8002}, a.DataSetWriterIDs)
	b, err := r2.ReserveIDs(ctx, transport.ProfileUDPUADP, 1, 1)
	require.NoError(t, err)
	require.Equal(t, []uint16{0x8003}, b.WriterGroupIDs)
	require.Equal(t, []uint16{0x8003}, b.DataSetWriterIDs)
	_, err = r2.ReserveIDs(ctx, transport.ProfileUDPUADP, 2000, 0)
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
}

func updateResult(t *testing.T, r *remote.Client, cfg *ua.PubSubConfiguration2DataType, require_ bool, refs ...*ua.PubSubConfigurationRefDataType) *remote.UpdateResult {
	t.Helper()
	res, err := r.UpdateConfiguration(context.Background(), cfg, refs, require_)
	require.NoError(t, err)
	require.Len(t, res.Results, len(refs))
	return res
}

// TestPubSubConfigurationCloseAndUpdate: CloseAndUpdate applies the element
// operations of the file (Part 14 §9.1.3.7.6): a PublishedAction with its
// connection, group and writer, ids and names the server assigns, Match,
// Modify and Remove, and RequireCompleteUpdate.
func TestPubSubConfigurationCloseAndUpdate(t *testing.T) {
	t.Parallel()
	url := pubsubUDPURL(t)
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil))
	c := testutil.NewTestClient(t, surl)
	r := remote.New(c)
	rt := srv.PubSub()

	conn := pubsub.UDPConnection("Responder", url, uint16(7))
	conn.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Actions", 0, 50*time.Millisecond, pubsub.DataSetWriter("", 0, "Calc"))}
	file := &ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{calcAction()}, Connections: []*ua.PubSubConnectionDataType{conn}}
	res := updateResult(t, r, file, true,
		remote.Ref(refAdd, refWriter, 0, 0, 0),
		remote.Ref(refAdd, refWG, 0, 0, 0),
		remote.Ref(refAdd, refConn, 0, 0, 0),
		remote.Ref(refAdd, refPDS, 0, 0, 0))
	require.True(t, res.ChangesApplied)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusOK}, res.Results)
	require.Len(t, res.Values, 4)
	byName := map[string]*ua.PubSubConfigurationValueDataType{}
	for _, v := range res.Values {
		byName[v.Name] = v
	}
	require.Equal(t, uint16(7), byName["Responder"].Identifier.Value())
	require.Equal(t, uint16(0x8000), byName["Actions"].Identifier.Value())
	require.Equal(t, uint16(0x8000), byName["DataSetWriter1"].Identifier.Value())
	require.Nil(t, byName["Calc"].Identifier.Value())
	require.Len(t, res.Objects, 4)
	for i, o := range res.Objects {
		_, ok := srv.PubSubComponentID(o)
		require.True(t, ok, "object %d: %v", i, o)
	}
	cid, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "Responder")
	require.True(t, ok)
	gid, ok := rt.Lookup(pubsub.KindWriterGroup, cid, "Actions")
	require.True(t, ok)
	_, ok = rt.Lookup(pubsub.KindDataSetWriter, gid, "DataSetWriter1")
	require.True(t, ok)

	// Match the connection by its parameters and add a group to it; the
	// connection keeps running.
	before, err := rt.Component(cid)
	require.NoError(t, err)
	m := pubsub.UDPConnection("", url, nil)
	m.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("More", 0x10, time.Second)}
	res = updateResult(t, r, &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{m}}, false,
		remote.Ref(refMatch, refConn, 0, 0, 0), remote.Ref(refAdd, refWG, 0, 0, 0))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, res.Results)
	require.Equal(t, "Responder", res.Values[0].Name)
	after, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "Responder")
	require.True(t, ok)
	require.Equal(t, before.ID, after)
	_, ok = rt.Lookup(pubsub.KindWriterGroup, cid, "More")
	require.True(t, ok)
	// A match alone changes nothing.
	res = updateResult(t, r, &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{m}}, false, remote.Ref(refMatch, refConn, 0, 0, 0))
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.Results)
	require.False(t, res.ChangesApplied)

	// Element errors; without RequireCompleteUpdate the others apply.
	dup := pubsub.UDPConnection("Responder", url, uint16(7))
	dup.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Nope", 0x11, time.Second), pubsub.WriterGroup("More", 0x10, 2*time.Second)}
	dup.ReaderGroups = []*ua.ReaderGroupDataType{pubsub.ReaderGroup("RG")}
	ghost := pubsub.UDPConnection("Ghost", url, uint16(9))
	ghost.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("G", 1, time.Second)}
	two := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{dup, ghost}}
	refs := []*ua.PubSubConfigurationRefDataType{
		remote.Ref(refAdd, refConn, 0, 0, 0),         // duplicated name
		remote.Ref(refRemove, refWG, 0, 0, 0),        // no group Nope
		remote.Ref(refAdd, refWG, 1, 0, 0),           // parent Ghost missing
		remote.Ref(refAdd, refWG, 5, 0, 0),           // bad index
		remote.Ref(refAdd|refModify, refWG, 0, 0, 0), // bad operation
		remote.Ref(refAdd, refWG|refRG, 0, 0, 0),     // two kinds
		remote.Ref(refMatch, refWriter, 0, 0, 0),     // match a writer
		remote.Ref(refAdd, ua.PubSubConfigurationRefMaskReferenceSecurityGroup, 0, 0, 0),
		remote.Ref(refModify, refWG, 0, 1, 0), // More: 2 s
		remote.Ref(refAdd, refRG, 0, 0, 0),    // RG
	}
	want := []ua.StatusCode{ua.StatusBadBrowseNameDuplicated, ua.StatusBadNoMatch, ua.StatusBadNotFound, ua.StatusBadInvalidArgument,
		ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument, ua.StatusBadNotSupported, ua.StatusOK, ua.StatusOK}
	res = updateResult(t, r, two, true, refs...)
	require.False(t, res.ChangesApplied)
	require.Equal(t, want, res.Results)
	_, ok = rt.Lookup(pubsub.KindReaderGroup, cid, "RG")
	require.False(t, ok, "RequireCompleteUpdate applied a change")
	res = updateResult(t, r, two, false, refs...)
	require.True(t, res.ChangesApplied)
	require.Equal(t, want, res.Results)
	_, ok = rt.Lookup(pubsub.KindReaderGroup, cid, "RG")
	require.True(t, ok)
	more, ok := rt.Lookup(pubsub.KindWriterGroup, cid, "More")
	require.True(t, ok)
	mcfg, err := rt.WriterGroupConfig(more)
	require.NoError(t, err)
	require.Equal(t, 2000.0, mcfg.PublishingInterval)
	// The Actions group was not touched by the modification of More.
	_, ok = rt.Lookup(pubsub.KindWriterGroup, cid, "Actions")
	require.True(t, ok)
	require.Equal(t, gid, func() pubsub.ComponentID { g, _ := rt.Lookup(pubsub.KindWriterGroup, cid, "Actions"); return g }())

	// An invalid result is refused per element.
	bad := pubsub.UDPConnection("Responder", url, uint16(7))
	bad.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Actions", 0, 50*time.Millisecond, pubsub.DataSetWriter("X", 1, "NoSuchDataSet"))}
	res = updateResult(t, r, &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{bad}}, false, remote.Ref(refAdd, refWriter, 0, 0, 0))
	require.Equal(t, []ua.StatusCode{ua.StatusBadConfigurationError}, res.Results)
	require.False(t, res.ChangesApplied)

	// Removing the PublishedAction removes its writer; removing the
	// connection removes its groups.
	res = updateResult(t, r, file, false, remote.Ref(refRemove, refPDS, 0, 0, 0), remote.Ref(refRemove, refConn, 0, 0, 0))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, res.Results)
	require.True(t, res.ChangesApplied)
	require.Equal(t, []*ua.NodeID{ua.NewTwoByteNodeID(0), ua.NewTwoByteNodeID(0)}, res.Objects)
	require.Empty(t, rt.Configuration().Connections)
	require.Empty(t, rt.Configuration().PublishedDataSets)
}

// TestPubSubConfigurationCloseAndUpdateErrors: the method results of
// CloseAndUpdate.
func TestPubSubConfigurationCloseAndUpdateErrors(t *testing.T) {
	t.Parallel()
	_, surl := testutil.NewTestServer(t, server.WithPubSub(nil), server.WithPubSubAuthorizer(func(_ context.Context, _ *server.MethodCaller, method string) ua.StatusCode {
		if method == "ReserveIds" {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}))
	c := testutil.NewTestClient(t, surl)
	ctx := context.Background()
	refs := ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(remote.Ref(refAdd, refPDS, 0, 0, 0))})

	_, err := remote.New(c).ReserveIDs(ctx, transport.ProfileUDPUADP, 1, 1)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	res := cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(uint32(99)), ua.MustVariant(false), refs)
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)

	h, sc := openCfg(t, c, 0x06)
	require.Equal(t, ua.StatusOK, sc)
	write := func(b []byte) {
		t.Helper()
		res := cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationWrite, ua.MustVariant(h), ua.MustVariant(b))
		require.Equal(t, ua.StatusOK, res.StatusCode)
	}
	write([]byte("not a file"))
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(h), ua.MustVariant(false), refs)
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	// A file of another structure.
	b, err := ua.Encode(&ua.UABinaryFileDataType{Body: ua.MustVariant(ua.NewExtensionObject(&ua.PubSubConfigurationDataType{}))})
	require.NoError(t, err)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationSetPosition, ua.MustVariant(h), ua.MustVariant(uint64(0)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	write(b)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(h), ua.MustVariant(false), refs)
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)

	// No references; the handle stays open.
	require.Equal(t, ua.StatusOK, closeCfg(t, c, h))
	h, sc = openCfg(t, c, 0x06)
	require.Equal(t, ua.StatusOK, sc)
	b, err = ua.Encode(&ua.UABinaryFileDataType{Body: ua.MustVariant(ua.NewExtensionObject(&ua.PubSubConfiguration2DataType{}))})
	require.NoError(t, err)
	write(b)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(h), ua.MustVariant(false), ua.MustVariant([]*ua.ExtensionObject{}))
	require.Equal(t, ua.StatusBadNothingToDo, res.StatusCode)
	res = cfgFileCall(t, c, id.PublishSubscribePubSubConfigurationCloseAndUpdate, ua.MustVariant(h), ua.MustVariant(false), refs)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, false, res.OutputArguments[0].Value())
	require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument}, res.OutputArguments[1].Value())
	// CloseAndUpdate closed it.
	require.Equal(t, ua.StatusBadInvalidArgument, closeCfg(t, c, h))
}

// TestPubSubConfigurationActionGroup: a WriterGroup of Actions without a
// PublishingInterval is valid only with its writer, so CloseAndUpdate checks
// the result of all the references, and refuses the group when its writer
// fails.
func TestPubSubConfigurationActionGroup(t *testing.T) {
	t.Parallel()
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil))
	r := remote.New(testutil.NewTestClient(t, surl))
	conn := pubsub.UDPConnection("Responder", pubsubUDPURL(t), uint16(7))
	conn.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Actions", 1, 0, pubsub.DataSetWriter("W", 1, "Calc"), pubsub.DataSetWriter("X", 2, "Nope"))}
	file := &ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{calcAction()}, Connections: []*ua.PubSubConnectionDataType{conn}}

	res := updateResult(t, r, file, false,
		remote.Ref(refAdd, refPDS, 0, 0, 0), remote.Ref(refAdd, refConn, 0, 0, 0),
		remote.Ref(refAdd, refWG, 0, 0, 0), remote.Ref(refAdd, refWriter, 0, 0, 1))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusBadConfigurationError, ua.StatusBadConfigurationError}, res.Results)
	require.True(t, res.ChangesApplied)
	require.Len(t, res.Values, 2)
	cid, ok := srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "Responder")
	require.True(t, ok)
	_, ok = srv.PubSub().Lookup(pubsub.KindWriterGroup, cid, "Actions")
	require.False(t, ok)

	res = updateResult(t, r, file, true, remote.Ref(refAdd, refWG, 0, 0, 0), remote.Ref(refAdd, refWriter, 0, 0, 0))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, res.Results)
	require.True(t, res.ChangesApplied)
	_, ok = srv.PubSub().Lookup(pubsub.KindWriterGroup, cid, "Actions")
	require.True(t, ok)
}
