// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// PubSub Actions (Part 14 §5.4.2) with a server as the Responder and a
// standalone runtime as the Requestor over UDP.

func psReverse(_ context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	s, ok := in[0].Value().(string)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return []*ua.Variant{ua.MustVariant(string(r))}, ua.StatusGood
}

// TestPubSub_ActionChunksServerResponder calls the PublishedAction of a
// server, unsecured and with SignAndEncrypt, with inputs and outputs
// larger than the MaxNetworkMessageSize: requests and responses go as
// chunks (§7.2.4.4.4) and are reassembled. Small calls are not chunked.
func TestPubSub_ActionChunksServerResponder(t *testing.T) {
	parallel(t)
	ring := psRing(t, "sg")
	respURL, reqURL := psUDPURL(t), psUDPURL(t)
	pds := pubsub.PublishedActions("Blob",
		[]pubsub.Field{{Name: "Data", Type: ua.TypeIDString}},
		[]pubsub.Field{{Name: "Reversed", Type: ua.TypeIDString}},
		pubsub.ActionTargetOf(1, "Reverse"))
	none := pubsub.WriterGroup("none", 1, 50*time.Millisecond, pubsub.DataSetWriter("BlobNone", 100, "Blob"))
	sae := pubsub.WriterGroup("sae", 2, 50*time.Millisecond, pubsub.DataSetWriter("BlobSecure", 200, "Blob"))
	pubsub.Secure(sae, ua.MessageSecurityModeSignAndEncrypt, "sg")
	for _, g := range []*ua.WriterGroupDataType{none, sae} {
		g.MaxNetworkMessageSize = 600
	}
	srv, _ := newServer(t, server.WithPubSub(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachWriterGroups(pubsub.UDPConnection("Responder", respURL, uint16(1)), none, sae)),
		pubsub.WithKeySource("sg", ring), pubsub.WithActionHandler("Blob", 1, psReverse)))
	resp := srv.PubSub()

	req, err := pubsub.New(pubsub.NewConfiguration(nil, pubsub.UDPConnection("Requestor", reqURL, uint16(9))),
		pubsub.WithKeySource("sg", ring))
	require.NoError(t, err)
	require.NoError(t, req.Start(context.Background()))
	t.Cleanup(func() { _ = req.Close() })

	ids := map[string]pubsub.ComponentID{}
	for _, c := range resp.Components() {
		ids[c.Name] = c.ID
	}
	require.Eventually(t, func() bool {
		for _, n := range []string{"none", "sae"} {
			if st, err := resp.Status(ids[n]); err != nil || st.State != ua.PubSubStateOperational {
				return false
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond)

	for _, rt := range []struct {
		group  string
		writer uint16
		mode   ua.MessageSecurityMode
	}{{"none", 100, ua.MessageSecurityModeNone}, {"sae", 200, ua.MessageSecurityModeSignAndEncrypt}} {
		t.Run(rt.group, func(t *testing.T) {
			tg := pubsub.ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: rt.writer, ActionTargetID: 1,
				RequestAddress: respURL, Timeout: 5 * time.Second, ResendInterval: 200 * time.Millisecond, MaxNetworkMessageSize: 600}
			if rt.mode > ua.MessageSecurityModeNone {
				tg.SecurityMode, tg.SecurityGroupID = rt.mode, "sg"
			}
			before, err := resp.Status(ids[rt.group])
			require.NoError(t, err)
			for i, in := range []string{"small", psBig(fmt.Sprint(rt.group, "-1"), 5000), psBig(fmt.Sprint(rt.group, "-2"), 12000)} {
				res, err := req.CallAction(context.Background(), tg, []*ua.Variant{ua.MustVariant(in)})
				require.NoError(t, err, "call %d", i)
				require.Equal(t, ua.StatusGood, res.Status)
				require.Len(t, res.Outputs, 1)
				want, _ := psReverse(context.Background(), []*ua.Variant{ua.MustVariant(in)})
				require.Equal(t, want[0].Value(), res.Outputs[0].Value(), "call %d", i)
			}
			// The Responder counts the chunks once they are sent, which
			// may be after the Requestor has the response.
			require.Eventually(t, func() bool {
				after, err := resp.Status(ids[rt.group])
				return err == nil && after.Counters.ChunksSent >= before.Counters.ChunksSent+20
			}, 5*time.Second, 5*time.Millisecond, "the big responses are chunked")
		})
	}
	rc, err := resp.Status(ids["Responder"])
	require.NoError(t, err)
	require.GreaterOrEqual(t, rc.Counters.ChunkedMessagesReceived, uint64(4), "the big requests are reassembled")
	require.Zero(t, rc.Counters.DecodeErrors)
	qc, err := req.Status(pubsub.Root)
	require.NoError(t, err)
	require.GreaterOrEqual(t, qc.Counters.ChunkedMessagesReceived, uint64(4))
	require.Zero(t, qc.Counters.DecodeErrors)
}

// TestPubSub_ActionMethodServerResponder calls the targets of a
// PublishedActionMethod of a server (Part 14 §6.2.3.10.4): each calls its
// Method of the address space. A target whose Method does not exist
// answers like the Call service; a handler registered for a target takes
// precedence over its Method.
func TestPubSub_ActionMethodServerResponder(t *testing.T) {
	parallel(t)
	respURL, reqURL := psUDPURL(t), psUDPURL(t)
	srv, _ := newServer(t, server.WithPubSub(nil))
	f := testutil.AddFixture(t, srv)
	resp := srv.PubSub()
	missing := ua.NewStringNodeID(f.NSIndex, "NoSuchMethod")
	_, err := resp.AddPublishedDataSet(pubsub.PublishedActionMethods("Square",
		[]pubsub.Field{{Name: "n", Type: ua.TypeIDInt32}},
		[]pubsub.Field{{Name: "result", Type: ua.TypeIDInt32}},
		[]*ua.ActionTargetDataType{pubsub.ActionTargetOf(1, "Square"), pubsub.ActionTargetOf(2, "Missing"), pubsub.ActionTargetOf(3, "Overridden")},
		[]*ua.ActionMethodDataType{
			pubsub.ActionMethodOf(f.MethodObject, f.SquareMethod),
			pubsub.ActionMethodOf(f.MethodObject, missing),
			pubsub.ActionMethodOf(f.MethodObject, f.SquareMethod),
		}))
	require.NoError(t, err)
	resp.SetActionHandler("Square", 3, func(context.Context, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return []*ua.Variant{ua.MustVariant(int32(-1))}, ua.StatusGood
	})
	conn, err := resp.AddConnection(pubsub.UDPConnection("Responder", respURL, uint16(1)))
	require.NoError(t, err)
	gid, err := resp.AddWriterGroup(conn, pubsub.WriterGroup("Actions", 1, 50*time.Millisecond, pubsub.DataSetWriter("SquareWriter", 100, "Square")))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		st, err := resp.Status(gid)
		return err == nil && st.State == ua.PubSubStateOperational
	}, 10*time.Second, 10*time.Millisecond)

	req := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.UDPConnection("Requestor", reqURL, uint16(9))))
	call := func(target uint16, in any) *pubsub.ActionResult {
		t.Helper()
		res, err := req.CallAction(context.Background(), pubsub.ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 100,
			ActionTargetID: target, RequestAddress: respURL, Timeout: 5 * time.Second, ResendInterval: 200 * time.Millisecond}, []*ua.Variant{ua.MustVariant(in)})
		require.NoError(t, err)
		return res
	}
	res := call(1, int32(9))
	require.Equal(t, ua.StatusGood, res.Status)
	require.Equal(t, []*ua.Variant{ua.MustVariant(int32(81))}, res.Outputs)
	require.Equal(t, ua.StatusBadMethodInvalid, call(2, int32(9)).Status)
	res = call(3, int32(9))
	require.Equal(t, ua.StatusGood, res.Status)
	require.Equal(t, int32(-1), res.Outputs[0].Value())
	require.Equal(t, ua.StatusBadTypeMismatch, call(1, "nine").Status)
}

// TestPubSub_ActionConfigurationFile: a client configures a
// PublishedActionMethod with its connection, group and writer through the
// PubSubConfiguration file (ReserveIds, then CloseAndUpdate, Part 14
// §9.1.3.7); a Requestor calls the Method with the ids the client reserved.
func TestPubSub_ActionConfigurationFile(t *testing.T) {
	parallel(t)
	respURL, reqURL := psUDPURL(t), psUDPURL(t)
	srv, url := newServer(t, server.WithPubSub(nil))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	r := remote.New(newClient(t, url))

	ids, err := r.ReserveIDs(ctx, transport.ProfileUDPUADP, 1, 1)
	require.NoError(t, err)
	pds := pubsub.PublishedActionMethods("Square",
		[]pubsub.Field{{Name: "n", Type: ua.TypeIDInt32}},
		[]pubsub.Field{{Name: "result", Type: ua.TypeIDInt32}},
		[]*ua.ActionTargetDataType{pubsub.ActionTargetOf(1, "Square")},
		[]*ua.ActionMethodDataType{pubsub.ActionMethodOf(f.MethodObject, f.SquareMethod)})
	conn := pubsub.AttachWriterGroups(pubsub.UDPConnection("Responder", respURL, nil),
		pubsub.WriterGroup("Actions", ids.WriterGroupIDs[0], 50*time.Millisecond, pubsub.DataSetWriter("SquareWriter", ids.DataSetWriterIDs[0], "Square")))
	res, err := r.UpdateConfiguration(ctx, &ua.PubSubConfiguration2DataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
		Connections:       []*ua.PubSubConnectionDataType{conn},
	}, []*ua.PubSubConfigurationRefDataType{
		remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferencePubDataset, 0, 0, 0),
		remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceConnection, 0, 0, 0),
		remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriterGroup, 0, 0, 0),
		remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriter, 0, 0, 0),
	}, true)
	require.NoError(t, err)
	require.True(t, res.ChangesApplied)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusOK}, res.Results)
	// The connection got the default PublisherId.
	require.Equal(t, ids.DefaultPublisherID.Value(), res.Values[1].Identifier.Value())
	cfg, err := r.ReadConfiguration(ctx)
	require.NoError(t, err)
	require.Equal(t, "Square", cfg.PublishedDataSets[0].Name)
	require.Equal(t, ids.WriterGroupIDs[0], cfg.Connections[0].WriterGroups[0].WriterGroupID)

	req := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.UDPConnection("Requestor", reqURL, uint16(9))))
	require.Eventually(t, func() bool {
		out, err := req.CallAction(ctx, pubsub.ActionTarget{Connection: "Requestor", PublisherID: ids.DefaultPublisherID.Value(),
			DataSetWriterID: ids.DataSetWriterIDs[0], ActionTargetID: 1, RequestAddress: respURL,
			Timeout: time.Second, ResendInterval: 200 * time.Millisecond}, []*ua.Variant{ua.MustVariant(int32(7))})
		return err == nil && out.Status == ua.StatusGood && out.Outputs[0].Value() == int32(49)
	}, 20*time.Second, 50*time.Millisecond)
}

// TestPubSub_ActionDiscoveryServerBroker: a server Responder publishes the
// ActionMetaData of its PublishedActionMethod writer retained on an MQTT
// broker (Part 14 §7.3.4.7.12), UADP and JSON; a Requestor that starts
// later discovers it - targets, request and response DataSetMetaData and
// the Methods - and calls the Method with it.
func TestPubSub_ActionDiscoveryServerBroker(t *testing.T) {
	parallel(t)
	b := psBroker(t)
	srv, _ := newServer(t, server.WithPubSub(nil))
	f := testutil.AddFixture(t, srv)
	resp := srv.PubSub()
	_, err := resp.AddPublishedDataSet(pubsub.PublishedActionMethods("Square",
		[]pubsub.Field{{Name: "n", Type: ua.TypeIDInt32}},
		[]pubsub.Field{{Name: "result", Type: ua.TypeIDInt32}},
		[]*ua.ActionTargetDataType{pubsub.ActionTargetOf(1, "Square")},
		[]*ua.ActionMethodDataType{pubsub.ActionMethodOf(f.MethodObject, f.SquareMethod)}))
	require.NoError(t, err)
	for i, m := range []pubsub.MessageMapping{pubsub.MappingUADP, pubsub.MappingJSON} {
		name := []string{"uadp", "json"}[i]
		t.Run(name, func(t *testing.T) {
			pub := fmt.Sprint("srv-", name)
			queue := pubsub.ActionRequestTopic("conf", m, pub, "Actions")
			meta := pubsub.ActionMetaDataTopic("conf", m, pub, "Actions", "SquareWriter")
			w := pubsub.SetWriterQueue(pubsub.DataSetWriter("SquareWriter", 100, "Square"), "", meta)
			var g *ua.WriterGroupDataType
			if m == pubsub.MappingJSON {
				g = pubsub.JSONWriterGroup("Actions", uint16(1+i), 0, queue, w)
			} else {
				g = pubsub.WriterGroup("Actions", uint16(1+i), 0, w)
				g.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: queue,
					RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce})
			}
			conn, err := resp.AddConnection(pubsub.MQTTConnection(name, b.URL(), pub, m))
			require.NoError(t, err)
			gid, err := resp.AddWriterGroup(conn, g)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				st, err := resp.Status(gid)
				return err == nil && st.State == ua.PubSubStateOperational
			}, 10*time.Second, 10*time.Millisecond)

			req := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.MQTTConnection("Requestor", b.URL(), "req-"+name, m)))
			require.Eventually(t, func() bool {
				for _, c := range req.Components() {
					if st, err := req.Status(c.ID); c.Kind == pubsub.KindConnection && err == nil && st.State == ua.PubSubStateOperational {
						return true
					}
				}
				return false
			}, 10*time.Second, 10*time.Millisecond)
			tg := pubsub.ActionTarget{Connection: "Requestor", PublisherID: pub, DataSetWriterID: 100, ActionTargetID: 1,
				RequestAddress: queue, MetaDataAddress: meta, Timeout: 5 * time.Second}
			md, err := req.DiscoverAction(context.Background(), tg)
			require.NoError(t, err)
			require.Equal(t, "Square", md.Target(1).Name)
			require.Equal(t, "n", md.Request.Fields[0].Name)
			require.Equal(t, "result", md.Response.Fields[0].Name)
			require.Equal(t, md.Response.ConfigurationVersion, md.Request.ConfigurationVersion)
			require.Len(t, md.ActionMethods, 1)
			require.Equal(t, f.SquareMethod.String(), md.ActionMethods[0].MethodID.String())
			res, err := req.CallAction(context.Background(), md.Apply(tg), []*ua.Variant{ua.MustVariant(int32(7))})
			require.NoError(t, err)
			require.Equal(t, ua.StatusGood, res.Status)
			require.Equal(t, int32(49), res.Outputs[0].Value())
		})
	}
}
