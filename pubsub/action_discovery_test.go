// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// checkCalcMetaData checks the ActionMetaData of the Calc writer of
// actionPDS.
func checkCalcMetaData(t *testing.T, m *ActionMetaData) {
	t.Helper()
	require.Equal(t, uint16(100), m.DataSetWriterID)
	require.Equal(t, "1", m.Responder.String())
	require.Len(t, m.ActionTargets, 2)
	require.Equal(t, "Add", m.Target(1).Name)
	require.Equal(t, "Echo", m.Target(2).Name)
	require.Nil(t, m.Target(3))
	require.Equal(t, []string{"A", "B"}, []string{m.Request.Fields[0].Name, m.Request.Fields[1].Name})
	require.Equal(t, "Sum", m.Response.Fields[0].Name)
	// Part 14 Table 177: the Name and ConfigurationVersion of the request
	// and the response are equal.
	require.Equal(t, m.Response.Name, m.Request.Name)
	require.Equal(t, m.Response.ConfigurationVersion, m.Request.ConfigurationVersion)
	require.Empty(t, m.ActionMethods)
}

// TestDiscoverActionDatagram: a Requestor probes for the ActionMetaData on
// the shared address of a datagram connection, unsecured and with
// SignAndEncrypt, and calls the Action with it. A Requestor without the
// keys learns nothing from a secured Responder.
func TestDiscoverActionDatagram(t *testing.T) {
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			url := memURL(t)
			var opts []Option
			if mode > ua.MessageSecurityModeNone {
				ks := regressKeys(t, "sg")
				opts = append(opts, WithKeySource("sg", regressSource(t, ks, "sg")))
			}
			resp := startReal(t, responderConfig(url, 50*time.Millisecond, mode), append(opts, WithActionHandler("Calc", 1, addHandler))...)
			req := startReal(t, requestorConfig(url), opts...)
			waitRunning(t, resp, "Responder")
			waitRunning(t, req, "Requestor")
			waitResponder(t, resp)

			tg := calcTarget()
			tg.ResponseMetaData = nil
			if mode > ua.MessageSecurityModeNone {
				tg.SecurityMode, tg.SecurityGroupID = mode, "sg"
			}
			m, err := req.DiscoverAction(context.Background(), tg)
			require.NoError(t, err)
			checkCalcMetaData(t, m)
			res, err := req.CallAction(context.Background(), m.Apply(tg), int32s(2, 3))
			require.NoError(t, err)
			require.Equal(t, ua.StatusGood, res.Status)
			require.Equal(t, int32(5), res.Outputs[0].Value())

			// The Responder counts a response once it has been sent: the
			// Requestor may have it first.
			require.Eventually(t, func() bool {
				rc := actCounters(resp, mustID(t, resp, KindConnection, Root, "Responder"))
				return rc.DiscoveryRequestsReceived > 0 && rc.DiscoveryResponsesSent > 0
			}, 5*time.Second, time.Millisecond)
			qc := actCounters(req, mustID(t, req, KindConnection, Root, "Requestor"))
			require.Positive(t, qc.DiscoveryRequestsSent)
			require.Positive(t, qc.DiscoveryResponsesReceived)

			// A writer that does not exist, and (secured) a Requestor
			// without the keys.
			tg.DataSetWriterID, tg.Timeout = 101, 300*time.Millisecond
			_, err = req.DiscoverAction(context.Background(), tg)
			require.ErrorIs(t, err, ua.StatusBadTimeout)
			if mode > ua.MessageSecurityModeNone {
				other := startReal(t, NewConfiguration(nil, memConnection("Requestor", url, uint16(3))))
				waitRunning(t, other, "Requestor")
				tg := calcTarget()
				tg.Timeout = 500 * time.Millisecond
				_, err := other.DiscoverAction(context.Background(), tg)
				require.ErrorIs(t, err, ua.StatusBadTimeout)
			}
		})
	}
}

// TestDiscoverActionMethods: the ActionMetaData of a PublishedActionMethod
// carries its ActionMethods.
func TestDiscoverActionMethods(t *testing.T) {
	url := memURL(t)
	resp := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{calcMethodPDS()},
		AttachWriterGroups(memConnection("Responder", url, uint16(1)), WriterGroup("Actions", 10, 50*time.Millisecond, DataSetWriter("CalcWriter", 100, "Calc")))))
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)
	m, err := req.DiscoverAction(context.Background(), calcTarget())
	require.NoError(t, err)
	require.Len(t, m.ActionMethods, 2)
	require.Equal(t, "Add", m.ActionMethods[0].MethodID.StringID())
	require.Equal(t, "Sub", m.ActionMethods[1].MethodID.StringID())
	require.Equal(t, "Calc", m.ActionMethods[1].ObjectID.StringID())
}

// TestActionAnnouncementsDatagram: a Responder announces the ActionMetaData
// of its Action writers unprompted on its discovery channel when they
// start and every DiscoveryAnnounceRate, and answers a PubSubConnections
// probe with the ActionResponder configuration too.
func TestActionAnnouncementsDatagram(t *testing.T) {
	url := memURL(t)
	cfg := responderConfig(url, 50*time.Millisecond, ua.MessageSecurityModeNone)
	g := cfg.Connections[0].WriterGroups[0]
	g.TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{DiscoveryAnnounceRate: 1}) // seconds
	got := make(chan *message.Discovery, 64)
	tap := startReal(t, NewConfiguration(nil, memConnection("Tap", url, uint16(9))))
	waitRunning(t, tap, "Tap")
	tapConn := tap.conns[0]
	unsub, err := tapConn.tc.Subscribe(context.Background(), "", 0, func(m *transport.Message) {
		nm, err := uadp.Decode(m.Payload, nil)
		if err == nil && nm.Discovery != nil {
			select {
			case got <- nm.Discovery:
			default:
			}
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = unsub() })

	resp := startReal(t, cfg, WithActionHandler("Calc", 1, addHandler))
	waitRunning(t, resp, "Responder")
	n := 0
	deadline := time.After(10 * time.Second)
	for n < 3 {
		select {
		case d := <-got:
			if d.Type == message.DiscoveryActionMetaData {
				require.Equal(t, uint16(100), d.DataSetWriterID)
				require.Equal(t, "Sum", d.MetaData.Fields[0].Name)
				n++
			}
		case <-deadline:
			t.Fatalf("%d ActionMetaData announcements", n)
		}
	}
	require.Positive(t, actCounters(resp, mustID(t, resp, KindDataSetWriter, mustID(t, resp, KindWriterGroup,
		mustID(t, resp, KindConnection, Root, "Responder"), "Actions"), "CalcWriter")).MetaDataSent)

	// A PubSubConnections probe: the connection and the ActionResponder.
	probe, err := uadp.Encode(&message.NetworkMessage{
		Type: message.NetworkMessageDiscoveryRequest, UADPMask: ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 1),
		Request: &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationPubSubConnections,
			IncludeWriterGroups: true, IncludeDataSetWriters: true},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, tapConn.tc.Send(context.Background(), probe, transport.PublishOptions{}))
	deadline = time.After(5 * time.Second)
	for {
		select {
		case d := <-got:
			if d.Type != message.DiscoveryActionResponder {
				continue
			}
			require.Len(t, d.Connections, 1)
			c := d.Connections[0]
			require.Equal(t, "Responder", c.Name)
			require.Empty(t, c.ReaderGroups)
			require.Len(t, c.WriterGroups, 1)
			require.Equal(t, "CalcWriter", c.WriterGroups[0].DataSetWriters[0].Name)
			return
		case <-deadline:
			t.Fatal("no ActionResponder announcement")
		}
	}
}

// TestDiscoverActionBroker: on a broker the Responder publishes the
// ActionMetaData of its writer retained on its MetaDataQueueName and the
// ActionResponder on the action-responder topic, UADP and JSON; a
// Requestor that starts later reads the ActionMetaData and calls with it.
func TestDiscoverActionBroker(t *testing.T) {
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	for name, m := range map[string]MessageMapping{"uadp": MappingUADP, "json": MappingJSON} {
		t.Run(name, func(t *testing.T) {
			prefix := "disc-" + name
			queue := ActionRequestTopic(prefix, m, "1", "Actions")
			meta := ActionMetaDataTopic(prefix, m, "1", "Actions", "CalcWriter")
			rcfg, qcfg := brokerActionPair(brokerConnection("Responder", b.URL(), uint16(1), m), brokerConnection("Requestor", b.URL(), uint16(2), m), m, queue)
			SetWriterQueue(rcfg.Connections[0].WriterGroups[0].DataSetWriters[0], "", meta)
			resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
			waitRunning(t, resp, "Responder")
			waitResponder(t, resp)
			require.Eventually(t, func() bool {
				return b.Retained(meta) != nil && b.Retained(ActionResponderTopic(prefix, m, "1")) != nil
			}, 5*time.Second, 5*time.Millisecond)
			if m == MappingJSON {
				rm, err := jsonmsg.DecodeActionResponder(b.Retained(ActionResponderTopic(prefix, m, "1")), nil)
				require.NoError(t, err)
				require.Equal(t, "CalcWriter", rm.Connection.WriterGroups[0].DataSetWriters[0].Name)
			} else {
				nm, err := uadp.Decode(b.Retained(ActionResponderTopic(prefix, m, "1")), nil)
				require.NoError(t, err)
				require.Equal(t, message.DiscoveryActionResponder, nm.Discovery.Type)
				require.Equal(t, "CalcWriter", nm.Discovery.Connections[0].WriterGroups[0].DataSetWriters[0].Name)
			}

			req := startReal(t, qcfg)
			waitRunning(t, req, "Requestor")
			tg := calcTarget()
			tg.RequestAddress, tg.MetaDataAddress, tg.ResponseMetaData = queue, meta, nil
			md, err := req.DiscoverAction(context.Background(), tg)
			require.NoError(t, err)
			checkCalcMetaData(t, md)
			res, err := req.CallAction(context.Background(), md.Apply(tg), int32s(4, 5))
			require.NoError(t, err)
			require.Equal(t, int32(9), res.Outputs[0].Value())

			tg.MetaDataAddress = ""
			_, err = req.DiscoverAction(context.Background(), tg)
			require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
		})
	}
}

func TestDiscoverActionErrors(t *testing.T) {
	url := memURL(t)
	req := startReal(t, requestorConfig(url))
	waitRunning(t, req, "Requestor")
	ctx := context.Background()
	for name, tg := range map[string]ActionTarget{
		"no publisher": {Connection: "Requestor", DataSetWriterID: 1},
		"no writer":    {Connection: "Requestor", PublisherID: uint16(1)},
		"bad id":       {Connection: "Requestor", PublisherID: 1.5, DataSetWriterID: 1},
		"no group":     {Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 1, SecurityMode: ua.MessageSecurityModeSign},
	} {
		_, err := req.DiscoverAction(ctx, tg)
		require.ErrorIs(t, err, ua.StatusBadInvalidArgument, name)
	}
	_, err := req.DiscoverAction(ctx, ActionTarget{Connection: "Nope", PublisherID: uint16(1), DataSetWriterID: 1})
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// A unicast UDP connection without DiscoveryAddress has no discovery
	// channel.
	uni := startReal(t, NewConfiguration(nil, UDPConnection("Uni", fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t)), uint16(2))))
	waitRunning(t, uni, "Uni")
	_, err = uni.DiscoverAction(ctx, ActionTarget{Connection: "Uni", PublisherID: uint16(1), DataSetWriterID: 1})
	require.ErrorIs(t, err, ua.StatusBadInvalidState)

	// A cancelled context, and a closed runtime.
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err = req.DiscoverAction(cctx, ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 1})
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, req.Close())
	_, err = req.DiscoverAction(ctx, ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 1})
	require.ErrorIs(t, err, ErrClosed)
}

func TestActionDiscoveryTopics(t *testing.T) {
	require.Equal(t, "p/json/action-metadata/r/g/w", ActionMetaDataTopic("p", MappingJSON, "r", "g", "w"))
	require.Equal(t, "p/uadp/action-responder/r", ActionResponderTopic("p", MappingUADP, "r"))
	require.Equal(t, "p/uadp/action-responder/r", responderTopic(ActionRequestTopic("p", MappingUADP, "r", "g")))
	require.Empty(t, responderTopic("my/queue"))
	require.Empty(t, responderTopic("p/uadp/action-request/r"))
	require.Empty(t, responderTopic("p/uadp/action-request//g"))
}
