// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/ua"
)

// End-to-end PubSub Actions with the real transports.

func e2eCall(t *testing.T, resp, req *PubSub, tg ActionTarget) {
	t.Helper()
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)
	tg.RequestMetaData = MetaData("CalcRequest", Field{Name: "A", Type: ua.TypeIDInt32}, Field{Name: "B", Type: ua.TypeIDInt32})
	for i := int32(0); i < 3; i++ {
		res, err := req.CallAction(context.Background(), tg, int32s(i, 100))
		require.NoError(t, err)
		require.Equal(t, ua.StatusGood, res.Status)
		require.Equal(t, i+100, res.Outputs[0].Value())
	}
}

// waitResponder waits until the Responder listens for requests: a request
// sent before is lost on a broker (Part 14 §6.2.11.2.2: the Requestor needs
// its own timeout).
func waitResponder(t *testing.T, p *PubSub) {
	t.Helper()
	require.Eventually(t, func() bool {
		p.lock()
		defer p.unlock()
		c := p.conns[0]
		return len(c.subscribed) > 0 && len(c.wgs) > 0 && c.wgs[0].state == ua.PubSubStateOperational
	}, 5*time.Second, time.Millisecond)
}

func TestE2EActionUDP(t *testing.T) {
	t.Parallel()
	respURL := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
	reqURL := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
	for _, secured := range []bool{false, true} {
		t.Run(fmt.Sprint("secured=", secured), func(t *testing.T) {
			mode := ua.MessageSecurityModeNone
			var opts []Option
			if secured {
				mode = ua.MessageSecurityModeSignAndEncrypt
				ks := regressKeys(t, "sg")
				opts = append(opts, WithKeySource("sg", regressSource(t, ks, "sg")))
			}
			rcfg := responderConfig(respURL, 50*time.Millisecond, mode)
			rcfg.Connections[0] = AttachWriterGroups(UDPConnection("Responder", respURL, uint16(1)), rcfg.Connections[0].WriterGroups...)
			resp := startReal(t, rcfg, append(opts, WithActionHandler("Calc", 1, addHandler))...)
			req := startReal(t, NewConfiguration(nil, UDPConnection("Requestor", reqURL, uint16(2))), opts...)
			tg := calcTarget()
			tg.RequestAddress = respURL
			tg.ResendInterval = 50 * time.Millisecond
			if secured {
				tg.SecurityMode, tg.SecurityGroupID = mode, "sg"
			}
			e2eCall(t, resp, req, tg)
			// The Idle acknowledgements are confirmed: the calls end.
			require.Eventually(t, func() bool {
				req.lock()
				defer req.unlock()
				return len(req.conns[0].act.calls) == 0 && len(req.conns[0].act.listen) == 0
			}, 5*time.Second, 5*time.Millisecond)
			require.NoError(t, resp.Close())
			require.NoError(t, req.Close())
		})
	}
}

func TestE2EActionMQTT(t *testing.T) {
	t.Parallel()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	for _, m := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			t.Parallel()
			queue := ActionRequestTopic(fmt.Sprintf("e2e%d", m), m, "1", "Actions")
			rcfg, qcfg := brokerActionPair(MQTTConnection("Responder", b.URL(), uint16(1), m), MQTTConnection("Requestor", b.URL(), uint16(2), m), m, queue)
			resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
			req := startReal(t, qcfg)
			tg := calcTarget()
			tg.RequestAddress = queue
			e2eCall(t, resp, req, tg)
		})
	}
}

func TestE2EActionMQTT5(t *testing.T) {
	t.Parallel()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	queue := ActionRequestTopic("e2e5", MappingJSON, "1", "Actions")
	rcfg, qcfg := brokerActionPair(SetMQTTVersion(MQTTConnection("Responder", b.URL(), uint16(1), MappingJSON), MQTTVersion5),
		SetMQTTVersion(MQTTConnection("Requestor", b.URL(), uint16(2), MappingJSON), MQTTVersion5), MappingJSON, queue)
	resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
	req := startReal(t, qcfg)
	tg := calcTarget()
	tg.RequestAddress = queue
	tg.ResponseAddress = "e2e5/replies/requestor-2"
	e2eCall(t, resp, req, tg)
}

func TestE2EActionAMQP(t *testing.T) {
	t.Parallel()
	b := startAMQPBroker(t, amqpbroker.Options{})
	for _, m := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			t.Parallel()
			queue := fmt.Sprintf("/queues/calc.%d/action-request/1", m)
			rcfg, qcfg := brokerActionPair(AMQPConnection("Responder", b.URL(), uint16(1), m), AMQPConnection("Requestor", b.URL(), uint16(2), m), m, queue)
			resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
			req := startReal(t, qcfg)
			tg := calcTarget()
			tg.RequestAddress = queue
			e2eCall(t, resp, req, tg)
		})
	}
}

// brokerActionPair returns the configurations of a Responder (writer group
// "Actions" with the request queue) and a Requestor on broker connections.
func brokerActionPair(rc, qc *ua.PubSubConnectionDataType, m MessageMapping, queue string) (resp, req *ua.PubSubConfigurationDataType) {
	var g *ua.WriterGroupDataType
	if m == MappingJSON {
		g = JSONWriterGroup("Actions", 10, 0, queue, DataSetWriter("CalcWriter", 100, "Calc"))
	} else {
		g = WriterGroup("Actions", 10, 0, DataSetWriter("CalcWriter", 100, "Calc"))
		g.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: queue,
			RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce})
	}
	return NewConfiguration([]*ua.PublishedDataSetDataType{actionPDS()}, AttachWriterGroups(rc, g)), NewConfiguration(nil, qc)
}
