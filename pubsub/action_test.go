// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// actionPDS is a PublishedAction "Calc" with target 1 "Add" (two Int32
// inputs, one Int32 output) and target 2 "Echo".
func actionPDS() *ua.PublishedDataSetDataType {
	return PublishedActions("Calc",
		[]Field{{Name: "A", Type: ua.TypeIDInt32}, {Name: "B", Type: ua.TypeIDInt32}},
		[]Field{{Name: "Sum", Type: ua.TypeIDInt32}},
		ActionTargetOf(1, "Add"), ActionTargetOf(2, "Echo"))
}

func addHandler(_ context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	a, _ := in[0].Value().(int32)
	b, _ := in[1].Value().(int32)
	return []*ua.Variant{ua.MustVariant(a + b)}, ua.StatusGood
}

func int32s(v ...int32) []*ua.Variant {
	out := make([]*ua.Variant, len(v))
	for i, x := range v {
		out[i] = ua.MustVariant(x)
	}
	return out
}

// startReal starts a runtime with the real codecs.
func startReal(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...Option) *PubSub {
	t.Helper()
	opts = append([]Option{WithRetryInterval(20 * time.Millisecond)}, opts...)
	p, err := New(cfg, opts...)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// responderConfig is a datagram Responder on url with PublisherId 1, writer
// group 10 and Action writer 100.
func responderConfig(url string, interval time.Duration, secure ua.MessageSecurityMode) *ua.PubSubConfigurationDataType {
	g := WriterGroup("Actions", 10, interval, DataSetWriter("CalcWriter", 100, "Calc"))
	if secure > ua.MessageSecurityModeNone {
		Secure(g, secure, "sg")
	}
	return NewConfiguration([]*ua.PublishedDataSetDataType{actionPDS()},
		AttachWriterGroups(memConnection("Responder", url, uint16(1)), g))
}

func requestorConfig(url string) *ua.PubSubConfigurationDataType {
	return NewConfiguration(nil, memConnection("Requestor", url, uint16(2)))
}

func calcTarget() ActionTarget {
	return ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 100, ActionTargetID: 1,
		Timeout: 3 * time.Second, ResponseMetaData: MetaData("Calc", Field{Name: "Sum", Type: ua.TypeIDInt32})}
}

func actCounters(p *PubSub, id ComponentID) Counters {
	st, _ := p.Status(id)
	return st.Counters
}

func waitRunning(t *testing.T, p *PubSub, conn string) {
	t.Helper()
	waitState(t, p, mustID(t, p, KindConnection, Root, conn), ua.PubSubStateOperational)
}

func TestActionDatagram(t *testing.T) {
	url := memURL(t)
	resp := startReal(t, responderConfig(url, 50*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, addHandler))
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	res, err := req.CallAction(context.Background(), calcTarget(), int32s(2, 3))
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, res.Status)
	require.Len(t, res.Outputs, 1)
	require.Equal(t, int32(5), res.Outputs[0].Value())

	// A target without handler.
	tg := calcTarget()
	tg.ActionTargetID = 2
	res, err = req.CallAction(context.Background(), tg, int32s(1, 1))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotImplemented, res.Status)
	require.Empty(t, res.Outputs)

	// Bad inputs.
	res, err = req.CallAction(context.Background(), calcTarget(), int32s(1))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadArgumentsMissing, res.Status)
	res, err = req.CallAction(context.Background(), calcTarget(), int32s(1, 2, 3))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTooManyArguments, res.Status)
	res, err = req.CallAction(context.Background(), calcTarget(), []*ua.Variant{ua.MustVariant("x"), ua.MustVariant(int32(1))})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTypeMismatch, res.Status)

	wid := mustID(t, resp, KindDataSetWriter, mustID(t, resp, KindWriterGroup, mustID(t, resp, KindConnection, Root, "Responder"), "Actions"), "CalcWriter")
	cid := mustID(t, req, KindConnection, Root, "Requestor")
	require.Eventually(t, func() bool {
		wc := actCounters(resp, wid)
		rc := actCounters(req, cid)
		return wc.ActionRequestsReceived == 10 && wc.ActionResponsesSent >= 10 &&
			rc.ActionRequestsSent >= 10 && rc.ActionResponsesReceived >= 5
	}, 3*time.Second, 5*time.Millisecond, "%+v %+v", actCounters(resp, wid), actCounters(req, cid))
}

func TestActionTimeout(t *testing.T) {
	url := memURL(t)
	req := startReal(t, requestorConfig(url))
	waitRunning(t, req, "Requestor")
	tg := calcTarget()
	tg.Timeout = 50 * time.Millisecond
	tg.ResendInterval = 10 * time.Millisecond
	_, err := req.CallAction(context.Background(), tg, int32s(1, 2))
	require.ErrorIs(t, err, ErrActionTimeout)
	require.ErrorIs(t, err, ua.StatusBadTimeout)
	cid := mustID(t, req, KindConnection, Root, "Requestor")
	require.Eventually(t, func() bool {
		c := actCounters(req, cid)
		return c.ActionTimeouts == 1 && c.ActionRequestsSent >= 2
	}, 3*time.Second, 5*time.Millisecond)
}

func TestActionHandlerTimeoutAndPanic(t *testing.T) {
	url := memURL(t)
	var calls atomic.Int32
	var deadline atomic.Bool
	release := make(chan struct{})
	slow := func(ctx context.Context, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		calls.Add(1)
		_, ok := ctx.Deadline()
		deadline.Store(ok)
		<-release
		return nil, ua.StatusBadTimeout
	}
	resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone),
		WithActionHandler("Calc", 1, slow),
		WithActionHandler("Calc", 2, func(context.Context, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) { panic("boom") }))
	t.Cleanup(func() { close(release) })
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	tg := calcTarget()
	tg.ActionTargetID = 2
	res, err := req.CallAction(context.Background(), tg, int32s(1, 2))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadInternalError, res.Status)

	// The Requestor resends and is answered with Executing meanwhile; the
	// request runs once, with the TimeoutHint as deadline.
	tg = calcTarget()
	tg.Timeout = 300 * time.Millisecond
	tg.ResendInterval = 20 * time.Millisecond
	_, err = req.CallAction(context.Background(), tg, int32s(1, 2))
	require.ErrorIs(t, err, ErrActionTimeout)
	require.Equal(t, int32(1), calls.Load())
	require.True(t, deadline.Load())
}

func TestActionSetHandlerAndInvocation(t *testing.T) {
	url := memURL(t)
	resp := startReal(t, responderConfig(url, 50*time.Millisecond, ua.MessageSecurityModeNone))
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)
	got := make(chan ActionInvocation, 1)
	resp.SetActionHandler("Calc", 1, func(ctx context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		inv, _ := ActionInvocationFrom(ctx)
		got <- inv
		return addHandler(ctx, in)
	})
	res, err := req.CallAction(context.Background(), calcTarget(), int32s(4, 5))
	require.NoError(t, err)
	require.Equal(t, int32(9), res.Outputs[0].Value())
	inv := <-got
	require.Equal(t, uint16(100), inv.DataSetWriterID)
	require.Equal(t, "Calc", inv.DataSet)
	require.Equal(t, uint16(1), inv.ActionTargetID)
	require.Equal(t, res.RequestID, inv.RequestID)
	require.NotNil(t, inv.RequestorID)
	require.Equal(t, "2", inv.RequestorID.String())

	resp.SetActionHandler("Calc", 1, nil)
	res, err = req.CallAction(context.Background(), calcTarget(), int32s(4, 5))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotImplemented, res.Status)
}

func TestActionCallErrors(t *testing.T) {
	url := memURL(t)
	cfg := NewConfiguration(nil, memConnection("Requestor", url, uint16(2)), memConnection("NoPub", memURL(t)+"x", nil))
	req := startReal(t, cfg)
	waitRunning(t, req, "Requestor")
	ctx := context.Background()
	for name, tg := range map[string]ActionTarget{
		"no publisher":   {Connection: "Requestor", DataSetWriterID: 1},
		"bad publisher":  {Connection: "Requestor", PublisherID: 1.5, DataSetWriterID: 1},
		"no writer":      {Connection: "Requestor", PublisherID: uint16(1)},
		"no group":       {Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 1, SecurityMode: ua.MessageSecurityModeSign},
		"no connection":  {Connection: "Nope", PublisherID: uint16(1), DataSetWriterID: 1},
		"no requestorid": {Connection: "NoPub", PublisherID: uint16(1), DataSetWriterID: 1},
	} {
		_, err := req.CallAction(ctx, tg, nil)
		require.Error(t, err, name)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := req.CallAction(cctx, calcTarget(), nil)
	require.ErrorIs(t, err, context.Canceled)

	require.NoError(t, req.Close())
	_, err = req.CallAction(ctx, calcTarget(), nil)
	require.True(t, errors.Is(err, ErrClosed))
}

func brokerActionConfigs(url string, m MessageMapping) (resp, req *ua.PubSubConfigurationDataType, queue string) {
	queue = ActionRequestTopic("opcua", m, "1", "Actions")
	var g *ua.WriterGroupDataType
	if m == MappingJSON {
		g = JSONWriterGroup("Actions", 10, 0, queue, DataSetWriter("CalcWriter", 100, "Calc"))
	} else {
		g = WriterGroup("Actions", 10, 0, DataSetWriter("CalcWriter", 100, "Calc"))
		g.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: queue})
	}
	resp = NewConfiguration([]*ua.PublishedDataSetDataType{actionPDS()}, AttachWriterGroups(brokerConnection("Responder", url, uint16(1), m), g))
	req = NewConfiguration(nil, brokerConnection("Requestor", url, uint16(2), m))
	return resp, req, queue
}

func TestActionBroker(t *testing.T) {
	for _, m := range []MessageMapping{MappingUADP, MappingJSON} {
		t.Run(map[MessageMapping]string{MappingUADP: "UADP", MappingJSON: "JSON"}[m], func(t *testing.T) {
			url := memURL(t)
			rcfg, qcfg, queue := brokerActionConfigs(url, m)
			resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
			req := startReal(t, qcfg)
			waitRunning(t, resp, "Responder")
			waitRunning(t, req, "Requestor")
			waitResponder(t, resp)
			tg := calcTarget()
			tg.RequestAddress = queue
			tg.RequestMetaData = MetaData("CalcRequest", Field{Name: "A", Type: ua.TypeIDInt32}, Field{Name: "B", Type: ua.TypeIDInt32})
			for i := int32(0); i < 3; i++ {
				res, err := req.CallAction(context.Background(), tg, int32s(i, 10))
				require.NoError(t, err)
				require.Equal(t, ua.StatusGood, res.Status)
				require.Equal(t, i+10, res.Outputs[0].Value())
			}
			// The responses went to the default action-response topic.
			respTopic := ActionResponseTopic("opcua", m, "1", "Actions")
			require.Eventually(t, func() bool {
				n := 0
				for _, s := range bus.sentTo(url) {
					if s.Topic == respTopic && s.QoS == 1 {
						n++
					}
				}
				return n >= 6
			}, 3*time.Second, 5*time.Millisecond)

			// Without a RequestAddress the call cannot be made.
			tg.RequestAddress = ""
			_, err := req.CallAction(context.Background(), tg, nil)
			require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
			tg.RequestAddress = "some/queue"
			_, err = req.CallAction(context.Background(), tg, nil)
			require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
		})
	}
}

func TestActionConnectionStops(t *testing.T) {
	url := memURL(t)
	started := make(chan struct{}, 4)
	h := func(ctx context.Context, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ua.StatusBadShutdown
	}
	resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, h))
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	// The Requestor's connection stops during the call.
	cid := mustID(t, req, KindConnection, Root, "Requestor")
	errc := make(chan error, 1)
	go func() {
		_, err := req.CallAction(context.Background(), calcTarget(), int32s(1, 2))
		errc <- err
	}()
	<-started
	require.NoError(t, req.Disable(cid))
	require.ErrorIs(t, <-errc, ua.StatusBadNotConnected)
	_, err := req.CallAction(context.Background(), calcTarget(), int32s(1, 2))
	require.ErrorIs(t, err, ua.StatusBadInvalidState)

	// The Responder's connection stops: the running handler is cancelled.
	require.NoError(t, req.Enable(cid))
	waitRunning(t, req, "Requestor")
	go func() {
		_, err := req.CallAction(context.Background(), calcTarget(), int32s(1, 2))
		errc <- err
	}()
	<-started
	rid := mustID(t, resp, KindConnection, Root, "Responder")
	require.NoError(t, resp.Disable(rid))
	require.Eventually(t, func() bool { return exchanges(resp) == 0 }, 3*time.Second, time.Millisecond)
	// Closing the Requestor ends the call.
	require.NoError(t, req.Close())
	require.ErrorIs(t, <-errc, ErrClosed)
}
