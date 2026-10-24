// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// rawRequest encodes an ActionRequest of a Requestor with PublisherId 7 for
// writer 100 of the Responder 1.
func rawRequest(t *testing.T, pub uint16, target, reqID uint16, state ua.ActionState, corr string, inputs ...int32) []byte {
	t.Helper()
	rid := message.NewPublisherID(message.PublisherIDUInt16, 7)
	dsm := &message.DataSetMessage{DataSetWriterID: 100, Type: message.DataSetMessageActionRequest, Valid: true,
		ActionTargetID: target, RequestID: reqID, ActionState: state}
	for i, v := range inputs {
		dsm.Fields = append(dsm.Fields, &message.Field{Index: uint16(i), Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}})
	}
	nm := &message.NetworkMessage{
		Type: message.NetworkMessageDataSet, PublisherID: message.NewPublisherID(message.PublisherIDUInt16, uint64(pub)),
		UADPMask: ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader,
		Messages: []*message.DataSetMessage{dsm},
		Action: &message.ActionHeader{Type: message.ActionRequest, CorrelationData: []byte(corr), RequestorID: &rid,
			TimeoutHint: 5000},
	}
	b, err := uadp.Encode(nm, nil)
	require.NoError(t, err)
	return b
}

type rawResponse struct {
	reqID  uint16
	corr   string
	state  ua.ActionState
	status ua.StatusCode
	fields int
}

// responses returns the ActionResponses sent to url.
func responses(url string) []rawResponse {
	var out []rawResponse
	for _, s := range bus.sentTo(url) {
		if !uadp.PeekAction(s.Payload) {
			continue
		}
		nm, err := uadp.Decode(s.Payload, nil)
		if err != nil || nm.Action == nil || nm.Action.Type != message.ActionResponse {
			continue
		}
		for _, dsm := range nm.Messages {
			out = append(out, rawResponse{reqID: dsm.RequestID, corr: string(nm.Action.CorrelationData), state: dsm.ActionState, status: dsm.Status, fields: len(dsm.Fields)})
		}
	}
	return out
}

func countResponses(url string, reqID uint16, state ua.ActionState) int {
	n := 0
	for _, r := range responses(url) {
		if r.reqID == reqID && r.state == state {
			n++
		}
	}
	return n
}

func exchanges(p *PubSub) int {
	p.lock()
	defer p.unlock()
	n := 0
	for _, c := range p.conns {
		n += len(c.act.exchanges)
	}
	return n
}

func TestActionResponderStates(t *testing.T) {
	url := memURL(t)
	var calls atomic.Int32
	release := make(chan struct{})
	h := func(ctx context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return addHandler(ctx, in)
	}
	resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, h))
	waitRunning(t, resp, "Responder")
	waitResponder(t, resp)

	// Executing is repeated every PublishingInterval while the handler runs;
	// repeated requests do not run it again.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c1", 2, 3))
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateExecuting) >= 2 }, 3*time.Second, time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c1", 2, 3))
	time.Sleep(actionDuplicateGuard + 10*time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c1", 2, 3))
	// An Idle request of a running exchange is ignored.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateIdle, "c1"))
	wid := mustID(t, resp, KindDataSetWriter, mustID(t, resp, KindWriterGroup, mustID(t, resp, KindConnection, Root, "Responder"), "Actions"), "CalcWriter")
	require.Eventually(t, func() bool { return actCounters(resp, wid).ActionRequestsReceived == 4 }, 3*time.Second, time.Millisecond)
	require.Equal(t, int32(1), calls.Load())

	// Done is repeated until the acknowledgement.
	close(release)
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateDone) >= 2 }, 3*time.Second, time.Millisecond)
	for _, r := range responses(url) {
		if r.state == ua.ActionStateDone {
			require.Equal(t, ua.StatusGood, r.status)
			require.Equal(t, 1, r.fields)
			require.Equal(t, "c1", r.corr)
		}
		if r.state == ua.ActionStateExecuting {
			require.Equal(t, 0, r.fields)
		}
	}
	// A repeated request after Done gets Done again.
	time.Sleep(actionDuplicateGuard + 10*time.Millisecond)
	n := countResponses(url, 1, ua.ActionStateDone)
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c1", 2, 3))
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateDone) > n }, 3*time.Second, time.Millisecond)
	require.Equal(t, int32(1), calls.Load())

	// Idle acknowledges Done: confirmed with Idle, the exchange ends.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateIdle, "c1"))
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateIdle) == 1 && exchanges(resp) == 0 }, 3*time.Second, time.Millisecond)

	// Idle of an unknown request is confirmed too.
	bus.inject(url, "", rawRequest(t, 1, 1, 9, ua.ActionStateIdle, "c9"))
	require.Eventually(t, func() bool { return countResponses(url, 9, ua.ActionStateIdle) == 1 }, 3*time.Second, time.Millisecond)

	// Other CorrelationData is another request.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c2", 1, 1))
	require.Eventually(t, func() bool { return calls.Load() == 2 }, 3*time.Second, time.Millisecond)

	// Unknown targets, writers and other Responders get no response.
	cid := mustID(t, resp, KindConnection, Root, "Responder")
	before := len(responses(url))
	bus.inject(url, "", rawRequest(t, 1, 5, 2, ua.ActionStateExecuting, "c3"))
	bus.inject(url, "", rawRequest(t, 3, 1, 3, ua.ActionStateExecuting, "c3"))
	require.Eventually(t, func() bool { return actCounters(resp, cid).ActionRequestsRejected >= 1 }, 3*time.Second, time.Millisecond)
	for _, r := range responses(url)[before:] {
		require.NotEqual(t, uint16(2), r.reqID)
		require.NotEqual(t, uint16(3), r.reqID)
	}

	// Garbage is counted as a decode error.
	b := rawRequest(t, 1, 1, 4, ua.ActionStateExecuting, "c4")
	bus.inject(url, "", b[:len(b)-3])
	require.Eventually(t, func() bool { return actCounters(resp, cid).DecodeErrors >= 1 }, 3*time.Second, time.Millisecond)
}

func TestActionResponderExpiry(t *testing.T) {
	url := memURL(t)
	resp := startReal(t, responderConfig(url, 10*time.Millisecond, ua.MessageSecurityModeNone),
		WithActionHandler("Calc", 1, addHandler), WithActionOptions(ActionOptions{MaxTimeout: 50 * time.Millisecond}))
	waitRunning(t, resp, "Responder")
	waitResponder(t, resp)
	// The TimeoutHint (5 s) is capped at MaxTimeout: an unacknowledged Done
	// is dropped then.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c1", 2, 3))
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateDone) >= 1 }, 3*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return exchanges(resp) == 0 }, 3*time.Second, time.Millisecond)
}

func TestActionResponderLimits(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		url := memURL(t)
		resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone),
			WithActionHandler("Calc", 1, addHandler), WithActionOptions(ActionOptions{Rate: 0.001, Burst: 2}))
		waitRunning(t, resp, "Responder")
		waitResponder(t, resp)
		for i := uint16(1); i <= 5; i++ {
			bus.inject(url, "", rawRequest(t, 1, 1, i, ua.ActionStateExecuting, "c", 1, 2))
		}
		cid := mustID(t, resp, KindConnection, Root, "Responder")
		require.Eventually(t, func() bool { return actCounters(resp, cid).ActionRequestsRejected == 3 }, 3*time.Second, time.Millisecond)
		require.Eventually(t, func() bool {
			return countResponses(url, 1, ua.ActionStateDone) >= 1 && countResponses(url, 2, ua.ActionStateDone) >= 1
		}, 3*time.Second, time.Millisecond)
		for i := uint16(3); i <= 5; i++ {
			require.Zero(t, countResponses(url, i, ua.ActionStateDone))
		}
	})
	t.Run("concurrency", func(t *testing.T) {
		url := memURL(t)
		release := make(chan struct{})
		h := func(ctx context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			<-release
			return addHandler(ctx, in)
		}
		resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone),
			WithActionHandler("Calc", 1, h), WithActionOptions(ActionOptions{MaxConcurrent: 1}))
		t.Cleanup(func() { close(release) })
		waitRunning(t, resp, "Responder")
		waitResponder(t, resp)
		bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c", 1, 2))
		require.Eventually(t, func() bool { return exchanges(resp) == 1 }, 3*time.Second, time.Millisecond)
		bus.inject(url, "", rawRequest(t, 1, 1, 2, ua.ActionStateExecuting, "c", 1, 2))
		require.Eventually(t, func() bool {
			for _, r := range responses(url) {
				if r.reqID == 2 && r.state == ua.ActionStateDone && r.status == ua.StatusBadTooManyOperations {
					return true
				}
			}
			return false
		}, 3*time.Second, time.Millisecond)
	})
}

func TestActionSecured(t *testing.T) {
	url := memURL(t)
	ks := regressKeys(t, "sg")
	resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeSignAndEncrypt),
		WithActionHandler("Calc", 1, addHandler), WithKeySource("sg", regressSource(t, ks, "sg")))
	req := startReal(t, requestorConfig(url), WithKeySource("sg", regressSource(t, ks, "sg")))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	tg := calcTarget()
	tg.SecurityMode, tg.SecurityGroupID = ua.MessageSecurityModeSignAndEncrypt, "sg"
	res, err := req.CallAction(context.Background(), tg, int32s(20, 22))
	require.NoError(t, err)
	require.Equal(t, int32(42), res.Outputs[0].Value())
	for _, s := range bus.sentTo(url) {
		if uadp.PeekAction(s.Payload) {
			// Secured: not readable without the keys.
			_, err := uadp.Decode(s.Payload, nil)
			require.Error(t, err)
		}
	}

	// An unsecured request is not answered, nor one signed by other keys.
	tg.SecurityMode, tg.SecurityGroupID = ua.MessageSecurityModeNone, ""
	tg.Timeout = 100 * time.Millisecond
	_, err = req.CallAction(context.Background(), tg, int32s(1, 2))
	require.ErrorIs(t, err, ErrActionTimeout)
	other := regressKeys(t, "sg")
	req.SetKeySource("sg", regressSource(t, other, "sg"))
	tg.SecurityMode, tg.SecurityGroupID = ua.MessageSecurityModeSign, "sg"
	_, err = req.CallAction(context.Background(), tg, int32s(1, 2))
	require.ErrorIs(t, err, ErrActionTimeout)

	// Without keys the request cannot be sent.
	tg.SecurityGroupID = "none"
	_, err = req.CallAction(context.Background(), tg, int32s(1, 2))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrActionTimeout)
}
