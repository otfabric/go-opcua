// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// rotatingRing returns a KeyRing of three Aes128-CTR keys (tokens 1, 2,
// 3) whose current key changes every lifetime of the clock *now, keeping
// one past key.
func rotatingRing(t *testing.T, now *atomic.Int64, lifetime time.Duration) *security.KeyRing {
	t.Helper()
	p := security.Aes128CTR()
	r := security.NewKeyRing("sg", p, security.WithMaxPastKeys(1),
		security.WithClock(func() time.Time { return time.Unix(0, now.Load()) }))
	var keys [][]byte
	for range 3 {
		k, err := security.GenerateKey(p, nil)
		require.NoError(t, err)
		keys = append(keys, k)
	}
	require.NoError(t, r.SetKeys(p.URI(), 1, keys, lifetime, lifetime))
	return r
}

func TestNonceCounterResetsOnTokenChange(t *testing.T) {
	t.Parallel()
	var n nonceCounter
	require.Equal(t, uint32(1), n.next(7))
	require.Equal(t, uint32(2), n.next(7))
	require.Equal(t, uint32(3), n.next(7))
	require.Equal(t, uint32(1), n.next(8), "a new SecurityTokenId starts the sequence at 1")
	require.Equal(t, uint32(2), n.next(8))

	// Through the encoder: the MessageNonce of a writer group's messages
	// counts per token of the keys they are secured with.
	var clock atomic.Int64
	clock.Store(time.Unix(1000, 0).UnixNano())
	ring := rotatingRing(t, &clock, time.Minute)
	g := &writerGroup{}
	opts := &uadp.EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: ring, NextNonceSequenceForToken: g.nextNonce}
	nm := msg(message.DataSetMessageKeyFrame, 1, 1)
	nonceOf := func() (uint32, uint32) {
		b, err := uadp.Encode(nm, opts)
		require.NoError(t, err)
		out, err := uadp.Decode(b, &uadp.DecodeOptions{Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
			return ua.MessageSecurityModeSign, ring, nil
		}})
		require.NoError(t, err)
		return out.Security.SecurityTokenID, binary.LittleEndian.Uint32(out.Security.MessageNonce[4:])
	}
	for i := uint32(1); i <= 3; i++ {
		tok, seq := nonceOf()
		require.Equal(t, uint32(1), tok)
		require.Equal(t, i, seq)
	}
	clock.Add(int64(time.Minute))
	tok, seq := nonceOf()
	require.Equal(t, uint32(2), tok)
	require.Equal(t, uint32(1), seq)

	// Chunks take one number each.
	nm.Messages[0].Fields = []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(make([]byte, 300))}}}
	chunks, err := uadp.EncodeChunks(nm, opts, 200)
	require.NoError(t, err)
	require.Greater(t, len(chunks), 1)
	_, seq = nonceOf()
	require.Equal(t, uint32(2+len(chunks)), seq)
}

func TestNonceTrackerSequenceRules(t *testing.T) {
	t.Parallel()
	var clock atomic.Int64
	clock.Store(time.Unix(1000, 0).UnixNano())
	ring := rotatingRing(t, &clock, time.Minute)
	tr := newNonceTracker()
	now := time.Unix(1000, 0)
	k := nonceKey{kind: nonceDataSet, sender: "7", token: 1, group: "sg"}

	require.True(t, tr.accept(k, ring, 10, 0, now))
	require.False(t, tr.accept(k, ring, 10, 0, now), "the same number again")
	require.False(t, tr.accept(k, ring, 9, 0, now), "an older number")
	require.True(t, tr.accept(k, ring, 10+nonceWindow-1, 0, now))
	require.False(t, tr.accept(k, ring, 10, 0, now))
	require.False(t, tr.accept(k, ring, 10+nonceWindow-1, 0, now), "the same number again")
	// A number a quarter of the space or more away: the sender's
	// numbers are not a sequence, its messages are no longer checked.
	kr := k
	kr.sender = "random"
	require.True(t, tr.accept(kr, ring, 10, 0, now))
	require.True(t, tr.accept(kr, ring, 10+nonceWindow+5, 0, now))
	require.True(t, tr.accept(kr, ring, 3, 0, now))
	require.True(t, tr.accept(kr, ring, 3, 0, now))
	// Wraparound.
	k2 := k
	k2.sender = "8"
	require.True(t, tr.accept(k2, ring, 0xffffffff, 0, now))
	require.True(t, tr.accept(k2, ring, 1, 0, now))
	require.False(t, tr.accept(k2, ring, 0xffffffff, 0, now))
	// Other senders, kinds and tokens have sequences of their own.
	k3 := k
	k3.kind = nonceActionRequest
	require.True(t, tr.accept(k3, ring, 1, 0, now))
	k4 := k
	k4.token = 2
	require.True(t, tr.accept(k4, ring, 1, 0, now))

	// A record with an expiry is discarded after it without a message it
	// took: a lower number is taken again (Part 14 §7.2.3).
	k5 := k
	k5.sender = "9"
	require.True(t, tr.accept(k5, ring, 100, time.Second, now))
	require.False(t, tr.accept(k5, ring, 1, time.Second, now.Add(900*time.Millisecond)))
	require.True(t, tr.accept(k5, ring, 1, time.Second, now.Add(1100*time.Millisecond)), "a discarded message does not refresh the record")

	// The records of a token that left the KeyRing are dropped.
	before := tr.len()
	clock.Add(int64(2 * time.Minute)) // token 3 is current, 2 past, 1 gone
	require.True(t, tr.accept(nonceKey{kind: nonceDataSet, sender: "x", token: 3, group: "sg"}, ring, 1, 0, now.Add(time.Hour)))
	require.Less(t, tr.len(), before)
	for key := range tr.records {
		require.NotEqual(t, uint32(1), key.token)
	}

	// The records are bounded.
	tr2 := newNonceTracker()
	for i := range maxNonceRecords + 10 {
		require.True(t, tr2.accept(nonceKey{kind: nonceDataSet, corr: string(rune(i)), token: 3}, ring, 1, 0, now.Add(time.Duration(i))))
	}
	require.Equal(t, maxNonceRecords, tr2.len())

	// A nil tracker, and messages of other policies, are not checked.
	var nilTracker *nonceTracker
	require.True(t, nilTracker.accept(k, ring, 1, 0, now))
	_, ok := nonceSequence(&message.SecurityHeader{Signed: true, MessageNonce: make([]byte, 8)}, nil)
	require.False(t, ok)
	_, ok = nonceSequence(&message.SecurityHeader{Signed: true, MessageNonce: make([]byte, 4)}, ring)
	require.False(t, ok)
	seq, ok := nonceSequence(&message.SecurityHeader{Signed: true, MessageNonce: []byte{1, 2, 3, 4, 5, 0, 0, 0}}, ring)
	require.True(t, ok)
	require.Equal(t, uint32(5), seq)
}

// signedSender encodes signed DataSetMessages of publisher 8, writer group
// 1, writer 1, with consecutive MessageNonce sequence numbers.
type signedSender struct {
	t     *testing.T
	keys  security.KeySource
	nonce uint32
}

func (s *signedSender) encode(seq uint16, v int32) []byte {
	s.nonce++
	b, err := uadp.Encode(&message.NetworkMessage{
		Type: message.NetworkMessageDataSet, UADPMask: DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 8),
		GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: seq},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
			UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: uint32(seq),
			Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}},
		}},
	}, &uadp.EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: s.keys, NonceSequence: s.nonce})
	require.NoError(s.t, err)
	return b
}

func signedSubscriber(t *testing.T, url string, timeout float64, opts ...Option) (*PubSub, ComponentID, ComponentID, *recorder) {
	t.Helper()
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	r := DataSetReader("ra", uint16(8), 1, 1, md)
	r.MessageReceiveTimeout = timeout
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		Secure(ReaderGroup("rg", r), ua.MessageSecurityModeSign, "sg"))),
		append([]Option{WithDataSetHandler(rec.handler)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	cid := mustID(t, sub, KindConnection, Root, "sub")
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, cid, "rg"), "ra")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)
	return sub, cid, rid, rec
}

func nonceDiscards(t *testing.T, p *PubSub, id ComponentID) uint64 {
	t.Helper()
	st, err := p.Status(id)
	require.NoError(t, err)
	return st.Counters.NonceSequenceDiscards
}

// TestRegressionSignedReplayRejected: a copy of a signed message whose
// MessageNonce sequence number the reader processed before is ignored
// (Part 14 §7.2.4.4.3.2, §7.2.3), whatever its DataSetMessage sequence
// number: while the reader is Operational and after it timed out.
func TestRegressionSignedReplayRejected(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ks := regressKeys(t, "sg")
	src := regressSource(t, ks, "sg")
	sub, cid, rid, rec := signedSubscriber(t, url, 100, WithKeySource("sg", src))
	s := &signedSender{t: t, keys: src}

	first := s.encode(1, 1)
	bus.inject(url, "", first)
	bus.inject(url, "", s.encode(10001, 2))
	second := s.encode(20001, 3)
	bus.inject(url, "", second)
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 3 }, 3*time.Second, time.Millisecond)

	// Far behind in the DataSetMessage sequence numbers, and the last
	// message again.
	bus.inject(url, "", first)
	bus.inject(url, "", second)
	require.Eventually(t, func() bool { return nonceDiscards(t, sub, cid) == 2 }, 3*time.Second, time.Millisecond)

	// After the MessageReceiveTimeout.
	waitState(t, sub, rid, ua.PubSubStateError)
	bus.inject(url, "", first)
	require.Eventually(t, func() bool { return nonceDiscards(t, sub, cid) == 3 }, 3*time.Second, time.Millisecond)
	require.Len(t, rec.dataSets(), 3)

	// The publisher goes on.
	bus.inject(url, "", s.encode(20002, 4))
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 4 }, 3*time.Second, time.Millisecond)
	require.Equal(t, []int32{4}, int32Values(rec.dataSets()[3]))
}

// TestNonceSequenceRestartedPublisher: a publisher restarted on the same
// SecurityTokenId counts its MessageNonces from 1 again. A reader ignores
// it until the sequence record expires, two MessageReceiveTimeouts without
// a message it took (Part 14 §7.2.3); with WithNonceSequencePerToken until
// the publisher uses the next token.
func TestNonceSequenceRestartedPublisher(t *testing.T) {
	t.Parallel()
	for _, perToken := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "per-token"}[perToken], func(t *testing.T) {
			t.Parallel()
			url := memURL(t)
			ks := regressKeys(t, "sg")
			src := regressSource(t, ks, "sg")
			sub, cid, _, rec := signedSubscriber(t, url, 50, WithKeySource("sg", src), WithNonceSequencePerToken(perToken))
			s := &signedSender{t: t, keys: src}
			// Far more messages than the restarted publisher sends in
			// the test.
			for i := range uint16(1000) {
				bus.inject(url, "", s.encode(i+1, 1))
			}
			require.Eventually(t, func() bool { return len(rec.dataSets()) == 1000 }, 5*time.Second, time.Millisecond)

			restarted := &signedSender{t: t, keys: src}
			deadline := time.Now().Add(time.Second)
			for seq := uint16(1); time.Now().Before(deadline); seq++ {
				bus.inject(url, "", restarted.encode(seq, 2))
				time.Sleep(5 * time.Millisecond)
				if len(rec.dataSets()) > 1000 {
					break
				}
			}
			require.NotZero(t, nonceDiscards(t, sub, cid))
			if perToken {
				require.Len(t, rec.dataSets(), 1000, "a restarted publisher on the same token was taken")
				return
			}
			require.Greater(t, len(rec.dataSets()), 1000, "the restarted publisher was not taken after two MessageReceiveTimeouts")
			require.Equal(t, []int32{2}, int32Values(rec.dataSets()[1000]))
		})
	}
}

// TestRegressionSignedActionReplayAfterTombstone: a Responder ignores a
// copy of a signed ActionRequest it executed, also after it forgot the
// ended exchange.
func TestRegressionSignedActionReplayAfterTombstone(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ks := regressKeys(t, "sg")
	var runs atomic.Int32
	h := func(ctx context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		runs.Add(1)
		return addHandler(ctx, in)
	}
	resp := startReal(t, responderConfig(url, 50*time.Millisecond, ua.MessageSecurityModeSign),
		WithActionHandler("Calc", 1, h), WithKeySource("sg", regressSource(t, ks, "sg")))
	req := startReal(t, requestorConfig(url), WithKeySource("sg", regressSource(t, ks, "sg")))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	tg := calcTarget()
	tg.SecurityMode, tg.SecurityGroupID = ua.MessageSecurityModeSign, "sg"
	call := func(a, b int32) {
		res, err := req.CallAction(context.Background(), tg, int32s(a, b))
		require.NoError(t, err)
		require.Equal(t, a+b, res.Outputs[0].Value())
	}
	call(2, 3)
	require.Equal(t, int32(1), runs.Load())

	src := regressSource(t, ks, "sg")
	dopts := &uadp.DecodeOptions{Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
		return ua.MessageSecurityModeSign, src, nil
	}}
	var captured []byte
	for _, s := range bus.sentTo(url) {
		nm, err := uadp.Decode(s.Payload, dopts)
		if err == nil && nm.Action != nil && nm.Action.Type == message.ActionRequest && nm.Messages[0].ActionState == ua.ActionStateExecuting {
			captured = s.Payload
			break
		}
	}
	require.NotNil(t, captured)

	// The Responder forgets the ended exchange (actionLinger).
	c := resp.conns[0]
	require.Eventually(t, func() bool {
		resp.lock()
		defer resp.unlock()
		if len(c.act.exchanges) > 0 {
			return false
		}
		for k, ex := range c.act.tombs {
			ex.stop()
			delete(c.act.tombs, k)
		}
		return true
	}, 3*time.Second, time.Millisecond)

	cid := mustID(t, resp, KindConnection, Root, "Responder")
	st, err := resp.Status(cid)
	require.NoError(t, err)
	rejected := st.Counters.ActionRequestsRejected
	bus.inject(url, "", captured)
	require.Eventually(t, func() bool { return nonceDiscards(t, resp, cid) > 0 }, 3*time.Second, time.Millisecond)
	st, err = resp.Status(cid)
	require.NoError(t, err)
	require.Greater(t, st.Counters.ActionRequestsRejected, rejected)
	require.Equal(t, int32(1), runs.Load(), "a copy of an executed request was executed again")

	// New calls of the Requestor still run, also concurrent ones: the
	// requests share the Requestor's nonce counter.
	var wg sync.WaitGroup
	for i := range int32(4) {
		wg.Go(func() { call(i, 10) })
	}
	wg.Wait()
	require.Equal(t, int32(5), runs.Load())
}
