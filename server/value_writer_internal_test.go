// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestRunValueWriters_SessionOrder: a session's deferred Writes reach their
// writers in the order they were handed over, the next one only after the
// previous returned; another session's Write does not wait for them.
func TestRunValueWriters_SessionOrder(t *testing.T) {
	s := newTestServer()
	a, b := &session{}, &session{}
	release := make(chan struct{})
	order := make(chan string, 3)
	job := func(name string, wait bool) []valueWriteJob {
		return []valueWriteJob{{index: 0, write: &ValueWrite{}, writer: func(context.Context, *ValueWrite) ua.StatusCode {
			if wait {
				<-release
			}
			order <- name
			return ua.StatusOK
		}}}
	}
	answered := make(chan []ua.StatusCode, 3)
	answer := func(r []ua.StatusCode) { answered <- r }
	ctx := context.Background()

	s.runValueWriters(ctx, a, nil, job("a1", true), make([]ua.StatusCode, 1), answer)
	s.runValueWriters(ctx, a, nil, job("a2", false), make([]ua.StatusCode, 1), answer)
	s.runValueWriters(ctx, b, nil, job("b1", false), make([]ua.StatusCode, 1), answer)
	require.Equal(t, "b1", <-order, "another session does not wait")
	select {
	case got := <-order:
		t.Fatalf("%s ran before a1 returned", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	require.Equal(t, "a1", <-order)
	require.Equal(t, "a2", <-order)
	for range 3 {
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, <-answered)
	}
	s.writers.Wait()
}

// TestRunValueWriters_TimeoutHint: a Write whose TimeoutHint elapsed while it
// waited for the session's earlier Write fails with Bad_Timeout and its
// writer is not called.
func TestRunValueWriters_TimeoutHint(t *testing.T) {
	s := newTestServer()
	sess := &session{}
	release := make(chan struct{})
	defer close(release)
	slow := []valueWriteJob{{write: &ValueWrite{}, writer: func(context.Context, *ValueWrite) ua.StatusCode { <-release; return ua.StatusOK }}}
	called := false
	late := []valueWriteJob{{write: &ValueWrite{}, writer: func(context.Context, *ValueWrite) ua.StatusCode { called = true; return ua.StatusOK }}}
	answered := make(chan []ua.StatusCode, 1)

	s.runValueWriters(context.Background(), sess, nil, slow, make([]ua.StatusCode, 1), func([]ua.StatusCode) {})
	s.runValueWriters(context.Background(), sess, &ua.RequestHeader{TimeoutHint: 20}, late, make([]ua.StatusCode, 1), func(r []ua.StatusCode) { answered <- r })
	require.Equal(t, []ua.StatusCode{ua.StatusBadTimeout}, <-answered)
	require.False(t, called)
}

// TestWrite_ValueWriterWithoutDispatcher: called directly (no dispatcher to
// answer later), the Write service runs the writer before it returns.
func TestWrite_ValueWriterWithoutDispatcher(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:direct")
	n := NewVariableNode(ua.NewStringNodeID(ns.ID(), "X"), "X", int32(0))
	ns.AddNode(n)
	var got int32
	n.SetValueWriter(func(_ context.Context, w *ValueWrite) ua.StatusCode {
		got = w.Value.Value.Value().(int32)
		return ua.StatusBadOutOfRange
	})
	require.NotNil(t, n.ValueWriter())
	sess := s.sb.NewSession()
	hdr := &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID, Timestamp: time.Now()}
	svc := &AttributeService{srv: s}
	resp, err := svc.Write(context.Background(), nil, &ua.WriteRequest{RequestHeader: hdr, NodesToWrite: []*ua.WriteValue{
		{NodeID: n.ID(), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(9))}},
	}}, 1)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange}, resp.(*ua.WriteResponse).Results)
	require.Equal(t, int32(9), got)
}
