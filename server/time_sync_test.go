// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestTimestampsFromHostClock: the server's time is the clock of the
// operating system (docs/server-guide.md, Time synchronization; the
// ConformanceUnit Time Sync – OS based support of OPC 10000-7): the
// ServerStatus CurrentTime, the ResponseHeader timestamp and the
// SourceTimestamp of a written value are those of time.Now.
func TestTimestampsFromHostClock(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	v := ns.AddNewVariableStringNode("clock", int32(0))
	obj.AddRef(v, id.HasComponent, true)
	svc := &AttributeService{srv: srv}

	before := time.Now()
	wr, err := svc.Write(context.Background(), nil, &ua.WriteRequest{
		RequestHeader: reqHeader(),
		NodesToWrite: []*ua.WriteValue{{NodeID: v.ID(), AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))}}},
	}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, wr.(*ua.WriteResponse).Results[0])
	resp, err := svc.Read(context.Background(), nil, &ua.ReadRequest{
		RequestHeader:      reqHeader(),
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), AttributeID: ua.AttributeIDValue},
			{NodeID: v.ID(), AttributeID: ua.AttributeIDValue},
		},
	}, 2)
	require.NoError(t, err)
	after := time.Now()
	within := func(what string, ts time.Time) {
		t.Helper()
		require.False(t, ts.Before(before) || ts.After(after), "%s %v not within [%v, %v]", what, ts, before, after)
	}
	rr := resp.(*ua.ReadResponse)
	within("ResponseHeader.Timestamp", rr.ResponseHeader.Timestamp)
	within("Write ResponseHeader.Timestamp", wr.Header().Timestamp)
	current, ok := rr.Results[0].Value.Value().(time.Time)
	require.True(t, ok, "%T", rr.Results[0].Value.Value())
	within("CurrentTime", current)
	within("SourceTimestamp of the written value", rr.Results[1].SourceTimestamp)
}
