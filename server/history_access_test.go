// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// historyDenier refuses reads and writes of one node.
type historyDenier struct {
	DefaultAccessController
	node *ua.NodeID
}

func (d historyDenier) CheckRead(_ context.Context, _ *Session, n *ua.NodeID) ua.StatusCode {
	if n.Equal(d.node) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func (d historyDenier) CheckWrite(_ context.Context, _ *Session, n *ua.NodeID) ua.StatusCode {
	if n.Equal(d.node) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func dataHistoryServer(t *testing.T) (*Server, *AttributeService, *Historian, *Node) {
	t.Helper()
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:history")
	v := ns.AddNewVariableStringNode("Tank", int32(1))
	h := NewHistorian()
	h.EnableNode(v.ID(), 0)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		h.RecordValue(v.ID(), &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(int32(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	s.SetHistorian(h)
	return s, &AttributeService{srv: s}, h, v
}

func historyReadRaw(t *testing.T, svc *AttributeService, nodes ...*ua.NodeID) []*ua.HistoryReadResult {
	t.Helper()
	ids := make([]*ua.HistoryReadValueID, len(nodes))
	for i, n := range nodes {
		ids[i] = &ua.HistoryReadValueID{NodeID: n}
	}
	resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
		RequestHeader: reqHeader(),
		HistoryReadDetails: ua.NewExtensionObject(&ua.ReadRawModifiedDetails{
			StartTime: time.Now().Add(-2 * time.Hour), EndTime: time.Now(),
		}),
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        ids,
	}, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryReadResponse).Results
}

func TestHistoryReadUpdate_DeniedByAccessController(t *testing.T) {
	s, svc, _, v := dataHistoryServer(t)
	require.Equal(t, ua.StatusOK, historyReadRaw(t, svc, v.ID())[0].StatusCode)

	s.cfg.accessController = historyDenier{node: v.ID()}
	require.Equal(t, ua.StatusBadUserAccessDenied, historyReadRaw(t, svc, v.ID())[0].StatusCode)
	for _, d := range []any{
		&ua.UpdateDataDetails{NodeID: v.ID(), PerformInsertReplace: ua.PerformUpdateTypeInsert,
			UpdateValues: []*ua.DataValue{{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(int32(-1)), SourceTimestamp: time.Now()}}},
		&ua.DeleteRawModifiedDetails{NodeID: v.ID(), StartTime: time.Now().Add(-2 * time.Hour), EndTime: time.Now()},
		ua.DeleteAtTimeDetails{NodeID: v.ID(), ReqTimes: []time.Time{time.Now()}},
	} {
		r := historyUpdate(t, svc, d)
		require.Equal(t, ua.StatusBadUserAccessDenied, r[0].StatusCode, "%T", d)
	}
	// The history is unchanged.
	s.cfg.accessController = DefaultAccessController{}
	res := historyReadRaw(t, svc, v.ID())
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	require.Len(t, res[0].HistoryData.Value.(*ua.HistoryData).DataValues, 3)
}

func TestHistoryRead_AccessLevelHistoryBit(t *testing.T) {
	_, svc, _, v := dataHistoryServer(t)
	v.mu.Lock()
	v.attr[ua.AttributeIDAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))
	v.mu.Unlock()
	require.Equal(t, ua.StatusBadNotReadable, historyReadRaw(t, svc, v.ID())[0].StatusCode)
	r := historyUpdate(t, svc, &ua.DeleteRawModifiedDetails{NodeID: v.ID(), EndTime: time.Now()})
	require.Equal(t, ua.StatusBadNotWritable, r[0].StatusCode)

	v.mu.Lock()
	v.attr[ua.AttributeIDAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeHistoryRead | ua.AccessLevelTypeHistoryWrite))
	v.attr[ua.AttributeIDUserAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))
	v.mu.Unlock()
	require.Equal(t, ua.StatusBadUserAccessDenied, historyReadRaw(t, svc, v.ID())[0].StatusCode)
	r = historyUpdate(t, svc, ua.UpdateDataDetails{NodeID: v.ID(), PerformInsertReplace: ua.PerformUpdateTypeInsert})
	require.Equal(t, ua.StatusBadUserAccessDenied, r[0].StatusCode)

	v.mu.Lock()
	v.attr[ua.AttributeIDUserAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeHistoryRead))
	v.mu.Unlock()
	require.Equal(t, ua.StatusOK, historyReadRaw(t, svc, v.ID())[0].StatusCode)
}

func TestHistoryRead_DataNodeChecks(t *testing.T) {
	_, svc, _, v := dataHistoryServer(t)
	res := historyReadRaw(t, svc, nil, ua.NewStringNodeID(9, "not-in-address-space"))
	require.Equal(t, ua.StatusBadNodeIDInvalid, res[0].StatusCode)
	// A node of the provider only is left to the provider.
	require.NotEqual(t, ua.StatusBadUserAccessDenied, res[1].StatusCode)

	// AccessRestrictions apply to data history as to Read.
	v.mu.Lock()
	v.attr[ua.AttributeIDAccessRestrictions] = DataValueFromValue(uint16(ua.AccessRestrictionTypeEncryptionRequired))
	v.mu.Unlock()
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, historyReadRaw(t, svc, v.ID())[0].StatusCode)
	r := historyUpdate(t, svc, &ua.DeleteAtTimeDetails{NodeID: v.ID()})
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, r[0].StatusCode)
}
