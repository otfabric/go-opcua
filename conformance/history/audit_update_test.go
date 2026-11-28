// SPDX-License-Identifier: MIT

package history

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The audit events of HistoryUpdate (Part 11 §5.8, Part 5 §6.4.26) over
// the wire, with auditing on.

// watchHistoryAudit subscribes c to the events of type typ of the Server
// object, selecting fields of that type, and returns their fields.
func watchHistoryAudit(t *testing.T, c *opcua.Client, typ uint32, fields ...string) <-chan []*ua.Variant {
	t.Helper()
	b := ua.NewEventFilter().TypeDefinition(ua.NewNumericNodeID(0, typ)).Select(fields...)
	b.Where(conformkit.Element(ua.FilterOperatorOfType, conformkit.Lit(ua.NewNumericNodeID(0, typ))))
	sub, ch, err := c.NewSubscription().Interval(fastInterval).
		MonitorEvents(b.Build(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	out := make(chan []*ua.Variant, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	cleanup.Register(t, func() { close(done); <-exited })
	go func() {
		defer close(exited)
		for {
			select {
			case msg := <-ch:
				enl, ok := msg.Value.(*ua.EventNotificationList)
				if !ok {
					continue
				}
				for _, e := range enl.Events {
					select {
					case out <- e.EventFields:
					case <-done:
						return
					}
				}
			case <-done:
				return
			}
		}
	}()
	return out
}

func nextHistoryAudit(t *testing.T, ch <-chan []*ua.Variant) []*ua.Variant {
	t.Helper()
	select {
	case f := <-ch:
		return f
	case <-time.After(waitTimeout):
		t.Fatal("no audit event")
		return nil
	}
}

func TestAudit_HistoryUpdate(t *testing.T) {
	parallel(t)
	c, f, _, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h := server.NewHistorian()
		h.EnableNode(f.HistoryVar, 0)
		for i := range 4 {
			h.RecordValue(f.HistoryVar, histSample(i, float64(i)))
		}
		srv.SetHistorian(h)
		require.NoError(t, srv.EnableAnnotations(f.HistoryVar))
	}, server.WithAuditing(true))
	ctx := context.Background()
	values := watchHistoryAudit(t, c, id.AuditHistoryValueUpdateEventType,
		"SourceName", "Status", "UpdatedNode", "PerformInsertReplace", "NewValues", "OldValues", "ParameterDataTypeId")
	deletes := watchHistoryAudit(t, c, id.AuditHistoryAtTimeDeleteEventType, "SourceName", "Status", "ReqTimes", "OldValues")
	annotations := watchHistoryAudit(t, c, id.AuditHistoryAnnotationUpdateEventType, "Status", "PerformInsertReplace", "NewValues", "OldValues")

	// A replace carries the values before and after.
	resp, err := c.HistoryUpdateData(ctx, &ua.UpdateDataDetails{NodeID: f.HistoryVar, PerformInsertReplace: ua.PerformUpdateTypeReplace,
		UpdateValues: []*ua.DataValue{histSample(1, 10)}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].OperationResults[0])
	ev := nextHistoryAudit(t, values)
	require.Equal(t, "Attribute/HistoryUpdate", ev[0].Value())
	require.Equal(t, true, ev[1].Value())
	require.Equal(t, f.HistoryVar.String(), ev[2].Value().(*ua.NodeID).String())
	require.Equal(t, int32(ua.PerformUpdateTypeReplace), ev[3].Value())
	require.Equal(t, 10.0, ev[4].Value().([]*ua.DataValue)[0].Value.Value())
	require.Equal(t, 1.0, ev[5].Value().([]*ua.DataValue)[0].Value.Value())
	require.Equal(t, uint32(id.UpdateDataDetails), ev[6].Value().(*ua.NodeID).IntID())

	// A delete at time carries the values deleted.
	dresp, err := c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{NodeID: f.HistoryVar, ReqTimes: []time.Time{histAt(2)}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dresp.Results[0].OperationResults[0])
	ev = nextHistoryAudit(t, deletes)
	require.Equal(t, true, ev[1].Value())
	require.Equal(t, []time.Time{histAt(2)}, ev[2].Value())
	require.Equal(t, 2.0, ev[3].Value().([]*ua.DataValue)[0].Value.Value())

	// Annotations: an insert, then a replace with the Annotation replaced.
	_, err = c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeInsert, note(1, "first"))
	require.NoError(t, err)
	ev = nextHistoryAudit(t, annotations)
	require.Equal(t, true, ev[0].Value())
	require.Equal(t, int32(ua.PerformUpdateTypeInsert), ev[1].Value())
	require.Equal(t, "first", ev[2].Value().([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)
	_, err = c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeReplace, note(1, "second"))
	require.NoError(t, err)
	ev = nextHistoryAudit(t, annotations)
	require.Equal(t, "second", ev[2].Value().([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)
	require.Equal(t, "first", ev[3].Value().([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)

	// A failed update is audited too.
	resp, err = c.HistoryUpdateData(ctx, &ua.UpdateDataDetails{NodeID: f.NoHistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert,
		UpdateValues: []*ua.DataValue{histSample(1, 1)}})
	require.NoError(t, err)
	require.True(t, resp.Results[0].StatusCode&ua.StatusBad != 0)
	ev = nextHistoryAudit(t, values)
	require.Equal(t, false, ev[1].Value())
	require.Equal(t, f.NoHistoryVar.String(), ev[2].Value().(*ua.NodeID).String())
}
