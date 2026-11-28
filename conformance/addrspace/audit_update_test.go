// SPDX-License-Identifier: MIT

package addrspace

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The audit events of the Write (Part 4 §6.5.8) and NodeManagement (Part 4
// §6.5.7) Service Sets over the wire, with auditing on.

// watchAudit subscribes c to the events of type typ of the Server object,
// selecting fields of that type, and returns their fields.
func watchAudit(t *testing.T, c *opcua.Client, typ uint32, fields ...string) <-chan []*ua.Variant {
	t.Helper()
	b := ua.NewEventFilter().TypeDefinition(ua.NewNumericNodeID(0, typ)).Select(fields...)
	b.Where(element(ua.FilterOperatorOfType, lit(ua.NewNumericNodeID(0, typ))))
	sub, ch, err := c.NewSubscription().Interval(fastInterval).
		MonitorEvents(b.Build(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	out := make(chan []*ua.Variant, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(done); <-exited })
	go func() {
		defer close(exited)
		for {
			select {
			case msg := <-ch:
				if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
					for _, e := range enl.Events {
						select {
						case out <- e.EventFields:
						case <-done:
							return
						}
					}
				}
			case <-done:
				return
			}
		}
	}()
	return out
}

func nextAudit(t *testing.T, ch <-chan []*ua.Variant) []*ua.Variant {
	t.Helper()
	select {
	case f := <-ch:
		return f
	case <-time.After(waitTimeout):
		t.Fatal("no audit event")
		return nil
	}
}

func TestAudit_Write(t *testing.T) {
	parallel(t)
	c, f, _, _ := setupWith(t, nil, server.WithAuditing(true))
	ctx := context.Background()
	ch := watchAudit(t, c, id.AuditWriteUpdateEventType, "SourceName", "Status", "SourceNode", "AttributeId", "OldValue", "NewValue")

	old, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	writeInt32(t, c, f.Int32, 4711)
	ev := nextAudit(t, ch)
	require.Equal(t, "Attribute/Write", ev[0].Value())
	require.Equal(t, true, ev[1].Value())
	require.Equal(t, f.Int32.String(), ev[2].Value().(*ua.NodeID).String())
	require.Equal(t, uint32(ua.AttributeIDValue), ev[3].Value())
	require.Equal(t, old.Value.Value(), ev[4].Value())
	require.Equal(t, int32(4711), ev[5].Value())

	// A failed Write is audited too.
	st, err := c.WriteNodeValue(ctx, f.ReadOnly, int32(1))
	require.NoError(t, err)
	require.True(t, st&ua.StatusBad != 0)
	ev = nextAudit(t, ch)
	require.Equal(t, false, ev[1].Value())
	require.Equal(t, f.ReadOnly.String(), ev[2].Value().(*ua.NodeID).String())
}

func TestAudit_WriteOff(t *testing.T) {
	parallel(t)
	c, f, _, _ := setupWith(t, nil, server.WithAuditing(true), server.WithChangeAuditing(false))
	ch := watchAudit(t, c, id.AuditWriteUpdateEventType, "SourceName")
	writeInt32(t, c, f.Int32, 1)
	select {
	case ev := <-ch:
		t.Fatalf("audit event with change auditing off: %v", ev)
	case <-time.After(10 * fastInterval):
	}
}

func TestAudit_NodeManagement(t *testing.T) {
	parallel(t)
	c, f, _, _ := setupWith(t, nil, server.WithAuditing(true), server.EnableNodeManagement())
	ctx := context.Background()
	adds := watchAudit(t, c, id.AuditAddNodesEventType, "SourceName", "Status", "SourceNode", "NodesToAdd")
	deletes := watchAudit(t, c, id.AuditDeleteNodesEventType, "SourceName", "Status", "NodesToDelete")

	newID := ua.NewStringNodeID(f.NSIndex, "AuditedVar")
	item := &ua.AddNodesItem{
		ParentNodeID:       ua.NewExpandedNodeID(f.MethodObject, "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
		RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: "AuditedVar"},
		NodeClass:          ua.NodeClassVariable,
		TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
	}
	resp, err := c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{item}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	ev := nextAudit(t, adds)
	require.Equal(t, "NodeManagement/AddNodes", ev[0].Value())
	require.Equal(t, true, ev[1].Value())
	require.Equal(t, uint32(id.Server), ev[2].Value().(*ua.NodeID).IntID())
	added := ev[3].Value().([]*ua.ExtensionObject)
	require.Len(t, added, 1)
	require.Equal(t, "AuditedVar", added[0].Value.(*ua.AddNodesItem).BrowseName.Name)

	// The same node again fails.
	resp, err = c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{item}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDExists, resp.Results[0].StatusCode)
	require.Equal(t, false, nextAudit(t, adds)[1].Value())

	del, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{{NodeID: newID, DeleteTargetReferences: true}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, del.Results[0])
	ev = nextAudit(t, deletes)
	require.Equal(t, "NodeManagement/DeleteNodes", ev[0].Value())
	require.Equal(t, true, ev[1].Value())
	require.Equal(t, newID.String(), ev[2].Value().([]*ua.ExtensionObject)[0].Value.(*ua.DeleteNodesItem).NodeID.String())
}
