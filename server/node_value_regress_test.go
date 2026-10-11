// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression tests for defects found by the chaos suite in chaos/datachange.

// TestNodeValue_ConcurrentWithSetAttribute verifies that the value of a node
// can be read through Node.Value while it is written. Node.Value read the
// value function without the node's lock; the DataType attribute of a
// variable is derived through it, which every CreateMonitoredItems and
// ModifyMonitoredItems with a deadband filter reads. Run with -race.
func TestNodeValue_ConcurrentWithSetAttribute(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	node := ua.NewStringNodeID(ns.ID(), "rw_int32")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if sc := ns.SetAttribute(node, ua.AttributeIDValue, DataValueFromValue(int32(i))); sc != ua.StatusOK {
				t.Errorf("SetAttribute: %v", sc)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if !srv.MonitoredItemService.hasNumericDataType(node) || ns.Node(node).Value() == nil {
				t.Errorf("value or data type of the node not available")
				return
			}
		}
	}()
	wg.Wait()
}

// TestWrite_IndexRangeIntoUncertainValue verifies that a range can be written
// into an array whose current value has Uncertain quality. Only a Good value
// was accepted; anything else answered BadIndexRangeInvalid, as if the range
// were malformed.
func TestWrite_IndexRangeIntoUncertainValue(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	arr := ns.AddNewVariableStringNode("uncertain_array", []int32{1, 2, 3})
	obj.AddRef(arr, id.HasComponent, true)
	nid := arr.ID()
	svc := &AttributeService{srv: srv}

	write := func() ua.StatusCode {
		resp, err := svc.Write(context.Background(), nil, &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nid, AttributeID: ua.AttributeIDValue, IndexRange: "1:1",
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{99})},
			}},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.WriteResponse).Results[0]
	}
	set := func(status ua.StatusCode) {
		require.Equal(t, ua.StatusOK, ns.SetAttribute(nid, ua.AttributeIDValue, &ua.DataValue{
			EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
			Value:        ua.MustVariant([]int32{1, 2, 3}),
			Status:       status,
		}))
	}

	set(ua.StatusUncertainLastUsableValue)
	require.Equal(t, ua.StatusOK, write())
	require.Equal(t, []int32{1, 99, 3}, ns.Attribute(nid, ua.AttributeIDValue).Value.Value())

	set(ua.StatusBadSensorFailure)
	require.Equal(t, ua.StatusBadIndexRangeInvalid, write(), "a Bad value cannot be merged into")
}
