// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// readAttrs reads the given attributes of one node in a single request.
func readAttrs(t *testing.T, c *opcua.Client, node *ua.NodeID, attrs ...ua.AttributeID) []*ua.DataValue {
	t.Helper()
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, a := range attrs {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: node, AttributeID: a})
	}
	resp, err := c.Read(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Results, len(attrs))
	return resp.Results
}

// TestAttribute_CommonAttributesPerNodeClass reads the attributes shared by all
// node classes on a node of every class, in the fixture namespace and in the
// standard namespace.
func TestAttribute_CommonAttributesPerNodeClass(t *testing.T) {
	c, f, _ := setup(t)

	cases := []struct {
		name       string
		node       *ua.NodeID
		class      ua.NodeClass
		browseName string
	}{
		{"Variable", f.Int32, ua.NodeClassVariable, "Int32"},
		{"Object", f.Motor, ua.NodeClassObject, "Motor"},
		{"Method", f.SquareMethod, ua.NodeClassMethod, "Square"},
		{"VariableType", f.CustomVarType, ua.NodeClassVariableType, "CustomVarType"},
		{"ObjectType", f.CustomEventType, ua.NodeClassObjectType, "CustomEventType"},
		{"StdObject", ua.NewNumericNodeID(0, id.Server), ua.NodeClassObject, "Server"},
		{"StdVariable", ua.NewNumericNodeID(0, id.ServerNamespaceArray), ua.NodeClassVariable, "Namespaces"},
		{"StdStatusState", ua.NewNumericNodeID(0, id.ServerServerStatusState), ua.NodeClassVariable, "State"},
		{"StdManufacturerName", ua.NewNumericNodeID(0, id.ServerServerStatusBuildInfoManufacturerName), ua.NodeClassVariable, "ManufacturerName"},
		{"StdMethod", ua.NewNumericNodeID(0, id.ServerGetMonitoredItems), ua.NodeClassMethod, "GetMonitoredItems"},
		{"StdObjectType", ua.NewNumericNodeID(0, id.BaseEventType), ua.NodeClassObjectType, "BaseEventType"},
		{"StdVariableType", ua.NewNumericNodeID(0, id.BaseDataVariableType), ua.NodeClassVariableType, "BaseDataVariableType"},
		{"StdReferenceType", ua.NewNumericNodeID(0, id.HasComponent), ua.NodeClassReferenceType, "HasComponent"},
		{"StdDataType", ua.NewNumericNodeID(0, id.Int32), ua.NodeClassDataType, "Int32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dvs := readAttrs(t, c, tc.node,
				ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName, ua.AttributeIDDisplayName, ua.AttributeIDDescription)
			for i, dv := range dvs {
				require.Equal(t, ua.StatusOK, dv.Status, "attribute %d", i+1)
			}
			require.Equal(t, tc.node.String(), dvs[0].Value.Value().(*ua.NodeID).String())
			// NodeClass is an Int32 on the wire.
			require.Equal(t, int32(tc.class), dvs[1].Value.Value())
			require.Equal(t, tc.browseName, dvs[2].Value.Value().(*ua.QualifiedName).Name)
			require.NotEmpty(t, dvs[3].Value.Value().(*ua.LocalizedText).Text)
			_, isLT := dvs[4].Value.Value().(*ua.LocalizedText)
			require.True(t, isLT, "Description must be a LocalizedText, got %T", dvs[4].Value.Value())
		})
	}
}

// TestAttribute_ClassSpecificAttributes reads the attributes that only exist
// for particular node classes and checks they are refused elsewhere.
func TestAttribute_ClassSpecificAttributes(t *testing.T) {
	c, f, _ := setup(t)
	invalid := ua.StatusBadAttributeIDInvalid

	t.Run("ReferenceType", func(t *testing.T) {
		dvs := readAttrs(t, c, ua.NewNumericNodeID(0, id.HasComponent),
			ua.AttributeIDIsAbstract, ua.AttributeIDSymmetric, ua.AttributeIDInverseName, ua.AttributeIDValue)
		require.Equal(t, false, dvs[0].Value.Value())
		require.Equal(t, false, dvs[1].Value.Value())
		require.Equal(t, "ComponentOf", dvs[2].Value.Value().(*ua.LocalizedText).Text)
		require.Equal(t, invalid, dvs[3].Status)

		// An abstract reference type.
		dvs = readAttrs(t, c, ua.NewNumericNodeID(0, id.HierarchicalReferences), ua.AttributeIDIsAbstract)
		require.Equal(t, true, dvs[0].Value.Value())
	})

	t.Run("TypesAreAbstractOrNot", func(t *testing.T) {
		require.Equal(t, true, readAttrs(t, c, ua.NewNumericNodeID(0, id.BaseEventType), ua.AttributeIDIsAbstract)[0].Value.Value())
		require.Equal(t, false, readAttrs(t, c, ua.NewNumericNodeID(0, id.Int32), ua.AttributeIDIsAbstract)[0].Value.Value())
		require.Equal(t, true, readAttrs(t, c, ua.NewNumericNodeID(0, id.Number), ua.AttributeIDIsAbstract)[0].Value.Value())
	})

	t.Run("Variable", func(t *testing.T) {
		dvs := readAttrs(t, c, f.Int32Array,
			ua.AttributeIDValue, ua.AttributeIDDataType, ua.AttributeIDIsAbstract, ua.AttributeIDSymmetric,
			ua.AttributeIDInverseName, ua.AttributeIDExecutable)
		require.Equal(t, []int32{1, 2, 3, 4, 5}, dvs[0].Value.Value())
		require.Equal(t, uint32(id.Int32), dvs[1].Value.NodeID().IntID(), "DataType of an Int32 array is Int32")
		for i := 2; i < len(dvs); i++ {
			require.Equal(t, invalid, dvs[i].Status, "attribute index %d", i)
		}

		// DataType follows the value for every scalar type of the fixture.
		for node, want := range map[*ua.NodeID]uint32{
			f.Bool: id.Boolean, f.SByte: id.SByte, f.Byte: id.Byte, f.Int16: id.Int16, f.Uint16: id.UInt16,
			f.Uint32: id.UInt32, f.Int64: id.Int64, f.Uint64: id.UInt64, f.Float: id.Float, f.Double: id.Double,
			f.String: id.String, f.ByteString: id.ByteString,
		} {
			dv := readAttrs(t, c, node, ua.AttributeIDDataType)[0]
			require.Equal(t, ua.StatusOK, dv.Status)
			require.Equal(t, ua.TypeIDNodeID, dv.Value.Type(), "DataType must be a NodeId")
			require.Equal(t, want, dv.Value.NodeID().IntID(), "node %s", node)
		}
	})

	t.Run("AccessLevels", func(t *testing.T) {
		rw := byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite)
		dvs := readAttrs(t, c, f.Writable, ua.AttributeIDAccessLevel, ua.AttributeIDUserAccessLevel)
		require.Equal(t, rw, dvs[0].Value.Value())
		require.Equal(t, rw, dvs[1].Value.Value())
		dvs = readAttrs(t, c, f.ReadOnly, ua.AttributeIDAccessLevel, ua.AttributeIDUserAccessLevel)
		require.Equal(t, byte(ua.AccessLevelTypeCurrentRead), dvs[0].Value.Value())
		require.Equal(t, byte(ua.AccessLevelTypeCurrentRead), dvs[1].Value.Value())
		// Without read access no attribute is disclosed at all.
		for _, dv := range readAttrs(t, c, f.NoAccess, ua.AttributeIDValue, ua.AttributeIDBrowseName, ua.AttributeIDAccessLevel) {
			require.Equal(t, ua.StatusBadUserAccessDenied, dv.Status)
			require.Nil(t, dv.Value.Value())
		}
	})

	t.Run("Object", func(t *testing.T) {
		dvs := readAttrs(t, c, f.EventObject, ua.AttributeIDEventNotifier, ua.AttributeIDValue, ua.AttributeIDIsAbstract)
		require.Equal(t, byte(1), dvs[0].Value.Value(), "EventNotifier is a Byte with SubscribeToEvents set")
		require.Equal(t, invalid, dvs[1].Status)
		require.Equal(t, invalid, dvs[2].Status)

		require.Equal(t, byte(0), readAttrs(t, c, f.Motor, ua.AttributeIDEventNotifier)[0].Value.Value())
	})

	t.Run("RolePermissions", func(t *testing.T) {
		// Standard nodes carry the role permissions of the standard nodeset.
		dvs := readAttrs(t, c, ua.NewNumericNodeID(0, id.Server), ua.AttributeIDRolePermissions, ua.AttributeIDUserRolePermissions)
		for _, dv := range dvs {
			require.Equal(t, ua.StatusOK, dv.Status)
			eos, ok := dv.Value.Value().([]*ua.ExtensionObject)
			require.True(t, ok, "got %T", dv.Value.Value())
			require.NotEmpty(t, eos)
			roles := map[string]ua.PermissionType{}
			for _, eo := range eos {
				rp, ok := eo.Value.(*ua.RolePermissionType)
				require.True(t, ok, "got %T", eo.Value)
				require.NotNil(t, rp.RoleID)
				roles[rp.RoleID.String()] = rp.Permissions
			}
			anon := ua.RoleAnonymous.NodeID().String()
			require.Contains(t, roles, anon)
			require.NotZero(t, roles[anon]&ua.PermissionTypeBrowse, "anonymous may browse the Server object")
		}
		// Nodes without role permissions do not have the attribute.
		require.Equal(t, invalid, readAttrs(t, c, f.Int32, ua.AttributeIDRolePermissions)[0].Status)
	})

	t.Run("InvalidAttributeIDs", func(t *testing.T) {
		// (Attribute id 0 cannot be sent through Client.Read, which treats it
		// as "not set" and substitutes Value.)
		for _, a := range []ua.AttributeID{28, 999, ua.AttributeID(0xFFFFFFFF)} {
			require.Equal(t, invalid, readAttrs(t, c, f.Int32, a)[0].Status, "attribute id %d", a)
		}
	})
}

func TestAttribute_IndexRangeRead(t *testing.T) {
	c, f, ctx := setup(t)

	cases := []struct {
		name   string
		node   *ua.NodeID
		rng    string
		want   any
		status ua.StatusCode
	}{
		{"ArraySingleElement", f.Int32Array, "1", []int32{2}, ua.StatusOK},
		{"ArrayRange", f.Int32Array, "1:3", []int32{2, 3, 4}, ua.StatusOK},
		{"ArrayWholeRange", f.Int32Array, "0:4", []int32{1, 2, 3, 4, 5}, ua.StatusOK},
		{"ArrayRangeClippedAtEnd", f.Int32Array, "3:10", []int32{4, 5}, ua.StatusOK},
		{"ArrayBeyondEnd", f.Int32Array, "10", nil, ua.StatusBadIndexRangeNoData},
		{"ArrayRangeBeyondEnd", f.Int32Array, "10:12", nil, ua.StatusBadIndexRangeNoData},
		{"ArrayDescendingBounds", f.Int32Array, "3:1", nil, ua.StatusBadIndexRangeInvalid},
		{"ArraySyntaxError", f.Int32Array, "abc", nil, ua.StatusBadIndexRangeInvalid},
		{"ArrayNegative", f.Int32Array, "-1", nil, ua.StatusBadIndexRangeInvalid},
		{"ArrayTooManyDimensions", f.Int32Array, "0:1,0", nil, ua.StatusBadIndexRangeInvalid},
		{"StringArray", f.StringArray, "0:1", []string{"a", "b"}, ua.StatusOK},
		{"DoubleArray", f.DoubleArray, "2:3", []float64{2.5, 3.5}, ua.StatusOK},
		{"ByteStringRange", f.ByteArray, "2:4", []byte{2, 3, 4}, ua.StatusOK},
		{"ByteStringSingle", f.ByteArray, "0", []byte{0}, ua.StatusOK},
		{"ByteStringClipped", f.ByteArray, "8:20", []byte{8, 9}, ua.StatusOK},
		{"ByteStringBeyondEnd", f.ByteArray, "20", nil, ua.StatusBadIndexRangeNoData},
		{"MatrixSubBlock", f.Matrix, "0:1,1:2", [][]int32{{2, 3}, {5, 6}}, ua.StatusOK},
		{"MatrixRow", f.Matrix, "1,0:2", [][]int32{{4, 5, 6}}, ua.StatusOK},
		{"MatrixCell", f.Matrix, "0,0", [][]int32{{1}}, ua.StatusOK},
		{"MatrixTooFewDimensions", f.Matrix, "1", nil, ua.StatusBadIndexRangeInvalid},
		{"MatrixBeyondEnd", f.Matrix, "5,0", nil, ua.StatusBadIndexRangeNoData},
		{"Scalar", f.Int32, "0", nil, ua.StatusBadIndexRangeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := c.ReadMulti(ctx, []opcua.ReadItem{{NodeID: tc.node, AttributeID: ua.AttributeIDValue, IndexRange: tc.rng}})
			require.NoError(t, err)
			require.Equal(t, tc.status, res[0].StatusCode)
			if tc.status == ua.StatusOK {
				require.Equal(t, tc.want, res[0].DataValue.Value.Value())
			}
		})
	}

	t.Run("NonValueAttribute", func(t *testing.T) {
		res, err := c.ReadMulti(ctx, []opcua.ReadItem{{NodeID: f.Int32Array, AttributeID: ua.AttributeIDBrowseName, IndexRange: "0"}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadIndexRangeInvalid, res[0].StatusCode)
	})

	t.Run("MixedBatchKeepsOrder", func(t *testing.T) {
		res, err := c.ReadMulti(ctx, []opcua.ReadItem{
			{NodeID: f.Int32Array, AttributeID: ua.AttributeIDValue, IndexRange: "4"},
			{NodeID: f.Int32Array, AttributeID: ua.AttributeIDValue, IndexRange: "9"},
			{NodeID: f.Int32Array, AttributeID: ua.AttributeIDValue},
			{NodeID: f.String, AttributeID: ua.AttributeIDValue},
		}, opcua.ReadMultiWithChunkSize(3))
		require.NoError(t, err)
		require.Len(t, res, 4)
		require.Equal(t, []int32{5}, res[0].DataValue.Value.Value())
		require.Equal(t, ua.StatusBadIndexRangeNoData, res[1].StatusCode)
		require.Equal(t, []int32{1, 2, 3, 4, 5}, res[2].DataValue.Value.Value())
		require.Equal(t, "hello", res[3].DataValue.Value.Value())
	})
}

func TestAttribute_IndexRangeWrite(t *testing.T) {
	c, f, ctx := setup(t)

	write := func(node *ua.NodeID, rng string, v any) ua.StatusCode {
		t.Helper()
		sts, err := c.WriteValues(ctx, &ua.WriteValue{
			NodeID: node, AttributeID: ua.AttributeIDValue, IndexRange: rng,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		})
		require.NoError(t, err)
		require.Len(t, sts, 1)
		return sts[0]
	}
	current := func(node *ua.NodeID) any {
		t.Helper()
		dv, err := c.ReadValue(ctx, node)
		require.NoError(t, err)
		return dv.Value.Value()
	}

	// One-dimensional array.
	require.Equal(t, ua.StatusOK, write(f.Int32Array, "1:2", []int32{20, 30}))
	require.Equal(t, []int32{1, 20, 30, 4, 5}, current(f.Int32Array))
	require.Equal(t, ua.StatusOK, write(f.Int32Array, "4", []int32{50}))
	require.Equal(t, []int32{1, 20, 30, 4, 50}, current(f.Int32Array))
	require.Equal(t, ua.StatusOK, write(f.Int32Array, "0", int32(10)), "a scalar may fill a single element")
	require.Equal(t, []int32{10, 20, 30, 4, 50}, current(f.Int32Array))

	// Rejected writes leave the array untouched.
	require.Equal(t, ua.StatusBadIndexRangeDataMismatch, write(f.Int32Array, "1:2", []int32{7}))
	require.Equal(t, ua.StatusBadIndexRangeNoData, write(f.Int32Array, "4:6", []int32{1, 2, 3}))
	require.Equal(t, ua.StatusBadTypeMismatch, write(f.Int32Array, "0:1", []string{"a", "b"}))
	require.Equal(t, ua.StatusBadIndexRangeInvalid, write(f.Int32Array, "2:1", []int32{1, 2}))
	require.Equal(t, ua.StatusBadIndexRangeInvalid, write(f.Int32, "0", int32(5)), "scalars have no index range")
	require.Equal(t, []int32{10, 20, 30, 4, 50}, current(f.Int32Array))
	require.Equal(t, int32(42), current(f.Int32))

	// ByteString and matrix.
	require.Equal(t, ua.StatusOK, write(f.ByteArray, "8:9", []byte{0xAA, 0xBB}))
	require.Equal(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0xAA, 0xBB}, current(f.ByteArray))
	require.Equal(t, ua.StatusOK, write(f.Matrix, "0:1,0", [][]int32{{7}, {6}}))
	require.Equal(t, [][]int32{{7, 2, 3}, {6, 5, 6}}, current(f.Matrix))
	require.Equal(t, ua.StatusOK, write(f.Matrix, "1,1:2", []int32{8, 9}))
	require.Equal(t, [][]int32{{7, 2, 3}, {6, 8, 9}}, current(f.Matrix))

	// A ranged write is a data change like any other.
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32Array).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()
	require.Equal(t, []int32{10, 20, 30, 4, 50}, nextDataChanges(t, ch)[0].DV.Value.Value())
	require.Equal(t, ua.StatusOK, write(f.Int32Array, "2", []int32{-3}))
	require.Equal(t, []int32{10, 20, -3, 4, 50}, nextDataChanges(t, ch)[0].DV.Value.Value())
}

func TestAttribute_WriteStatuses(t *testing.T) {
	c, f, ctx := setup(t)
	val := func(v any) *ua.DataValue {
		return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
	}

	t.Run("MixedBatch", func(t *testing.T) {
		sts, err := c.WriteValues(ctx,
			&ua.WriteValue{NodeID: f.Int32, AttributeID: ua.AttributeIDValue, Value: val(int32(1))},
			&ua.WriteValue{NodeID: ua.NewStringNodeID(f.NSIndex, "Nope"), AttributeID: ua.AttributeIDValue, Value: val(int32(1))},
			&ua.WriteValue{NodeID: f.ReadOnly, AttributeID: ua.AttributeIDValue, Value: val(int32(1))},
			&ua.WriteValue{NodeID: f.Int32, AttributeID: ua.AttributeIDValue, Value: val("wrong type")},
			&ua.WriteValue{NodeID: ua.NewNumericNodeID(250, 1), AttributeID: ua.AttributeIDValue, Value: val(int32(1))},
			&ua.WriteValue{NodeID: f.Double, AttributeID: ua.AttributeIDValue, Value: val(2.5)},
		)
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{
			ua.StatusOK,
			ua.StatusBadNodeIDUnknown,
			ua.StatusBadUserAccessDenied,
			ua.StatusBadTypeMismatch,
			ua.StatusBadNodeNotInView,
			ua.StatusOK,
		}, sts)

		// Only the accepted writes took effect.
		dvs, err := c.ReadValues(ctx, f.Int32, f.ReadOnly, f.Double)
		require.NoError(t, err)
		require.Equal(t, int32(1), dvs[0].Value.Value())
		require.Equal(t, int32(20), dvs[1].Value.Value())
		require.Equal(t, 2.5, dvs[2].Value.Value())
	})

	t.Run("TimestampsAndStatusNotWritable", func(t *testing.T) {
		now := time.Now().UTC()
		for name, dv := range map[string]*ua.DataValue{
			"SourceTimestamp": {EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(int32(5)), SourceTimestamp: now},
			"ServerTimestamp": {EncodingMask: ua.DataValueValue | ua.DataValueServerTimestamp, Value: ua.MustVariant(int32(5)), ServerTimestamp: now},
			"StatusCode":      {EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: ua.MustVariant(int32(5)), Status: ua.StatusUncertain},
		} {
			st, err := c.WriteValue(ctx, f.Int16, dv)
			require.NoError(t, err, name)
			require.Equal(t, ua.StatusBadWriteNotSupported, st, name)
		}
		got, err := c.ReadValue(ctx, f.Int16)
		require.NoError(t, err)
		require.Equal(t, int16(-1234), got.Value.Value(), "rejected writes must not change the value")
	})

	t.Run("WriteAttributeOtherThanValue", func(t *testing.T) {
		st, err := c.WriteAttribute(ctx, f.String, ua.AttributeIDDescription, val(ua.NewLocalizedText("a described node")))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
		desc, err := c.Node(f.String).Description(ctx)
		require.NoError(t, err)
		require.Equal(t, "a described node", desc.Text)

		// Not writable without write access.
		st, err = c.WriteAttribute(ctx, f.ReadOnly, ua.AttributeIDDescription, val(ua.NewLocalizedText("x")))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadUserAccessDenied, st)
	})
}

func TestAttribute_ReadTimestampsToReturn(t *testing.T) {
	c, f, ctx := setup(t)

	read := func(ts ua.TimestampsToReturn) (*ua.DataValue, error) {
		resp, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ts,
			NodesToRead:        []*ua.ReadValueID{{NodeID: f.Double, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			return nil, err
		}
		return resp.Results[0], nil
	}

	for _, tc := range []struct {
		ts             ua.TimestampsToReturn
		source, server bool
	}{
		{ua.TimestampsToReturnSource, true, false},
		{ua.TimestampsToReturnServer, false, true},
		{ua.TimestampsToReturnBoth, true, true},
		{ua.TimestampsToReturnNeither, false, false},
	} {
		// Repeated so that one request cannot leak its timestamp selection
		// into the node for the next one.
		for round := 0; round < 2; round++ {
			dv, err := read(tc.ts)
			require.NoError(t, err)
			require.Equal(t, 3.14159, dv.Value.Value())
			require.Equal(t, tc.source, !dv.SourceTimestamp.IsZero(), "%s source timestamp (round %d)", tc.ts, round)
			require.Equal(t, tc.server, !dv.ServerTimestamp.IsZero(), "%s server timestamp (round %d)", tc.ts, round)
		}
	}

	_, err := read(ua.TimestampsToReturn(9))
	require.ErrorIs(t, err, ua.StatusBadTimestampsToReturnInvalid)

	// Error results never carry fabricated timestamps.
	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        []*ua.ReadValueID{{NodeID: f.NoAccess, AttributeID: ua.AttributeIDValue}},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadUserAccessDenied, resp.Results[0].Status)
}

// TestAttribute_ServerSideValueSources covers values produced by the hosting
// application: a value function evaluated on every read, and an out-of-band
// change announced with ChangeNotification.
func TestAttribute_ServerSideValueSources(t *testing.T) {
	var counter atomic.Int32
	var dynamic, pushed *server.Node
	current := atomic.Pointer[ua.DataValue]{}
	current.Store(server.DataValueFromValue("initial"))

	c, f, srv, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		dynamic = server.NewVariableNode(ua.NewStringNodeID(f.NSIndex, "Dynamic"), "Dynamic", func() *ua.DataValue {
			return server.DataValueFromValue(counter.Add(1))
		})
		f.NS.AddNode(dynamic)
		f.NS.Objects().AddRef(dynamic, server.RefTypeIDHasComponent, true)

		pushed = server.NewVariableNode(ua.NewStringNodeID(f.NSIndex, "Pushed"), "Pushed", func() *ua.DataValue {
			return current.Load()
		})
		f.NS.AddNode(pushed)
		f.NS.Objects().AddRef(pushed, server.RefTypeIDHasComponent, true)
	})
	ctx := context.Background()

	// Every read evaluates the function again.
	a, err := c.ReadValue(ctx, dynamic.ID())
	require.NoError(t, err)
	b, err := c.ReadValue(ctx, dynamic.ID())
	require.NoError(t, err)
	require.Equal(t, a.Value.Value().(int32)+1, b.Value.Value().(int32))

	// The application changes a value behind the server's back and announces it.
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(pushed.ID()).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()
	awaitValue(t, ch, 0, "initial")

	current.Store(server.DataValueFromValue("pushed by the application"))
	srv.ChangeNotification(pushed.ID())
	awaitValue(t, ch, 0, "pushed by the application")

	current.Store(server.DataValueFromValue("via the namespace"))
	f.NS.ChangeNotification(pushed.ID())
	awaitValue(t, ch, 0, "via the namespace")
}

// TestAttribute_ServerInfoFromOptions verifies the server identity options are
// visible to clients through ServerStatus, the endpoints and FindServers.
func TestAttribute_ServerInfoFromOptions(t *testing.T) {
	c, _, srv, url := setupWith(t, nil,
		server.ServerName("Conformance Test Server"),
		server.ManufacturerName("otfabric QA"),
		server.ProductName("conformance-product"),
		server.SoftwareVersion("9.8.7"),
	)
	ctx := context.Background()

	st, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateRunning, st.State)
	require.Equal(t, "otfabric QA", st.BuildInfo.ManufacturerName)
	require.Equal(t, "conformance-product", st.BuildInfo.ProductName)
	require.Equal(t, "9.8.7", st.BuildInfo.SoftwareVersion)
	require.WithinDuration(t, time.Now(), st.CurrentTime, time.Minute)
	require.False(t, st.StartTime.After(st.CurrentTime))
	require.Equal(t, ua.ServerStateRunning, srv.Status().State)

	// The individual status variables agree with the structure.
	for nodeID, want := range map[uint32]any{
		id.ServerServerStatusBuildInfoManufacturerName: "otfabric QA",
		id.ServerServerStatusBuildInfoProductName:      "conformance-product",
		id.ServerServerStatusBuildInfoSoftwareVersion:  "9.8.7",
		id.ServerServerStatusState:                     int32(ua.ServerStateRunning),
	} {
		v, err := c.Node(ua.NewNumericNodeID(0, nodeID)).Value(ctx)
		require.NoError(t, err, "i=%d", nodeID)
		require.Equal(t, want, v.Value(), "i=%d", nodeID)
	}

	// CurrentTime advances between reads.
	t1, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime)).Value(ctx)
	require.NoError(t, err)
	eventually(t, func() bool {
		t2, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime)).Value(ctx)
		return err == nil && t2.Value().(time.Time).After(t1.Value().(time.Time))
	}, "server clock advances")

	eps, err := c.GetEndpoints(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, eps.Endpoints)
	require.Equal(t, "Conformance Test Server", eps.Endpoints[0].Server.ApplicationName.Text)
	require.Equal(t, ua.ApplicationTypeServer, eps.Endpoints[0].Server.ApplicationType)
	require.Equal(t, []string{url}, eps.Endpoints[0].Server.DiscoveryURLs)
	require.Equal(t, srv.URLs(), eps.Endpoints[0].Server.DiscoveryURLs)

	// Operation limits are exposed as readable UInt32 variables.
	for _, nodeID := range []uint32{
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerWrite,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerBrowse,
		id.ServerServerCapabilitiesOperationLimitsMaxMonitoredItemsPerCall,
	} {
		v, err := c.Node(ua.NewNumericNodeID(0, nodeID)).Value(ctx)
		require.NoError(t, err, "i=%d", nodeID)
		_, ok := v.Value().(uint32)
		require.True(t, ok, "i=%d is %T", nodeID, v.Value())
	}
}
