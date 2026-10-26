// SPDX-License-Identifier: MIT

package addrspace

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NodeManagement
// ---------------------------------------------------------------------------

func TestNodeMgmt_AddedNodesAreFullyUsable(t *testing.T) {
	c, f, ctx := setup(t)

	addItem := func(name string, class ua.NodeClass, attrs any) *ua.AddNodesItem {
		item := &ua.AddNodesItem{
			ParentNodeID:       ua.NewExpandedNodeID(f.Plant, "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(f.NSIndex, name), "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: name},
			NodeClass:          class,
			TypeDefinition:     ua.NewTwoByteExpandedNodeID(0),
		}
		if attrs != nil {
			item.NodeAttributes = ua.NewExtensionObject(attrs)
		} else {
			item.NodeAttributes = ua.NewExtensionObject(nil)
		}
		return item
	}

	resp, err := c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{
		addItem("Line3", ua.NodeClassObject, nil),
		addItem("Counter", ua.NodeClassVariable, &ua.VariableAttributes{
			SpecifiedAttributes: uint32(ua.NodeAttributesMaskValue | ua.NodeAttributesMaskDisplayName | ua.NodeAttributesMaskDescription),
			DisplayName:         ua.NewLocalizedText("Part counter"),
			Description:         ua.NewLocalizedText("counts finished parts"),
			Value:               ua.MustVariant(uint32(17)),
		}),
		addItem("Line1", ua.NodeClassObject, nil), // already exists
		addItem("Reset", ua.NodeClassMethod, nil),
	}})
	require.NoError(t, err)
	require.Len(t, resp.Results, 4)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	require.Equal(t, ua.StatusOK, resp.Results[1].StatusCode)
	require.Equal(t, ua.StatusBadNodeIDExists, resp.Results[2].StatusCode)
	require.Equal(t, ua.StatusOK, resp.Results[3].StatusCode)
	line3, counter, reset := resp.Results[0].AddedNodeID, resp.Results[1].AddedNodeID, resp.Results[3].AddedNodeID
	require.Equal(t, ua.NewStringNodeID(f.NSIndex, "Line3").String(), line3.String())

	// The new nodes show up below their parent with the right class...
	refs, err := c.Node(f.Plant).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	classes := map[string]ua.NodeClass{}
	for _, r := range refs {
		classes[r.NodeID.NodeID.String()] = r.NodeClass
	}
	require.Equal(t, ua.NodeClassObject, classes[line3.String()])
	require.Equal(t, ua.NodeClassVariable, classes[counter.String()])
	require.Equal(t, ua.NodeClassMethod, classes[reset.String()])
	require.Len(t, classes, 5, "Line1, Line2 and the three new nodes")

	// ...carry the requested attributes...
	n := c.Node(counter)
	v, err := n.Value(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(17), v.Value())
	dn, err := n.DisplayName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Part counter", dn.Text)
	desc, err := n.Description(ctx)
	require.NoError(t, err)
	require.Equal(t, "counts finished parts", desc.Text)
	bn, err := n.BrowseName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Counter", bn.Name)
	nc, err := c.Node(reset).NodeClass(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassMethod, nc)

	// ...and behave like any other node: writable, monitorable, resolvable.
	st, err := c.WriteNodeValue(ctx, counter, uint32(18))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(counter).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()
	awaitValue(t, ch, 0, uint32(18))
	st, err = c.WriteNodeValue(ctx, counter, uint32(19))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	awaitValue(t, ch, 0, uint32(19))

	got, err := c.NodeFromPath(ctx, "Plant.Counter")
	require.NoError(t, err)
	require.Equal(t, counter.String(), got.ID.String())
}

func TestNodeMgmt_ReferencesAndDeletion(t *testing.T) {
	c, f, ctx := setup(t)
	forward := func(node *ua.NodeID, refTypeID uint32) []string {
		t.Helper()
		refs, err := c.Node(node).References(ctx, refTypeID, ua.BrowseDirectionForward, ua.NodeClassAll, false)
		require.NoError(t, err)
		return targets(refs)
	}
	inverse := func(node *ua.NodeID, refTypeID uint32) []string {
		t.Helper()
		refs, err := c.Node(node).References(ctx, refTypeID, ua.BrowseDirectionInverse, ua.NodeClassAll, false)
		require.NoError(t, err)
		return targets(refs)
	}
	exp := func(n *ua.NodeID) *ua.ExpandedNodeID { return ua.NewExpandedNodeID(n, "", 0) }

	t.Run("AddReferences", func(t *testing.T) {
		resp, err := c.AddReferences(ctx, &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{
			{SourceNodeID: f.Line2, ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor), TargetNodeClass: ua.NodeClassObject},
			{SourceNodeID: f.Motor, ReferenceTypeID: refType(id.Organizes), IsForward: false, TargetNodeID: exp(f.Line2), TargetNodeClass: ua.NodeClassObject},
			{SourceNodeID: ua.NewStringNodeID(f.NSIndex, "Nope"), ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor)},
			{SourceNodeID: f.Line2, ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(ua.NewStringNodeID(f.NSIndex, "Nope"))},
		}})
		require.NoError(t, err)
		// The second item is the first reference seen from its other end,
		// which the first added already (Part 3 §7.1, Part 4 §5.7.3).
		require.Equal(t, []ua.StatusCode{
			ua.StatusOK, ua.StatusBadDuplicateReferenceNotAllowed, ua.StatusBadSourceNodeIDInvalid, ua.StatusBadTargetNodeIDInvalid,
		}, resp.Results)

		require.Equal(t, ids(f.Motor), forward(f.Line2, id.Organizes))
		require.Equal(t, ids(f.Line2), inverse(f.Motor, id.Organizes))
		// The new edge is usable for path resolution.
		got, err := c.Node(f.Line2).TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Motor.SerialNumber")
		require.NoError(t, err)
		require.Equal(t, f.MotorSerial.String(), got.String())
	})

	t.Run("DeleteReferences", func(t *testing.T) {
		resp, err := c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{
			// Bidirectional: removes Line2 -> Motor and the inverse on Motor.
			{SourceNodeID: f.Line2, ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor), DeleteBidirectional: true},
			// Already gone.
			{SourceNodeID: f.Line2, ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor)},
			// Wrong reference type and wrong direction do not match the HasComponent edge.
			{SourceNodeID: f.Line1, ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor)},
			{SourceNodeID: f.Line1, ReferenceTypeID: refType(id.HasComponent), IsForward: false, TargetNodeID: exp(f.Motor)},
			{SourceNodeID: ua.NewStringNodeID(f.NSIndex, "Nope"), ReferenceTypeID: refType(id.Organizes), IsForward: true, TargetNodeID: exp(f.Motor)},
		}})
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{
			ua.StatusOK, ua.StatusBadNotFound, ua.StatusBadNotFound, ua.StatusBadNotFound, ua.StatusBadSourceNodeIDInvalid,
		}, resp.Results)

		require.Empty(t, forward(f.Line2, id.Organizes))
		require.Empty(t, inverse(f.Motor, id.Organizes))
		// The untouched HasComponent edge is still there.
		require.Equal(t, ids(f.Motor), forward(f.Line1, id.HasComponent))

		// One-directional delete leaves the inverse in place.
		resp, err = c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{
			{SourceNodeID: f.Line1, ReferenceTypeID: refType(id.HasComponent), IsForward: true, TargetNodeID: exp(f.Motor)},
		}})
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp.Results)
		require.Empty(t, forward(f.Line1, id.HasComponent))
		require.Equal(t, ids(f.Line1), inverse(f.Motor, id.HasComponent))
	})

	t.Run("DeleteNodes", func(t *testing.T) {
		resp, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{
			{NodeID: f.MotorSerial},
			{NodeID: f.MotorSerial},
			{NodeID: ua.NewNumericNodeID(240, 1)},
		}})
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNodeIDUnknown, ua.StatusBadNodeIDUnknown}, resp.Results)

		dv, err := c.ReadValue(ctx, f.MotorSerial)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
		st, err := c.WriteNodeValue(ctx, f.MotorSerial, "SN-2")
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadNodeIDUnknown, st)
		// Its sibling is unaffected.
		dv, err = c.ReadValue(ctx, f.MotorSpeed)
		require.NoError(t, err)
		require.Equal(t, float64(1500), dv.Value.Value())

		// The id can be reused afterwards.
		add, err := c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       exp(f.Motor),
			ReferenceTypeID:    refType(id.HasProperty),
			RequestedNewNodeID: exp(f.MotorSerial),
			BrowseName:         &ua.QualifiedName{Name: "SerialNumber"},
			NodeClass:          ua.NodeClassVariable,
			NodeAttributes: ua.NewExtensionObject(&ua.VariableAttributes{
				SpecifiedAttributes: uint32(ua.NodeAttributesMaskValue),
				Value:               ua.MustVariant("SN-0002"),
			}),
			TypeDefinition: ua.NewTwoByteExpandedNodeID(0),
		}}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, add.Results[0].StatusCode)
		dv, err = c.ReadValue(ctx, f.MotorSerial)
		require.NoError(t, err)
		require.Equal(t, "SN-0002", dv.Value.Value())
	})
}

// ---------------------------------------------------------------------------
// Query: one case per ContentFilter operator
// ---------------------------------------------------------------------------

// TestQuery_FilterOperators evaluates every ContentFilter operator the Query
// service implements against the three typed fixture variables
// (CustomVarA=10, CustomVarB=20 of CustomVarType; CustomSubVar=30 of its
// subtype).
func TestQuery_FilterOperators(t *testing.T) {
	c, f, ctx := setup(t)
	value := func() *ua.ExtensionObject { return attributeOperand(ua.AttributeIDValue) }
	typeID := func(n uint32) *ua.NodeID { return ua.NewNumericNodeID(0, n) }

	cases := []struct {
		name  string
		where []*ua.ContentFilterElement
		want  []int32
	}{
		{"Equals", []*ua.ContentFilterElement{element(ua.FilterOperatorEquals, value(), lit(int32(20)))}, []int32{20}},
		{"EqualsAcrossNumericTypes", []*ua.ContentFilterElement{element(ua.FilterOperatorEquals, value(), lit(float64(20)))}, []int32{20}},
		{"GreaterThan", []*ua.ContentFilterElement{element(ua.FilterOperatorGreaterThan, value(), lit(int32(10)))}, []int32{20, 30}},
		{"LessThan", []*ua.ContentFilterElement{element(ua.FilterOperatorLessThan, value(), lit(int32(30)))}, []int32{10, 20}},
		{"GreaterThanOrEqual", []*ua.ContentFilterElement{element(ua.FilterOperatorGreaterThanOrEqual, value(), lit(int32(20)))}, []int32{20, 30}},
		{"LessThanOrEqual", []*ua.ContentFilterElement{element(ua.FilterOperatorLessThanOrEqual, value(), lit(int32(20)))}, []int32{10, 20}},
		{"Between", []*ua.ContentFilterElement{element(ua.FilterOperatorBetween, value(), lit(int32(15)), lit(int32(30)))}, []int32{20, 30}},
		{"InList", []*ua.ContentFilterElement{element(ua.FilterOperatorInList, value(), lit(int32(10)), lit(int32(30)), lit(int32(99)))}, []int32{10, 30}},
		{"InListNoMatch", []*ua.ContentFilterElement{element(ua.FilterOperatorInList, value(), lit(int32(1)), lit(int32(2)))}, nil},
		{"And", []*ua.ContentFilterElement{
			element(ua.FilterOperatorAnd, elementOperand(1), elementOperand(2)),
			element(ua.FilterOperatorGreaterThan, value(), lit(int32(10))),
			element(ua.FilterOperatorLessThan, value(), lit(int32(30)))}, []int32{20}},
		{"Or", []*ua.ContentFilterElement{
			element(ua.FilterOperatorOr, elementOperand(1), elementOperand(2)),
			element(ua.FilterOperatorEquals, value(), lit(int32(10))),
			element(ua.FilterOperatorEquals, value(), lit(int32(30)))}, []int32{10, 30}},
		{"Not", []*ua.ContentFilterElement{
			element(ua.FilterOperatorNot, elementOperand(1)),
			element(ua.FilterOperatorEquals, value(), lit(int32(20)))}, []int32{10, 30}},
		{"IsNullOnPresentValue", []*ua.ContentFilterElement{element(ua.FilterOperatorIsNull, value())}, nil},
		{"IsNullOnMissingAttribute", []*ua.ContentFilterElement{element(ua.FilterOperatorIsNull, attributeOperand(ua.AttributeIDInverseName))}, []int32{10, 20, 30}},
		{"NotIsNull", []*ua.ContentFilterElement{
			element(ua.FilterOperatorNot, elementOperand(1)),
			element(ua.FilterOperatorIsNull, value())}, []int32{10, 20, 30}},
		{"LikePercent", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("CustomVarA"), lit("Custom%A"))}, []int32{10, 20, 30}},
		{"LikeUnderscore", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("abc"), lit("a_c"))}, []int32{10, 20, 30}},
		{"LikeUnderscoreIsExactlyOneChar", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("ac"), lit("a_c"))}, nil},
		{"LikeCharacterSet", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("abc"), lit("a[bx]c"))}, []int32{10, 20, 30}},
		{"LikeNegatedSet", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("abc"), lit("a[^b]c"))}, nil},
		{"LikeEscapedWildcard", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("50%"), lit(`50\%`))}, []int32{10, 20, 30}},
		{"LikeEscapedWildcardIsLiteral", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("50x"), lit(`50\%`))}, nil},
		{"LikeIsAnchored", []*ua.ContentFilterElement{element(ua.FilterOperatorLike, lit("xabcx"), lit("abc"))}, nil},
		{"CastThenCompare", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, elementOperand(1), lit(float64(20))),
			element(ua.FilterOperatorCast, value(), lit(typeID(id.Double)))}, []int32{20}},
		{"CastToStringThenLike", []*ua.ContentFilterElement{
			element(ua.FilterOperatorLike, elementOperand(1), lit("%0")),
			element(ua.FilterOperatorCast, value(), lit(typeID(id.String)))}, []int32{10, 20, 30}},
		{"OfTypeSubtypeOnly", []*ua.ContentFilterElement{element(ua.FilterOperatorOfType, lit(f.CustomVarSubType))}, []int32{30}},
		{"OfTypeBaseIncludesSubtypes", []*ua.ContentFilterElement{element(ua.FilterOperatorOfType, lit(f.CustomVarType))}, []int32{10, 20, 30}},
		{"OfTypeUnrelated", []*ua.ContentFilterElement{element(ua.FilterOperatorOfType, lit(typeID(id.BaseEventType)))}, nil},
		{"InViewNullViewIsWholeAddressSpace", []*ua.ContentFilterElement{element(ua.FilterOperatorInView, lit(ua.NewTwoByteNodeID(0)))}, []int32{10, 20, 30}},
		{"InViewUnknownView", []*ua.ContentFilterElement{element(ua.FilterOperatorInView, lit(typeID(id.ViewsFolder)))}, nil},
		// 10=01010b, 20=10100b, 30=11110b
		{"BitwiseAnd", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, elementOperand(1), lit(int64(16))),
			element(ua.FilterOperatorBitwiseAnd, value(), lit(int32(16)))}, []int32{20, 30}},
		{"BitwiseOr", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, elementOperand(1), lit(int64(30))),
			element(ua.FilterOperatorBitwiseOr, value(), lit(int32(20)))}, []int32{10, 30}},
		{"AttributeOperandOnOtherAttribute", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, attributeOperand(ua.AttributeIDNodeClass), lit(int32(ua.NodeClassVariable)))}, []int32{10, 20, 30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := queryByType(ctx, c, f.CustomVarType, true, &ua.ContentFilter{Elements: tc.where}, 0)
			require.NoError(t, err)
			if resp.FilterResult != nil {
				for i, er := range resp.FilterResult.ElementResults {
					require.Equal(t, ua.StatusOK, er.StatusCode, "filter element %d", i)
				}
			}
			var got []int32
			for _, ds := range resp.QueryDataSets {
				require.Len(t, ds.Values, 1)
				got = append(got, ds.Values[0].Value().(int32))
			}
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("RelatedTo", func(t *testing.T) {
		// Give CustomVarA a reference to an instance of the subtype.
		_, err := c.AddReferences(ctx, &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{{
			SourceNodeID: f.CustomVarA, ReferenceTypeID: refType(id.HasComponent), IsForward: true,
			TargetNodeID: ua.NewExpandedNodeID(f.CustomSubVar, "", 0), TargetNodeClass: ua.NodeClassVariable,
		}}})
		require.NoError(t, err)

		related := func(src, ref, tgt *ua.NodeID) []int32 {
			resp, err := queryByType(ctx, c, f.CustomVarType, true, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				element(ua.FilterOperatorRelatedTo, lit(src), lit(ref), lit(tgt), lit(uint32(1))),
			}}, 0)
			require.NoError(t, err)
			var got []int32
			for _, ds := range resp.QueryDataSets {
				got = append(got, ds.Values[0].Value().(int32))
			}
			return got
		}
		require.Equal(t, []int32{10}, related(f.CustomVarType, refType(id.HasComponent), f.CustomVarSubType))
		// The supertype of the reference matches too, an unrelated one does not.
		require.Equal(t, []int32{10}, related(f.CustomVarType, refType(id.HierarchicalReferences), f.CustomVarSubType))
		require.Empty(t, related(f.CustomVarType, refType(id.HasProperty), f.CustomVarSubType))
		// No instance of the subtype has such a reference.
		require.Empty(t, related(f.CustomVarSubType, refType(id.HasComponent), f.CustomVarSubType))
	})

	t.Run("InvalidFiltersAreReportedPerElement", func(t *testing.T) {
		for name, tc := range map[string]struct {
			el   *ua.ContentFilterElement
			want ua.StatusCode
		}{
			"OperandCountMismatch":   {element(ua.FilterOperatorEquals, value()), ua.StatusBadFilterOperandCountMismatch},
			"UnknownOperator":        {element(ua.FilterOperator(250), value(), value()), ua.StatusBadFilterOperatorInvalid},
			"ElementIndexOutOfRange": {element(ua.FilterOperatorNot, elementOperand(9)), ua.StatusBadFilterOperandInvalid},
		} {
			resp, err := queryByType(ctx, c, f.CustomVarType, true, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{tc.el}}, 0)
			require.ErrorIs(t, err, ua.StatusBadContentFilterInvalid, name)
			_ = resp
		}
	})
}

// ---------------------------------------------------------------------------
// Method
// ---------------------------------------------------------------------------

// argumentsProperty builds an InputArguments/OutputArguments property node.
func argumentsProperty(nodeID *ua.NodeID, name string, args ...*ua.Argument) *server.Node {
	eos := make([]*ua.ExtensionObject, len(args))
	for i, a := range args {
		eos[i] = ua.NewExtensionObject(a)
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(eos)}
	return server.NewNode(nodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
}

type methodCall struct {
	object, method string
	args           []any
}

// TestMethod_ArgumentValidationAndDispatch registers methods with different
// signatures and checks argument validation, handler dispatch and results.
func TestMethod_ArgumentValidationAndDispatch(t *testing.T) {
	var mu sync.Mutex
	var calls []methodCall
	var join, ping, fail *ua.NodeID

	c, f, _, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		newMethod := func(name string) *server.Node {
			n := server.NewFolderNode(ua.NewStringNodeID(f.NSIndex, name), name)
			n.SetNodeClass(ua.NodeClassMethod)
			f.NS.AddNode(n)
			f.NS.Objects().AddRef(n, server.RefTypeIDHasComponent, true)
			return n
		}
		record := func(objectID, methodID *ua.NodeID, args []*ua.Variant) {
			call := methodCall{object: objectID.String(), method: methodID.String()}
			for _, a := range args {
				call.args = append(call.args, a.Value())
			}
			mu.Lock()
			calls = append(calls, call)
			mu.Unlock()
		}

		// Join(sep String, repeat Int32, parts String[]) -> (joined String, count Int32)
		m := newMethod("Join")
		join = m.ID()
		in := argumentsProperty(ua.NewStringNodeID(f.NSIndex, "Join.In"), "InputArguments",
			&ua.Argument{Name: "sep", DataType: ua.NewNumericNodeID(0, id.String), ValueRank: -1, Description: ua.NewLocalizedText("separator")},
			&ua.Argument{Name: "repeat", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("repetitions")},
			&ua.Argument{Name: "parts", DataType: ua.NewNumericNodeID(0, id.String), ValueRank: 1, Description: ua.NewLocalizedText("parts")},
		)
		out := argumentsProperty(ua.NewStringNodeID(f.NSIndex, "Join.Out"), "OutputArguments",
			&ua.Argument{Name: "joined", DataType: ua.NewNumericNodeID(0, id.String), ValueRank: -1, Description: ua.NewLocalizedText("result")},
			&ua.Argument{Name: "count", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("number of parts")},
		)
		f.NS.AddNode(in)
		f.NS.AddNode(out)
		m.AddRef(in, id.HasProperty, true)
		m.AddRef(out, id.HasProperty, true)
		srv.RegisterMethod(f.MethodObject, join, func(_ context.Context, obj, meth *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			record(obj, meth, args)
			sep := args[0].Value().(string)
			parts := args[2].Value().([]string)
			joined := strings.Repeat(strings.Join(parts, sep), int(args[1].Value().(int32)))
			return []*ua.Variant{ua.MustVariant(joined), ua.MustVariant(int32(len(parts)))}, ua.StatusOK
		})

		// Ping() -> () : no InputArguments property at all.
		ping = newMethod("Ping").ID()
		srv.RegisterMethod(f.MethodObject, ping, func(_ context.Context, obj, meth *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			record(obj, meth, args)
			return nil, ua.StatusOK
		})

		// Fail() always reports an application error along with an output.
		fail = newMethod("Fail").ID()
		srv.RegisterMethod(f.MethodObject, fail, func(_ context.Context, obj, meth *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			record(obj, meth, args)
			return []*ua.Variant{ua.MustVariant("diagnostic detail")}, ua.StatusBadInvalidState
		})
	})
	ctx := context.Background()
	recorded := func() []methodCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]methodCall(nil), calls...)
	}

	t.Run("MultipleArgumentsAndOutputs", func(t *testing.T) {
		res, err := c.CallMethod(ctx, f.MethodObject, join, "-", int32(2), []string{"a", "b", "c"})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK}, res.InputArgumentResults)
		require.Len(t, res.OutputArguments, 2)
		require.Equal(t, "a-b-ca-b-c", res.OutputArguments[0].Value())
		require.Equal(t, int32(3), res.OutputArguments[1].Value())

		got := recorded()
		require.Len(t, got, 1)
		require.Equal(t, methodCall{
			object: f.MethodObject.String(), method: join.String(),
			args: []any{"-", int32(2), []string{"a", "b", "c"}},
		}, got[0])
	})

	t.Run("SignatureDiscovery", func(t *testing.T) {
		in, out, err := c.MethodArguments(ctx, f.MethodObject, join)
		require.NoError(t, err)
		require.Len(t, in, 3)
		require.Equal(t, []string{"sep", "repeat", "parts"}, []string{in[0].Name, in[1].Name, in[2].Name})
		require.Equal(t, uint32(id.String), in[0].DataType.IntID())
		require.Equal(t, uint32(id.Int32), in[1].DataType.IntID())
		require.Equal(t, int32(1), in[2].ValueRank)
		require.Equal(t, "separator", in[0].Description.Text)
		require.Len(t, out, 2)
		require.Equal(t, []string{"joined", "count"}, []string{out[0].Name, out[1].Name})

		// A method without declared arguments has none.
		in, out, err = c.MethodArguments(ctx, f.MethodObject, ping)
		require.NoError(t, err)
		require.Empty(t, in)
		require.Empty(t, out)
	})

	t.Run("ValidationRejectsBeforeTheHandlerRuns", func(t *testing.T) {
		before := len(recorded())
		for _, tc := range []struct {
			name    string
			args    []any
			status  ua.StatusCode
			results []ua.StatusCode
		}{
			{"MissingAll", nil, ua.StatusBadArgumentsMissing,
				[]ua.StatusCode{ua.StatusBadArgumentsMissing, ua.StatusBadArgumentsMissing, ua.StatusBadArgumentsMissing}},
			{"MissingLast", []any{"-", int32(1)}, ua.StatusBadArgumentsMissing,
				[]ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusBadArgumentsMissing}},
			{"TooMany", []any{"-", int32(1), []string{"a"}, true}, ua.StatusBadTooManyArguments,
				[]ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusOK}},
			{"WrongScalarType", []any{"-", int64(1), []string{"a"}}, ua.StatusBadTypeMismatch,
				[]ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch, ua.StatusOK}},
			{"ScalarWhereArrayExpected", []any{"-", int32(1), "a"}, ua.StatusBadTypeMismatch,
				[]ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusBadTypeMismatch}},
			{"ArrayWhereScalarExpected", []any{[]string{"-"}, int32(1), []string{"a"}}, ua.StatusBadTypeMismatch,
				[]ua.StatusCode{ua.StatusBadTypeMismatch, ua.StatusOK, ua.StatusOK}},
			{"SeveralWrong", []any{int32(0), "x", []string{"a"}}, ua.StatusBadTypeMismatch,
				[]ua.StatusCode{ua.StatusBadTypeMismatch, ua.StatusBadTypeMismatch, ua.StatusOK}},
		} {
			res, err := c.CallMethod(ctx, f.MethodObject, join, tc.args...)
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.status, res.StatusCode, tc.name)
			require.Equal(t, tc.results, res.InputArgumentResults, tc.name)
			require.Empty(t, res.OutputArguments, tc.name)
		}
		require.Len(t, recorded(), before, "the handler must not run for invalid arguments")
	})

	t.Run("MethodWithoutArguments", func(t *testing.T) {
		res, err := c.CallMethod(ctx, f.MethodObject, ping)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.StatusCode)
		require.Empty(t, res.OutputArguments)

		res, err = c.CallMethod(ctx, f.MethodObject, ping, int32(1))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadTooManyArguments, res.StatusCode)
	})

	t.Run("HandlerStatusAndOutputsAreReturned", func(t *testing.T) {
		res, err := c.CallMethod(ctx, f.MethodObject, fail)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadInvalidState, res.StatusCode)
		require.Len(t, res.OutputArguments, 1)
		require.Equal(t, "diagnostic detail", res.OutputArguments[0].Value())
	})

	t.Run("WrongObjectForMethod", func(t *testing.T) {
		// The method exists but is not registered on this object.
		res, err := c.CallMethod(ctx, f.Motor, ping)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadMethodInvalid, res.StatusCode)
	})

	t.Run("SeveralMethodsInOneRequest", func(t *testing.T) {
		before := len(recorded())
		resp := mustSendRaw[ua.CallResponse](t, c, &ua.CallRequest{MethodsToCall: []*ua.CallMethodRequest{
			{ObjectID: f.MethodObject, MethodID: f.SquareMethod, InputArguments: []*ua.Variant{ua.MustVariant(int32(5))}},
			{ObjectID: f.MethodObject, MethodID: ua.NewStringNodeID(f.NSIndex, "Nope")},
			{ObjectID: f.MethodObject, MethodID: ping},
			{ObjectID: ua.NewStringNodeID(f.NSIndex, "NoObject"), MethodID: ping},
			{ObjectID: f.MethodObject, MethodID: f.SquareMethod, InputArguments: []*ua.Variant{ua.MustVariant("five")}},
		}})
		require.Len(t, resp.Results, 5)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, int32(25), resp.Results[0].OutputArguments[0].Value())
		require.Equal(t, ua.StatusBadMethodInvalid, resp.Results[1].StatusCode)
		require.Equal(t, ua.StatusOK, resp.Results[2].StatusCode)
		require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[3].StatusCode)
		require.Equal(t, ua.StatusBadTypeMismatch, resp.Results[4].StatusCode)
		require.Len(t, recorded(), before+1, "only Ping reached a recording handler")
	})
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func TestDiscovery_FindServersAndGetEndpoints(t *testing.T) {
	_, url := secureServer(t, server.ServerName("Discoverable"))
	ctx := context.Background()

	// Package-level helpers: no session, short-lived channel.
	servers, err := opcua.FindServers(ctx, url)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.Equal(t, "Discoverable", servers[0].ApplicationName.Text)
	require.Equal(t, serverAppURI, servers[0].ApplicationURI)
	require.Equal(t, ua.ApplicationTypeServer, servers[0].ApplicationType)
	require.Equal(t, []string{url}, servers[0].DiscoveryURLs)

	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	require.Len(t, eps, 1+len(securePolicies)*len(secureModes))
	for _, ep := range eps {
		require.Equal(t, url, ep.EndpointURL)
		require.Equal(t, "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary", ep.TransportProfileURI)
		require.Equal(t, "Discoverable", ep.Server.ApplicationName.Text)
		require.NotEmpty(t, ep.UserIdentityTokens)
	}

	// The same through a connected client.
	c := newClient(t, url)
	viaClient, err := c.GetEndpoints(ctx)
	require.NoError(t, err)
	require.Len(t, viaClient.Endpoints, len(eps))
	fs, err := c.FindServers(ctx)
	require.NoError(t, err)
	require.Len(t, fs.Servers, 1)
	require.Equal(t, serverAppURI, fs.Servers[0].ApplicationURI)

	// Endpoint selection helpers work on the result.
	best, err := ua.SelectEndpoint(eps, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.NoError(t, err)
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, best.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, best.SecurityMode)

	// Nothing listening: the helpers fail instead of hanging.
	_, err = opcua.GetEndpoints(ctx, "opc.tcp://localhost:1", opcua.DialTimeout(waitTimeout))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// NodeSet2 import
// ---------------------------------------------------------------------------

const machineNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://otfabric.com/conformance/machine</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasComponent">i=47</Alias>
    <Alias Alias="HasProperty">i=46</Alias>
    <Alias Alias="Organizes">i=35</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
  </Aliases>
  <UAReferenceType NodeId="ns=1;i=4000" BrowseName="1:Feeds" Symmetric="false">
    <DisplayName>Feeds</DisplayName>
    <Description>Material flows from the source to the target</Description>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=33</Reference>
    </References>
    <InverseName>FedBy</InverseName>
  </UAReferenceType>
  <UAObjectType NodeId="ns=1;i=3000" BrowseName="1:MachineType" IsAbstract="true">
    <DisplayName>MachineType</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=58</Reference>
    </References>
  </UAObjectType>
  <UAObject NodeId="ns=1;i=1000" BrowseName="1:Machine">
    <DisplayName>Machine</DisplayName>
    <Description>An imported machine</Description>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>
      <Reference ReferenceType="HasTypeDefinition">ns=1;i=3000</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=1001</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=1002</Reference>
    </References>
  </UAObject>
  <UAObject NodeId="ns=1;i=1100" BrowseName="1:Conveyor">
    <DisplayName>Conveyor</DisplayName>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=1001" BrowseName="1:Temperature" DataType="Double">
    <DisplayName>Temperature</DisplayName>
    <Description>Spindle temperature</Description>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=1000</Reference>
    </References>
  </UAVariable>
  <UAMethod NodeId="ns=1;i=1002" BrowseName="1:Start">
    <DisplayName>Start</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=1000</Reference>
    </References>
  </UAMethod>
</UANodeSet>`

// TestNodeSet_ImportIsServedToClients imports a NodeSet2 document into a
// running server and verifies the imported model through the client.
func TestNodeSet_ImportIsServedToClients(t *testing.T) {
	srv, url := newServer(t)
	require.NoError(t, srv.ImportNodeSetXML([]byte(machineNodeSet)))
	require.Error(t, srv.ImportNodeSetXML([]byte("<UANodeSet><broken")), "malformed XML must be rejected")
	c := newClient(t, url)
	ctx := context.Background()

	ns, err := c.FindNamespace(ctx, "http://otfabric.com/conformance/machine")
	require.NoError(t, err)
	require.Equal(t, uint16(1), ns)
	node := func(i uint32) *ua.NodeID { return ua.NewNumericNodeID(ns, i) }

	t.Run("NodesAndAttributes", func(t *testing.T) {
		for _, tc := range []struct {
			id               uint32
			class            ua.NodeClass
			browse, display  string
			description      string
			checkDescription bool
		}{
			{1000, ua.NodeClassObject, "Machine", "Machine", "An imported machine", true},
			{1001, ua.NodeClassVariable, "Temperature", "Temperature", "Spindle temperature", true},
			{1002, ua.NodeClassMethod, "Start", "Start", "", false},
			{3000, ua.NodeClassObjectType, "MachineType", "MachineType", "", false},
			{4000, ua.NodeClassReferenceType, "Feeds", "Feeds", "Material flows from the source to the target", true},
		} {
			n := c.Node(node(tc.id))
			nc, err := n.NodeClass(ctx)
			require.NoError(t, err, "i=%d", tc.id)
			require.Equal(t, tc.class, nc, "i=%d", tc.id)
			bn, err := n.BrowseName(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.browse, bn.Name)
			require.Equal(t, ns, bn.NamespaceIndex, "imported browse names keep their namespace")
			dn, err := n.DisplayName(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.display, dn.Text)
			if tc.checkDescription {
				d, err := n.Description(ctx)
				require.NoError(t, err)
				require.Equal(t, tc.description, d.Text)
			}
		}

		dvs := readAttrs(t, c, node(4000), ua.AttributeIDIsAbstract, ua.AttributeIDSymmetric, ua.AttributeIDInverseName)
		require.Equal(t, false, dvs[0].Value.Value())
		require.Equal(t, false, dvs[1].Value.Value())
		require.Equal(t, "FedBy", dvs[2].Value.Value().(*ua.LocalizedText).Text)
		require.Equal(t, true, readAttrs(t, c, node(3000), ua.AttributeIDIsAbstract)[0].Value.Value())
	})

	t.Run("References", func(t *testing.T) {
		machine := c.Node(node(1000))
		comps, err := machine.References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassAll, false)
		require.NoError(t, err)
		require.Equal(t, ids(node(1001), node(1002)), targets(comps))
		require.Equal(t, ua.NodeClassVariable, comps[0].NodeClass)
		require.Equal(t, ua.NodeClassMethod, comps[1].NodeClass)

		td, err := machine.TypeDefinition(ctx)
		require.NoError(t, err)
		require.Equal(t, node(3000).String(), td.String())

		// It hangs below the standard Objects folder (declared as an inverse
		// reference in the nodeset).
		top, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).References(ctx, id.Organizes, ua.BrowseDirectionForward, ua.NodeClassObject, false)
		require.NoError(t, err)
		require.Contains(t, targets(top), node(1000).String())
		require.Contains(t, targets(top), node(1100).String())

		// A reference declared on one end only is browsable from both ends.
		conveyor, err := c.Node(node(1100)).References(ctx, id.Organizes, ua.BrowseDirectionInverse, ua.NodeClassAll, false)
		require.NoError(t, err)
		require.Equal(t, []string{ua.NewNumericNodeID(0, id.ObjectsFolder).String()}, targets(conveyor))

		// Declaring a reference on both ends must not duplicate it.
		parents, err := c.Node(node(1001)).References(ctx, id.HasComponent, ua.BrowseDirectionInverse, ua.NodeClassAll, false)
		require.NoError(t, err)
		require.Equal(t, ids(node(1000)), targets(parents))

		// The standard namespace is free of duplicate references as well.
		for _, n := range []uint32{id.Server, id.ServerServerCapabilities, id.BaseEventType, id.BaseObjectType} {
			res := browseOne(t, c, &ua.BrowseDescription{
				NodeID: ua.NewNumericNodeID(0, n), BrowseDirection: ua.BrowseDirectionBoth,
				ReferenceTypeID: refType(id.References), IncludeSubtypes: true,
			}, 0)
			seen := map[string]bool{}
			for _, r := range res.References {
				key := fmt.Sprintf("%s|%s|%v", r.ReferenceTypeID, r.NodeID.NodeID, r.IsForward)
				require.False(t, seen[key], "i=%d has duplicate reference %s", n, key)
				seen[key] = true
			}
			require.NotEmpty(t, seen)
		}
	})

	t.Run("PathsWithNamespaceQualifiedNames", func(t *testing.T) {
		n, err := c.NodeFromQualifiedPath(ctx, "1:Machine.1:Temperature")
		require.NoError(t, err)
		require.Equal(t, node(1001).String(), n.ID.String())
		n, err = c.NodeFromPathInNamespace(ctx, ns, "Machine.Start")
		require.NoError(t, err)
		require.Equal(t, node(1002).String(), n.ID.String())
		_, err = c.NodeFromQualifiedPath(ctx, "1:Machine.2:Temperature")
		require.ErrorIs(t, err, ua.StatusBadNoMatch)
	})

	t.Run("ImportedTypeIsAnEventTypeCandidate", func(t *testing.T) {
		// An imported ObjectType can be registered with a method handler's
		// object or used wherever the server looks up user-defined types; here:
		// attaching a method implementation to the imported method node.
		srv.RegisterMethod(node(1000), node(1002), func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return []*ua.Variant{ua.MustVariant("started")}, ua.StatusOK
		})
		res, err := c.CallMethod(ctx, node(1000), node(1002))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.StatusCode)
		require.Equal(t, "started", res.OutputArguments[0].Value())
	})
}
