// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"sort"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// browseOne browses a single node, requesting every result field, and returns
// the result.
func browseOne(t *testing.T, c *opcua.Client, desc *ua.BrowseDescription, max uint32) *ua.BrowseResult {
	t.Helper()
	desc.ResultMask = uint32(ua.BrowseResultMaskAll)
	return browseMasked(t, c, desc, max)
}

// browseMasked browses a single node with the result mask of desc as given.
func browseMasked(t *testing.T, c *opcua.Client, desc *ua.BrowseDescription, max uint32) *ua.BrowseResult {
	t.Helper()
	resp, err := c.Browse(context.Background(), &ua.BrowseRequest{
		NodesToBrowse:                 []*ua.BrowseDescription{desc},
		RequestedMaxReferencesPerNode: max,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	return resp.Results[0]
}

// targets returns the string ids of the reference targets, in order.
func targets(refs []*ua.ReferenceDescription) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.NodeID.NodeID.String()
	}
	return out
}

func ids(nodes ...*ua.NodeID) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.String()
	}
	return out
}

func refType(n uint32) *ua.NodeID { return ua.NewNumericNodeID(0, n) }

func TestView_BrowseDirection(t *testing.T) {
	c, f, _ := setup(t)

	fwd := browseOne(t, c, &ua.BrowseDescription{NodeID: f.Plant, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType(id.References), IncludeSubtypes: true}, 0)
	require.Equal(t, ua.StatusOK, fwd.StatusCode)
	require.Equal(t, ids(f.Line1, f.Line2), targets(fwd.References))
	for _, r := range fwd.References {
		require.True(t, r.IsForward)
		require.Equal(t, uint32(id.HasComponent), r.ReferenceTypeID.IntID())
		require.Equal(t, ua.NodeClassObject, r.NodeClass)
	}
	require.Equal(t, "Line1", fwd.References[0].BrowseName.Name)
	require.Equal(t, "Line1", fwd.References[0].DisplayName.Text)

	inv := browseOne(t, c, &ua.BrowseDescription{NodeID: f.Plant, BrowseDirection: ua.BrowseDirectionInverse, ReferenceTypeID: refType(id.References), IncludeSubtypes: true}, 0)
	require.Equal(t, ids(f.MethodObject), targets(inv.References))
	require.False(t, inv.References[0].IsForward)
	require.Equal(t, uint32(id.Organizes), inv.References[0].ReferenceTypeID.IntID())

	both := browseOne(t, c, &ua.BrowseDescription{NodeID: f.Plant, BrowseDirection: ua.BrowseDirectionBoth, ReferenceTypeID: refType(id.References), IncludeSubtypes: true}, 0)
	require.ElementsMatch(t, ids(f.MethodObject, f.Line1, f.Line2), targets(both.References))
}

func TestView_BrowseReferenceTypeAndSubtypes(t *testing.T) {
	c, f, _ := setup(t)

	cases := []struct {
		name     string
		node     *ua.NodeID
		refType  uint32
		subtypes bool
		want     []*ua.NodeID
	}{
		{"ExactHasComponent", f.Line1, id.HasComponent, false, []*ua.NodeID{f.Motor}},
		{"ExactOrganizes", f.Line1, id.Organizes, false, []*ua.NodeID{f.Line2}},
		{"HierarchicalWithSubtypes", f.Line1, id.HierarchicalReferences, true, []*ua.NodeID{f.Motor, f.Line2}},
		{"AbstractTypeWithoutSubtypes", f.Line1, id.HierarchicalReferences, false, nil},
		{"AggregatesCoversComponentAndProperty", f.Motor, id.Aggregates, true, []*ua.NodeID{f.MotorSpeed, f.MotorSerial}},
		{"HasPropertyOnly", f.Motor, id.HasProperty, true, []*ua.NodeID{f.MotorSerial}},
		{"HasChildIncludesAggregates", f.Motor, id.HasChild, true, []*ua.NodeID{f.MotorSpeed, f.MotorSerial}},
		{"UnrelatedBranchOfTypeTree", f.Motor, id.NonHierarchicalReferences, true, nil},
		{"NullReferenceTypeMeansAll", f.Line1, 0, false, []*ua.NodeID{f.Motor, f.Line2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := browseOne(t, c, &ua.BrowseDescription{
				NodeID: tc.node, BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: refType(tc.refType), IncludeSubtypes: tc.subtypes,
			}, 0)
			require.Equal(t, ua.StatusOK, res.StatusCode)
			require.Equal(t, ids(tc.want...), targets(res.References))
		})
	}
}

func TestView_BrowseNodeClassMask(t *testing.T) {
	c, f, _ := setup(t)
	browse := func(node *ua.NodeID, mask ua.NodeClass) []string {
		res := browseOne(t, c, &ua.BrowseDescription{
			NodeID: node, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: refType(id.HierarchicalReferences), IncludeSubtypes: true,
			NodeClassMask: uint32(mask),
		}, 0)
		require.Equal(t, ua.StatusOK, res.StatusCode)
		return targets(res.References)
	}

	require.Equal(t, ids(f.Motor, f.Line2), browse(f.Line1, ua.NodeClassObject))
	require.Empty(t, browse(f.Line1, ua.NodeClassVariable))
	require.Equal(t, ids(f.MotorSpeed, f.MotorSerial), browse(f.Motor, ua.NodeClassVariable))
	require.Empty(t, browse(f.Motor, ua.NodeClassObject|ua.NodeClassMethod))
	require.Equal(t, ids(f.MotorSpeed, f.MotorSerial), browse(f.Motor, ua.NodeClassObject|ua.NodeClassVariable))

	// The fixture's Objects folder holds exactly one method.
	require.Equal(t, ids(f.SquareMethod), browse(f.MethodObject, ua.NodeClassMethod))
	// A zero mask means "all classes".
	require.Equal(t, browse(f.Motor, ua.NodeClassAll), browse(f.Motor, 0))
}

func TestView_BrowseResultMask(t *testing.T) {
	c, f, _ := setup(t)
	desc := func(mask ua.BrowseResultMask) *ua.BrowseDescription {
		return &ua.BrowseDescription{
			NodeID: f.Motor, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: refType(id.HasComponent), ResultMask: uint32(mask),
		}
	}

	full := browseMasked(t, c, desc(ua.BrowseResultMaskAll), 0).References
	require.Len(t, full, 1)
	require.Equal(t, "Speed", full[0].BrowseName.Name)
	require.Equal(t, "Speed", full[0].DisplayName.Text)
	require.Equal(t, ua.NodeClassVariable, full[0].NodeClass)
	require.True(t, full[0].IsForward)
	require.Equal(t, uint32(id.HasComponent), full[0].ReferenceTypeID.IntID())

	// Only BrowseName and NodeClass requested: the rest must be blank, the
	// target NodeId is always returned.
	some := browseMasked(t, c, desc(ua.BrowseResultMaskBrowseName|ua.BrowseResultMaskNodeClass), 0).References
	require.Len(t, some, 1)
	require.Equal(t, f.MotorSpeed.String(), some[0].NodeID.NodeID.String())
	require.Equal(t, "Speed", some[0].BrowseName.Name)
	require.Equal(t, ua.NodeClassVariable, some[0].NodeClass)
	require.Empty(t, some[0].DisplayName.Text)
	require.False(t, some[0].IsForward)
	require.Zero(t, some[0].ReferenceTypeID.IntID())

	none := browseMasked(t, c, desc(ua.BrowseResultMaskNone), 0).References
	require.Len(t, none, 1)
	require.Equal(t, f.MotorSpeed.String(), none[0].NodeID.NodeID.String())
	require.Empty(t, none[0].BrowseName.Name)
	require.Equal(t, ua.NodeClassUnspecified, none[0].NodeClass)
}

// TestView_BrowseContinuation pages through a large folder and checks the
// pieces add up exactly to the unlimited result, plus continuation point
// lifetime rules.
func TestView_BrowseContinuation(t *testing.T) {
	c, f, ctx := setup(t)
	desc := func(node *ua.NodeID) *ua.BrowseDescription {
		return &ua.BrowseDescription{
			NodeID: node, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: refType(id.HierarchicalReferences), IncludeSubtypes: true,
		}
	}
	all := targets(browseOne(t, c, desc(f.MethodObject), 0).References)
	require.Greater(t, len(all), 20, "fixture folder should be large")

	next := func(release bool, cps ...[]byte) []*ua.BrowseResult {
		t.Helper()
		resp, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: cps, ReleaseContinuationPoints: release})
		require.NoError(t, err)
		require.Len(t, resp.Results, len(cps))
		return resp.Results
	}

	t.Run("PagesAddUp", func(t *testing.T) {
		first := browseOne(t, c, desc(f.MethodObject), 7)
		require.Equal(t, ua.StatusOK, first.StatusCode)
		require.Len(t, first.References, 7)
		require.NotEmpty(t, first.ContinuationPoint)

		got := targets(first.References)
		cp := first.ContinuationPoint
		for rounds := 0; len(cp) > 0; rounds++ {
			require.Less(t, rounds, len(all), "continuation never terminated")
			res := next(false, cp)[0]
			require.Equal(t, ua.StatusOK, res.StatusCode)
			require.NotEmpty(t, res.References)
			got = append(got, targets(res.References)...)
			cp = res.ContinuationPoint
		}
		require.Equal(t, all, got, "paged browse must equal the unlimited browse, in order")
	})

	t.Run("LimitNotReachedMeansNoContinuationPoint", func(t *testing.T) {
		res := browseOne(t, c, desc(f.Motor), 2)
		require.Len(t, res.References, 2)
		require.Empty(t, res.ContinuationPoint)
		res = browseOne(t, c, desc(f.MethodObject), uint32(len(all)))
		require.Len(t, res.References, len(all))
		require.Empty(t, res.ContinuationPoint)
	})

	t.Run("ConsumedPointIsInvalid", func(t *testing.T) {
		first := browseOne(t, c, desc(f.MethodObject), 5)
		require.Equal(t, ua.StatusOK, next(false, first.ContinuationPoint)[0].StatusCode)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, next(false, first.ContinuationPoint)[0].StatusCode)
	})

	t.Run("ReleaseThenReuse", func(t *testing.T) {
		first := browseOne(t, c, desc(f.MethodObject), 5)
		rel := next(true, first.ContinuationPoint)[0]
		require.Equal(t, ua.StatusOK, rel.StatusCode)
		require.Empty(t, rel.References, "a release returns no references")
		require.Equal(t, ua.StatusBadContinuationPointInvalid, next(false, first.ContinuationPoint)[0].StatusCode)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, next(true, first.ContinuationPoint)[0].StatusCode)
	})

	t.Run("PerNodePointsAndGarbage", func(t *testing.T) {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{
			NodesToBrowse: []*ua.BrowseDescription{
				{NodeID: f.MethodObject, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType(id.HierarchicalReferences), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)},
				{NodeID: f.Motor, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType(id.HierarchicalReferences), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)},
				{NodeID: ua.NewStringNodeID(f.NSIndex, "Nope"), BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType(id.HierarchicalReferences), ResultMask: uint32(ua.BrowseResultMaskAll)},
			},
			RequestedMaxReferencesPerNode: 1,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 3)
		require.NotEmpty(t, resp.Results[0].ContinuationPoint)
		require.NotEmpty(t, resp.Results[1].ContinuationPoint)
		require.NotEqual(t, resp.Results[0].ContinuationPoint, resp.Results[1].ContinuationPoint)
		require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[2].StatusCode)

		res := next(false, resp.Results[1].ContinuationPoint, []byte("garbage"), resp.Results[0].ContinuationPoint)
		require.Equal(t, ids(f.MotorSerial), targets(res[0].References))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, res[1].StatusCode)
		require.Equal(t, all[1:], targets(res[2].References))
	})
}

func TestView_RegisteredNodeIDsAreUsable(t *testing.T) {
	c, f, ctx := setup(t)

	reg, err := c.RegisterNodes(ctx, &ua.RegisterNodesRequest{
		NodesToRegister: []*ua.NodeID{f.Int32, ua.NewStringNodeID(f.NSIndex, "Nope"), f.MotorSpeed},
	})
	require.NoError(t, err)
	require.Len(t, reg.RegisteredNodeIDs, 3)
	intID, speedID := reg.RegisteredNodeIDs[0], reg.RegisteredNodeIDs[2]
	require.NotNil(t, intID)
	require.NotNil(t, speedID)

	// The registered ids address the very same nodes for every service.
	st, err := c.WriteNodeValue(ctx, intID, int32(808))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(808), dv.Value.Value())

	dvs, err := c.ReadValues(ctx, intID, speedID)
	require.NoError(t, err)
	require.Equal(t, int32(808), dvs[0].Value.Value())
	require.Equal(t, float64(1500), dvs[1].Value.Value())

	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(intID).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()
	awaitValue(t, ch, 0, int32(808))

	un, err := c.UnregisterNodes(ctx, &ua.UnregisterNodesRequest{NodesToUnregister: []*ua.NodeID{intID, speedID}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, un.ResponseHeader.ServiceResult)
}

func TestView_TranslateBrowsePaths(t *testing.T) {
	c, f, ctx := setup(t)
	objects := c.Node(f.MethodObject)

	t.Run("MultiHop", func(t *testing.T) {
		got, err := objects.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Plant.Line1.Motor.Speed")
		require.NoError(t, err)
		require.Equal(t, f.MotorSpeed.String(), got.String())

		got, err = objects.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Plant.Line2.Speed")
		require.NoError(t, err)
		require.Equal(t, f.Line2Speed.String(), got.String())

		// Via the second, Organizes path to Line2.
		got, err = objects.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Plant.Line1.Line2.Speed")
		require.NoError(t, err)
		require.Equal(t, f.Line2Speed.String(), got.String())
	})

	t.Run("FromIntermediateNode", func(t *testing.T) {
		got, err := c.Node(f.Line1).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{
			{Name: "Motor"},
			{Name: "SerialNumber"},
		})
		require.NoError(t, err)
		require.Equal(t, f.MotorSerial.String(), got.String())
	})

	t.Run("ClientPathHelpers", func(t *testing.T) {
		// These helpers start at the standard Objects folder (i=85).
		n, err := c.NodeFromPath(ctx, "Plant.Line1.Motor.Speed")
		require.NoError(t, err)
		require.Equal(t, f.MotorSpeed.String(), n.ID.String())

		n, err = c.NodeFromPathInNamespace(ctx, 0, "Plant.Line2")
		require.NoError(t, err)
		require.Equal(t, f.Line2.String(), n.ID.String())

		n, err = c.NodeFromQualifiedPath(ctx, "0:Plant.0:Line1.0:Motor.0:SerialNumber")
		require.NoError(t, err)
		require.Equal(t, f.MotorSerial.String(), n.ID.String())

		n, err = c.NodeFromPath(ctx, "Server.ServerStatus")
		require.NoError(t, err)
		require.Equal(t, uint32(id.ServerServerStatus), n.ID.IntID())

		_, err = c.NodeFromPath(ctx, "Plant.Line1.Nope")
		require.ErrorIs(t, err, ua.StatusBadNoMatch)
		// A segment qualified with the wrong namespace does not match.
		_, err = c.NodeFromQualifiedPath(ctx, "0:Plant.7:Line1")
		require.ErrorIs(t, err, ua.StatusBadNoMatch)
		_, err = c.NodeFromPathInNamespace(ctx, 7, "Plant")
		require.ErrorIs(t, err, ua.StatusBadNoMatch)

		for _, bad := range []string{"", "NoNamespacePrefix", "x:Name", "1:"} {
			_, err = c.NodeFromQualifiedPath(ctx, bad)
			require.Error(t, err, "path %q", bad)
			require.NotErrorIs(t, err, ua.StatusBadNoMatch, "path %q must be rejected before reaching the server", bad)
		}
	})

	t.Run("Negative", func(t *testing.T) {
		_, err := objects.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Plant.Line1.Motor.Torque")
		require.ErrorIs(t, err, ua.StatusBadNoMatch, "last hop missing")
		_, err = objects.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Factory.Line1")
		require.ErrorIs(t, err, ua.StatusBadNoMatch, "first hop missing")
		// Right name, wrong namespace.
		_, err = objects.TranslateBrowsePathInNamespaceToNodeID(ctx, f.NSIndex+5, "Plant")
		require.ErrorIs(t, err, ua.StatusBadNoMatch)
		_, err = c.Node(ua.NewStringNodeID(f.NSIndex, "Nope")).TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Plant")
		require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown, "unknown starting node")
	})

	t.Run("ReferenceTypeAndDirection", func(t *testing.T) {
		translate := func(start *ua.NodeID, elems ...*ua.RelativePathElement) *ua.BrowsePathResult {
			t.Helper()
			res := mustSendRaw[ua.TranslateBrowsePathsToNodeIDsResponse](t, c, &ua.TranslateBrowsePathsToNodeIDsRequest{
				BrowsePaths: []*ua.BrowsePath{{StartingNode: start, RelativePath: &ua.RelativePath{Elements: elems}}},
			})
			require.Len(t, res.Results, 1)
			return res.Results[0]
		}
		name := func(s string) *ua.QualifiedName { return &ua.QualifiedName{Name: s} }

		// Forward via the exact reference type.
		r := translate(f.Motor, &ua.RelativePathElement{ReferenceTypeID: refType(id.HasProperty), TargetName: name("SerialNumber")})
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Len(t, r.Targets, 1)
		require.Equal(t, f.MotorSerial.String(), r.Targets[0].TargetID.NodeID.String())
		require.Equal(t, uint32(0xFFFFFFFF), r.Targets[0].RemainingPathIndex)

		// The wrong reference type does not match, even though the name does.
		r = translate(f.Motor, &ua.RelativePathElement{ReferenceTypeID: refType(id.Organizes), IncludeSubtypes: true, TargetName: name("SerialNumber")})
		require.Equal(t, ua.StatusBadNoMatch, r.StatusCode)
		// A supertype matches only with IncludeSubtypes.
		r = translate(f.Motor, &ua.RelativePathElement{ReferenceTypeID: refType(id.Aggregates), IncludeSubtypes: false, TargetName: name("SerialNumber")})
		require.Equal(t, ua.StatusBadNoMatch, r.StatusCode)
		r = translate(f.Motor, &ua.RelativePathElement{ReferenceTypeID: refType(id.Aggregates), IncludeSubtypes: true, TargetName: name("SerialNumber")})
		require.Equal(t, ua.StatusOK, r.StatusCode)

		// Inverse hops walk up the hierarchy: Speed -> Motor -> Line1.
		r = translate(f.MotorSpeed,
			&ua.RelativePathElement{ReferenceTypeID: refType(id.HasComponent), IsInverse: true, TargetName: name("Motor")},
			&ua.RelativePathElement{ReferenceTypeID: refType(id.HasComponent), IsInverse: true, TargetName: name("Line1")},
		)
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Equal(t, f.Line1.String(), r.Targets[0].TargetID.NodeID.String())
		// The same hop without IsInverse finds nothing.
		r = translate(f.MotorSpeed, &ua.RelativePathElement{ReferenceTypeID: refType(id.HasComponent), TargetName: name("Motor")})
		require.Equal(t, ua.StatusBadNoMatch, r.StatusCode)

		// Several paths in one request get independent results.
		res := mustSendRaw[ua.TranslateBrowsePathsToNodeIDsResponse](t, c, &ua.TranslateBrowsePathsToNodeIDsRequest{
			BrowsePaths: []*ua.BrowsePath{
				{StartingNode: f.Plant, RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{{TargetName: name("Line2")}}}},
				{StartingNode: f.Plant, RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{{TargetName: name("Line9")}}}},
			},
		})
		require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
		require.Equal(t, f.Line2.String(), res.Results[0].Targets[0].TargetID.NodeID.String())
		require.Equal(t, ua.StatusBadNoMatch, res.Results[1].StatusCode)
	})
}

type walkStep struct {
	depth int
	id    string
}

func TestNode_WalkVariants(t *testing.T) {
	c, f, ctx := setup(t)
	plant := c.Node(f.Plant)

	collect := func(it func(func(opcua.WalkResult, error) bool)) []walkStep {
		t.Helper()
		var out []walkStep
		for wr, err := range it {
			require.NoError(t, err)
			out = append(out, walkStep{wr.Depth, wr.Ref.NodeID.NodeID.String()})
		}
		return out
	}
	s := func(depth int, n *ua.NodeID) walkStep { return walkStep{depth, n.String()} }

	// Depth-first, in the server's reference order. Line2 is reachable twice.
	full := []walkStep{
		s(0, f.Line1), s(1, f.Motor), s(2, f.MotorSpeed), s(2, f.MotorSerial),
		s(1, f.Line2), s(2, f.Line2Speed),
		s(0, f.Line2), s(1, f.Line2Speed),
	}
	require.Equal(t, full, collect(plant.Walk(ctx)))
	require.Equal(t, full, collect(plant.WalkLimit(ctx, -1)))
	require.Equal(t, full, collect(plant.WalkLimit(ctx, 5)))

	require.Equal(t, []walkStep{s(0, f.Line1), s(0, f.Line2)}, collect(plant.WalkLimit(ctx, 0)))
	require.Equal(t, []walkStep{
		s(0, f.Line1), s(1, f.Motor), s(1, f.Line2), s(0, f.Line2), s(1, f.Line2Speed),
	}, collect(plant.WalkLimit(ctx, 1)))

	// Dedup yields every node once, at its first position.
	require.Equal(t, []walkStep{
		s(0, f.Line1), s(1, f.Motor), s(2, f.MotorSpeed), s(2, f.MotorSerial),
		s(1, f.Line2), s(2, f.Line2Speed),
	}, collect(plant.WalkLimitDedup(ctx, -1)))
	require.Equal(t, []walkStep{s(0, f.Line1), s(0, f.Line2)}, collect(plant.WalkLimitDedup(ctx, 0)))

	// The caller can stop early.
	var seen int
	for _, err := range plant.Walk(ctx) {
		require.NoError(t, err)
		seen++
		if seen == 3 {
			break
		}
	}
	require.Equal(t, 3, seen)

	// A walk from an unknown node reports the browse status once and stops.
	var errs []error
	for _, err := range c.Node(ua.NewStringNodeID(f.NSIndex, "Nope")).Walk(ctx) {
		errs = append(errs, err)
	}
	require.Empty(t, errs, "an unknown node has no references to yield")
}

func TestNode_BrowseWithDepth(t *testing.T) {
	c, f, ctx := setup(t)
	plant := c.Node(f.Plant)
	flat := func(res []opcua.BrowseWithDepthResult) []walkStep {
		out := make([]walkStep, len(res))
		for i, r := range res {
			out[i] = walkStep{r.Depth, r.Ref.NodeID.NodeID.String()}
		}
		return out
	}
	s := func(depth int, n *ua.NodeID) walkStep { return walkStep{depth, n.String()} }

	res, err := plant.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: -1, IncludeSubtypes: true})
	require.NoError(t, err)
	require.Equal(t, []walkStep{
		s(0, f.Line1), s(1, f.Motor), s(2, f.MotorSpeed), s(2, f.MotorSerial),
		s(1, f.Line2), s(2, f.Line2Speed),
		s(0, f.Line2), s(1, f.Line2Speed),
	}, flat(res))

	// Only HasComponent, exact type: the Organizes edge and the property drop out.
	res, err = plant.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: -1, RefType: id.HasComponent})
	require.NoError(t, err)
	require.Equal(t, []walkStep{
		s(0, f.Line1), s(1, f.Motor), s(2, f.MotorSpeed),
		s(0, f.Line2), s(1, f.Line2Speed),
	}, flat(res))

	// Depth limit and node class mask.
	res, err = plant.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: 0, IncludeSubtypes: true})
	require.NoError(t, err)
	require.Equal(t, []walkStep{s(0, f.Line1), s(0, f.Line2)}, flat(res))

	res, err = c.Node(f.Motor).BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{
		MaxDepth: -1, IncludeSubtypes: true, NodeClassMask: ua.NodeClassVariable,
	})
	require.NoError(t, err)
	require.Equal(t, []walkStep{s(0, f.MotorSpeed), s(0, f.MotorSerial)}, flat(res))

	// Inverse direction climbs towards the root.
	res, err = c.Node(f.MotorSpeed).BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{
		MaxDepth: 1, RefType: id.HasComponent, Direction: ua.BrowseDirectionInverse,
	})
	require.NoError(t, err)
	require.Equal(t, []walkStep{s(0, f.Motor), s(1, f.Line1)}, flat(res))

	_, err = c.Node(ua.NewNumericNodeID(77, 1)).BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{IncludeSubtypes: true})
	require.NoError(t, err, "a browse error status of the start node is not a transport error")
}

func TestNode_ReferenceHelpers(t *testing.T) {
	c, f, ctx := setup(t)
	motor := c.Node(f.Motor)
	require.Equal(t, f.Motor.String(), motor.String())

	nodeIDs := func(nodes []*opcua.Node) []string {
		out := make([]string, len(nodes))
		for i, n := range nodes {
			out[i] = n.ID.String()
		}
		return out
	}

	children, err := motor.Children(ctx, 0, ua.NodeClassAll)
	require.NoError(t, err)
	require.Equal(t, ids(f.MotorSpeed, f.MotorSerial), nodeIDs(children))

	children, err = motor.Children(ctx, id.HasProperty, ua.NodeClassVariable)
	require.NoError(t, err)
	require.Equal(t, ids(f.MotorSerial), nodeIDs(children))

	parents, err := motor.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionInverse, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.Equal(t, ids(f.Line1), nodeIDs(parents))

	all, err := motor.ReferencedNodes(ctx, 0, ua.BrowseDirectionBoth, 0, true)
	require.NoError(t, err)
	require.ElementsMatch(t, ids(f.Line1, f.MotorSpeed, f.MotorSerial), nodeIDs(all))

	refs, err := motor.References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "Speed", refs[0].BrowseName.Name)
	require.Equal(t, ua.NodeClassVariable, refs[0].NodeClass)

	var streamed []string
	for ref, err := range motor.BrowseAll(ctx, id.Aggregates, ua.BrowseDirectionForward, ua.NodeClassVariable, true) {
		require.NoError(t, err)
		streamed = append(streamed, ref.NodeID.NodeID.String())
	}
	require.Equal(t, ids(f.MotorSpeed, f.MotorSerial), streamed)

	// Client.BrowseAll returns the forward hierarchical references.
	viaClient, err := c.BrowseAll(ctx, f.Motor)
	require.NoError(t, err)
	require.Equal(t, ids(f.MotorSpeed, f.MotorSerial), targets(viaClient))

	// TypeDefinition follows HasTypeDefinition.
	td, err := c.Node(f.CustomSubVar).TypeDefinition(ctx)
	require.NoError(t, err)
	require.Equal(t, f.CustomVarSubType.String(), td.String())
	td, err = c.Node(f.MotorSpeed).TypeDefinition(ctx)
	require.NoError(t, err)
	require.Nil(t, td, "a node without HasTypeDefinition has no type definition")

	// NodeFromExpandedNodeID round-trips a browse result into a usable node.
	n := c.NodeFromExpandedNodeID(refs[0].NodeID)
	v, err := n.Value(ctx)
	require.NoError(t, err)
	require.Equal(t, float64(1500), v.Value())
}

func TestNode_AttributeHelpers(t *testing.T) {
	c, f, ctx := setup(t)
	speed := c.Node(f.MotorSpeed)

	nc, err := speed.NodeClass(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, nc)

	bn, err := speed.BrowseName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Speed", bn.Name)

	dn, err := speed.DisplayName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Speed", dn.Text)

	desc, err := speed.Description(ctx)
	require.NoError(t, err)
	require.Empty(t, desc.Text)

	dt, err := speed.DataType(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NewNumericNodeID(0, id.Double).String(), dt.String())

	v, err := speed.Value(ctx)
	require.NoError(t, err)
	require.Equal(t, float64(1500), v.Value())

	av, err := speed.Attribute(ctx, ua.AttributeIDBrowseName)
	require.NoError(t, err)
	require.Equal(t, "Speed", av.Value().(*ua.QualifiedName).Name)

	_, err = speed.Attribute(ctx, ua.AttributeIDIsAbstract)
	require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid)

	dvs, err := speed.Attributes(ctx, ua.AttributeIDNodeClass, ua.AttributeIDIsAbstract, ua.AttributeIDValue)
	require.NoError(t, err)
	require.Len(t, dvs, 3)
	require.Equal(t, int32(ua.NodeClassVariable), dvs[0].Value.Value())
	require.Equal(t, ua.StatusBadAttributeIDInvalid, dvs[1].Status)
	require.Equal(t, float64(1500), dvs[2].Value.Value())

	// Access level helpers on the access-controlled fixture nodes.
	for _, tc := range []struct {
		node        *ua.NodeID
		level       ua.AccessLevelType
		read, write bool
	}{
		{f.Writable, ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite, true, true},
		{f.ReadOnly, ua.AccessLevelTypeCurrentRead, true, false},
	} {
		n := c.Node(tc.node)
		al, err := n.AccessLevel(ctx)
		require.NoError(t, err)
		require.Equal(t, tc.level, al)
		ual, err := n.UserAccessLevel(ctx)
		require.NoError(t, err)
		require.Equal(t, tc.level, ual)

		ok, err := n.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentRead)
		require.NoError(t, err)
		require.Equal(t, tc.read, ok)
		ok, err = n.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentWrite)
		require.NoError(t, err)
		require.Equal(t, tc.write, ok)
		ok, err = n.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentWrite)
		require.NoError(t, err)
		require.Equal(t, tc.write, ok)
		ok, err = n.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
		require.NoError(t, err)
		require.Equal(t, tc.read && tc.write, ok)
	}
	// A node that may not be read does not even reveal its access level.
	_, err = c.Node(f.NoAccess).AccessLevel(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	// Errors for a node that does not exist.
	ghost := c.Node(ua.NewStringNodeID(f.NSIndex, "Ghost"))
	_, err = ghost.NodeClass(ctx)
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	_, err = ghost.BrowseName(ctx)
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	_, err = ghost.Value(ctx)
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
}

func TestNode_Summary(t *testing.T) {
	c, f, ctx := setup(t)

	s, err := c.Node(f.CustomVarA).Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, f.CustomVarA.String(), s.NodeID.String())
	require.Equal(t, ua.NodeClassVariable, s.NodeClass)
	require.Equal(t, "CustomVarA", s.BrowseName.Name)
	require.Equal(t, "CustomVarA", s.DisplayName.Text)
	require.NotNil(t, s.Description)
	require.Equal(t, ua.NewNumericNodeID(0, id.Int32).String(), s.DataType.String())
	require.NotNil(t, s.Value)
	require.Equal(t, int32(10), s.Value.Value.Value())
	require.Equal(t, f.CustomVarType.String(), s.TypeDefinition.String())

	s, err = c.Node(f.ReadOnly).Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.AccessLevelTypeCurrentRead, s.AccessLevel)
	require.Equal(t, ua.AccessLevelTypeCurrentRead, s.UserAccessLevel)
	require.Equal(t, int32(20), s.Value.Value.Value())

	// An object has no value or data type.
	s, err = c.Node(f.Motor).Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassObject, s.NodeClass)
	require.Equal(t, "Motor", s.BrowseName.Name)
	require.Nil(t, s.Value)
	require.Nil(t, s.TypeDefinition)
}

// TestView_MapNamespace serves a namespace backed by a plain Go map and
// verifies it through browse, read, write and subscriptions.
func TestView_MapNamespace(t *testing.T) {
	var mns *server.MapNamespace
	c, _, _, _ := setupWith(t, func(srv *server.Server, _ *testutil.Fixture) {
		mns = server.NewMapNamespace(srv, "http://otfabric.com/conformance/map")
		mns.Data["Text"] = "hello"
		mns.Data["Count"] = int32(7)
		mns.Data["Ratio"] = 0.25
		mns.Data["Flag"] = true
		mns.Data["Big"] = 9_000_000_000 // a Go int is served as Int64
	})
	ctx := context.Background()

	nsIdx, err := c.FindNamespace(ctx, "http://otfabric.com/conformance/map")
	require.NoError(t, err)
	require.Equal(t, mns.ID(), nsIdx)
	key := func(k string) *ua.NodeID { return ua.NewStringNodeID(nsIdx, k) }

	t.Run("Browse", func(t *testing.T) {
		refs, err := c.Node(ua.NewNumericNodeID(nsIdx, id.ObjectsFolder)).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
		require.NoError(t, err)
		var names []string
		for _, r := range refs {
			names = append(names, r.BrowseName.Name)
			require.Equal(t, ua.NodeClassVariable, r.NodeClass)
		}
		sort.Strings(names)
		require.Equal(t, []string{"Big", "Count", "Flag", "Ratio", "Text"}, names)
	})

	t.Run("ReadValuesAndTypes", func(t *testing.T) {
		for k, want := range map[string]struct {
			value    any
			dataType uint32
		}{
			"Text":  {"hello", id.String},
			"Count": {int32(7), id.Int32},
			"Ratio": {0.25, id.Double},
			"Flag":  {true, id.Boolean},
			"Big":   {int64(9_000_000_000), id.Int64},
		} {
			n := c.Node(key(k))
			v, err := n.Value(ctx)
			require.NoError(t, err, k)
			require.Equal(t, want.value, v.Value(), k)
			dt, err := n.DataType(ctx)
			require.NoError(t, err, k)
			require.Equal(t, want.dataType, dt.IntID(), "data type of %s", k)
			nc, err := n.NodeClass(ctx)
			require.NoError(t, err)
			require.Equal(t, ua.NodeClassVariable, nc)
			bn, err := n.BrowseName(ctx)
			require.NoError(t, err)
			require.Equal(t, k, bn.Name)
		}
		dv, err := c.ReadValue(ctx, key("Missing"))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	})

	t.Run("WriteReachesTheMap", func(t *testing.T) {
		st, err := c.WriteNodeValue(ctx, key("Count"), int32(8))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
		require.Equal(t, int32(8), mns.GetValue("Count"))
	})

	t.Run("ServerSideChangeNotifiesSubscribers", func(t *testing.T) {
		sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(key("Text")).Start(ctx)
		require.NoError(t, err)
		defer func() { _ = sub.Cancel(ctx) }()
		awaitValue(t, ch, 0, "hello")

		mns.SetValue("Text", "changed by the application")
		awaitValue(t, ch, 0, "changed by the application")
	})
}
