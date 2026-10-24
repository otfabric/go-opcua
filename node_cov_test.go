// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

func TestNodeCovAttributeAccessors(t *testing.T) {
	c, f, ctx := setupFixture(t)

	n := c.Node(f.Writable)
	require.Equal(t, f.Writable.String(), n.String())

	nc, err := n.NodeClass(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, nc)

	bn, err := n.BrowseName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Writable", bn.Name)

	dn, err := n.DisplayName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Writable", dn.Text)

	desc, err := n.Description(ctx)
	require.NoError(t, err)
	require.NotNil(t, desc)

	al, err := n.AccessLevel(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite, al)

	ual, err := n.UserAccessLevel(ctx)
	require.NoError(t, err)
	require.Equal(t, al, ual)

	ok, err := n.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentWrite)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = n.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	require.NoError(t, err)
	require.True(t, ok)

	ro := c.Node(f.ReadOnly)
	ok, err = ro.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentWrite)
	require.NoError(t, err)
	require.False(t, ok, "ReadOnly must not report write access")
	ok, err = ro.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentWrite)
	require.NoError(t, err)
	require.False(t, ok)

	dt, err := n.DataType(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NewNumericNodeID(0, id.Int32), dt)

	v, err := n.Value(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(10), v.Value())
}

// Every attribute accessor reports the per-node status of the server as its
// error, here for a node that does not exist.
func TestNodeCovAccessorErrors(t *testing.T) {
	c, f, ctx := setupFixture(t)
	n := c.Node(ua.NewStringNodeID(f.NSIndex, "does-not-exist"))

	calls := map[string]func() error{
		"NodeClass":          func() error { _, err := n.NodeClass(ctx); return err },
		"BrowseName":         func() error { _, err := n.BrowseName(ctx); return err },
		"Description":        func() error { _, err := n.Description(ctx); return err },
		"DisplayName":        func() error { _, err := n.DisplayName(ctx); return err },
		"AccessLevel":        func() error { _, err := n.AccessLevel(ctx); return err },
		"HasAccessLevel":     func() error { _, err := n.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentRead); return err },
		"UserAccessLevel":    func() error { _, err := n.UserAccessLevel(ctx); return err },
		"HasUserAccessLevel": func() error { _, err := n.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentRead); return err },
		"DataType":           func() error { _, err := n.DataType(ctx); return err },
		"Value":              func() error { _, err := n.Value(ctx); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(), ua.StatusBadNodeIDUnknown)
		})
	}
}

// A closed client fails every node operation with BadServerNotConnected
// instead of hanging or panicking.
func TestNodeCovClosedClient(t *testing.T) {
	c, f, ctx := setupFixture(t)
	require.NoError(t, c.Close(ctx))
	n := c.Node(f.Plant)

	_, err := n.Summary(ctx)
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	_, err = n.Attributes(ctx, ua.AttributeIDValue)
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	_, err = n.TypeDefinition(ctx)
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	_, err = n.Children(ctx, 0, ua.NodeClassAll)
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	_, err = n.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: -1})
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	_, err = n.TranslateBrowsePathInNamespaceToNodeID(ctx, f.NSIndex, "Line1")
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)

	var walkErr error
	count := 0
	for _, err := range n.Walk(ctx) {
		count++
		walkErr = err
	}
	require.Equal(t, 1, count, "a failing walk yields exactly the error")
	require.ErrorIs(t, walkErr, ua.StatusBadServerNotConnected)
}

func TestNodeCovSummaryVariable(t *testing.T) {
	c, f, ctx := setupFixture(t)

	s, err := c.Node(f.Writable).Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, f.Writable, s.NodeID)
	require.Equal(t, ua.NodeClassVariable, s.NodeClass)
	require.Equal(t, "Writable", s.BrowseName.Name)
	require.Equal(t, "Writable", s.DisplayName.Text)
	require.NotNil(t, s.Value)
	require.Equal(t, int32(10), s.Value.Value.Value())
	require.Equal(t, ua.NewNumericNodeID(0, id.Int32), s.DataType)
	require.Equal(t, ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite, s.AccessLevel)
	require.Equal(t, s.AccessLevel, s.UserAccessLevel)

	// A folder has no Value, DataType or AccessLevel: those stay unset.
	s, err = c.Node(f.Plant).Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassObject, s.NodeClass)
	require.Equal(t, "Plant", s.BrowseName.Name)
	require.Nil(t, s.Value)
	require.Nil(t, s.DataType)
	require.Zero(t, s.AccessLevel)
}

func TestNodeCovChildrenAndReferencedNodes(t *testing.T) {
	c, f, ctx := setupFixture(t)

	// refs 0 means hierarchical references
	children, err := c.Node(f.Plant).Children(ctx, 0, ua.NodeClassAll)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{f.Line1.String(), f.Line2.String()}, nodeIDStrings(children))

	// refs 0 means all references; inverse from Line1 leads back to Plant
	parents, err := c.Node(f.Line1).ReferencedNodes(ctx, 0, ua.BrowseDirectionInverse, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.Contains(t, nodeIDStrings(parents), f.Plant.String())

	// refType 0 and mask 0 mean all references of all node classes
	refs, err := c.Node(f.Motor).References(ctx, 0, ua.BrowseDirectionForward, 0, true)
	require.NoError(t, err)
	var names []string
	for _, r := range refs {
		names = append(names, r.BrowseName.Name)
	}
	require.Contains(t, names, "Speed")
	require.Contains(t, names, "SerialNumber")

	// a node without HasTypeDefinition reference has no type definition
	n := c.Node(ua.NewStringNodeID(f.NSIndex, "does-not-exist"))
	td, err := n.TypeDefinition(ctx)
	require.NoError(t, err)
	require.Nil(t, td)
}

func nodeIDStrings(nodes []*opcua.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.ID.String())
	}
	return out
}

// Line2 is reachable from Plant directly and through Line1: Walk yields it
// twice, WalkLimitDedup once.
func TestNodeCovWalkDedup(t *testing.T) {
	c, f, ctx := setupFixture(t)
	n := c.Node(f.Plant)

	count := func(seq func(func(opcua.WalkResult, error) bool)) map[string]int {
		seen := map[string]int{}
		for wr, err := range seq {
			require.NoError(t, err)
			seen[wr.Ref.NodeID.NodeID.String()]++
		}
		return seen
	}

	all := count(n.Walk(ctx))
	require.Equal(t, 2, all[f.Line2.String()])
	require.Equal(t, 2, all[f.Line2Speed.String()])

	dedup := count(n.WalkLimitDedup(ctx, -1))
	for k, v := range dedup {
		require.Equal(t, 1, v, "node %s yielded more than once", k)
	}
	require.Len(t, dedup, len(all))
	require.Contains(t, dedup, f.MotorSpeed.String())

	// the start node itself is never yielded
	require.NotContains(t, dedup, f.Plant.String())

	// stopping early stops the walk
	n1 := 0
	for _, err := range n.WalkLimitDedup(ctx, -1) {
		require.NoError(t, err)
		n1++
		break
	}
	require.Equal(t, 1, n1)
}

func TestNodeCovBrowseWithDepth(t *testing.T) {
	c, f, ctx := setupFixture(t)
	n := c.Node(f.Plant)

	// any negative MaxDepth means unlimited
	unlimited, err := n.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: -7, IncludeSubtypes: true})
	require.NoError(t, err)
	minusOne, err := n.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: -1, IncludeSubtypes: true})
	require.NoError(t, err)
	require.Len(t, unlimited, len(minusOne))
	maxDepth := 0
	for _, r := range unlimited {
		maxDepth = max(maxDepth, r.Depth)
	}
	require.Equal(t, 2, maxDepth, "Plant/Line1/Motor/Speed is three levels deep")

	// depth 0 returns the direct children only
	direct, err := n.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: 0, IncludeSubtypes: true})
	require.NoError(t, err)
	require.Len(t, direct, 2)
}

// browseHandler answers each BrowseDescription with the result fn returns.
func browseHandler(fn func(d *ua.BrowseDescription) *ua.BrowseResult) server.Handler {
	return respond(func(r ua.Request) ua.Response {
		req := r.(*ua.BrowseRequest)
		res := &ua.BrowseResponse{ResponseHeader: okHeader(req)}
		for _, d := range req.NodesToBrowse {
			res.Results = append(res.Results, fn(d))
		}
		return res
	})
}

func refTo(name string) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
		IsForward:       true,
		NodeID:          ua.NewExpandedNodeID(ua.NewStringNodeID(1, name), "", 0),
		BrowseName:      &ua.QualifiedName{NamespaceIndex: 1, Name: name},
		DisplayName:     ua.NewLocalizedText(name),
		NodeClass:       ua.NodeClassObject,
		TypeDefinition:  ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.FolderType), "", 0),
	}
}

func refNames(refs []*ua.ReferenceDescription) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.BrowseName.Name)
	}
	return out
}

// A server that pages references with continuation points: Browse returns
// "a" and a continuation point, BrowseNext returns "b" and "c".
func pagingHandlers(next server.Handler) map[uint16]server.Handler {
	return map[uint16]server.Handler{
		id.BrowseRequestEncodingDefaultBinary: browseHandler(func(d *ua.BrowseDescription) *ua.BrowseResult {
			if d.NodeID.StringID() != "root" {
				return &ua.BrowseResult{StatusCode: ua.StatusOK}
			}
			return &ua.BrowseResult{
				StatusCode:        ua.StatusOK,
				ContinuationPoint: []byte("cp1"),
				References:        []*ua.ReferenceDescription{refTo("a")},
			}
		}),
		id.BrowseNextRequestEncodingDefaultBinary: next,
	}
}

func browseNextOK() server.Handler {
	return respond(func(r ua.Request) ua.Response {
		req := r.(*ua.BrowseNextRequest)
		return &ua.BrowseNextResponse{
			ResponseHeader: okHeader(req),
			Results: []*ua.BrowseResult{{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{refTo("b"), refTo("c")},
			}},
		}
	})
}

func browseNextEmpty() server.Handler {
	return respond(func(r ua.Request) ua.Response {
		return &ua.BrowseNextResponse{ResponseHeader: okHeader(r)}
	})
}

func browseNextFault() server.Handler {
	return func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) {
		return nil, ua.StatusBadContinuationPointInvalid
	}
}

func TestNodeCovContinuationPoints(t *testing.T) {
	ctx := context.Background()
	root := ua.NewStringNodeID(1, "root")

	t.Run("followed", func(t *testing.T) {
		_, url := newScriptedServer(t, pagingHandlers(browseNextOK()))
		c := connectCovClient(t, url)
		n := c.Node(root)

		refs, err := n.References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
		require.NoError(t, err)
		require.Equal(t, []string{"a", "b", "c"}, refNames(refs))

		var streamed []*ua.ReferenceDescription
		for ref, err := range n.BrowseAll(ctx, 0, ua.BrowseDirectionForward, 0, true) {
			require.NoError(t, err)
			streamed = append(streamed, ref)
		}
		require.Equal(t, []string{"a", "b", "c"}, refNames(streamed))

		// stop in the first page and in a continuation page
		for _, stopAfter := range []int{1, 2} {
			got := 0
			for _, err := range n.BrowseAll(ctx, 0, ua.BrowseDirectionForward, 0, true) {
				require.NoError(t, err)
				got++
				if got == stopAfter {
					break
				}
			}
			require.Equal(t, stopAfter, got)
		}

		all, err := c.BrowseAll(ctx, root)
		require.NoError(t, err)
		require.Equal(t, []string{"a", "b", "c"}, refNames(all))
	})

	t.Run("BrowseNext fails", func(t *testing.T) {
		_, url := newScriptedServer(t, pagingHandlers(browseNextFault()))
		c := connectCovClient(t, url)
		n := c.Node(root)

		_, err := n.References(ctx, 0, ua.BrowseDirectionForward, 0, true)
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)

		var got []string
		var last error
		for ref, err := range n.BrowseAll(ctx, 0, ua.BrowseDirectionForward, 0, true) {
			if err != nil {
				last = err
				continue
			}
			got = append(got, ref.BrowseName.Name)
		}
		require.Equal(t, []string{"a"}, got)
		require.ErrorIs(t, last, ua.StatusBadContinuationPointInvalid)

		refs, err := c.BrowseAll(ctx, root)
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)
		require.Equal(t, []string{"a"}, refNames(refs), "references before the error are returned")
	})

	t.Run("BrowseNext without results", func(t *testing.T) {
		_, url := newScriptedServer(t, pagingHandlers(browseNextEmpty()))
		c := connectCovClient(t, url)
		n := c.Node(root)

		_, err := n.References(ctx, 0, ua.BrowseDirectionForward, 0, true)
		require.ErrorIs(t, err, ua.StatusBadUnknownResponse)

		var last error
		for _, err := range n.BrowseAll(ctx, 0, ua.BrowseDirectionForward, 0, true) {
			last = err
		}
		require.ErrorIs(t, last, ua.StatusBadUnknownResponse)
	})
}

func TestNodeCovBrowseWithoutResults(t *testing.T) {
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.BrowseRequestEncodingDefaultBinary: respond(func(r ua.Request) ua.Response {
			return &ua.BrowseResponse{ResponseHeader: okHeader(r)}
		}),
	})
	c := connectCovClient(t, url)
	n := c.Node(ua.NewStringNodeID(1, "root"))

	_, err := n.References(ctx, 0, ua.BrowseDirectionForward, 0, true)
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)

	var last error
	count := 0
	for _, err := range n.BrowseAll(ctx, 0, ua.BrowseDirectionForward, 0, true) {
		count++
		last = err
	}
	require.Equal(t, 1, count)
	require.ErrorIs(t, last, ua.StatusBadUnknownResponse)
}

// A Browse that fails below the start node fails the whole recursive browse.
func TestNodeCovBrowseWithDepthChildError(t *testing.T) {
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.BrowseRequestEncodingDefaultBinary: func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
			req := r.(*ua.BrowseRequest)
			if req.NodesToBrowse[0].NodeID.StringID() != "root" {
				return nil, ua.StatusBadTooManyOperations
			}
			return &ua.BrowseResponse{
				ResponseHeader: okHeader(req),
				Results:        []*ua.BrowseResult{{References: []*ua.ReferenceDescription{refTo("child")}}},
			}, nil
		},
	})
	c := connectCovClient(t, url)

	res, err := c.Node(ua.NewStringNodeID(1, "root")).BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: 3})
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
	require.Len(t, res, 1, "the reference found before the failure is kept")
	require.Equal(t, "child", res[0].Ref.BrowseName.Name)
}

func TestNodeCovAttributeWithoutResults(t *testing.T) {
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.ReadRequestEncodingDefaultBinary: respond(func(r ua.Request) ua.Response {
			req := r.(*ua.ReadRequest)
			if req.NodesToRead[0].NodeID.IntID() == id.ServerNamespaceArray {
				return &ua.ReadResponse{ResponseHeader: okHeader(req), Results: []*ua.DataValue{valueDV([]string{"urn:x"})}}
			}
			return &ua.ReadResponse{ResponseHeader: okHeader(req)}
		}),
	})
	c := connectCovClient(t, url)

	_, err := c.Node(ua.NewStringNodeID(1, "x")).Value(ctx)
	require.ErrorIs(t, err, ua.StatusBadUnexpectedError)
}

// A server that returns attribute values of the wrong type gets an error,
// not a panic.
func TestNodeCovAttributeWrongType(t *testing.T) {
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.ReadRequestEncodingDefaultBinary: readHandler(func(*ua.ReadValueID) *ua.DataValue {
			return valueDV("not the expected type")
		}),
	})
	c := connectCovClient(t, url)
	n := c.Node(ua.NewStringNodeID(1, "x"))

	_, err := n.BrowseName(ctx)
	require.ErrorContains(t, err, "unexpected BrowseName type string")
	_, err = n.DisplayName(ctx)
	require.ErrorContains(t, err, "unexpected DisplayName type string")
	_, err = n.Description(ctx)
	require.ErrorContains(t, err, "unexpected Description type string")
	_, err = n.AccessLevel(ctx)
	require.ErrorContains(t, err, "unexpected AccessLevel type string")
	_, err = n.UserAccessLevel(ctx)
	require.ErrorContains(t, err, "unexpected UserAccessLevel type string")

	// Summary skips values of the wrong type
	s, err := n.Summary(ctx)
	require.NoError(t, err)
	require.Nil(t, s.BrowseName)
	require.Nil(t, s.DisplayName)
	require.Nil(t, s.Description)
	require.Zero(t, s.AccessLevel)
	require.Zero(t, s.UserAccessLevel)
	require.Equal(t, "not the expected type", s.Value.Value.Value())
}

func TestNodeCovTranslateBrowsePaths(t *testing.T) {
	c, f, ctx := setupFixture(t)

	// resolves from a custom start node, one namespace for all segments (the
	// fixture's browse names are in namespace 0)
	nid, err := c.Node(f.Plant).TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Line1.Motor.Speed")
	require.NoError(t, err)
	require.Equal(t, f.MotorSpeed, nid)

	// a path that does not resolve reports the status of the result
	_, err = c.Node(f.Plant).TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Line1.NoSuchChild")
	require.Error(t, err)
	require.ErrorIs(t, err, ua.StatusBadNoMatch)
}

func TestNodeCovTranslateBrowsePathsMalformed(t *testing.T) {
	ctx := context.Background()
	translate := func(fn func(r ua.Request) ua.Response) map[uint16]server.Handler {
		return map[uint16]server.Handler{id.TranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary: respond(fn)}
	}
	tests := []struct {
		name string
		fn   func(r ua.Request) ua.Response
	}{
		{"no results", func(r ua.Request) ua.Response {
			return &ua.TranslateBrowsePathsToNodeIDsResponse{ResponseHeader: okHeader(r)}
		}},
		{"no targets", func(r ua.Request) ua.Response {
			return &ua.TranslateBrowsePathsToNodeIDsResponse{
				ResponseHeader: okHeader(r),
				Results:        []*ua.BrowsePathResult{{StatusCode: ua.StatusOK}},
			}
		}},
		{"wrong response type", func(r ua.Request) ua.Response {
			return &ua.ReadResponse{ResponseHeader: okHeader(r)}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, url := newScriptedServer(t, translate(tt.fn))
			c := connectCovClient(t, url)
			nid, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Server")
			require.ErrorIs(t, err, ua.StatusBadUnexpectedError)
			require.Nil(t, nid)
		})
	}
}
