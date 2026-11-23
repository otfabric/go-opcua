// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// supertypeFault passes the calls of Inspect to a client and spoils every
// Browse for a supertype (inverse HasSubtype) in the way of mode.
type supertypeFault struct {
	client
	mode    string
	spoiled int
}

func (f *supertypeFault) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	d := req.NodesToBrowse[0]
	if d.BrowseDirection != ua.BrowseDirectionInverse || !d.ReferenceTypeID.Equal(ua.NewNumericNodeID(0, id.HasSubtype)) {
		return f.client.Browse(ctx, req)
	}
	f.spoiled++
	switch f.mode {
	case "error":
		return nil, ua.StatusBadTimeout
	case "status":
		return &ua.BrowseResponse{Results: []*ua.BrowseResult{{StatusCode: ua.StatusBadOutOfService}}}, nil
	default: // "count"
		return &ua.BrowseResponse{}, nil
	}
}

// TestInspectSupertypeFaults checks that a supertype the server cannot
// tell ends the inspection with ErrInspect. The endpoint ToLine is a
// PubSubConnectionEndpoint: whether it is a ConnectionEndpoint takes a
// supertype lookup, and a report without it would hide the fault.
func TestInspectSupertypeFaults(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()
	want, err := inspect(ctx, c, Limits{}, 0)
	require.NoError(t, err)
	require.Len(t, want.AutomationComponents[0].FunctionalEntities[0].ConnectionEndpoints, 2)

	for _, mode := range []string{"error", "status", "count"} {
		f := &supertypeFault{client: c, mode: mode}
		r, err := inspect(ctx, f, Limits{}, 0)
		require.Positive(t, f.spoiled, mode)
		require.ErrorIs(t, err, ErrInspect, mode)
		assert.Nil(t, r, mode)
	}
}

// pager answers every Browse with refs references and a continuation
// point, and records the BrowseNext calls.
type pager struct {
	client
	refs     int
	nexts    int
	releases []error // the state of the context of each release
	bounded  []bool  // whether it had a deadline
}

func (p *pager) Browse(context.Context, *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	res := &ua.BrowseResult{ContinuationPoint: []byte{1}}
	for i := range p.refs {
		res.References = append(res.References, &ua.ReferenceDescription{
			NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(9, uint32(i)), "", 0), BrowseName: &ua.QualifiedName{Name: "x"},
		})
	}
	return &ua.BrowseResponse{Results: []*ua.BrowseResult{res}}, nil
}

func (p *pager) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	if req.ReleaseContinuationPoints {
		_, ok := ctx.Deadline()
		p.releases = append(p.releases, ctx.Err())
		p.bounded = append(p.bounded, ok)
		return &ua.BrowseNextResponse{Results: []*ua.BrowseResult{{}}}, nil
	}
	p.nexts++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ua.BrowseNextResponse{Results: []*ua.BrowseResult{{}}}, nil
}

func newPagerInspector(p *pager, lim Limits) *inspector {
	return &inspector{c: p, lim: lim.withDefaults(), r: &Report{}, supertypes: map[string]*ua.NodeID{}, visited: map[string]bool{}}
}

// TestBrowseFirstPageLimit checks that a first page with more references
// than the limit is cut to it, and its continuation point released.
func TestBrowseFirstPageLimit(t *testing.T) {
	p := &pager{refs: 100}
	in := newPagerInspector(p, Limits{MaxChildren: 1}) // 4 references
	refs, err := in.browse(context.Background(), ua.NewNumericNodeID(9, 1), id.HierarchicalReferences, ua.NodeClassAll)
	require.NoError(t, err)
	assert.Len(t, refs, 4)
	assert.True(t, in.r.Truncated)
	assert.Zero(t, p.nexts, "no further page")
	assert.Len(t, p.releases, 1)
}

// TestBrowseReleaseAfterCancel checks that the continuation point is
// released with a context of its own when the context of the caller is
// done, which is why the browse returns early.
func TestBrowseReleaseAfterCancel(t *testing.T) {
	p := &pager{refs: 1}
	in := newPagerInspector(p, Limits{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := in.browse(ctx, ua.NewNumericNodeID(9, 1), id.HierarchicalReferences, ua.NodeClassAll)
	require.ErrorIs(t, err, ErrInspect)
	require.True(t, errors.Is(err, context.Canceled))
	require.Len(t, p.releases, 1)
	assert.NoError(t, p.releases[0], "the release has a live context")
	assert.True(t, p.bounded[0], "the release is bounded")
}
