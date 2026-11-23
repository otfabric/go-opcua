// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// faulty passes the calls of Inspect to a client and spoils the call
// number fail: with an error, or with a response of the wrong length.
type faulty struct {
	client
	calls, fail int
	short       bool // return a response without results instead of an error
}

var errFault = errors.New("injected fault")

func (f *faulty) hit() bool { f.calls++; return f.calls == f.fail }

func (f *faulty) NamespaceArray(ctx context.Context) ([]string, error) {
	if f.hit() {
		return nil, errFault
	}
	return f.client.NamespaceArray(ctx)
}

func (f *faulty) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	if f.hit() {
		if f.short {
			return &ua.BrowseResponse{}, nil
		}
		return nil, errFault
	}
	return f.client.Browse(ctx, req)
}

func (f *faulty) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	if f.hit() {
		if f.short {
			return &ua.BrowseNextResponse{}, nil
		}
		return nil, errFault
	}
	return f.client.BrowseNext(ctx, req)
}

func (f *faulty) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	if f.hit() {
		if f.short {
			return &ua.ReadResponse{}, nil
		}
		return nil, errFault
	}
	return f.client.Read(ctx, req)
}

// TestInspectPaged checks that a server returning one reference per
// Browse, with continuation points, gives the same report.
func TestInspectPaged(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()
	want, err := inspect(ctx, c, Limits{}, 0)
	require.NoError(t, err)
	got, err := inspect(ctx, c, Limits{}, 1)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// MaxChildren 1 reads at most 4 references of a node: the rest is
	// left with its continuation point released.
	got, err = inspect(ctx, c, Limits{MaxChildren: 1}, 1)
	require.NoError(t, err)
	assert.True(t, got.Truncated)
}

// TestInspectFaults fails each service call of an inspection in turn,
// paged so that BrowseNext is among them: Inspect returns ErrInspect or,
// for a call whose failure it tolerates, a report; it never panics.
func TestInspectFaults(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()
	count := &faulty{client: c, fail: -1}
	_, err := inspect(ctx, count, Limits{}, 2)
	require.NoError(t, err)
	total := count.calls
	require.Greater(t, total, 20)

	failed := 0
	for _, short := range []bool{false, true} {
		for k := 1; k <= total; k++ {
			f := &faulty{client: c, fail: k, short: short}
			r, err := inspect(ctx, f, Limits{}, 2)
			if err != nil {
				require.ErrorIs(t, err, ErrInspect, "call %d", k)
				require.Nil(t, r)
				failed++
				continue
			}
			require.NotNil(t, r, "call %d", k)
		}
	}
	assert.Greater(t, failed, total, "most faults end the inspection")
}

// readSizes passes the calls of Inspect to a client and records the
// number of nodes of every Read.
type readSizes struct {
	client
	sizes []int
}

func (r *readSizes) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	r.sizes = append(r.sizes, len(req.NodesToRead))
	return r.client.Read(ctx, req)
}

// TestInspectMaxNodesPerRead checks that Inspect splits its Reads by the
// MaxNodesPerRead of the server (Part 5 §6.3.11).
func TestInspectMaxNodesPerRead(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()
	want, err := inspect(ctx, c, Limits{}, 0)
	require.NoError(t, err)
	unlimited := &readSizes{client: c}
	_, err = inspect(ctx, unlimited, Limits{}, 0)
	require.NoError(t, err)
	require.Greater(t, slices.Max(unlimited.sizes), 2, "the test needs Reads of more than 2 nodes")

	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(fxtest.AppNS),
		server.WithOperationLimits(server.OperationalLimits{MaxNodesPerRead: 2, MaxNodesPerBrowse: 1}),
	)
	require.NoError(t, err)
	_, err = fxtest.Prepare(srv, false)
	require.NoError(t, err)
	limited := &readSizes{client: StartTestServer(t, srv)}
	got, err := inspect(ctx, limited, Limits{}, 0)
	require.NoError(t, err)
	assert.LessOrEqual(t, slices.Max(limited.sizes), 2)
	assert.Equal(t, want, got)
}
