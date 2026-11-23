// SPDX-License-Identifier: MIT

package uafx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// supertypeFault passes the calls of Inspect to a client and spoils every
// Browse for a supertype (inverse HasSubtype) in the way of mode.
type supertypeFault struct {
	uafx.InspectClient
	mode    string
	spoiled int
}

func (f *supertypeFault) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	d := req.NodesToBrowse[0]
	if d.BrowseDirection != ua.BrowseDirectionInverse || !d.ReferenceTypeID.Equal(ua.NewNumericNodeID(0, id.HasSubtype)) {
		return f.InspectClient.Browse(ctx, req)
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
// tell ends the inspection with uafx.ErrInspect. The endpoint ToLine is a
// PubSubConnectionEndpoint: whether it is a ConnectionEndpoint takes a
// supertype lookup, and a report without it would hide the fault.
func TestInspectSupertypeFaults(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()
	want, err := uafx.InspectWith(ctx, c, uafx.Limits{}, 0)
	require.NoError(t, err)
	require.Len(t, want.AutomationComponents[0].FunctionalEntities[0].ConnectionEndpoints, 2)

	for _, mode := range []string{"error", "status", "count"} {
		f := &supertypeFault{InspectClient: c, mode: mode}
		r, err := uafx.InspectWith(ctx, f, uafx.Limits{}, 0)
		require.Positive(t, f.spoiled, mode)
		require.ErrorIs(t, err, uafx.ErrInspect, mode)
		assert.Nil(t, r, mode)
	}
}
