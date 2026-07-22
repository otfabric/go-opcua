//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go Browse ResultMask bit companions.
// COVERAGE.md: browse / browse.result-mask

package interop

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// TestGoServer_BrowseResultMaskBits verifies each ResultMask field bit and a
// combined mask.
func TestGoServer_BrowseResultMaskBits(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	objectsID := ua.NewNumericNodeID(nsIdx, id.ObjectsFolder)

	browse := func(mask ua.BrowseResultMask) []*ua.ReferenceDescription {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{
			NodesToBrowse: []*ua.BrowseDescription{{
				NodeID: objectsID, BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
				IncludeSubtypes: true, ResultMask: uint32(mask),
			}},
		})
		if err != nil {
			t.Fatalf("Browse: %v", err)
		}
		return resp.Results[0].References
	}

	t.Run("BrowseNameOnly", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskBrowseName)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		r := refs[0]
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Error("BrowseName missing")
		}
		if r.DisplayName != nil && r.DisplayName.Text != "" {
			t.Error("DisplayName should be cleared")
		}
		if r.NodeClass != 0 {
			t.Error("NodeClass should be zero")
		}
	})

	t.Run("NodeClassOnly", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskNodeClass)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		if refs[0].NodeClass == 0 {
			t.Error("NodeClass missing")
		}
		if refs[0].BrowseName != nil && refs[0].BrowseName.Name != "" {
			t.Error("BrowseName should be cleared")
		}
	})

	t.Run("CombinedBrowseNameNodeClass", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskBrowseName | ua.BrowseResultMaskNodeClass)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		r := refs[0]
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Error("BrowseName missing")
		}
		if r.NodeClass == 0 {
			t.Error("NodeClass missing")
		}
		if r.DisplayName != nil && r.DisplayName.Text != "" {
			t.Error("DisplayName should be cleared")
		}
	})
}
