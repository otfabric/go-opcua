// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestApplyBrowseResultMask_Encode(t *testing.T) {
	rf := &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
		IsForward:       true,
		NodeID:          ua.NewStringExpandedNodeID(1, "x"),
		BrowseName:      &ua.QualifiedName{NamespaceIndex: 1, Name: "x"},
		DisplayName:     &ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: "x"},
		NodeClass:       ua.NodeClassVariable,
		TypeDefinition:  ua.NewNumericExpandedNodeID(0, id.BaseDataVariableType),
	}
	masked := applyBrowseResultMask(rf, uint32(ua.BrowseResultMaskBrowseName))
	if _, err := ua.Encode(masked); err != nil {
		t.Fatalf("encode masked ref: %v", err)
	}
	br := &ua.BrowseResult{StatusCode: ua.StatusOK, References: []*ua.ReferenceDescription{masked}}
	if _, err := ua.Encode(br); err != nil {
		t.Fatalf("encode browse result: %v", err)
	}
}
