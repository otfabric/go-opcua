// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// sharedChildFilter is a filter whose element i is Or(element i+1, element
// i+1), ending in a FALSE comparison: 2^n paths over n elements.
func sharedChildFilter(n int) *ua.ContentFilter {
	el := make([]*ua.ContentFilterElement, n)
	for i := 0; i < n-1; i++ {
		op := ua.NewExtensionObject(&ua.ElementOperand{Index: uint32(i + 1)})
		el[i] = &ua.ContentFilterElement{FilterOperator: ua.FilterOperatorOr, FilterOperands: []*ua.ExtensionObject{op, op}}
	}
	el[n-1] = &ua.ContentFilterElement{FilterOperator: ua.FilterOperatorEquals, FilterOperands: []*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(int32(1))}),
		ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(int32(2))}),
	}}
	return &ua.ContentFilter{Elements: el}
}

func TestContentFilterSharedChildLinear(t *testing.T) {
	srv := newTestServer()
	f := sharedChildFilter(64)
	_, ok := validateFilter(f)
	require.True(t, ok)
	node := srv.Node(ua.NewNumericNodeID(0, id.Server))

	done := make(chan struct{})
	var q tvl
	var e bool
	go func() {
		defer close(done)
		q = evalFilter(srv, node, f)
		e = srv.evalEventFilter(&BaseEvent{EventType: ua.NewNumericNodeID(0, id.BaseEventType)}, f)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("filter evaluation is not linear")
	}
	require.Equal(t, tvlFalse, q)
	require.False(t, e)
}

func TestFilterElementLimit(t *testing.T) {
	big := sharedChildFilter(maxFilterElements + 1)
	_, ok := validateFilter(big)
	require.False(t, ok)
	_, ok = validateFilter(sharedChildFilter(maxFilterElements))
	require.True(t, ok)

	srv := newTestServer()
	sel := []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}}
	_, _, st := srv.validateEventFilter(&ua.EventFilter{SelectClauses: sel, WhereClause: big})
	require.Equal(t, ua.StatusBadEventFilterInvalid, st)
}
