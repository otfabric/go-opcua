// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// hostile is a server, seen through the client interface of Inspect, whose
// every answer is drawn from data: references to a small set of nodes (so
// that cycles and repeats are common), any type, continuation points that
// never end, bad statuses, wrong result counts and values of any type.
type hostile struct {
	data  []byte
	pos   int
	calls int
}

// maxHostileCalls is far above what Inspect may make with the Limits of the
// fuzz target; reaching it means a loop without bound.
const maxHostileCalls = 200_000

func (h *hostile) next() byte {
	if h.pos >= len(h.data) {
		return 0
	}
	b := h.data[h.pos]
	h.pos++
	return b
}

func (h *hostile) call(t interface{ Fatalf(string, ...any) }) {
	h.calls++
	if h.calls > maxHostileCalls {
		t.Fatalf("Inspect made more than %d calls", maxHostileCalls)
	}
}

// Namespace indexes of the hostile server: 1 DI, 2 Data, 3 AC, 4 CM.
var hostileNamespaces = []string{"http://opcfoundation.org/UA/", diid.NamespaceURI, fxdataid.NamespaceURI, fxacid.NamespaceURI, fxcmid.NamespaceURI}

var hostileNames = []string{
	"Assets", "FunctionalEntities", "ConnectionEndpoints", "Descriptors", "ComponentCapabilities",
	"AggregatedHealth", "ConformanceName", "EstablishConnections", "CloseConnections", "Status",
	"IsPersistent", "CleanupTimeout", "RelatedEndpoint", "Mode", "AuthorAssignedVersion",
	"OperationalHealth", "Manufacturer", "ConnectionConfigurationSets", "NamespaceUri",
	"NamespaceVersion", "NamespacePublicationDate", "X",
}

func (h *hostile) nodeID() *ua.NodeID {
	switch h.next() % 8 {
	case 0:
		return ua.NewNumericNodeID(2, fxdataid.FxRoot)
	case 1:
		return ua.NewNumericNodeID(3, fxacid.AutomationComponentType)
	case 2:
		return ua.NewStringNodeID(5, string(rune('a'+h.next()%4)))
	default:
		return ua.NewNumericNodeID(uint16(h.next()%6), uint32(h.next()%16)+1000)
	}
}

func (h *hostile) typeDef() *ua.ExpandedNodeID {
	ids := []*ua.NodeID{
		ua.NewNumericNodeID(3, fxacid.AutomationComponentType),
		ua.NewNumericNodeID(3, fxacid.FunctionalEntityType),
		ua.NewNumericNodeID(3, fxacid.FxAssetType),
		ua.NewNumericNodeID(3, fxacid.ConnectionEndpointType),
		ua.NewNumericNodeID(3, fxacid.PubSubConnectionEndpointType),
		ua.NewNumericNodeID(3, fxacid.AcDescriptorType),
		ua.NewNumericNodeID(4, fxcmid.ConnectionManagerType),
		ua.NewNumericNodeID(0, 61),
	}
	b := h.next()
	if int(b) < len(ids) {
		return &ua.ExpandedNodeID{NodeID: ids[b]}
	}
	if b == 0xff {
		return nil
	}
	return &ua.ExpandedNodeID{NodeID: ua.NewNumericNodeID(uint16(b%6), uint32(b))}
}

func (h *hostile) refs() []*ua.ReferenceDescription {
	n := int(h.next() % 6)
	out := make([]*ua.ReferenceDescription, 0, n)
	for range n {
		r := &ua.ReferenceDescription{
			NodeID:         &ua.ExpandedNodeID{NodeID: h.nodeID()},
			BrowseName:     &ua.QualifiedName{NamespaceIndex: uint16(h.next() % 6), Name: hostileNames[int(h.next())%len(hostileNames)]},
			DisplayName:    ua.NewLocalizedText("d"),
			NodeClass:      []ua.NodeClass{ua.NodeClassObject, ua.NodeClassVariable, ua.NodeClassMethod}[h.next()%3],
			TypeDefinition: h.typeDef(),
		}
		switch h.next() % 16 {
		case 0:
			r.NodeID = nil
		case 1:
			r.BrowseName = nil
		case 2:
			r.NodeID = &ua.ExpandedNodeID{}
		}
		out = append(out, r)
	}
	return out
}

func (h *hostile) status() ua.StatusCode {
	switch h.next() % 16 {
	case 0:
		return ua.StatusBadNodeIDUnknown
	case 1:
		return ua.StatusBadInternalError
	case 2:
		return ua.StatusBadDataTypeIDUnknown
	}
	return ua.StatusOK
}

func (h *hostile) cp() []byte {
	if h.next()%3 == 0 {
		return []byte{1}
	}
	return nil
}

func (h *hostile) NamespaceArray(context.Context) ([]string, error) {
	switch h.next() % 8 {
	case 0:
		return nil, ua.StatusBadInternalError
	case 1:
		return hostileNamespaces[:3], nil // no AC, no CM
	}
	return hostileNamespaces, nil
}

func (h *hostile) Browse(_ context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	switch h.next() % 32 {
	case 0:
		return nil, ua.StatusBadTimeout
	case 1:
		return &ua.BrowseResponse{}, nil
	}
	res := make([]*ua.BrowseResult, len(req.NodesToBrowse))
	for i := range res {
		res[i] = &ua.BrowseResult{StatusCode: h.status(), References: h.refs(), ContinuationPoint: h.cp()}
	}
	return &ua.BrowseResponse{Results: res}, nil
}

func (h *hostile) BrowseNext(_ context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	if req.ReleaseContinuationPoints {
		return &ua.BrowseNextResponse{}, nil
	}
	switch h.next() % 32 {
	case 0:
		return nil, ua.StatusBadTimeout
	case 1:
		return &ua.BrowseNextResponse{}, nil
	}
	return &ua.BrowseNextResponse{Results: []*ua.BrowseResult{{StatusCode: h.status(), References: h.refs(), ContinuationPoint: h.cp()}}}, nil
}

func (h *hostile) value() *ua.Variant {
	enc := []uint32{fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, fxacid.FxVersionEncodingDefaultBinary, 1}[h.next()%3]
	body := make([]byte, h.next()%10)
	for i := range body {
		body[i] = h.next()
	}
	vals := []any{
		"s", ua.NewLocalizedText("t"), int32(3), int32(-1), uint32(1 << 17), true, 1500.0, math.NaN(), math.Inf(1),
		[]string{"FXAC"}, &ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(uint16(h.next()%5), enc), EncodingMask: ua.ExtensionObjectBinary, RawBody: body},
		&ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(3, enc), EncodingMask: ua.ExtensionObjectBinary, Value: body},
		&ua.ExtensionObject{EncodingMask: ua.ExtensionObjectEmpty},
	}
	b := h.next()
	if int(b) >= len(vals) {
		return nil
	}
	return ua.MustVariant(vals[b])
}

func (h *hostile) Read(_ context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	switch h.next() % 32 {
	case 0:
		return nil, ua.StatusBadTimeout
	case 1:
		return &ua.ReadResponse{}, nil
	}
	res := make([]*ua.DataValue, len(req.NodesToRead))
	for i := range res {
		if h.next()%16 == 0 {
			continue // a nil DataValue
		}
		res[i] = &ua.DataValue{Status: h.status(), Value: h.value()}
	}
	return &ua.ReadResponse{Results: res}, nil
}

// counting wraps hostile so that every call is counted against
// maxHostileCalls.
type counting struct {
	*hostile
	t testing.TB
}

func (c counting) NamespaceArray(ctx context.Context) ([]string, error) {
	c.call(c.t)
	return c.hostile.NamespaceArray(ctx)
}

func (c counting) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	c.call(c.t)
	return c.hostile.Browse(ctx, req)
}

func (c counting) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	c.call(c.t)
	return c.hostile.BrowseNext(ctx, req)
}

func (c counting) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	c.call(c.t)
	return c.hostile.Read(ctx, req)
}

// FuzzInspectHostileServer runs Inspect against a server whose answers come
// from the fuzzer: Inspect returns a report or ErrInspect, never panics and
// makes a bounded number of calls.
func FuzzInspectHostileServer(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{2, 5, 0, 3, 3, 0, 4, 0, 1, 1, 3, 0, 0, 0, 7, 2, 2, 0, 9, 9, 9})
	f.Add([]byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := &hostile{data: data}
		r, err := inspect(context.Background(), counting{h, t}, Limits{MaxComponents: 8, MaxChildren: 16, MaxDepth: 4, MaxNodes: 256}, 0)
		if err != nil {
			if r != nil {
				t.Fatal("a report and an error")
			}
			return
		}
		if r == nil {
			t.Fatal("neither a report nor an error")
		}
		_ = r.IsFXServer()
		for _, f := range r.Findings {
			_ = f.String()
		}
	})
}

// cyclic is a server whose FunctionalEntity holds itself and whose every
// Browse continues with a continuation point and an empty page.
type cyclic struct {
	browses, nexts int
}

func (c *cyclic) NamespaceArray(context.Context) ([]string, error) { return hostileNamespaces, nil }

func (c *cyclic) Browse(_ context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	c.browses++
	d := req.NodesToBrowse[0]
	var refs []*ua.ReferenceDescription
	ref := func(id uint32, name string, typ uint32, ns uint16) {
		refs = append(refs, &ua.ReferenceDescription{
			NodeID:         ua.NewNumericExpandedNodeID(5, id),
			BrowseName:     &ua.QualifiedName{NamespaceIndex: 3, Name: name}, // the AC namespace
			NodeClass:      ua.NodeClassObject,
			TypeDefinition: ua.NewNumericExpandedNodeID(ns, typ),
		})
	}
	switch {
	case d.BrowseDirection == ua.BrowseDirectionInverse:
		// Supertypes: none, the types are the UAFX types themselves.
	case d.NodeID.Equal(ua.NewNumericNodeID(2, fxdataid.FxRoot)):
		ref(1, "AC", fxacid.AutomationComponentType, 3)
	case d.NodeID.Equal(ua.NewNumericNodeID(5, 1)):
		ref(2, "FunctionalEntities", 61, 0)
	case d.NodeID.Equal(ua.NewNumericNodeID(5, 2)), d.NodeID.Equal(ua.NewNumericNodeID(5, 3)):
		ref(3, "Loop", fxacid.FunctionalEntityType, 3) // the entity holds itself
	}
	return &ua.BrowseResponse{Results: []*ua.BrowseResult{{References: refs, ContinuationPoint: []byte{7}}}}, nil
}

func (c *cyclic) BrowseNext(_ context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	c.nexts++
	if req.ReleaseContinuationPoints {
		return &ua.BrowseNextResponse{Results: []*ua.BrowseResult{{}}}, nil
	}
	return &ua.BrowseNextResponse{Results: []*ua.BrowseResult{{ContinuationPoint: []byte{7}}}}, nil
}

func (c *cyclic) Read(_ context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	return &ua.ReadResponse{Results: make([]*ua.DataValue, len(req.NodesToRead))}, nil
}

// TestInspectCycles checks that a FunctionalEntity that holds itself is
// reported once and that empty pages with continuation points end.
func TestInspectCycles(t *testing.T) {
	c := &cyclic{}
	r, err := inspect(context.Background(), c, Limits{}, 0)
	require.NoError(t, err)
	assert.True(t, r.Truncated)
	require.Len(t, r.AutomationComponents, 1)
	fes := r.AutomationComponents[0].FunctionalEntities
	require.Len(t, fes, 1)
	assert.Equal(t, "Loop", fes[0].BrowseName.Name)
	assert.Empty(t, fes[0].SubFunctionalEntities, "the entity is not its own sub-entity")
	assert.Less(t, c.browses, 50)
	assert.Less(t, c.nexts, 2*c.browses+1, "one BrowseNext and one release at most per Browse")
}

// TestInspectNodeBudget checks MaxNodes.
func TestInspectNodeBudget(t *testing.T) {
	r, err := inspect(context.Background(), &cyclic{}, Limits{MaxNodes: 1}, 0)
	require.NoError(t, err)
	assert.True(t, r.Truncated)
	require.Len(t, r.AutomationComponents, 1)
	assert.Empty(t, r.AutomationComponents[0].FunctionalEntities)
}

// TestInspectSupertypeBudget checks that a server with a new type per node
// cannot make Inspect look up supertypes without end.
func TestInspectSupertypeBudget(t *testing.T) {
	in := &inspector{c: &chain{}, lim: Limits{}.withDefaults(), r: &Report{}, supertypes: map[string]*ua.NodeID{}, visited: map[string]bool{}}
	base := ua.NewNumericNodeID(3, fxacid.AutomationComponentType)
	for i := range uint32(maxSupertypeLookups + 10) {
		ok, err := in.isSubtype(context.Background(), ua.NewNumericNodeID(7, i), base)
		require.NoError(t, err)
		assert.False(t, ok)
	}
	assert.True(t, in.r.Truncated)
	assert.LessOrEqual(t, len(in.supertypes), maxSupertypeLookups)
}

// chain answers every supertype question with a type of its own, one
// above: a hierarchy without end.
type chain struct{ cyclic }

func (c *chain) Browse(_ context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	id := req.NodesToBrowse[0].NodeID
	return &ua.BrowseResponse{Results: []*ua.BrowseResult{{References: []*ua.ReferenceDescription{{
		NodeID: ua.NewNumericExpandedNodeID(7, id.IntID()+1_000_000),
	}}}}}, nil
}
