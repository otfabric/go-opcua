// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// fakeTypes is a server whose Read and Browse answer the DataTypes of its
// tables, for the answers the go-opcua server never gives.
type fakeTypes struct {
	mu        sync.Mutex
	defs      map[string]any // the DataTypeDefinition value
	abstract  map[string]bool
	supers    map[string]*ua.NodeID
	encodings map[string]*ua.NodeID // encoding → DataType

	// faultFrom makes the Reads of DataTypes from the faultFrom-th on
	// fail (0: none); reads counts them.
	faultFrom, reads                    int
	readShort, browseFault, browseShort bool
}

var fakeNamespaces = []string{"http://opcfoundation.org/UA/", "urn:test:server", "urn:test:fake", "urn:test:other"}

func fakeID(ns uint16, n uint32) *ua.NodeID { return ua.NewNumericNodeID(ns, n) }

func newFakeTypes() *fakeTypes {
	return &fakeTypes{defs: map[string]any{}, abstract: map[string]bool{}, supers: map[string]*ua.NodeID{}, encodings: map[string]*ua.NodeID{}}
}

func (f *fakeTypes) header(req ua.Request) *ua.ResponseHeader {
	return &ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.Header().RequestHandle, ServiceDiagnostics: &ua.DiagnosticInfo{}, AdditionalHeader: ua.NewExtensionObject(nil)}
}

func (f *fakeTypes) read(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	req := r.(*ua.ReadRequest)
	res := &ua.ReadResponse{ResponseHeader: f.header(req)}
	types := false
	for _, rv := range req.NodesToRead {
		key := rv.NodeID.String()
		dv := &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNodeIDUnknown}
		switch rv.AttributeID {
		case ua.AttributeIDValue:
			if rv.NodeID.Namespace() == 0 && rv.NodeID.IntID() == id.ServerNamespaceArray {
				dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(fakeNamespaces)}
			}
		case ua.AttributeIDDataTypeDefinition:
			types = true
			dv.Status = ua.StatusBadAttributeIDInvalid
			if d, ok := f.defs[key]; ok {
				dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.NewExtensionObject(d))}
			}
		case ua.AttributeIDBrowseName:
			dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(&ua.QualifiedName{NamespaceIndex: 2, Name: "T" + key})}
		case ua.AttributeIDIsAbstract:
			dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(f.abstract[key])}
		default:
		}
		res.Results = append(res.Results, dv)
	}
	if types {
		f.reads++
		if f.faultFrom > 0 && f.reads >= f.faultFrom {
			return nil, ua.StatusBadInternalError
		}
		if f.readShort {
			res.Results = res.Results[:1]
		}
	}
	return res, nil
}

func (f *fakeTypes) browse(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.browseFault {
		return nil, ua.StatusBadInternalError
	}
	req := r.(*ua.BrowseRequest)
	res := &ua.BrowseResponse{ResponseHeader: f.header(req)}
	for _, d := range req.NodesToBrowse {
		key := d.NodeID.String()
		var target *ua.NodeID
		switch d.ReferenceTypeID.IntID() {
		case id.HasSubtype:
			target = f.supers[key]
		case id.HasEncoding:
			target = f.encodings[key]
		}
		br := &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
		if target != nil {
			br = &ua.BrowseResult{References: []*ua.ReferenceDescription{{
				ReferenceTypeID: d.ReferenceTypeID,
				NodeID:          &ua.ExpandedNodeID{NodeID: target},
				BrowseName:      &ua.QualifiedName{},
				DisplayName:     &ua.LocalizedText{},
				NodeClass:       ua.NodeClassDataType,
				TypeDefinition:  ua.NewTwoByteExpandedNodeID(0),
			}}}
		}
		res.Results = append(res.Results, br)
	}
	if f.browseShort {
		res.Results = nil
	}
	return res, nil
}

func (f *fakeTypes) set(fn func(f *fakeTypes)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// structure adds the Structure n of namespace ns with the encoding enc
// and fields.
func (f *fakeTypes) structure(n, enc *ua.NodeID, fields ...*ua.StructureField) {
	f.defs[n.String()] = &ua.StructureDefinition{DefaultEncodingID: enc, BaseDataType: ua.NewNumericNodeID(0, id.Structure), Fields: fields}
	f.supers[n.String()] = ua.NewNumericNodeID(0, id.Structure)
	if enc != nil {
		f.encodings[enc.String()] = n
	}
}

func newFakeClient(t *testing.T, f *fakeTypes) *Client {
	t.Helper()
	srv, err := server.New(server.InsecureNoSecurity(), server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.EndPoint("localhost", 0))
	require.NoError(t, err)
	srv.RegisterHandler(id.ReadRequestEncodingDefaultBinary, f.read)
	srv.RegisterHandler(id.BrowseRequestEncodingDefaultBinary, f.browse)
	srv.RegisterHandler(id.HistoryReadRequestEncodingDefaultBinary, func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) {
		return nil, ua.StatusBadHistoryOperationUnsupported
	})
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return dynClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))
}

func field(name string, dataType *ua.NodeID) *ua.StructureField {
	return &ua.StructureField{Name: name, DataType: dataType, ValueRank: -1}
}

// TestDynamicTypes_Supertypes resolves simple DataTypes by their
// supertypes.
func TestDynamicTypes_Supertypes(t *testing.T) {
	f := newFakeTypes()
	c := newFakeClient(t, f)
	ctx := context.Background()
	ns2 := func(n uint32) *ua.NodeID { return fakeID(2, n) }
	f.set(func(f *fakeTypes) {
		// A chain of three simple types: two more reads.
		f.supers[ns2(1).String()] = ns2(2)
		f.supers[ns2(2).String()] = ns2(3)
		f.supers[ns2(3).String()] = ua.NewNumericNodeID(0, id.String)
		// A subtype of a Structure without a definition of its own
		// (another server than go-opcua): an ExtensionObject.
		f.structure(ns2(10), ns2(110))
		f.supers[ns2(11).String()] = ns2(10)
		f.supers[ns2(12).String()] = ns2(11)
		// No supertype; a supertype that has none; a cycle; a supertype
		// that is a string NodeId of namespace 0.
		f.supers[ns2(21).String()] = ns2(20)
		f.supers[ns2(30).String()] = ns2(31)
		f.supers[ns2(31).String()] = ns2(30)
		f.supers[ns2(40).String()] = ua.NewStringNodeID(0, "x")
		// A subtype that sorts before its Structure supertype.
		f.structure(ns2(50), ns2(150))
		f.supers[ns2(5).String()] = ns2(50)
		// A chain longer than the walk.
		for i := uint32(200); i < 200+maxSupertypeDepth+2; i++ {
			f.supers[ns2(i).String()] = ns2(i + 1)
		}
	})
	require.NoError(t, c.LoadDataTypes(ctx, ns2(1), ns2(12)))
	types := c.DynamicTypes()
	for _, n := range []uint32{1, 2, 3} {
		require.Equal(t, ua.TypeIDString, types.Type(ns2(n)).BuiltIn, n)
	}
	require.Equal(t, ua.TypeIDExtensionObject, types.Type(ns2(11)).BuiltIn)
	require.Equal(t, ua.TypeIDExtensionObject, types.Type(ns2(12)).BuiltIn)

	// Supertypes in the set already.
	f.set(func(f *fakeTypes) {
		f.supers[ns2(4).String()] = ns2(1)
		f.supers[ns2(13).String()] = ns2(10)
	})
	require.NoError(t, c.LoadDataTypes(ctx, ns2(4), ns2(13)))
	require.Equal(t, ua.TypeIDString, c.DynamicTypes().Type(ns2(4)).BuiltIn)
	require.Equal(t, ua.TypeIDExtensionObject, c.DynamicTypes().Type(ns2(13)).BuiltIn)

	require.NoError(t, c.LoadDataTypes(ctx, ns2(5)))
	require.Equal(t, ua.TypeIDExtensionObject, c.DynamicTypes().Type(ns2(5)).BuiltIn)

	for _, n := range []uint32{20, 21, 30, 40, 200} {
		err := c.LoadDataTypes(ctx, ns2(n))
		require.ErrorIs(t, err, ua.StatusBadDataTypeIDUnknown, n)
		require.Nil(t, c.DynamicTypes().Type(ns2(n)))
	}

	// The DataTypes of namespace 0 that end the walk.
	require.NoError(t, c.LoadDataTypes(ctx, ua.NewNumericNodeID(0, id.Enumeration), ua.NewNumericNodeID(0, id.OptionSet)))
	require.Equal(t, ua.TypeIDInt32, c.DynamicTypes().Type(ua.NewNumericNodeID(0, id.Enumeration)).BuiltIn)
	// Nothing to read.
	require.NoError(t, c.LoadDataTypes(ctx, nil, ua.NewNumericNodeID(0, id.Int32)))
}

// TestDynamicTypes_Unusable: DataTypes the client cannot use are left out
// and reported; the others are added.
func TestDynamicTypes_Unusable(t *testing.T) {
	f := newFakeTypes()
	c := newFakeClient(t, f)
	ctx := context.Background()
	ns2 := func(n uint32) *ua.NodeID { return fakeID(2, n) }
	f.set(func(f *fakeTypes) {
		f.structure(ns2(1), ns2(101), field("A", ua.NewNumericNodeID(0, id.Int32)))
		// NodeIds in a namespace the server does not have.
		f.structure(ns2(2), fakeID(9, 102))
		f.defs[ns2(3).String()] = &ua.StructureDefinition{DefaultEncodingID: ns2(103), BaseDataType: fakeID(9, 1)}
		f.structure(ns2(4), ns2(104), field("X", fakeID(9, 1)))
		// A field without a DataType, a ValueRank that is no rank.
		f.structure(ns2(5), ns2(105), nil)
		f.structure(ns2(6), ns2(106), &ua.StructureField{Name: "R", DataType: ua.NewNumericNodeID(0, id.Int32)})
		// A definition of another type is no definition.
		f.defs[ns2(7).String()] = &ua.Argument{}
		f.supers[ns2(7).String()] = ua.NewNumericNodeID(0, id.Int32)
	})
	err := c.LoadDataTypes(ctx, ns2(1), ns2(2), ns2(3), ns2(4), ns2(5), ns2(6), ns2(7), fakeID(9, 8))
	require.Error(t, err)
	types := c.DynamicTypes()
	require.NotNil(t, types.Type(ns2(1)))
	require.Equal(t, ua.TypeIDInt32, types.Type(ns2(7)).BuiltIn)
	for _, n := range []uint32{2, 3, 4, 5, 6} {
		require.Nil(t, types.Type(ns2(n)), n)
	}
	require.Nil(t, types.Type(fakeID(9, 8)))
}

// TestDynamicTypes_Faults: a failed Read or Browse fails the resolution
// and leaves nothing recorded as unknown.
func TestDynamicTypes_Faults(t *testing.T) {
	f := newFakeTypes()
	c := newFakeClient(t, f)
	ctx := context.Background()
	ns2 := func(n uint32) *ua.NodeID { return fakeID(2, n) }
	f.set(func(f *fakeTypes) {
		f.structure(ns2(1), ns2(101), field("A", ua.NewNumericNodeID(0, id.Int32)))
		f.supers[ns2(2).String()] = ns2(3)
		f.supers[ns2(3).String()] = ua.NewNumericNodeID(0, id.String)
	})
	// An encoding whose DataType cannot be used is not asked again.
	f.set(func(f *fakeTypes) {
		f.structure(ns2(6), ns2(106), &ua.StructureField{Name: "R", DataType: ua.NewNumericNodeID(0, id.Int32)})
	})
	bad := &ua.ExtensionObject{TypeID: &ua.ExpandedNodeID{NodeID: ns2(106)}, EncodingMask: ua.ExtensionObjectBinary, RawBody: []byte{1}}
	require.ErrorIs(t, c.DecodeExtensionObjects(ctx, bad), ua.StatusBadInvalidArgument)
	c.dynamic().mu.Lock()
	require.True(t, c.dynamic().unknown[ns2(106).String()])
	c.dynamic().mu.Unlock()

	eo := func() *ua.ExtensionObject {
		return &ua.ExtensionObject{TypeID: &ua.ExpandedNodeID{NodeID: ns2(101)}, EncodingMask: ua.ExtensionObjectBinary, RawBody: []byte{1, 0, 0, 0}}
	}
	cases := []struct {
		name  string
		fault func(f *fakeTypes)
		want  error
	}{
		{"browse of the encodings", func(f *fakeTypes) { f.browseFault = true }, ua.StatusBadInternalError},
		{"read", func(f *fakeTypes) { f.reads, f.faultFrom = 0, 1 }, ua.StatusBadInternalError},
		{"short read", func(f *fakeTypes) { f.readShort = true }, ua.StatusBadUnknownResponse},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			f.set(cs.fault)
			v := eo()
			require.ErrorIs(t, c.DecodeExtensionObjects(ctx, v), cs.want)
			require.Nil(t, v.Value)
			// With the server answering, the same value decodes.
			f.set(func(f *fakeTypes) { f.faultFrom, f.readShort, f.browseFault = 0, false, false })
			require.NoError(t, c.DecodeExtensionObjects(ctx, v))
			require.Equal(t, []any{int32(1)}, v.Value.(*ua.DynamicStructure).Fields)
			c.dynamic().mu.Lock()
			c.dynamic().cache = map[uriNodeID]*cachedType{}
			c.dynamic().view = nil
			c.dynamic().mu.Unlock()
		})
	}

	// The Browse of the supertypes, and the reads of supertypes.
	f.set(func(f *fakeTypes) { f.browseFault = true })
	require.ErrorIs(t, c.LoadDataTypes(ctx, ns2(2)), ua.StatusBadInternalError)
	f.set(func(f *fakeTypes) { f.browseFault, f.browseShort = false, true })
	require.ErrorIs(t, c.LoadDataTypes(ctx, ns2(2)), ua.StatusBadDataTypeIDUnknown, "no supertype")
	f.set(func(f *fakeTypes) { f.browseShort = false })
	// A failed Read and HistoryRead are not decoded.
	f.set(func(f *fakeTypes) { f.reads, f.faultFrom = 0, 1 })
	_, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ns2(1), AttributeID: ua.AttributeIDDataTypeDefinition}}})
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	_, err = c.HistoryReadRawModified(ctx, []*ua.HistoryReadValueID{{NodeID: ns2(1)}}, &ua.ReadRawModifiedDetails{})
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)

	// The read of the supertype fails: the first read passes.
	f.set(func(f *fakeTypes) { f.reads, f.faultFrom = 0, 2 })
	err = c.LoadDataTypes(ctx, ns2(2))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	require.Equal(t, ua.StatusBadInternalError.Error(), err.Error())
	f.set(func(f *fakeTypes) { f.faultFrom = 0 })
	require.NoError(t, c.LoadDataTypes(ctx, ns2(2)))
	require.Equal(t, ua.TypeIDString, c.DynamicTypes().Type(ns2(2)).BuiltIn)
}

// TestDynamicTypes_ResolveLimits: the rounds of a decoding, the DataTypes
// of one resolution.
func TestDynamicTypes_ResolveLimits(t *testing.T) {
	f := newFakeTypes()
	c := newFakeClient(t, f)
	ctx := context.Background()
	ns2 := func(n uint32) *ua.NodeID { return fakeID(2, n) }

	// A chain of nested ExtensionObjects of types that only the value
	// names: one more type per round.
	local := ua.NewDynamicTypes()
	const depth = maxResolveRounds + 2
	f.set(func(f *fakeTypes) {
		for i := uint32(1); i <= depth; i++ {
			f.structure(ns2(i), ns2(100+i), field("Next", ua.NewNumericNodeID(0, id.Structure)))
			require.NoError(t, local.Add(&ua.DynamicType{DataTypeID: ns2(i), Definition: f.defs[ns2(i).String()]}))
		}
	})
	var next *ua.ExtensionObject
	for i := uint32(depth); i >= 1; i-- {
		v, err := local.New(ns2(i))
		require.NoError(t, err)
		require.NoError(t, v.Set("Next", next))
		b, err := v.Encode()
		require.NoError(t, err)
		next = rawEO(ns2(100+i), b)
	}
	// As the binary decoder leaves it.
	next.Value, next.RawBody = nil, next.Value.([]byte)
	err := c.DecodeExtensionObjects(ctx, next)
	require.ErrorIs(t, err, ua.StatusBadDataTypeIDUnknown)
	got := 0
	for v := next; v != nil && v.Value != nil; got++ {
		d, ok := v.Value.(*ua.DynamicStructure)
		if !ok {
			break
		}
		v, _ = d.Fields[0].(*ua.ExtensionObject)
	}
	require.Equal(t, maxResolveRounds, got, "one level per resolution")

	// A definition that references ever more DataTypes.
	f.set(func(f *fakeTypes) {
		for i := uint32(1000); i < 1000+maxResolvedTypes+5; i++ {
			f.structure(ns2(i), nil, field("Next", ns2(i+1)))
		}
	})
	require.ErrorIs(t, c.LoadDataTypes(ctx, ns2(1000)), ua.StatusBadTooManyOperations)
}

// TestDynamicTypes_Busy: a decoding that may not resolve does not wait for
// a resolution in progress.
func TestDynamicTypes_Busy(t *testing.T) {
	c := &Client{cfg: &Config{}}
	c.atomicNamespaces.Store(fakeNamespaces)
	eo := &ua.ExtensionObject{TypeID: &ua.ExpandedNodeID{NodeID: fakeID(2, 1)}, EncodingMask: ua.ExtensionObjectBinary, RawBody: []byte{1}}
	d := c.dynamic()
	d.mu.Lock()
	require.ErrorIs(t, c.decodeDynamic(context.Background(), eo, false), ua.StatusBadResourceUnavailable)
	d.mu.Unlock()
	require.ErrorIs(t, c.decodeDynamic(context.Background(), eo, false), ua.StatusBadDataTypeIDUnknown)
	require.Nil(t, eo.Value)
}

// TestDynamicTypes_NamespaceTable: the conversions between the NodeIds of
// a session and those of the cache.
func TestDynamicTypes_NamespaceTable(t *testing.T) {
	ns := []string{opcUANamespace, "urn:a", "urn:b"}
	u, ok := toURI(nil, ns)
	require.True(t, ok)
	require.True(t, u.isZero())
	u, ok = toURI(ua.NewNumericNodeID(0, 5), nil)
	require.True(t, ok, "namespace 0 without a table")
	require.Equal(t, uriNodeID{uri: opcUANamespace, id: "i=5"}, u)
	_, ok = toURI(ua.NewNumericNodeID(3, 5), ns)
	require.False(t, ok)
	u, ok = toURI(ua.NewStringNodeID(2, "a;b"), ns)
	require.True(t, ok)
	require.Equal(t, uriNodeID{uri: "urn:b", id: "s=a;b"}, u)
	n, ok := fromURI(u, []string{opcUANamespace, "urn:b"})
	require.True(t, ok)
	require.Equal(t, "ns=1;s=a;b", n.String())
	n, ok = fromURI(uriNodeID{}, ns)
	require.True(t, ok)
	require.Nil(t, n)
	_, ok = fromURI(uriNodeID{uri: "urn:c", id: "i=1"}, ns)
	require.False(t, ok)

	require.True(t, equalStrings(ns, []string{opcUANamespace, "urn:a", "urn:b"}))
	require.False(t, equalStrings(ns, []string{opcUANamespace, "urn:a", "urn:c"}))
	require.False(t, equalStrings(ns, ns[:2]))

	// A cached type whose NodeIds are not all in the table.
	sd := &ua.StructureDefinition{Fields: []*ua.StructureField{nil, {Name: "X"}}}
	ct := &cachedType{dataType: uriNodeID{"urn:a", "i=1"}, structure: sd, encoding: uriNodeID{"urn:a", "i=2"}, fieldTypes: []uriNodeID{{}, {"urn:a", "i=3"}}}
	dt, ok := ct.dynamicType(ns)
	require.True(t, ok)
	require.Nil(t, dt.Definition.(*ua.StructureDefinition).Fields[0])
	// A nil field, which ua.DynamicTypes.Add refuses.
	d := &dynamicTypes{}
	loadedType := &loaded{id: ua.NewNumericNodeID(1, 1), def: &ua.StructureDefinition{Fields: []*ua.StructureField{nil}}}
	got, err := d.cacheType(loadedType, nil, ua.NewDynamicTypes(), ns)
	require.NoError(t, err)
	require.Equal(t, []uriNodeID{{}}, got.fieldTypes)
	for _, broken := range []*cachedType{
		{dataType: uriNodeID{"urn:c", "i=1"}},
		{dataType: uriNodeID{"urn:a", "i=1"}, structure: sd, encoding: uriNodeID{"urn:c", "i=2"}},
		{dataType: uriNodeID{"urn:a", "i=1"}, structure: sd, base: uriNodeID{"urn:c", "i=2"}},
		{dataType: uriNodeID{"urn:a", "i=1"}, structure: sd, fieldTypes: []uriNodeID{{}, {"urn:c", "i=3"}}},
	} {
		_, ok := broken.dynamicType(ns)
		require.False(t, ok)
	}
}

// TestDynamicTypes_Collect finds the ExtensionObjects of every value the
// decoding visits.
func TestDynamicTypes_Collect(t *testing.T) {
	raw := func(n int) *ua.ExtensionObject {
		return &ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(2, uint32(n)), EncodingMask: ua.ExtensionObjectBinary, RawBody: []byte{byte(n)}}
	}
	dv := func(n int) *ua.DataValue { return &ua.DataValue{Value: ua.MustVariant(raw(n))} }
	events := []*ua.EventFieldList{nil, {EventFields: []*ua.Variant{ua.MustVariant(raw(1))}}}
	values := []any{
		raw(1),
		[]*ua.ExtensionObject{raw(1), nil},
		ua.MustVariant(raw(1)),
		[]*ua.Variant{ua.MustVariant(raw(1)), nil},
		dv(1),
		[]*ua.DataValue{dv(1), nil},
		&ua.DynamicStructure{Fields: []any{raw(1)}},
		[]*ua.DynamicStructure{{Fields: []any{raw(1)}}, nil},
		&ua.DynamicMatrix{Values: []*ua.ExtensionObject{raw(1)}},
		&ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant(raw(1))}},
		ua.NewExtensionObject(&ua.HistoryData{DataValues: []*ua.DataValue{dv(1)}}),
		&ua.HistoryModifiedData{DataValues: []*ua.DataValue{dv(1)}},
		&ua.HistoryEvent{Events: []*ua.HistoryEventFieldList{nil, {EventFields: []*ua.Variant{ua.MustVariant(raw(1))}}}},
		&ua.DataChangeNotification{MonitoredItems: []*ua.MonitoredItemNotification{nil, {Value: dv(1)}}},
		&ua.EventNotificationList{Events: events},
	}
	for i, v := range values {
		require.Len(t, collectExtensionObjects(v, nil), 1, "%d %T", i, v)
	}
	for _, v := range []any{
		(*ua.ExtensionObject)(nil), (*ua.Variant)(nil), (*ua.DataValue)(nil), (*ua.DynamicStructure)(nil),
		(*ua.DynamicMatrix)(nil), (*ua.CallMethodResult)(nil), (*ua.HistoryData)(nil), (*ua.HistoryModifiedData)(nil),
		(*ua.HistoryEvent)(nil), (*ua.DataChangeNotification)(nil), (*ua.EventNotificationList)(nil), 5, "x",
	} {
		require.Empty(t, collectExtensionObjects(v, nil), "%T", v)
	}
}
