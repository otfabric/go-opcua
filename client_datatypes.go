// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// This file decodes the Structures and Unions a client has no Go type for
// with the DataTypeDefinition Attribute the server gives their DataTypes
// (OPC 10000-3 §5.8.3): "Servers should attempt to expose the DataType
// Nodes and the information about the structure of those DataTypes for
// Clients to read" (§5.8.1).
//
// The definitions are kept per namespace URI, as the NodeIds of a server
// depend on its namespace table, which may differ after a reconnect or on
// another server; "The content of this Attribute shall not be changed once
// it had been provided to Clients since Clients might persistently cache
// this information" (§5.8.4). The NodeIds of the session are those of the
// current namespace table.

// DynamicTypeDecoding makes the client decode ExtensionObjects of types
// without a registered Go type ([ua.RegisterExtensionObject]) with the
// DataTypeDefinition the server gives their DataType: the values of Read
// (and ReadValue, ReadValues, Node.Value), the output arguments of Call
// and CallMethod, the values and events of HistoryReadRawModified,
// HistoryReadProcessed, HistoryReadAtTime and HistoryReadEvent and the data
// changes and events of subscriptions. A decoded body is an
// ExtensionObject whose Value is a [*ua.DynamicStructure]; a type the
// client cannot resolve or decode keeps its RawBody, as without the
// option, and never fails the call.
//
// The first value of a new type costs a Browse of its encoding and a Read
// and Browse per DataType it uses; the definitions are kept for the
// lifetime of the client, by namespace URI. Without the option the client
// decodes nothing it has no Go type for; [Client.LoadDataTypes] and
// [Client.DecodeExtensionObjects] still work.
func DynamicTypeDecoding(enabled bool) Option {
	return func(cfg *Config) error {
		cfg.dynamicTypes = enabled
		return nil
	}
}

// dynamicTypes is the registry of a client.
type dynamicTypes struct {
	// mu serializes resolution and guards everything below.
	mu sync.Mutex
	// cache holds the DataTypes resolved so far, by namespace URI and
	// identifier.
	cache map[uriNodeID]*cachedType
	// ns is the namespace table of view, view the cache in its indexes.
	ns   []string
	view *ua.DynamicTypes
	// unknown are the encodings that the server could not resolve in
	// this namespace table, not asked for again.
	unknown map[string]bool
}

// opcUANamespace is the URI of namespace 0 (OPC 10000-6 §5.1.12; "0 is
// always the OPC UA namespace").
const opcUANamespace = "http://opcfoundation.org/UA/"

// uriNodeID is a NodeId with its namespace URI: the URI and the identifier
// in namespace 0 form ("i=5", "s=Name").
type uriNodeID struct {
	uri string
	id  string
}

func (u uriNodeID) isZero() bool { return u.id == "" }

// cachedType is a DataType of the cache with NodeIds by namespace URI.
type cachedType struct {
	dataType   uriNodeID
	name       string
	isAbstract bool
	builtIn    ua.TypeID
	enum       *ua.EnumDefinition
	structure  *ua.StructureDefinition // its NodeIds are not used
	encoding   uriNodeID               // DefaultEncodingId
	base       uriNodeID               // BaseDataType
	fieldTypes []uriNodeID
}

// toURI returns n with its namespace URI, false when ns has no namespace
// of its index.
func toURI(n *ua.NodeID, ns []string) (uriNodeID, bool) {
	if n == nil {
		return uriNodeID{}, true
	}
	s := n.String()
	rest := s
	if strings.HasPrefix(s, "ns=") {
		if i := strings.IndexByte(s, ';'); i > 0 {
			rest = s[i+1:]
		}
	}
	idx := int(n.Namespace())
	if idx >= len(ns) {
		if idx == 0 {
			return uriNodeID{uri: opcUANamespace, id: rest}, true
		}
		return uriNodeID{}, false
	}
	return uriNodeID{uri: ns[idx], id: rest}, true
}

// fromURI returns the NodeId of u in the namespace table ns, false when
// ns does not have its namespace.
func fromURI(u uriNodeID, ns []string) (*ua.NodeID, bool) {
	if u.isZero() {
		return nil, true
	}
	idx := -1
	if u.uri == opcUANamespace {
		idx = 0
	} else {
		for i, uri := range ns {
			if uri == u.uri {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return nil, false
	}
	text := u.id
	if idx > 0 {
		text = fmt.Sprintf("ns=%d;%s", idx, u.id)
	}
	n, err := ua.ParseNodeID(text)
	return n, err == nil
}

// dynamicTypeOf returns the DataType t in the namespace table ns, false
// when one of its NodeIds is in a namespace ns does not have.
func (t *cachedType) dynamicType(ns []string) (*ua.DynamicType, bool) {
	dataType, ok := fromURI(t.dataType, ns)
	if !ok {
		return nil, false
	}
	out := &ua.DynamicType{DataTypeID: dataType, Name: t.name, BuiltIn: t.builtIn, IsAbstract: t.isAbstract}
	switch {
	case t.structure != nil:
		sd := &ua.StructureDefinition{StructureType: t.structure.StructureType, Fields: make([]*ua.StructureField, len(t.structure.Fields))}
		if sd.DefaultEncodingID, ok = fromURI(t.encoding, ns); !ok {
			return nil, false
		}
		if sd.BaseDataType, ok = fromURI(t.base, ns); !ok {
			return nil, false
		}
		for i, f := range t.structure.Fields {
			if f == nil {
				continue // ua.DynamicTypes.Add refuses it
			}
			c := *f
			if c.DataType, ok = fromURI(t.fieldTypes[i], ns); !ok {
				return nil, false
			}
			sd.Fields[i] = &c
		}
		out.Definition = sd
	case t.enum != nil:
		out.Definition = t.enum
	}
	return out, true
}

// types returns the registry of the client, created on first use.
func (c *Client) dynamic() *dynamicTypes {
	c.dynOnce.Do(func() {
		c.dyn = &dynamicTypes{cache: map[uriNodeID]*cachedType{}, unknown: map[string]bool{}}
	})
	return c.dyn
}

// viewLocked returns the set in the indexes of the client's current
// namespace table, rebuilt from the cache when the table changed. d.mu is
// held.
func (d *dynamicTypes) viewLocked(ns []string) *ua.DynamicTypes {
	if d.view != nil && equalStrings(d.ns, ns) {
		return d.view
	}
	view := ua.NewDynamicTypes()
	for _, t := range d.cache {
		if dt, ok := t.dynamicType(ns); ok {
			_ = view.Add(dt) // the definitions were checked when they were added
		}
	}
	d.ns, d.view = append([]string(nil), ns...), view
	d.unknown = map[string]bool{}
	return view
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DynamicTypes returns the DataTypes the client resolved so far, with the
// NodeIds of the namespace table of the current session. Use it to make a
// value of a Structure the client has no Go type for, to write it or pass
// it to a Method:
//
//	v, err := c.DynamicTypes().New(dataTypeID)
//	v.Set("Name", "pump")
//	c.WriteNodeValue(ctx, nodeID, ua.NewExtensionObject(v))
//
// after [Client.LoadDataTypes] resolved dataTypeID. The set is replaced
// when the namespace table changes (a reconnect to a server with another
// table): get it again then.
func (c *Client) DynamicTypes() *ua.DynamicTypes {
	d := c.dynamic()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.viewLocked(c.Namespaces())
}

// LoadDataTypes reads the DataTypeDefinition of the DataTypes
// dataTypeIDs, and of the DataTypes of their fields, from the server into
// [Client.DynamicTypes]. A DataType without a StructureDefinition or
// EnumDefinition is resolved to the built-in type of its supertypes
// (OPC 10000-3 §5.8.2). It returns the first DataType it could not
// resolve; the others are added.
func (c *Client) LoadDataTypes(ctx context.Context, dataTypeIDs ...*ua.NodeID) error {
	d := c.dynamic()
	d.mu.Lock()
	defer d.mu.Unlock()
	ns := c.Namespaces()
	return c.loadDataTypesLocked(ctx, d, ns, dataTypeIDs)
}

// DecodeExtensionObjects decodes, with [Client.DynamicTypes], the
// ExtensionObjects of v that have no Go type and resolves their DataTypes
// from the server first. v is a *ua.DataValue, *ua.Variant,
// *ua.ExtensionObject, a slice of these, a *ua.CallMethodResult, a
// *ua.HistoryData, *ua.HistoryModifiedData, *ua.HistoryEvent,
// *ua.DataChangeNotification or *ua.EventNotificationList; nested values
// (a field of a decoded Structure, a Variant in a Variant array) are
// decoded as well. An ExtensionObject that cannot be decoded keeps its
// RawBody; the error is that of the first that could not, nil when all
// were decoded.
func (c *Client) DecodeExtensionObjects(ctx context.Context, v any) error {
	return c.decodeDynamic(ctx, v, true)
}

// decodeResponse decodes the ExtensionObjects of v when the client has the
// DynamicTypeDecoding option; resolve allows requests to the server for
// types the client has not resolved yet. It never fails the call: a value
// it cannot decode keeps its RawBody.
func (c *Client) decodeResponse(ctx context.Context, v any, resolve bool) {
	if !c.cfg.dynamicTypes {
		return
	}
	if err := c.decodeDynamic(ctx, v, resolve); err != nil {
		c.cfg.logger.Debug("dynamic type decoding", "error", err)
	}
}

// maxResolveRounds bounds the resolutions of one decoding: a decoded value
// may hold ExtensionObjects of further types (a field of DataType
// Structure), one resolution per level.
const maxResolveRounds = 8

// errDynamicBusy is the error of a decoding without resolution while a
// resolution is in progress.
var errDynamicBusy = fmt.Errorf("opcua: DataTypes are being resolved: %w", ua.StatusBadResourceUnavailable)

// decodeDynamic decodes the ExtensionObjects of v; without resolve it uses
// the DataTypes resolved so far only.
func (c *Client) decodeDynamic(ctx context.Context, v any, resolve bool) error {
	d := c.dynamic()
	var firstErr error
	// A pass without a resolution decodes at least one value, so the
	// passes end: only the resolutions are counted.
	for rounds := 0; ; {
		eos := collectExtensionObjects(v, nil)
		if len(eos) == 0 {
			return firstErr
		}
		if resolve {
			d.mu.Lock()
		} else if !d.mu.TryLock() {
			// A resolution holds the registry, waiting for the server:
			// the publish loop during a recovery does not wait for it,
			// and the values stay undecoded.
			return errDynamicBusy
		}
		ns := c.Namespaces()
		view := d.viewLocked(ns)
		var missing []*ua.NodeID
		seen := map[string]bool{}
		decoded := 0
		for _, eo := range eos {
			err := view.DecodeExtensionObject(eo)
			switch {
			case err == nil:
				decoded++
			case errors.Is(err, ua.StatusBadDataTypeIDUnknown) && view.TypeByEncoding(eo.TypeID.NodeID) == nil:
				key := eo.TypeID.NodeID.String()
				if resolve && !d.unknown[key] && !seen[key] {
					seen[key] = true
					missing = append(missing, eo.TypeID.NodeID)
				} else if firstErr == nil {
					firstErr = err
				}
			default:
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if len(missing) > 0 && rounds == maxResolveRounds {
			if firstErr == nil {
				firstErr = fmt.Errorf("opcua: ExtensionObjects nested in more than %d levels of new types: %w", maxResolveRounds, ua.StatusBadDataTypeIDUnknown)
			}
			missing = nil
		}
		if len(missing) == 0 {
			d.mu.Unlock()
			if decoded == 0 {
				return firstErr
			}
			continue // the decoded values may hold more
		}
		rounds++
		err := c.resolveEncodingsLocked(ctx, d, ns, missing)
		d.mu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
}

// collectExtensionObjects appends the ExtensionObjects of v that a set
// might decode: a binary body without a Go type.
func collectExtensionObjects(v any, out []*ua.ExtensionObject) []*ua.ExtensionObject {
	switch x := v.(type) {
	case *ua.ExtensionObject:
		if _, ok := ua.UndecodedBody(x); ok {
			return append(out, x)
		}
		if x == nil {
			return out
		}
		return collectExtensionObjects(x.Value, out)
	case []*ua.ExtensionObject:
		for _, e := range x {
			out = collectExtensionObjects(e, out)
		}
	case *ua.Variant:
		if x != nil {
			out = collectExtensionObjects(x.Value(), out)
		}
	case []*ua.Variant:
		for _, e := range x {
			out = collectExtensionObjects(e, out)
		}
	case *ua.DataValue:
		if x != nil {
			out = collectExtensionObjects(x.Value, out)
		}
	case []*ua.DataValue:
		for _, e := range x {
			out = collectExtensionObjects(e, out)
		}
	case *ua.DynamicStructure:
		if x != nil {
			for _, f := range x.Fields {
				out = collectExtensionObjects(f, out)
			}
		}
	case []*ua.DynamicStructure:
		for _, e := range x {
			out = collectExtensionObjects(e, out)
		}
	case *ua.DynamicMatrix:
		if x != nil {
			out = collectExtensionObjects(x.Values, out)
		}
	case *ua.CallMethodResult:
		if x != nil {
			out = collectExtensionObjects(x.OutputArguments, out)
		}
	case *ua.HistoryData:
		if x != nil {
			out = collectExtensionObjects(x.DataValues, out)
		}
	case *ua.HistoryModifiedData:
		if x != nil {
			out = collectExtensionObjects(x.DataValues, out)
		}
	case *ua.HistoryEvent:
		if x != nil {
			for _, e := range x.Events {
				if e != nil {
					out = collectExtensionObjects(e.EventFields, out)
				}
			}
		}
	case *ua.DataChangeNotification:
		if x != nil {
			for _, m := range x.MonitoredItems {
				if m != nil {
					out = collectExtensionObjects(m.Value, out)
				}
			}
		}
	case *ua.EventNotificationList:
		if x != nil {
			for _, e := range x.Events {
				if e != nil {
					out = collectExtensionObjects(e.EventFields, out)
				}
			}
		}
	}
	return out
}

// resolveEncodingsLocked finds the DataTypes of the encodings: "The
// DataTypeEncoding Node shall provide the inverse HasEncoding Reference to
// its DataType" (OPC 10000-3 §5.8.3), and loads them. d.mu is held.
func (c *Client) resolveEncodingsLocked(ctx context.Context, d *dynamicTypes, ns []string, encodings []*ua.NodeID) error {
	var dataTypes []*ua.NodeID
	var firstErr error
	for start := 0; start < len(encodings); start += resolveBatch {
		batch := encodings[start:min(start+resolveBatch, len(encodings))]
		req := &ua.BrowseRequest{NodesToBrowse: make([]*ua.BrowseDescription, len(batch))}
		for i, e := range batch {
			req.NodesToBrowse[i] = &ua.BrowseDescription{
				NodeID:          e,
				BrowseDirection: ua.BrowseDirectionInverse,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HasEncoding),
				IncludeSubtypes: false,
				NodeClassMask:   uint32(ua.NodeClassDataType),
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			}
		}
		res, err := send[ua.BrowseResponse](ctx, c, req)
		if err != nil {
			return err // nothing is recorded as unknown: try again later
		}
		for i, e := range batch {
			var target *ua.NodeID
			if i < len(res.Results) && res.Results[i] != nil && res.Results[i].StatusCode == ua.StatusOK {
				for _, r := range res.Results[i].References {
					if r != nil && r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.ServerIndex == 0 && r.NodeID.NamespaceURI == "" {
						target = r.NodeID.NodeID
						break
					}
				}
			}
			if target == nil {
				d.unknown[e.String()] = true
				if firstErr == nil {
					firstErr = fmt.Errorf("opcua: the server has no DataType for the encoding %s: %w", e, ua.StatusBadDataTypeIDUnknown)
				}
				continue
			}
			dataTypes = append(dataTypes, target)
		}
	}
	if err := c.loadDataTypesLocked(ctx, d, ns, dataTypes); err != nil {
		var re *requestError
		if errors.As(err, &re) {
			return err
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	// An encoding whose DataType could not be loaded is not asked again.
	view := d.viewLocked(ns)
	for _, e := range encodings {
		if view.TypeByEncoding(e) == nil {
			d.unknown[e.String()] = true
		}
	}
	return firstErr
}

// requestError is a request of the resolution that failed: its DataTypes
// are not recorded as unknown, the next value tries again.
type requestError struct{ err error }

func (e *requestError) Error() string { return e.err.Error() }
func (e *requestError) Unwrap() error { return e.err }

// resolveBatch is the number of nodes of one Browse or Read of the
// resolution: a Read of 30 operations (three Attributes per DataType), a
// Browse of 10, below the MaxNodesPerRead and MaxNodesPerBrowse of small
// servers (OPC 10000-5 §6.3.11, OperationLimitsType; the go-opcua server
// has 32).
const resolveBatch = 10

// maxResolvedTypes bounds the DataTypes one resolution reads, against a
// server whose types reference ever more types.
const maxResolvedTypes = 1000

// maxSupertypeDepth bounds the walk up the DataType hierarchy.
const maxSupertypeDepth = 16

// loaded is a DataType read from the server.
type loaded struct {
	id         *ua.NodeID
	name       string
	isAbstract bool
	def        any
	super      *ua.NodeID
}

// loadDataTypesLocked reads the DataTypes ids and the DataTypes their
// fields use, and adds them to the cache and the view. d.mu is held.
func (c *Client) loadDataTypesLocked(ctx context.Context, d *dynamicTypes, ns []string, ids []*ua.NodeID) error {
	view := d.viewLocked(ns)
	got := map[string]*loaded{}
	var firstErr error
	queue := append([]*ua.NodeID(nil), ids...)
	for len(queue) > 0 {
		if len(got) >= maxResolvedTypes {
			return fmt.Errorf("opcua: more than %d DataTypes to resolve: %w", maxResolvedTypes, ua.StatusBadTooManyOperations)
		}
		var batch []*ua.NodeID
		for len(queue) > 0 && len(batch) < resolveBatch {
			n := queue[0]
			queue = queue[1:]
			if n == nil || got[n.String()] != nil || knownDataType(view, n) {
				continue
			}
			got[n.String()] = &loaded{id: n}
			batch = append(batch, n)
		}
		if len(batch) == 0 {
			continue
		}
		if err := c.readDataTypes(ctx, batch, got); err != nil {
			return &requestError{err}
		}
		for _, n := range batch {
			l := got[n.String()]
			if sd, ok := l.def.(*ua.StructureDefinition); ok {
				for _, f := range sd.Fields {
					if f != nil && f.DataType != nil {
						queue = append(queue, f.DataType)
					}
				}
			}
		}
	}
	// The built-in type of each DataType that has no StructureDefinition,
	// from its supertypes; they may need more reads.
	if err := c.readSupertypes(ctx, got, view); err != nil {
		return &requestError{err}
	}
	for _, key := range sortedKeys(got) {
		l := got[key]
		t, err := d.cacheType(l, got, view, ns)
		if err == nil {
			// The NodeIds of t came from ns: dynamicType finds them all,
			// and Add refuses a nil type otherwise.
			dt, _ := t.dynamicType(ns)
			err = view.Add(dt)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		d.cache[t.dataType] = t
	}
	return firstErr
}

// knownDataType tells whether n needs no read: a built-in DataType, one of
// the abstract numbers, Decimal, or a DataType of the view.
func knownDataType(view *ua.DynamicTypes, n *ua.NodeID) bool {
	if n.Namespace() == 0 && n.Type() != ua.NodeIDTypeString && n.Type() != ua.NodeIDTypeGUID && n.Type() != ua.NodeIDTypeByteString {
		switch i := n.IntID(); {
		case i >= uint32(ua.TypeIDBoolean) && i <= uint32(ua.TypeIDDiagnosticInfo),
			i == id.Number, i == id.Integer, i == id.UInteger, i == id.Decimal:
			return true
		}
	}
	return view.Type(n) != nil
}

// readDataTypes reads the DataTypeDefinition, BrowseName and IsAbstract
// Attributes and the supertype of the DataTypes batch into got.
func (c *Client) readDataTypes(ctx context.Context, batch []*ua.NodeID, got map[string]*loaded) error {
	attrs := []ua.AttributeID{ua.AttributeIDDataTypeDefinition, ua.AttributeIDBrowseName, ua.AttributeIDIsAbstract}
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, n := range batch {
		for _, a := range attrs {
			req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: n, AttributeID: a})
		}
	}
	res, err := send[ua.ReadResponse](ctx, c, req)
	if err != nil {
		return err
	}
	if len(res.Results) != len(req.NodesToRead) {
		return ua.StatusBadUnknownResponse
	}
	for i, n := range batch {
		l := got[n.String()]
		def, name, abstract := res.Results[i*3], res.Results[i*3+1], res.Results[i*3+2]
		// A DataType without the Attribute answers
		// Bad_AttributeIdInvalid: it is no Structure or Enumeration.
		if def != nil && def.Status == ua.StatusOK && def.Value != nil {
			if eo, ok := def.Value.Value().(*ua.ExtensionObject); ok && eo != nil {
				switch v := eo.Value.(type) {
				case *ua.StructureDefinition, *ua.EnumDefinition:
					l.def = v
				}
			}
		}
		if name != nil && name.Status == ua.StatusOK && name.Value != nil {
			if qn, ok := name.Value.Value().(*ua.QualifiedName); ok && qn != nil {
				l.name = qn.Name
			}
		}
		if abstract != nil && abstract.Status == ua.StatusOK && abstract.Value != nil {
			l.isAbstract, _ = abstract.Value.Value().(bool)
		}
	}
	return c.browseSupertypes(ctx, batch, got)
}

// browseSupertypes sets the supertype of each DataType of batch: the
// source of its inverse HasSubtype Reference, which "the subtype provides
// ... to its supertype" (OPC 10000-3 §5.8.3).
func (c *Client) browseSupertypes(ctx context.Context, batch []*ua.NodeID, got map[string]*loaded) error {
	req := &ua.BrowseRequest{NodesToBrowse: make([]*ua.BrowseDescription, len(batch))}
	for i, n := range batch {
		req.NodesToBrowse[i] = &ua.BrowseDescription{
			NodeID:          n,
			BrowseDirection: ua.BrowseDirectionInverse,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HasSubtype),
			NodeClassMask:   uint32(ua.NodeClassDataType),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}
	}
	res, err := send[ua.BrowseResponse](ctx, c, req)
	if err != nil {
		return err
	}
	for i, n := range batch {
		if i >= len(res.Results) || res.Results[i] == nil {
			continue
		}
		for _, r := range res.Results[i].References {
			if r != nil && r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.ServerIndex == 0 {
				got[n.String()].super = r.NodeID.NodeID
				break
			}
		}
	}
	return nil
}

// readSupertypes reads the supertypes the DataTypes of got without a
// StructureDefinition need to find their built-in type.
func (c *Client) readSupertypes(ctx context.Context, got map[string]*loaded, view *ua.DynamicTypes) error {
	for range maxSupertypeDepth {
		var batch []*ua.NodeID
		for _, key := range sortedKeys(got) {
			l := got[key]
			if _, ok := l.def.(*ua.StructureDefinition); ok {
				continue
			}
			// At most maxSupertypeDepth steps: the server may give a
			// cycle.
			s := l.super
			for range maxSupertypeDepth {
				if s == nil || view.Type(s) != nil {
					break
				}
				if _, ok := rootBuiltIn(s); ok {
					break
				}
				next := got[s.String()]
				if next == nil {
					got[s.String()] = &loaded{id: s}
					batch = append(batch, s)
					break
				}
				if next.super == nil {
					break
				}
				s = next.super
			}
		}
		if len(batch) == 0 {
			return nil
		}
		for start := 0; start < len(batch); start += resolveBatch {
			if err := c.readDataTypes(ctx, batch[start:min(start+resolveBatch, len(batch))], got); err != nil {
				return err
			}
		}
	}
	return nil
}

// rootBuiltIn returns how a value of the DataType n of namespace 0 that
// ends a walk up the hierarchy is encoded: a built-in DataType as itself
// (Structure, 22, as an ExtensionObject, BaseDataType, 24, as a Variant),
// Number, Integer and UInteger as a Variant (OPC 10000-6 §5.1.6),
// Enumeration as an Int32 (§5.2.4) and OptionSet as the OptionSet
// Structure.
func rootBuiltIn(n *ua.NodeID) (ua.TypeID, bool) {
	if n.Namespace() != 0 || n.Type() == ua.NodeIDTypeString || n.Type() == ua.NodeIDTypeGUID || n.Type() == ua.NodeIDTypeByteString {
		return 0, false
	}
	switch i := n.IntID(); {
	case i >= uint32(ua.TypeIDBoolean) && i <= uint32(ua.TypeIDDiagnosticInfo):
		return ua.TypeID(i), true
	case i == id.Number, i == id.Integer, i == id.UInteger:
		return ua.TypeIDVariant, true
	case i == id.Enumeration:
		return ua.TypeIDInt32, true
	case i == id.OptionSet:
		return ua.TypeIDExtensionObject, true
	}
	return 0, false
}

// builtInOf returns the built-in type of the DataType l by its
// supertypes.
func builtInOf(l *loaded, got map[string]*loaded, view *ua.DynamicTypes) (ua.TypeID, bool) {
	if b, ok := rootBuiltIn(l.id); ok {
		return b, true
	}
	s := l.super
	for range maxSupertypeDepth {
		if s == nil {
			return 0, false
		}
		if b, ok := rootBuiltIn(s); ok {
			return b, true
		}
		if t := view.Type(s); t != nil {
			if _, ok := t.Definition.(*ua.StructureDefinition); ok {
				return ua.TypeIDExtensionObject, true
			}
			return t.BuiltIn, true
		}
		next := got[s.String()]
		if next == nil {
			return 0, false
		}
		if _, ok := next.def.(*ua.StructureDefinition); ok {
			return ua.TypeIDExtensionObject, true
		}
		s = next.super
	}
	return 0, false
}

// cacheType makes the cache entry of the DataType l.
func (d *dynamicTypes) cacheType(l *loaded, got map[string]*loaded, view *ua.DynamicTypes, ns []string) (*cachedType, error) {
	dataType, ok := toURI(l.id, ns)
	if !ok {
		return nil, fmt.Errorf("opcua: DataType %s: no namespace %d: %w", l.id, l.id.Namespace(), ua.StatusBadNodeIDUnknown)
	}
	t := &cachedType{dataType: dataType, name: l.name, isAbstract: l.isAbstract}
	if sd, ok := l.def.(*ua.StructureDefinition); ok {
		t.structure = sd
		t.builtIn = ua.TypeIDExtensionObject
		if t.encoding, ok = toURI(sd.DefaultEncodingID, ns); !ok {
			return nil, fmt.Errorf("opcua: DataType %s: DefaultEncodingId %s: %w", l.id, sd.DefaultEncodingID, ua.StatusBadNodeIDUnknown)
		}
		if t.base, ok = toURI(sd.BaseDataType, ns); !ok {
			return nil, fmt.Errorf("opcua: DataType %s: BaseDataType %s: %w", l.id, sd.BaseDataType, ua.StatusBadNodeIDUnknown)
		}
		t.fieldTypes = make([]uriNodeID, len(sd.Fields))
		for i, f := range sd.Fields {
			if f == nil {
				continue // ua.DynamicTypes.Add refuses it
			}
			if t.fieldTypes[i], ok = toURI(f.DataType, ns); !ok {
				return nil, fmt.Errorf("opcua: DataType %s: field %q: DataType %s: %w", l.id, f.Name, f.DataType, ua.StatusBadNodeIDUnknown)
			}
		}
		return t, nil
	}
	b, ok := builtInOf(l, got, view)
	if !ok {
		return nil, fmt.Errorf("opcua: DataType %s: no built-in supertype: %w", l.id, ua.StatusBadDataTypeIDUnknown)
	}
	t.builtIn = b
	t.enum, _ = l.def.(*ua.EnumDefinition)
	return t, nil
}

func sortedKeys(m map[string]*loaded) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
