// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// stepError is a failure of an operation of a run: the FxError and
// StatusCode it puts in the diagnostics (§10.19, design §5.7).
type stepError struct {
	fx     uafx.FxError
	status ua.StatusCode
	msg    string
}

func (e *stepError) Error() string {
	return fmt.Sprintf("fxcm: %s: %v (%v)", e.msg, e.fx, e.status)
}

func (e *stepError) Unwrap() []error { return []error{ErrManager, e.status} }

func failure(fx uafx.FxError, status ua.StatusCode, format string, args ...any) *stepError {
	return &stepError{fx: fx, status: status, msg: fmt.Sprintf(format, args...)}
}

// failureOf returns the Failure of err: the FxError and StatusCode of a
// stepError, fx and the StatusCode in the chain otherwise.
func failureOf(err error, fx uafx.FxError) Failure {
	var se *stepError
	if errors.As(err, &se) {
		return Failure{FxError: se.fx, Status: se.status}
	}
	st := StatusOf(err)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		st = ua.StatusBadTimeout
	case st == ua.StatusBad:
		st = ua.StatusBadCommunicationError
	}
	return Failure{FxError: fx, Status: st}
}

// TranslationNamespace is the namespace of the placeholder NodeIds of a
// PubSubCommunicationModelConfiguration (§6.16.3).
const TranslationNamespace = "http://opcfoundation.org/UA/FX/CM/Translation/"

// target is a server of a run: its session and what was read of it.
type target struct {
	addr ServerAddress
	sess Session
	nsa  []string
	idx  map[string]uint16
	// cache are the resolutions of identifiers on this server, valid for
	// its NamespaceArray and publication dates (CL-6, CL-8).
	cache *resolutionCache
}

// ns returns the index of uri on the server.
func (t *target) ns(uri string) (uint16, bool) {
	i, ok := t.idx[uri]
	return i, ok
}

// fxRoot returns the NodeId of FxRoot on the server (§12.2).
func (t *target) fxRoot() (*ua.NodeID, error) {
	d, ok := t.ns(fxdataid.NamespaceURI)
	if !ok {
		return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "%s has no UAFX Data namespace", t.addr.Address)
	}
	return ua.NewNumericNodeID(d, fxdataid.FxRoot), nil
}

// resolutionCache caches the NodeIds of identifiers on one server (CL-8)
// with the NamespaceArray and the NamespacePublicationDates they were
// resolved with: a change of either drops the cache (CL-6).
type resolutionCache struct {
	mu          sync.Mutex
	fingerprint string
	nodes       map[string]*ua.NodeID
}

type resolutionCaches struct {
	mu sync.Mutex
	m  map[ServerAddress]*resolutionCache
}

func (r *resolutionCaches) of(addr ServerAddress) *resolutionCache {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[ServerAddress]*resolutionCache{}
	}
	c := r.m[addr]
	if c == nil {
		c = &resolutionCache{nodes: map[string]*ua.NodeID{}}
		r.m[addr] = c
	}
	return c
}

func (c *resolutionCache) check(fingerprint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fingerprint != fingerprint {
		c.fingerprint = fingerprint
		c.nodes = map[string]*ua.NodeID{}
	}
}

func (c *resolutionCache) get(key string) *ua.NodeID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nodes[key]
}

func (c *resolutionCache) put(key string, n *ua.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[key] = n
}

// open reads the NamespaceArray and the NamespacePublicationDates of the
// server of t (§13.3.2, §13.3.3) and checks the cache against them.
func (t *target) open(ctx context.Context) error {
	nsa, err := t.sess.NamespaceArray(ctx)
	if err != nil {
		f := failureOf(err, uafx.FxErrorResolvingNamespacesError)
		return failure(f.FxError, f.Status, "NamespaceArray of %s: %v", t.addr.Address, err)
	}
	t.nsa = nsa
	t.idx = make(map[string]uint16, len(nsa))
	for i, u := range nsa {
		if _, dup := t.idx[u]; !dup && i <= 0xffff {
			t.idx[u] = uint16(i)
		}
	}
	dates := t.publicationDates(ctx)
	t.cache.check(strings.Join(nsa, "\x00") + "\x01" + dates)
	return nil
}

// publicationDates returns the NamespacePublicationDates of the
// NamespaceMetadata Objects of the server (Part 5 §6.3.13), as a string
// that changes when one changes. A server without them has none: the
// NamespaceArray alone decides then. Library interpretation: a failure to
// read them is not an error of the run.
func (t *target) publicationDates(ctx context.Context) string {
	res, err := t.sess.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: ua.NewNumericNodeID(0, id.ServerNamespaces), BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
		NodeClassMask: uint32(ua.NodeClassObject), ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	if err != nil || len(res.Results) != 1 || res.Results[0] == nil || res.Results[0].StatusCode != ua.StatusOK {
		return ""
	}
	req := &ua.TranslateBrowsePathsToNodeIDsRequest{}
	for _, r := range res.Results[0].References {
		if r == nil || r.NodeID == nil || r.NodeID.NodeID == nil {
			continue
		}
		for _, name := range []string{"NamespaceUri", "NamespacePublicationDate"} {
			req.BrowsePaths = append(req.BrowsePaths, &ua.BrowsePath{StartingNode: r.NodeID.NodeID, RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{{
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty), TargetName: &ua.QualifiedName{Name: name},
			}}}})
		}
	}
	if len(req.BrowsePaths) == 0 {
		return ""
	}
	tr, err := t.sess.TranslateBrowsePaths(ctx, req)
	if err != nil || len(tr.Results) != len(req.BrowsePaths) {
		return ""
	}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, r := range tr.Results {
		var n *ua.NodeID
		if r != nil && r.StatusCode == ua.StatusOK && len(r.Targets) == 1 && r.Targets[0].TargetID != nil {
			n = r.Targets[0].TargetID.NodeID
		}
		if n == nil {
			n = ua.NewNumericNodeID(0, 0)
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue})
	}
	rr, err := t.sess.Read(ctx, read)
	if err != nil || len(rr.Results) != len(read.NodesToRead) {
		return ""
	}
	var parts []string
	for i := 0; i+1 < len(rr.Results); i += 2 {
		uri, _ := dvValue(rr.Results[i]).(string)
		date, _ := dvValue(rr.Results[i+1]).(time.Time)
		parts = append(parts, uri+"="+date.UTC().Format(time.RFC3339Nano))
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}

// dvStructure returns the ExtensionObject of dv. opcua.Client marks a
// structure of a type package ua does not know, as those of the UAFX
// namespaces, with Bad_DataTypeIdUnknown and keeps its body.
func dvStructure(dv *ua.DataValue) *ua.ExtensionObject {
	if dv == nil || dv.Value == nil || dv.Status != ua.StatusOK && dv.Status != ua.StatusBadDataTypeIDUnknown {
		return nil
	}
	eo, _ := dv.Value.Value().(*ua.ExtensionObject)
	return eo
}

func dvValue(dv *ua.DataValue) any {
	if dv == nil || dv.Value == nil || dv.Status.Uint32()&0x80000000 != 0 {
		return nil
	}
	return dv.Value.Value()
}

// mapNodeID maps a NodeId of the scope of a ServerAddress (F.1.2.2) to the
// server.
func (t *target) mapNodeID(n *ua.NodeID, scope namespaceScope) (*ua.NodeID, error) {
	if n == nil {
		return nil, nil
	}
	uri, ok := scope.uri(n.Namespace())
	if !ok {
		return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "the namespace index %d is not in the Namespaces of the ServerAddress", n.Namespace())
	}
	return t.mapURI(n, uri)
}

// mapURI returns n in the namespace uri of the server (CL-5: an empty
// NamespaceUri is the local server, index 1).
func (t *target) mapURI(n *ua.NodeID, uri string) (*ua.NodeID, error) {
	idx, ok := uint16(1), true
	if uri != "" {
		idx, ok = t.ns(uri)
	}
	if !ok {
		return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "%s has no namespace %q", t.addr.Address, uri)
	}
	return withNamespace(n, idx), nil
}

// withNamespace returns n with the namespace index idx, in an encoding that
// can hold it.
func withNamespace(n *ua.NodeID, idx uint16) *ua.NodeID {
	switch n.Type() {
	case ua.NodeIDTypeString:
		return ua.NewStringNodeID(idx, n.StringID())
	case ua.NodeIDTypeGUID:
		return ua.NewGUIDNodeID(idx, n.StringID())
	case ua.NodeIDTypeByteString:
		b, _ := base64.StdEncoding.DecodeString(n.StringID())
		return ua.NewByteStringNodeID(idx, b)
	default:
		return ua.NewNumericNodeID(idx, n.IntID())
	}
}

// identifierKey is the key of the cache for an identifier resolved from
// start.
func identifierKey(kind string, start *ua.NodeID, scope []string, v any) string {
	b, err := ua.Encode(v)
	if err != nil {
		b = []byte(fmt.Sprint(v))
	}
	return kind + "\x00" + start.String() + "\x00" + strings.Join(scope, "\x01") + "\x00" + string(b)
}

// resolve returns the NodeId of id on the server: a NodeId mapped to the
// server's namespaces (§13.3.2), a RelativePath from start through
// TranslateBrowsePathsToNodeIds (§13.3.3). An AliasName (§13.3.4) is not
// supported: AliasNameProcessingError.
func (t *target) resolve(ctx context.Context, nid *uafx.NodeIdentifier, scope namespaceScope, start *ua.NodeID) (*ua.NodeID, error) {
	switch {
	case nid == nil:
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "no NodeIdentifier")
	case nid.Node != nil:
		return t.mapNodeID(nid.Node, scope)
	case nid.Alias != nil:
		return nil, failure(uafx.FxErrorAliasNameProcessingError, ua.StatusBadNotSupported, "the AliasName %q: AliasNames are not supported", *nid.Alias)
	case nid.IdentifierBrowsePath == nil:
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "the null NodeIdentifier")
	}
	key := identifierKey("path", start, scope, nid.IdentifierBrowsePath)
	if n := t.cache.get(key); n != nil {
		return n, nil
	}
	rp := &ua.RelativePath{}
	for _, el := range nid.IdentifierBrowsePath.Elements {
		ref, err := t.mapNodeID(el.ReferenceTypeID, scope)
		if err != nil {
			return nil, err
		}
		uri, ok := scope.uri(el.TargetName.NamespaceIndex)
		if !ok {
			return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "the namespace index %d is not in the Namespaces of the ServerAddress", el.TargetName.NamespaceIndex)
		}
		qn, err := t.qualifiedName(uri, el.TargetName.Name)
		if err != nil {
			return nil, err
		}
		rp.Elements = append(rp.Elements, &ua.RelativePathElement{ReferenceTypeID: ref, IsInverse: el.IsInverse, IncludeSubtypes: el.IncludeSubtypes, TargetName: qn})
	}
	n, err := t.translate(ctx, start, rp)
	if err != nil {
		return nil, err
	}
	t.cache.put(key, n)
	return n, nil
}

// resolvePortable returns the NodeId of a PortableNodeIdentifier (§6.16.3,
// §13.3): a PortableNodeId by its NamespaceUri, a PortableRelativePath from
// start.
func (t *target) resolvePortable(ctx context.Context, p *uafx.PortableNodeIdentifier, start *ua.NodeID) (*ua.NodeID, error) {
	switch {
	case p == nil:
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "no PortableNodeIdentifier")
	case p.Node != nil:
		if p.Node.Identifier == nil {
			return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "a PortableNodeId without Identifier")
		}
		return t.mapURI(p.Node.Identifier, p.Node.NamespaceURI)
	case p.Alias != nil:
		return nil, failure(uafx.FxErrorAliasNameProcessingError, ua.StatusBadNotSupported, "the AliasName %q: AliasNames are not supported", *p.Alias)
	case p.IdentifierBrowsePath == nil:
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "the null PortableNodeIdentifier")
	}
	key := identifierKey("portable", start, nil, p.IdentifierBrowsePath)
	if n := t.cache.get(key); n != nil {
		return n, nil
	}
	rp := &ua.RelativePath{}
	for _, el := range p.IdentifierBrowsePath.Elements {
		if el == nil || el.TargetName == nil {
			return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "a PortableRelativePath element without TargetName")
		}
		var ref *ua.NodeID
		if el.ReferenceTypeID != nil && el.ReferenceTypeID.Identifier != nil {
			r, err := t.mapURI(el.ReferenceTypeID.Identifier, el.ReferenceTypeID.NamespaceURI)
			if err != nil {
				return nil, err
			}
			ref = r
		}
		qn, err := t.qualifiedName(el.TargetName.NamespaceURI, el.TargetName.Name)
		if err != nil {
			return nil, err
		}
		rp.Elements = append(rp.Elements, &ua.RelativePathElement{ReferenceTypeID: ref, IsInverse: el.IsInverse, IncludeSubtypes: el.IncludeSubtypes, TargetName: qn})
	}
	n, err := t.translate(ctx, start, rp)
	if err != nil {
		return nil, err
	}
	t.cache.put(key, n)
	return n, nil
}

func (t *target) qualifiedName(uri, name string) (*ua.QualifiedName, error) {
	if uri == uaNamespace {
		return &ua.QualifiedName{Name: name}, nil
	}
	idx, ok := uint16(1), true
	if uri != "" {
		idx, ok = t.ns(uri)
	}
	if !ok {
		return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "%s has no namespace %q", t.addr.Address, uri)
	}
	return &ua.QualifiedName{NamespaceIndex: idx, Name: name}, nil
}

// translate resolves rp from start (§13.3.3): exactly one target, else
// ResolvingPathsError with the status of the service, or
// Bad_BrowseNameDuplicated for several targets.
func (t *target) translate(ctx context.Context, start *ua.NodeID, rp *ua.RelativePath) (*ua.NodeID, error) {
	if rp == nil || len(rp.Elements) == 0 {
		return start, nil
	}
	res, err := t.sess.TranslateBrowsePaths(ctx, &ua.TranslateBrowsePathsToNodeIDsRequest{
		BrowsePaths: []*ua.BrowsePath{{StartingNode: start, RelativePath: rp}},
	})
	if err != nil {
		f := failureOf(err, uafx.FxErrorResolvingPathsError)
		return nil, failure(f.FxError, f.Status, "TranslateBrowsePathsToNodeIds on %s: %v", t.addr.Address, err)
	}
	if res == nil || len(res.Results) != 1 || res.Results[0] == nil {
		return nil, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadUnexpectedError, "TranslateBrowsePathsToNodeIds on %s: no result", t.addr.Address)
	}
	r := res.Results[0]
	if r.StatusCode != ua.StatusOK {
		return nil, failure(uafx.FxErrorResolvingPathsError, r.StatusCode, "the path %s from %v on %s", pathString(rp), start, t.addr.Address)
	}
	var found []*ua.NodeID
	for _, tg := range r.Targets {
		if tg == nil || tg.TargetID == nil || tg.TargetID.NodeID == nil || tg.RemainingPathIndex != 0xffffffff {
			continue
		}
		if tg.TargetID.ServerIndex != 0 || tg.TargetID.NamespaceURI != "" {
			continue
		}
		found = append(found, tg.TargetID.NodeID)
	}
	switch len(found) {
	case 0:
		return nil, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch, "the path %s from %v on %s has no local target", pathString(rp), start, t.addr.Address)
	case 1:
		return found[0], nil
	}
	return nil, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadBrowseNameDuplicated, "the path %s from %v on %s has %d targets", pathString(rp), start, t.addr.Address, len(found))
}

func pathString(rp *ua.RelativePath) string {
	var b strings.Builder
	for _, el := range rp.Elements {
		b.WriteString("/")
		if el.TargetName != nil {
			fmt.Fprintf(&b, "%d:%s", el.TargetName.NamespaceIndex, el.TargetName.Name)
		}
	}
	return b.String()
}

// childNamed returns the child of parent with the BrowseName name in the
// namespace ns, by HierarchicalReferences, nil when there is none.
func (t *target) children(ctx context.Context, parent *ua.NodeID) ([]*ua.ReferenceDescription, error) {
	req := &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: parent, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
		NodeClassMask: uint32(ua.NodeClassObject | ua.NodeClassVariable), ResultMask: uint32(ua.BrowseResultMaskAll),
	}}}
	res, err := t.sess.Browse(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return nil, fmt.Errorf("fxcm: Browse of %v: %d results", parent, len(res.Results))
	}
	if sc := res.Results[0].StatusCode; sc != ua.StatusOK {
		return nil, sc
	}
	return res.Results[0].References, nil
}

// child returns the child of parent with the BrowseName (ns, name).
func child(refs []*ua.ReferenceDescription, ns uint16, name string) *ua.NodeID {
	for _, r := range refs {
		if r != nil && r.BrowseName != nil && r.BrowseName.NamespaceIndex == ns && r.BrowseName.Name == name &&
			r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.ServerIndex == 0 && r.NodeID.NamespaceURI == "" {
			return r.NodeID.NodeID
		}
	}
	return nil
}

// acNamespace returns the index of the UAFX AC namespace on the server.
func (t *target) acNamespace() (uint16, error) {
	n, ok := t.ns(fxacid.NamespaceURI)
	if !ok {
		return 0, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "%s has no UAFX AC namespace", t.addr.Address)
	}
	return n, nil
}
