// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

// ErrConnections reports that the connection Methods cannot be served.
var ErrConnections = errors.New("fxserver: connections")

// AssetVerifier verifies an Asset as its VerifyAsset Method does (Part 81
// §6.3.3): it compares the expected values with those of the Asset in the
// verification mode and returns the VerificationResult, the errors of the
// two lists (one StatusCode per element, Tables 33 and 34) and the status
// of the call (Good, Uncertain, Bad_InvalidArgument or Bad_NotSupported,
// Table 32). Which values make an Asset compatible is the Asset's to say.
type AssetVerifier func(ctx context.Context, asset *ua.NodeID, mode uafx.AssetVerificationMode, expected []*ua.KeyValuePair, additional []*uafx.NodeIDValuePair) (uafx.AssetVerificationResult, []ua.StatusCode, []ua.StatusCode, ua.StatusCode)

// ConnectionOptions configure [EnableConnections].
type ConnectionOptions struct {
	// AssetVerifier runs the VerifyAssetCmd of EstablishConnections. Without
	// it the command fails with Bad_NotSupported.
	AssetVerifier AssetVerifier
	// MaxConnections limits the ConnectionEndpoints of the server; 0 is no
	// limit. A ConnectionEndpoint over the limit fails with
	// Bad_ResourceUnavailable (Part 81 Table 12).
	MaxConnections uint32
	// MaxConnectionsPerCall limits the ConnectionEndpointConfigurations of
	// one EstablishConnections call; 0 is no limit. A call over the limit
	// fails with Bad_TooManyOperations (Part 81 Table 9).
	MaxConnectionsPerCall uint32
	// CommandBundleRequired makes EstablishConnections require the bundled
	// commands of Part 81 §6.2.4.3.1 in one call.
	CommandBundleRequired bool
	// UDPPort is the UDP port of unicast PubSub reception, which
	// ReserveCommunicationIds returns as TransportSpecificInfo for
	// UDP-UADP (Part 81 §6.2.4.3.4.2); 0 is 4840, the default port of
	// UADP (Part 14 §7.3.2.2).
	UDPPort uint16
	// Interval is how often the Status of the ConnectionEndpoints follows
	// their DataSetReaders and DataSetWriters; 0 is 100 ms.
	Interval time.Duration
	// Logger logs what the connections do; nil is slog.Default().
	Logger *slog.Logger
}

// Connections serves the connection Methods of the AutomationComponents of a
// server: EstablishConnections (Part 81 §6.2.4) and CloseConnections
// (§6.2.5) with the PubSub communication model, the Status of the
// PubSubConnectionEndpoints (§6.6.3) and the CommHealth and
// OperationalHealth they make up (§6.4.8, §10.34, §9.1.2).
//
// Persistent ConnectionEndpoints (IsPersistent, SupportsPersistence) and
// ControlGroups (EstablishControlCmd and ReassignControlCmd on a
// ControlGroup) are not supported: they fail with Bad_NotSupported.
type Connections struct {
	srv  *server.Server
	ns   Namespaces
	opts ConnectionOptions
	log  *slog.Logger

	// call serializes EstablishConnections and CloseConnections, which Part
	// 81 makes atomic (§6.2.4.3.9.1, §6.2.4.3.10.1, §6.2.5.2).
	call sync.Mutex

	mu        sync.Mutex
	acs       []*automationComponent
	endpoints map[string]*endpoint // by NodeId
	nextID    uint32

	stop chan struct{}
	done chan struct{}
	once sync.Once

	ops pubsubOps
	// beforeExpire, when set by a test, runs after the monitor found an
	// expired CleanupTimeout and before it takes c.call; guarded by mu.
	beforeExpire func()
	// retryCleanup is the shortest time after which a failed cleanup is
	// tried again; guarded by mu.
	retryCleanup time.Duration
}

// pubsubOps are the operations of the PubSub runtime that close
// ConnectionEndpoints; tests replace them to inject failures.
type pubsubOps struct {
	disable, removeReader, removeWriter func(pubsub.ComponentID) error
}

// automationComponent is an AutomationComponent of the server.
type automationComponent struct {
	id       *ua.NodeID
	health   *server.Node // AggregatedHealth, nil if absent
	feFolder *ua.NodeID   // FunctionalEntities
	assets   *ua.NodeID   // Assets
}

// EnableConnections makes srv serve EstablishConnections and
// CloseConnections on every AutomationComponent below FxRoot. It needs the
// AC and Data models (ns, from AddModel), the instances of the
// AutomationComponents (ImportNodeSet) and a PubSub runtime with its
// information model ([server.WithPubSub]). It adopts the
// PubSubConnectionEndpoints the AutomationComponents have already: their
// Status follows the DataSetReader and DataSetWriter their ToDataSetReader
// and ToDataSetWriter References point to.
//
// Call it before the server starts; Close stops the Status updates.
func EnableConnections(srv *server.Server, ns Namespaces, opts ConnectionOptions) (*Connections, error) {
	if ns.AC == 0 || ns.Data == 0 {
		return nil, fmt.Errorf("%w: the server has no UAFX AC model", ErrConnections)
	}
	if srv.PubSub() == nil {
		return nil, fmt.Errorf("%w: the server has no PubSub runtime (server.WithPubSub)", ErrConnections)
	}
	if opts.UDPPort == 0 {
		opts.UDPPort = 4840
	}
	if opts.Interval <= 0 {
		opts.Interval = 100 * time.Millisecond
	}
	c := &Connections{srv: srv, ns: ns, opts: opts, log: opts.Logger, endpoints: map[string]*endpoint{},
		stop: make(chan struct{}), done: make(chan struct{})}
	if c.log == nil {
		c.log = slog.Default()
	}
	c.retryCleanup = time.Second
	rt := srv.PubSub()
	c.ops = pubsubOps{disable: rt.Disable, removeReader: rt.RemoveDataSetReader, removeWriter: rt.RemoveDataSetWriter}
	for _, ref := range c.children(ua.NewNumericNodeID(ns.Data, fxRootID), id.Organizes) {
		n := ref.NodeID.NodeID
		if !c.isA(n, fxacid.AutomationComponentType) {
			continue
		}
		ac := &automationComponent{id: n,
			feFolder: c.childID(n, "FunctionalEntities"),
			assets:   c.childID(n, "Assets")}
		if h := c.childID(n, "AggregatedHealth"); h != nil {
			ac.health = c.node(h)
		}
		est, closeID := c.childID(n, "EstablishConnections"), c.childID(n, "CloseConnections")
		if est == nil || closeID == nil {
			return nil, fmt.Errorf("%w: the AutomationComponent %v has no EstablishConnections or CloseConnections Method", ErrConnections, n)
		}
		for _, m := range []struct {
			id   *ua.NodeID
			decl uint32
		}{{est, fxacid.AutomationComponentTypeEstablishConnections}, {closeID, fxacid.AutomationComponentTypeCloseConnections}} {
			if err := c.ensureArguments(m.id, m.decl); err != nil {
				return nil, err
			}
		}
		srv.RegisterMethod(n, est, c.establishHandler(ac))
		srv.RegisterMethod(n, closeID, c.closeHandler(ac))
		c.acs = append(c.acs, ac)
	}
	if len(c.acs) == 0 {
		return nil, fmt.Errorf("%w: the server has no AutomationComponent below FxRoot", ErrConnections)
	}
	for _, ac := range c.acs {
		for _, fe := range c.functionalEntities(ac) {
			c.adopt(fe)
		}
	}
	c.refreshAll()
	go c.monitor()
	return c, nil
}

// ensureArguments gives the Method m the InputArguments and
// OutputArguments Properties of its declaration decl in the AC namespace
// when it has none: Part 81 Tables 7 and 25 make them mandatory, and the
// Call service checks the arguments against them (Part 4 §5.11.2), but a
// NodeSet may leave them to the type.
func (c *Connections) ensureArguments(m *ua.NodeID, decl uint32) error {
	mn := c.node(m)
	ns, err := c.srv.Namespace(int(m.Namespace()))
	if mn == nil || err != nil {
		return fmt.Errorf("%w: no Method %v", ErrConnections, m)
	}
	have := map[string]bool{}
	for _, r := range c.children(m, id.HasProperty) {
		if r.BrowseName != nil {
			have[r.BrowseName.Name] = true
		}
	}
	for _, r := range c.children(ua.NewNumericNodeID(c.ns.AC, decl), id.HasProperty) {
		name := r.BrowseName.Name
		if have[name] || name != "InputArguments" && name != "OutputArguments" {
			continue
		}
		v := c.value(r.NodeID.NodeID)
		if v == nil {
			return fmt.Errorf("%w: the declaration of %v has no %s", ErrConnections, m, name)
		}
		p := server.NewVariableNode(c.newNodeID(m.Namespace()), name, v.Value())
		if err := setAttrs(p, map[ua.AttributeID]any{
			ua.AttributeIDBrowseName: &ua.QualifiedName{Name: name},
			ua.AttributeIDDataType:   ua.NewNumericExpandedNodeID(0, id.Argument),
			ua.AttributeIDValueRank:  int32(1),
		}); err != nil {
			return fmt.Errorf("%w: %s of %v: %w", ErrConnections, name, m, err)
		}
		ns.AddNode(p)
		mn.AddReference(p, ua.NewNumericNodeID(0, id.HasProperty), true)
		if pt := c.node(ua.NewNumericNodeID(0, id.PropertyType)); pt != nil {
			p.AddReference(pt, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		}
	}
	return nil
}

// fxRootID is FxRoot (Part 81 §12.2) in the Data namespace.
const fxRootID = 71

// Close stops the Status updates. The Methods stay registered.
func (c *Connections) Close() error {
	c.once.Do(func() { close(c.stop) })
	<-c.done
	return nil
}

// Endpoints returns the NodeIds of the ConnectionEndpoints the connections
// manage.
func (c *Connections) Endpoints() []*ua.NodeID {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*ua.NodeID, 0, len(c.endpoints))
	for _, e := range c.endpoints {
		out = append(out, e.id)
	}
	return out
}

// Status returns the Status of the ConnectionEndpoint endpoint, and false
// if the connections do not manage it.
func (c *Connections) Status(endpoint *ua.NodeID) (uafx.ConnectionEndpointStatus, bool) {
	c.mu.Lock()
	e := c.endpoints[endpoint.String()]
	c.mu.Unlock()
	if e == nil {
		return 0, false
	}
	return e.Status(), true
}

// RefreshHealth recomputes the AggregatedOperationalHealth of every
// AutomationComponent (Part 81 §9.1.2) from the OperationalHealth of its
// top-level FunctionalEntities. Call it after changing the bits of an
// OperationalHealth the connections do not own (16 to 31), or the
// FunctionalEntities: between calls of the Methods the health follows
// changes of the Status of the endpoints only.
func (c *Connections) RefreshHealth() { c.refreshAll() }

// --- address space -------------------------------------------------------

// children returns the targets of the forward references of n of the type
// refType or its subtypes.
func (c *Connections) children(n *ua.NodeID, refType uint32) []*ua.ReferenceDescription {
	return c.browse(n, ua.NewNumericNodeID(0, refType), ua.BrowseDirectionForward)
}

// browse returns the references of n of the type refType or its subtypes in
// the direction dir.
func (c *Connections) browse(n, refType *ua.NodeID, dir ua.BrowseDirection) []*ua.ReferenceDescription {
	if n == nil {
		return nil
	}
	ns, err := c.srv.Namespace(int(n.Namespace()))
	if err != nil {
		return nil
	}
	res := ns.Browse(&ua.BrowseDescription{NodeID: n, BrowseDirection: dir, ReferenceTypeID: refType,
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)})
	if res == nil || res.StatusCode != ua.StatusOK {
		return nil
	}
	var out []*ua.ReferenceDescription
	for _, r := range res.References {
		if r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.NamespaceURI == "" && r.NodeID.ServerIndex == 0 {
			out = append(out, r)
		}
	}
	return out
}

// child returns the reference to the hierarchical child of n with the
// BrowseName name in the AC namespace.
func (c *Connections) child(n *ua.NodeID, name string) *ua.ReferenceDescription {
	for _, r := range c.children(n, id.HierarchicalReferences) {
		if r.BrowseName != nil && r.BrowseName.Name == name && r.BrowseName.NamespaceIndex == c.ns.AC {
			return r
		}
	}
	return nil
}

// childID is child as a NodeId, nil if n has no such child.
func (c *Connections) childID(n *ua.NodeID, name string) *ua.NodeID {
	if r := c.child(n, name); r != nil {
		return r.NodeID.NodeID
	}
	return nil
}

// typeOf returns the TypeDefinition of n.
func (c *Connections) typeOf(n *ua.NodeID) *ua.NodeID {
	for _, r := range c.children(n, id.HasTypeDefinition) {
		return r.NodeID.NodeID
	}
	return nil
}

// isA reports whether n is an instance of the AC type typ or a subtype.
func (c *Connections) isA(n *ua.NodeID, typ uint32) bool {
	return c.isSubtype(c.typeOf(n), ua.NewNumericNodeID(c.ns.AC, typ))
}

// isSubtype reports whether t is base or a subtype of it.
func (c *Connections) isSubtype(t, base *ua.NodeID) bool {
	for range 64 { // a type hierarchy deeper than this is broken
		if t == nil {
			return false
		}
		if t.Equal(base) {
			return true
		}
		var super *ua.NodeID
		for _, r := range c.browse(t, ua.NewNumericNodeID(0, id.HasSubtype), ua.BrowseDirectionInverse) {
			super = r.NodeID.NodeID
		}
		t = super
	}
	return false
}

// node returns the node n of the server, nil for a nil n or a node the
// server does not have.
func (c *Connections) node(n *ua.NodeID) *server.Node {
	if n == nil {
		return nil
	}
	return c.srv.Node(n)
}

// value returns the value of the Variable n, nil if it has none.
func (c *Connections) value(n *ua.NodeID) *ua.Variant {
	node := c.node(n)
	if node == nil {
		return nil
	}
	dv := node.Value()
	if dv == nil || dv.Status != ua.StatusOK {
		return nil
	}
	return dv.Value
}

// functionalEntities returns the FunctionalEntities of ac with their
// SubFunctionalEntities.
func (c *Connections) functionalEntities(ac *automationComponent) []*ua.NodeID {
	var out []*ua.NodeID
	seen := map[string]bool{}
	var walk func(n *ua.NodeID, depth int)
	walk = func(n *ua.NodeID, depth int) {
		if depth > 16 {
			return
		}
		for _, r := range c.children(n, id.HierarchicalReferences) {
			x := r.NodeID.NodeID
			if seen[x.String()] || !c.isA(x, fxacid.FunctionalEntityType) {
				continue
			}
			seen[x.String()] = true
			out = append(out, x)
			walk(x, depth+1)
		}
	}
	walk(ac.feFolder, 0)
	return out
}

// below collects the Variables in the hierarchy below n (Organizes,
// HasComponent, ...), at most 4096.
func (c *Connections) below(n *ua.NodeID, into map[string]bool) {
	var walk func(n *ua.NodeID, depth int)
	walk = func(n *ua.NodeID, depth int) {
		if n == nil || depth > 16 || len(into) >= 4096 {
			return
		}
		for _, r := range c.children(n, id.HierarchicalReferences) {
			x := r.NodeID.NodeID
			if into[x.String()] {
				continue
			}
			if r.NodeClass == ua.NodeClassVariable {
				into[x.String()] = true
			}
			walk(x, depth+1)
		}
	}
	walk(n, 0)
}

// feScope returns fe and its SubFunctionalEntities.
func (c *Connections) feScope(fe *ua.NodeID) []*ua.NodeID {
	out := []*ua.NodeID{fe}
	seen := map[string]bool{fe.String(): true}
	for i := 0; i < len(out) && i < 256; i++ {
		for _, r := range c.children(out[i], id.HierarchicalReferences) {
			x := r.NodeID.NodeID
			if !seen[x.String()] && c.isA(x, fxacid.FunctionalEntityType) {
				seen[x.String()] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// folderVariables returns the Variables in the folder name (InputData,
// OutputData, ConfigurationData) of fe and its SubFunctionalEntities.
func (c *Connections) folderVariables(fe *ua.NodeID, name string) map[string]bool {
	vars := map[string]bool{}
	for _, x := range c.feScope(fe) {
		c.below(c.childID(x, name), vars)
	}
	return vars
}

// newNodeID returns a NodeId for a new node in the namespace ns.
func (c *Connections) newNodeID(ns uint16) *ua.NodeID {
	for {
		c.mu.Lock()
		c.nextID++
		n := ua.NewStringNodeID(ns, fmt.Sprintf("uafx-ce-%d", c.nextID))
		c.mu.Unlock()
		if c.node(n) == nil {
			return n
		}
	}
}
