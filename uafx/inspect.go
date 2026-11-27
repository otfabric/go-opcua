// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// Namespace is one namespace of the UAFX model on a server.
type Namespace struct {
	URI string
	// Index is the index of the namespace in the NamespaceArray of the
	// server, 0 when Present is false.
	Index   uint16
	Present bool
	// Version and PublicationDate are the NamespaceVersion and
	// NamespacePublicationDate of the NamespaceMetadata object of the
	// namespace (Part 5 §6.3.13, Part 81 §14.1), when the server has one.
	Version         string
	PublicationDate time.Time
}

// Report is what Inspect found on a server.
type Report struct {
	// Namespaces are DI, UAFX Data, UAFX AC and UAFX CM, in this order.
	Namespaces []Namespace
	// ServerCapabilities are the capability identifiers of the server
	// (Part 12 Annex D), from ServerConfiguration, when it has them. A
	// UAFX server announces FXAC and FXCM there.
	ServerCapabilities []string
	// FxRoot is the FxRoot object (Part 81 §12.2), nil if the server has
	// none.
	FxRoot *ua.NodeID
	// AutomationComponents are the AutomationComponents FxRoot organizes.
	AutomationComponents []AutomationComponent
	// ConnectionManagers are the ConnectionManagers FxRoot organizes
	// (Part 81 §12.3).
	ConnectionManagers []ConnectionManager
	// Findings are deviations of the model on the server from Part 81.
	Findings []Finding
	// Truncated reports that the server holds more than the Limits of
	// Inspect allowed it to read: the report leaves the rest out.
	Truncated bool
}

// Namespace returns the namespace uri of the report, and whether the
// server has it.
func (r *Report) Namespace(uri string) (Namespace, bool) {
	for _, n := range r.Namespaces {
		if n.URI == uri {
			return n, n.Present
		}
	}
	return Namespace{}, false
}

// HasFXNamespaces reports whether the server has the namespaces Part 81
// §14.2 (Table 260) makes mandatory for a UAFX server: DI, the UAFX Data
// namespace and at least one of AC and CM. It says nothing about the
// model in them.
func (r *Report) HasFXNamespaces() bool {
	_, di := r.Namespace(diid.NamespaceURI)
	_, data := r.Namespace(fxdataid.NamespaceURI)
	_, ac := r.Namespace(fxacid.NamespaceURI)
	_, cm := r.Namespace(fxcmid.NamespaceURI)
	return di && data && (ac || cm)
}

// IsFXServer reports whether the server has the structure of a UAFX
// server: the namespaces of HasFXNamespaces and FxRoot, which every server
// that exposes the UAFX model has (Part 81 §12.2). It is not a conformance
// statement: Findings lists what Inspect saw deviate from Part 81, and the
// behaviour of the model is not inspected at all.
func (r *Report) IsFXServer() bool {
	return r.HasFXNamespaces() && r.FxRoot != nil
}

// Finding is a deviation from Part 81 that Inspect found.
type Finding struct {
	// Node is the node concerned, nil for the server as a whole.
	Node *ua.NodeID
	// Path is the browse path of the node below FxRoot, "" for the
	// server as a whole.
	Path string
	// Clause is the clause of Part 81 the server deviates from.
	Clause string
	Text   string
}

func (f Finding) String() string {
	var b strings.Builder
	if f.Path != "" {
		b.WriteString(f.Path)
		b.WriteString(": ")
	}
	b.WriteString(f.Text)
	b.WriteString(" (Part 81 §")
	b.WriteString(f.Clause)
	b.WriteString(")")
	return b.String()
}

// Node is what a report holds of every node.
type Node struct {
	NodeID         *ua.NodeID
	BrowseName     *ua.QualifiedName
	DisplayName    string
	TypeDefinition *ua.NodeID
}

// AutomationComponent is an instance of AutomationComponentType (Part 81
// §6.2.2) or of a subtype.
type AutomationComponent struct {
	Node
	// ConformanceName is the URI of the product page at the OPC
	// Foundation, "" when the component has none.
	ConformanceName string
	// AggregatedHealth is nil when it cannot be read or decoded.
	AggregatedHealth   *AggregatedHealth
	Assets             []Asset
	FunctionalEntities []FunctionalEntity
	// Descriptors are the AcDescriptors (Part 81 §6.2.3) of the component.
	Descriptors []Node
	// Capabilities are the ComponentCapabilities of the component (Part
	// 81 §6.2.6 Table 26), nil when it has none.
	Capabilities *ComponentCapabilities
}

// ComponentCapabilities are the members of the ComponentCapabilities of an
// AutomationComponent (Part 81 §6.2.6 Table 26). Every member is optional:
// a nil field is one the component does not have or that cannot be read.
type ComponentCapabilities struct {
	// SupportsPersistence TRUE means the component supports persistent
	// ConnectionEndpoints (IsPersistent, §5.5.5); absent or FALSE means it
	// does not.
	SupportsPersistence   *bool
	MaxConnections        *uint32
	MaxConnectionsPerCall *uint32
	MaxFunctionalEntities *uint32
	MinConnections        *uint32
	CommandBundleRequired *bool
}

// Persistence reports whether the capabilities announce SupportsPersistence
// TRUE.
func (c *ComponentCapabilities) Persistence() bool {
	return c != nil && c.SupportsPersistence != nil && *c.SupportsPersistence
}

// Asset is an instance of FxAssetType (Part 81 §6.3.2) or of a subtype,
// with the nameplate the asset has. A field the asset does not have is
// empty.
type Asset struct {
	Node
	Manufacturer       string
	ManufacturerURI    string
	Model              string
	ProductCode        string
	HardwareRevision   string
	SoftwareRevision   string
	DeviceRevision     string
	SerialNumber       string
	ProductInstanceURI string
	AssetID            string
	ComponentName      string
	DeviceClass        string
}

// FunctionalEntity is an instance of FunctionalEntityType (Part 81 §6.4.2)
// or of a subtype.
type FunctionalEntity struct {
	Node
	AuthorURI                string
	AuthorAssignedIdentifier string
	// AuthorAssignedVersion is nil when the entity has none or it cannot
	// be decoded.
	AuthorAssignedVersion *FxVersion
	// OperationalHealth is nil when the entity has none.
	OperationalHealth   *OperationalHealth
	ConnectionEndpoints []ConnectionEndpoint
	// SubFunctionalEntities are the FunctionalEntities the entity holds.
	SubFunctionalEntities []FunctionalEntity
}

// ConnectionEndpoint is an instance of ConnectionEndpointType (Part 81
// §6.6.2) or of a subtype such as PubSubConnectionEndpointType (§6.6.3).
type ConnectionEndpoint struct {
	Node
	// Status is nil when it cannot be read.
	Status       *ConnectionEndpointStatus
	IsPersistent bool
	// CleanupTimeout is the CleanupTimeout of the endpoint, 0 when it is
	// negative (never cleaned up) or cannot be read; CleanupTimeoutMs has
	// the value itself.
	CleanupTimeout time.Duration
	// CleanupTimeoutMs is the CleanupTimeout as the server holds it, a
	// Duration in milliseconds (Part 3 §8.13), nil when it cannot be read.
	// A negative value means the endpoint is never cleaned up, which a
	// persistent endpoint requires (Part 81 §6.6.2).
	CleanupTimeoutMs *float64
	// CreationTime and ModificationTime are those of the Diagnostics of the
	// endpoint (Part 81 §6.6.2 Table 74), zero when it has none.
	CreationTime     time.Time
	ModificationTime time.Time
	// ConnectionManagerApplicationURI is the ApplicationUri of the
	// ConnectionManager that established the endpoint, when known.
	ConnectionManagerApplicationURI string
}

// ConnectionManager is an instance of ConnectionManagerType (Part 81
// §6.7.2) or of a subtype.
type ConnectionManager struct {
	Node
	// ConnectionConfigurationSets are the ConnectionConfigurationSets the
	// manager holds.
	ConnectionConfigurationSets []Node
}

// Limits bound what Inspect reads from a server, so that a server with a
// large or hostile address space cannot make it read without end. A zero
// field takes its default.
type Limits struct {
	// MaxComponents bounds the AutomationComponents and the
	// ConnectionManagers read. Default 256.
	MaxComponents int
	// MaxChildren bounds the children read of one node: Assets,
	// FunctionalEntities, ConnectionEndpoints. Default 1024.
	MaxChildren int
	// MaxDepth bounds the nesting of SubFunctionalEntities read.
	// Default 8.
	MaxDepth int
	// MaxNodes bounds the nodes the report holds in all: components,
	// Assets, FunctionalEntities, ConnectionEndpoints, Descriptors and
	// ConnectionConfigurationSets. Default 10000.
	MaxNodes int
}

func (l Limits) withDefaults() Limits {
	if l.MaxComponents <= 0 {
		l.MaxComponents = 256
	}
	if l.MaxChildren <= 0 {
		l.MaxChildren = 1024
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 8
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = 10000
	}
	return l
}

// maxSubtypeDepth bounds the walk from a type to its supertypes, and
// maxSupertypeLookups the types whose supertype Inspect asks the server
// for: a server with a type per node cannot make it browse without end.
const (
	maxSubtypeDepth     = 32
	maxSupertypeLookups = 4096
)

// The mandatory members of the UAFX ObjectTypes by browse name, as the
// ModellingRule Mandatory of the NodeSets of Part 81 version 1.00.04 marks
// them (TestMandatoryMatchesModel checks this against the embedded model).
var (
	mandatoryAC = []string{
		"AggregatedHealth", "Assets", "CloseConnections", "ComponentCapabilities",
		"Descriptors", "EstablishConnections", "FunctionalEntities",
	}
	mandatoryEndpoint       = []string{"CleanupTimeout", "IsPersistent", "RelatedEndpoint", "Status"}
	mandatoryPubSubEndpoint = []string{"Mode"}
	mandatoryCM             = []string{"ConnectionConfigurationSets"}
)

// ErrInspect wraps the errors of Inspect that end the inspection: a failed
// service call, not a deviation of the model, which is a Finding.
var ErrInspect = errors.New("uafx: inspect")

// Inspect reads the UAFX model of the server c is connected to: the
// namespaces, FxRoot, the AutomationComponents with their Assets,
// FunctionalEntities and ConnectionEndpoints, and the ConnectionManagers.
// A node that is missing or cannot be read is left out of the report or
// becomes a Finding; Inspect returns an error only when a service call
// fails. Its Browse and Read requests ask for one node at a time, or as
// many as the MaxNodesPerRead of the server allows (Part 5 §6.3.11).
func Inspect(ctx context.Context, c *opcua.Client, limits Limits) (*Report, error) {
	return inspect(ctx, c, limits, 0)
}

// client is what Inspect uses of an opcua.Client.
type client interface {
	NamespaceArray(ctx context.Context) ([]string, error)
	Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error)
	BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error)
	Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error)
}

var _ client = (*opcua.Client)(nil)

// inspect is Inspect with refsPerNode, the RequestedMaxReferencesPerNode
// of a Browse (0: as many as the server returns).
func inspect(ctx context.Context, c client, limits Limits, refsPerNode uint32) (*Report, error) {
	in := &inspector{
		c: c, lim: limits.withDefaults(), refsPerNode: refsPerNode,
		supertypes: map[string]*ua.NodeID{}, visited: map[string]bool{},
	}
	return in.run(ctx)
}

type inspector struct {
	c           client
	refsPerNode uint32
	maxRead     int // nodes per Read the server accepts, 0: no limit
	lim         Limits
	r           *Report
	ns          struct{ di, data, ac, cm uint16 }
	supertypes  map[string]*ua.NodeID // type → its supertype, nil at the root
	// visited holds the nodes the report holds. A node a server shows in
	// two places, or in a cycle, is reported once.
	visited map[string]bool
}

// visit reports whether the node n goes into the report: not yet in it,
// and within MaxNodes.
func (in *inspector) visit(n *ua.NodeID) bool {
	key := n.String()
	if in.visited[key] {
		return false
	}
	if len(in.visited) >= in.lim.MaxNodes {
		in.r.Truncated = true
		return false
	}
	in.visited[key] = true
	return true
}

func (in *inspector) run(ctx context.Context) (*Report, error) {
	in.r = &Report{}
	nsArray, err := in.c.NamespaceArray(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: read the NamespaceArray: %w", ErrInspect, err)
	}
	for _, x := range []struct {
		uri string
		idx *uint16
	}{
		{diid.NamespaceURI, &in.ns.di},
		{fxdataid.NamespaceURI, &in.ns.data},
		{fxacid.NamespaceURI, &in.ns.ac},
		{fxcmid.NamespaceURI, &in.ns.cm},
	} {
		n := Namespace{URI: x.uri}
		for i, u := range nsArray {
			if u == x.uri && i > 0 && i <= math.MaxUint16 {
				n.Index, n.Present = uint16(i), true
				break
			}
		}
		*x.idx = n.Index
		in.r.Namespaces = append(in.r.Namespaces, n)
	}
	if err := in.readOperationLimits(ctx); err != nil {
		return nil, err
	}
	if err := in.readNamespaceMetadata(ctx); err != nil {
		return nil, err
	}
	if err := in.readCapabilities(ctx); err != nil {
		return nil, err
	}
	if in.ns.data == 0 {
		if in.ns.ac != 0 || in.ns.cm != 0 {
			in.find(nil, "", "14.2", "the server has a UAFX AC or CM namespace without the mandatory UAFX Data namespace")
		}
		return in.r, nil
	}
	if in.ns.ac == 0 && in.ns.cm == 0 {
		in.find(nil, "", "14.2", "the server has the UAFX Data namespace but neither the AC nor the CM namespace")
	}
	if in.ns.di == 0 {
		in.find(nil, "", "14.2", "the server has the UAFX Data namespace but not the mandatory DI namespace")
	}
	if err := in.readFxRoot(ctx); err != nil {
		return nil, err
	}
	return in.r, nil
}

func (in *inspector) find(node *ua.NodeID, path, clause, format string, args ...any) {
	in.r.Findings = append(in.r.Findings, Finding{Node: node, Path: path, Clause: clause, Text: fmt.Sprintf(format, args...)})
}

// readNamespaceMetadata reads the NamespaceMetadata objects of the
// namespaces the server has, below Server/Namespaces (Part 5 §6.3.13).
func (in *inspector) readNamespaceMetadata(ctx context.Context) error {
	refs, err := in.children(ctx, ua.NewNumericNodeID(0, id.ServerNamespaces))
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if ref.NodeClass != ua.NodeClassObject {
			continue
		}
		props, err := in.readChildren(ctx, ref.NodeID.NodeID, 0, "NamespaceUri", "NamespaceVersion", "NamespacePublicationDate")
		if err != nil {
			return err
		}
		uri, _ := val(props["NamespaceUri"]).(string)
		for i := range in.r.Namespaces {
			n := &in.r.Namespaces[i]
			if !n.Present || n.URI != uri {
				continue
			}
			n.Version, _ = val(props["NamespaceVersion"]).(string)
			n.PublicationDate, _ = val(props["NamespacePublicationDate"]).(time.Time)
		}
	}
	return nil
}

// readOperationLimits reads MaxNodesPerRead of the OperationLimits of the
// server (Part 5 §6.3.11), so that no Read asks for more nodes than the
// server accepts. A server without the value, or with 0, has no limit.
func (in *inspector) readOperationLimits(ctx context.Context) error {
	vals, err := in.read(ctx, ua.NewNumericNodeID(0, id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead))
	if err != nil {
		return err
	}
	if n, ok := val(vals[0]).(uint32); ok && uint64(n) < math.MaxInt32 {
		in.maxRead = int(n)
	}
	return nil
}

// readCapabilities reads ServerConfiguration/ServerCapabilities, which a
// server need not have.
func (in *inspector) readCapabilities(ctx context.Context) error {
	vals, err := in.read(ctx, ua.NewNumericNodeID(0, id.ServerConfigurationServerCapabilities))
	if err != nil {
		return err
	}
	in.r.ServerCapabilities, _ = val(vals[0]).([]string)
	return nil
}

func (in *inspector) readFxRoot(ctx context.Context) error {
	root := ua.NewNumericNodeID(in.ns.data, fxdataid.FxRoot)
	refs, err := in.browse(ctx, root, id.Organizes, ua.NodeClassObject)
	if errors.Is(err, ua.StatusBadNodeIDUnknown) {
		in.find(nil, "", "12.2", "the server has the UAFX Data namespace but no FxRoot object")
		return nil
	}
	if err != nil {
		return err
	}
	in.r.FxRoot = root
	acType := ua.NewNumericNodeID(in.ns.ac, fxacid.AutomationComponentType)
	cmType := ua.NewNumericNodeID(in.ns.cm, fxcmid.ConnectionManagerType)
	n := 0
	for _, ref := range refs {
		if n >= in.lim.MaxComponents {
			in.r.Truncated = true
			break
		}
		node := nodeOf(ref)
		var isAC, isCM bool
		if in.ns.ac != 0 {
			if isAC, err = in.isSubtype(ctx, node.TypeDefinition, acType); err != nil {
				return err
			}
		}
		if !isAC && in.ns.cm != 0 {
			if isCM, err = in.isSubtype(ctx, node.TypeDefinition, cmType); err != nil {
				return err
			}
		}
		if (!isAC && !isCM) || !in.visit(node.NodeID) {
			continue
		}
		switch {
		case isAC:
			n++
			ac, err := in.readAC(ctx, node)
			if err != nil {
				return err
			}
			in.r.AutomationComponents = append(in.r.AutomationComponents, ac)
		default:
			n++
			cm, err := in.readCM(ctx, node)
			if err != nil {
				return err
			}
			in.r.ConnectionManagers = append(in.r.ConnectionManagers, cm)
		}
	}
	if len(in.r.ConnectionManagers) > 1 {
		in.find(root, "", "12.3", "FxRoot organizes %d ConnectionManagers; a server has at most one", len(in.r.ConnectionManagers))
	}
	return nil
}

func (in *inspector) readAC(ctx context.Context, ac Node) (AutomationComponent, error) {
	out := AutomationComponent{Node: ac}
	path := ac.BrowseName.Name
	members, err := in.children(ctx, ac.NodeID)
	if err != nil {
		return out, err
	}
	byName := index(members)
	in.checkMandatory(ac.NodeID, path, "6.2.2", "AutomationComponent", byName, in.ns.ac, mandatoryAC)

	vals, err := in.readRefs(ctx, byName, in.ns.ac, "ConformanceName", "AggregatedHealth")
	if err != nil {
		return out, err
	}
	out.ConformanceName, _ = val(vals["ConformanceName"]).(string)
	if v := vals["AggregatedHealth"]; val(v) != nil {
		h, err := decodeAggregatedHealth(v, in.ns.ac)
		if err != nil {
			in.find(byName.get(in.ns.ac, "AggregatedHealth").NodeID.NodeID, path+"/AggregatedHealth", "10.1", "%v", err)
		} else {
			out.AggregatedHealth = h
		}
	}

	if ref := byName.get(in.ns.ac, "Assets"); ref != nil {
		assetType := ua.NewNumericNodeID(in.ns.ac, fxacid.FxAssetType)
		assets, err := in.typedChildren(ctx, ref.NodeID.NodeID, assetType)
		if err != nil {
			return out, err
		}
		for _, a := range assets {
			asset, err := in.readAsset(ctx, a)
			if err != nil {
				return out, err
			}
			out.Assets = append(out.Assets, asset)
		}
	}
	if ref := byName.get(in.ns.ac, "FunctionalEntities"); ref != nil {
		fes, err := in.readFunctionalEntities(ctx, ref.NodeID.NodeID, path+"/FunctionalEntities", 0)
		if err != nil {
			return out, err
		}
		out.FunctionalEntities = fes
	}
	if ref := byName.get(in.ns.ac, "Descriptors"); ref != nil {
		descType := ua.NewNumericNodeID(in.ns.ac, fxacid.AcDescriptorType)
		descs, err := in.typedChildren(ctx, ref.NodeID.NodeID, descType)
		if err != nil {
			return out, err
		}
		out.Descriptors = descs
	}
	if ref := byName.get(in.ns.ac, "ComponentCapabilities"); ref != nil && ref.NodeClass == ua.NodeClassObject {
		caps, err := in.readCapabilitiesOf(ctx, ref.NodeID.NodeID)
		if err != nil {
			return out, err
		}
		out.Capabilities = caps
		in.checkPersistence(out)
	}
	return out, nil
}

// readCapabilitiesOf reads the members of the ComponentCapabilities n of
// an AutomationComponent (Part 81 §6.2.6 Table 26).
func (in *inspector) readCapabilitiesOf(ctx context.Context, n *ua.NodeID) (*ComponentCapabilities, error) {
	vals, err := in.readChildren(ctx, n, in.ns.ac, "SupportsPersistence", "MaxConnections",
		"MaxConnectionsPerCall", "MaxFunctionalEntities", "MinConnections", "CommandBundleRequired")
	if err != nil {
		return nil, err
	}
	return &ComponentCapabilities{
		SupportsPersistence:   valPtr[bool](vals["SupportsPersistence"]),
		MaxConnections:        valPtr[uint32](vals["MaxConnections"]),
		MaxConnectionsPerCall: valPtr[uint32](vals["MaxConnectionsPerCall"]),
		MaxFunctionalEntities: valPtr[uint32](vals["MaxFunctionalEntities"]),
		MinConnections:        valPtr[uint32](vals["MinConnections"]),
		CommandBundleRequired: valPtr[bool](vals["CommandBundleRequired"]),
	}, nil
}

// checkPersistence adds a Finding for each persistent ConnectionEndpoint
// of ac when ac does not announce SupportsPersistence TRUE: absent or
// FALSE means the component does not support persistent endpoints (Part
// 81 §6.2.6 Table 26).
func (in *inspector) checkPersistence(ac AutomationComponent) {
	if ac.Capabilities.Persistence() {
		return
	}
	var walk func(path string, fes []FunctionalEntity)
	walk = func(path string, fes []FunctionalEntity) {
		for _, fe := range fes {
			p := path + "/" + fe.BrowseName.Name
			for _, ep := range fe.ConnectionEndpoints {
				if ep.IsPersistent {
					in.find(ep.NodeID, p+"/ConnectionEndpoints/"+ep.BrowseName.Name, "6.2.6",
						"ConnectionEndpoint has IsPersistent TRUE, but its AutomationComponent does not announce SupportsPersistence TRUE")
				}
			}
			walk(p, fe.SubFunctionalEntities)
		}
	}
	walk(ac.BrowseName.Name+"/FunctionalEntities", ac.FunctionalEntities)
}

func (in *inspector) readAsset(ctx context.Context, a Node) (Asset, error) {
	out := Asset{Node: a}
	members, err := in.children(ctx, a.NodeID)
	if err != nil {
		return out, err
	}
	// The nameplate of an asset is that of the interfaces of DI it has
	// (Part 81 §6.3.2): its BrowseNames are in the DI namespace.
	if in.ns.di == 0 {
		return out, nil
	}
	vals, err := in.readRefs(ctx, index(members), in.ns.di,
		"Manufacturer", "ManufacturerUri", "Model", "ProductCode", "HardwareRevision", "SoftwareRevision",
		"DeviceRevision", "SerialNumber", "ProductInstanceUri", "AssetId", "ComponentName", "DeviceClass")
	if err != nil {
		return out, err
	}
	out.Manufacturer = text(vals["Manufacturer"])
	out.ManufacturerURI = text(vals["ManufacturerUri"])
	out.Model = text(vals["Model"])
	out.ProductCode = text(vals["ProductCode"])
	out.HardwareRevision = text(vals["HardwareRevision"])
	out.SoftwareRevision = text(vals["SoftwareRevision"])
	out.DeviceRevision = text(vals["DeviceRevision"])
	out.SerialNumber = text(vals["SerialNumber"])
	out.ProductInstanceURI = text(vals["ProductInstanceUri"])
	out.AssetID = text(vals["AssetId"])
	out.ComponentName = text(vals["ComponentName"])
	out.DeviceClass = text(vals["DeviceClass"])
	return out, nil
}

// readFunctionalEntities reads the FunctionalEntities below parent: the
// FunctionalEntities folder of an AutomationComponent, or a
// FunctionalEntity for its SubFunctionalEntities.
func (in *inspector) readFunctionalEntities(ctx context.Context, parent *ua.NodeID, path string, depth int) ([]FunctionalEntity, error) {
	feType := ua.NewNumericNodeID(in.ns.ac, fxacid.FunctionalEntityType)
	nodes, err := in.typedChildren(ctx, parent, feType)
	if err != nil {
		return nil, err
	}
	var out []FunctionalEntity
	for _, n := range nodes {
		fe, err := in.readFunctionalEntity(ctx, n, path+"/"+n.BrowseName.Name, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, fe)
	}
	return out, nil
}

func (in *inspector) readFunctionalEntity(ctx context.Context, n Node, path string, depth int) (FunctionalEntity, error) {
	out := FunctionalEntity{Node: n}
	members, err := in.children(ctx, n.NodeID)
	if err != nil {
		return out, err
	}
	byName := index(members)
	vals, err := in.readRefs(ctx, byName, in.ns.ac, "AuthorUri", "AuthorAssignedIdentifier", "AuthorAssignedVersion", "OperationalHealth")
	if err != nil {
		return out, err
	}
	out.AuthorURI = text(vals["AuthorUri"])
	out.AuthorAssignedIdentifier = text(vals["AuthorAssignedIdentifier"])
	if v := vals["AuthorAssignedVersion"]; val(v) != nil {
		ver, err := decodeFxVersion(v, in.ns.ac)
		if err != nil {
			in.find(n.NodeID, path+"/AuthorAssignedVersion", "10.28", "%v", err)
		} else {
			out.AuthorAssignedVersion = ver
		}
	}
	if v := vals["OperationalHealth"]; v != nil {
		if h, ok := val(v).(uint32); ok {
			oh := OperationalHealth(h)
			out.OperationalHealth = &oh
		}
	}
	if ref := byName.get(in.ns.ac, "ConnectionEndpoints"); ref != nil {
		ceType := ua.NewNumericNodeID(in.ns.ac, fxacid.ConnectionEndpointType)
		ces, err := in.typedChildren(ctx, ref.NodeID.NodeID, ceType)
		if err != nil {
			return out, err
		}
		for _, ce := range ces {
			e, err := in.readEndpoint(ctx, ce, path+"/ConnectionEndpoints/"+ce.BrowseName.Name)
			if err != nil {
				return out, err
			}
			out.ConnectionEndpoints = append(out.ConnectionEndpoints, e)
		}
	}
	if depth+1 >= in.lim.MaxDepth {
		subs, err := in.typedChildren(ctx, n.NodeID, ua.NewNumericNodeID(in.ns.ac, fxacid.FunctionalEntityType))
		if err != nil {
			return out, err
		}
		if len(subs) > 0 {
			in.r.Truncated = true
		}
		return out, nil
	}
	subs, err := in.readFunctionalEntities(ctx, n.NodeID, path, depth+1)
	if err != nil {
		return out, err
	}
	out.SubFunctionalEntities = subs
	return out, nil
}

func (in *inspector) readEndpoint(ctx context.Context, n Node, path string) (ConnectionEndpoint, error) {
	out := ConnectionEndpoint{Node: n}
	members, err := in.children(ctx, n.NodeID)
	if err != nil {
		return out, err
	}
	byName := index(members)
	in.checkMandatory(n.NodeID, path, "6.6.2", "ConnectionEndpoint", byName, in.ns.ac, mandatoryEndpoint)
	pubSub, err := in.isSubtype(ctx, n.TypeDefinition, ua.NewNumericNodeID(in.ns.ac, fxacid.PubSubConnectionEndpointType))
	if err != nil {
		return out, err
	}
	if pubSub {
		in.checkMandatory(n.NodeID, path, "6.6.3", "PubSubConnectionEndpoint", byName, in.ns.ac, mandatoryPubSubEndpoint)
	}
	vals, err := in.readRefs(ctx, byName, in.ns.ac, "Status", "IsPersistent", "CleanupTimeout", "ConnectionManagerApplicationUri")
	if err != nil {
		return out, err
	}
	if v := vals["Status"]; v != nil {
		if s, ok := val(v).(int32); ok {
			st := ConnectionEndpointStatus(s)
			out.Status = &st
		}
	}
	out.IsPersistent, _ = val(vals["IsPersistent"]).(bool)
	if ms, ok := val(vals["CleanupTimeout"]).(float64); ok {
		out.CleanupTimeout = durationOf(ms)
		out.CleanupTimeoutMs = &ms
		// "For a persistent ConnectionEndpoint, the CleanupTimeout shall be
		// set to a negative number" (Part 81 §6.6.2).
		if out.IsPersistent && !(ms < 0) {
			in.find(n.NodeID, path, "6.6.2", "persistent ConnectionEndpoint has CleanupTimeout %v ms; it shall be negative", ms)
		}
	}
	out.ConnectionManagerApplicationURI = text(vals["ConnectionManagerApplicationUri"])
	// The Diagnostics of the endpoint has the BrowseName of DI, its
	// members those of the AC namespace (Part 81 §6.6.2 Table 74).
	if ref := byName.get(in.ns.di, "Diagnostics"); in.ns.di != 0 && ref != nil && ref.NodeClass == ua.NodeClassObject {
		d, err := in.readChildren(ctx, ref.NodeID.NodeID, in.ns.ac, "CreationTime", "ModificationTime")
		if err != nil {
			return out, err
		}
		out.CreationTime, _ = val(d["CreationTime"]).(time.Time)
		out.ModificationTime, _ = val(d["ModificationTime"]).(time.Time)
	}
	return out, nil
}

func (in *inspector) readCM(ctx context.Context, n Node) (ConnectionManager, error) {
	out := ConnectionManager{Node: n}
	path := n.BrowseName.Name
	members, err := in.children(ctx, n.NodeID)
	if err != nil {
		return out, err
	}
	byName := index(members)
	in.checkMandatory(n.NodeID, path, "6.7.2", "ConnectionManager", byName, in.ns.cm, mandatoryCM)
	if ref := byName.get(in.ns.cm, "ConnectionConfigurationSets"); ref != nil {
		sets, err := in.children(ctx, ref.NodeID.NodeID)
		if err != nil {
			return out, err
		}
		for _, s := range sets {
			if s.NodeClass == ua.NodeClassObject && s.NodeID != nil && in.visit(s.NodeID.NodeID) {
				out.ConnectionConfigurationSets = append(out.ConnectionConfigurationSets, nodeOf(s))
			}
		}
	}
	return out, nil
}

// checkMandatory adds a Finding for each name of want, in the namespace
// ns, that has is missing.
func (in *inspector) checkMandatory(node *ua.NodeID, path, clause, what string, has members, ns uint16, want []string) {
	for _, m := range want {
		if has.get(ns, m) == nil {
			in.find(node, path, clause, "%s has no mandatory %s", what, m)
		}
	}
}

// typedChildren returns the Object children of parent whose type is typ or
// a subtype of it, at most MaxChildren.
func (in *inspector) typedChildren(ctx context.Context, parent *ua.NodeID, typ *ua.NodeID) ([]Node, error) {
	refs, err := in.children(ctx, parent)
	if err != nil {
		return nil, err
	}
	var out []Node
	for _, ref := range refs {
		if ref.NodeClass != ua.NodeClassObject {
			continue
		}
		n := nodeOf(ref)
		ok, err := in.isSubtype(ctx, n.TypeDefinition, typ)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if len(out) >= in.lim.MaxChildren {
			in.r.Truncated = true
			break
		}
		if in.visit(n.NodeID) {
			out = append(out, n)
		}
	}
	return out, nil
}

// children returns the forward hierarchical references of n.
func (in *inspector) children(ctx context.Context, n *ua.NodeID) ([]*ua.ReferenceDescription, error) {
	refs, err := in.browse(ctx, n, id.HierarchicalReferences, ua.NodeClassAll)
	if errors.Is(err, ua.StatusBadNodeIDUnknown) {
		return nil, nil
	}
	return refs, err
}

// browse returns the forward references of n of type refType and its
// subtypes to nodes of the classes of mask. A bad status of the node is an
// ErrInspect that wraps the status.
func (in *inspector) browse(ctx context.Context, n *ua.NodeID, refType uint32, mask ua.NodeClass) ([]*ua.ReferenceDescription, error) {
	req := &ua.BrowseRequest{
		View:                          &ua.ViewDescription{ViewID: ua.NewTwoByteNodeID(0)},
		RequestedMaxReferencesPerNode: in.refsPerNode,
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          n,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, refType),
			IncludeSubtypes: true,
			NodeClassMask:   uint32(mask),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	}
	resp, err := in.c.Browse(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: browse %v: %w", ErrInspect, n, err)
	}
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("%w: browse %v: %d results for 1 node", ErrInspect, n, len(resp.Results))
	}
	res := resp.Results[0]
	if res.StatusCode != ua.StatusOK {
		return nil, fmt.Errorf("%w: browse %v: %w", ErrInspect, n, res.StatusCode)
	}
	refs := res.References
	cp := res.ContinuationPoint
	// A continuation point holds resources of the session until it is
	// used up or released (Part 4 §5.8.3): release it on every way out.
	defer func() {
		if len(cp) > 0 {
			in.release(ctx, cp)
		}
	}()
	limit := in.lim.MaxChildren * 4 // members of a node besides its typed children
	for {
		if len(refs) > limit {
			refs = refs[:limit]
			in.r.Truncated = true
			break
		}
		if len(cp) == 0 {
			break
		}
		if len(refs) == limit {
			in.r.Truncated = true
			break
		}
		next, err := in.c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{cp}})
		if err != nil {
			return nil, fmt.Errorf("%w: browse next %v: %w", ErrInspect, n, err)
		}
		if len(next.Results) != 1 {
			return nil, fmt.Errorf("%w: browse next %v: %d results for 1 node", ErrInspect, n, len(next.Results))
		}
		if next.Results[0].StatusCode != ua.StatusOK {
			// The server dropped the continuation point.
			cp = nil
			in.r.Truncated = true
			break
		}
		page := next.Results[0].References
		cp = next.Results[0].ContinuationPoint
		if len(page) == 0 {
			// A page without references that continues: a server that
			// would keep Inspect browsing without end.
			in.r.Truncated = true
			break
		}
		refs = append(refs, page...)
	}
	// A reference without a target is of no use and would have to be
	// checked everywhere.
	out := refs[:0:0]
	for _, r := range refs {
		if r != nil && r.NodeID != nil && r.NodeID.NodeID != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// releaseTimeout bounds the BrowseNext that releases a continuation point.
const releaseTimeout = 5 * time.Second

// release releases the continuation point cp. It runs also when ctx is
// done, the reason Inspect returns early, so it has a context of its own
// that keeps the values of ctx.
func (in *inspector) release(ctx context.Context, cp []byte) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	_, _ = in.c.BrowseNext(ctx, &ua.BrowseNextRequest{ReleaseContinuationPoints: true, ContinuationPoints: [][]byte{cp}})
}

// readRefs reads the Value of the children byName has with the names in
// the namespace ns, in one Read. A child the server cannot read has no
// entry.
func (in *inspector) readRefs(ctx context.Context, byName members, ns uint16, names ...string) (map[string]*ua.Variant, error) {
	var ids []*ua.NodeID
	var have []string
	for _, n := range names {
		if ref := byName.get(ns, n); ref != nil && ref.NodeClass == ua.NodeClassVariable {
			ids = append(ids, ref.NodeID.NodeID)
			have = append(have, n)
		}
	}
	out := map[string]*ua.Variant{}
	if len(ids) == 0 {
		return out, nil
	}
	vals, err := in.read(ctx, ids...)
	if err != nil {
		return nil, err
	}
	for i, v := range vals {
		if v != nil {
			out[have[i]] = v
		}
	}
	return out, nil
}

// readChildren reads the Values of the children of n with the given
// browse names in the namespace ns.
func (in *inspector) readChildren(ctx context.Context, n *ua.NodeID, ns uint16, names ...string) (map[string]*ua.Variant, error) {
	refs, err := in.children(ctx, n)
	if err != nil {
		return nil, err
	}
	return in.readRefs(ctx, index(refs), ns, names...)
}

// read reads the Value attribute of ids. The value of a node the server
// cannot read is nil.
func (in *inspector) read(ctx context.Context, ids ...*ua.NodeID) ([]*ua.Variant, error) {
	out := make([]*ua.Variant, 0, len(ids))
	for len(ids) > 0 {
		n := len(ids)
		if in.maxRead > 0 && n > in.maxRead {
			n = in.maxRead
		}
		vals, err := in.readBatch(ctx, ids[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, vals...)
		ids = ids[n:]
	}
	return out, nil
}

// readBatch reads the Value attribute of ids in one Read.
func (in *inspector) readBatch(ctx context.Context, ids []*ua.NodeID) ([]*ua.Variant, error) {
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, n := range ids {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue})
	}
	resp, err := in.c.Read(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", ErrInspect, err)
	}
	if len(resp.Results) != len(ids) {
		return nil, fmt.Errorf("%w: read: %d results for %d nodes", ErrInspect, len(resp.Results), len(ids))
	}
	out := make([]*ua.Variant, len(ids))
	for i, dv := range resp.Results {
		if dv == nil || dv.Value == nil {
			continue
		}
		if dv.Status == ua.StatusOK {
			out[i] = dv.Value
			continue
		}
		// The client marks a structure of a type package ua does not know
		// with Bad_DataTypeIdUnknown and keeps its body, which
		// decodeAggregatedHealth and decodeFxVersion read.
		if _, ok := dv.Value.Value().(*ua.ExtensionObject); ok && dv.Status == ua.StatusBadDataTypeIDUnknown {
			out[i] = dv.Value
		}
	}
	return out, nil
}

// isSubtype reports whether typ is base or one of its subtypes, by the
// inverse HasSubtype references of typ and its supertypes. A type whose
// supertype the server cannot tell is an ErrInspect, not "no subtype": a
// component of a vendor type must not drop out of the report unnoticed. A
// chain longer than maxSubtypeDepth, or more types than
// maxSupertypeLookups, truncates the report.
func (in *inspector) isSubtype(ctx context.Context, typ, base *ua.NodeID) (bool, error) {
	for range maxSubtypeDepth {
		if typ == nil {
			return false, nil
		}
		if typ.Equal(base) {
			return true, nil
		}
		if typ.Namespace() == 0 {
			// The UAFX types derive from types of namespace 0, never
			// the other way around.
			return false, nil
		}
		key := typ.String()
		super, ok := in.supertypes[key]
		if !ok {
			if len(in.supertypes) >= maxSupertypeLookups {
				in.r.Truncated = true
				return false, nil
			}
			var err error
			if super, err = in.supertype(ctx, typ); err != nil {
				return false, err
			}
			in.supertypes[key] = super
		}
		typ = super
	}
	in.r.Truncated = true
	return false, nil
}

// supertype returns the supertype of typ, nil if it has none.
func (in *inspector) supertype(ctx context.Context, typ *ua.NodeID) (*ua.NodeID, error) {
	req := &ua.BrowseRequest{
		View: &ua.ViewDescription{ViewID: ua.NewTwoByteNodeID(0)},
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          typ,
			BrowseDirection: ua.BrowseDirectionInverse,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HasSubtype),
			NodeClassMask:   uint32(ua.NodeClassObjectType | ua.NodeClassVariableType),
			ResultMask:      uint32(ua.BrowseResultMaskNone),
		}},
	}
	resp, err := in.c.Browse(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: supertype of %v: %w", ErrInspect, typ, err)
	}
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("%w: supertype of %v: %d results for 1 node", ErrInspect, typ, len(resp.Results))
	}
	res := resp.Results[0]
	if res.StatusCode != ua.StatusOK {
		return nil, fmt.Errorf("%w: supertype of %v: %w", ErrInspect, typ, res.StatusCode)
	}
	if len(res.ContinuationPoint) > 0 {
		in.release(ctx, res.ContinuationPoint)
	}
	for _, ref := range res.References {
		if ref != nil && ref.NodeID != nil && ref.NodeID.NodeID != nil {
			return ref.NodeID.NodeID, nil
		}
	}
	return nil, nil
}

func nodeOf(ref *ua.ReferenceDescription) Node {
	n := Node{NodeID: ref.NodeID.NodeID, BrowseName: ref.BrowseName}
	if n.BrowseName == nil {
		n.BrowseName = &ua.QualifiedName{}
	}
	if ref.DisplayName != nil {
		n.DisplayName = ref.DisplayName.Text
	}
	if ref.TypeDefinition != nil {
		n.TypeDefinition = ref.TypeDefinition.NodeID
	}
	return n
}

// members are the children of a node by their BrowseName: namespace index
// and name. A member of a standard type has the BrowseName the standard
// gives it, in the namespace of the standard (Part 81 §14.2), so a vendor
// child of the same name in another namespace is a different member.
type members map[ua.QualifiedName]*ua.ReferenceDescription

// get returns the member with the name in the namespace ns, nil if there
// is none.
func (m members) get(ns uint16, name string) *ua.ReferenceDescription {
	return m[ua.QualifiedName{NamespaceIndex: ns, Name: name}]
}

// index maps the browse names of refs to the references. The first of two
// references with the same BrowseName wins.
func index(refs []*ua.ReferenceDescription) members {
	m := make(members, len(refs))
	for _, r := range refs {
		if r.BrowseName == nil || r.NodeID == nil {
			continue
		}
		if _, ok := m[*r.BrowseName]; !ok {
			m[*r.BrowseName] = r
		}
	}
	return m
}

// text returns a String or the text of a LocalizedText value, "" for
// anything else.
func text(v *ua.Variant) string {
	switch x := val(v).(type) {
	case string:
		return x
	case *ua.LocalizedText:
		if x != nil {
			return x.Text
		}
	}
	return ""
}

// val returns the value of v, nil for a nil v.
func val(v *ua.Variant) any {
	if v == nil {
		return nil
	}
	return v.Value()
}

// valPtr returns a pointer to the value of v when it is a T, nil
// otherwise.
func valPtr[T any](v *ua.Variant) *T {
	x, ok := val(v).(T)
	if !ok {
		return nil
	}
	return &x
}

// durationOf converts a Duration in milliseconds (Part 3 §8.13) to a
// time.Duration, saturating at its range; a negative or NaN value is 0.
func durationOf(ms float64) time.Duration {
	switch {
	case !(ms > 0):
		return 0
	case ms >= float64(math.MaxInt64/int64(time.Millisecond)):
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ms * float64(time.Millisecond))
}
