// SPDX-License-Identifier: MIT

// Package remote configures the PubSub of an OPC UA server through the
// methods of its PublishSubscribe information model (Part 14 §9):
// AddConnection, AddWriterGroup, AddDataSetWriter, AddReaderGroup,
// AddDataSetReader, AddPublishedDataItems, their Remove counterparts and
// the Enable and Disable methods of the PubSubStatus objects.
//
// It works with any server that implements the model: the methods are
// looked up by BrowseName below the object they are called on, so both the
// NodeIds of the type's method declarations (open62541, this module's
// server) and instance method nodes are found.
package remote

import (
	"context"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Well-known nodes of the PublishSubscribe object.
var (
	// PublishSubscribe is the PublishSubscribe object (i=14443); it is the
	// component of the runtime itself for Enable, Disable and State.
	PublishSubscribe = ua.NewNumericNodeID(0, id.PublishSubscribe)
	// PublishedDataSets is the folder of the published data sets.
	PublishedDataSets = ua.NewNumericNodeID(0, id.PublishSubscribePublishedDataSets)
)

// Client calls the PubSub configuration methods of a server.
type Client struct {
	c *opcua.Client

	mu      sync.Mutex
	methods map[string]*ua.NodeID
}

// New returns a Client that uses the session of c.
func New(c *opcua.Client) *Client {
	return &Client{c: c, methods: map[string]*ua.NodeID{}}
}

// Component is a PubSub component found in the address space.
type Component struct {
	NodeID *ua.NodeID
	Name   string
}

// method finds the method name of an object: a forward HasComponent
// reference to a Method with that BrowseName, or the fallback.
func (r *Client) method(ctx context.Context, obj *ua.NodeID, name string, fallback uint32) (*ua.NodeID, error) {
	key := obj.String() + "\x00" + name
	r.mu.Lock()
	m := r.methods[key]
	r.mu.Unlock()
	if m != nil {
		return m, nil
	}
	refs, err := r.c.Node(obj).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassMethod, true)
	if err != nil {
		return nil, err
	}
	m = ua.NewNumericNodeID(0, fallback)
	for _, ref := range refs {
		if ref.BrowseName != nil && ref.BrowseName.Name == name && ref.NodeID != nil {
			m = ref.NodeID.NodeID
			break
		}
	}
	r.mu.Lock()
	r.methods[key] = m
	r.mu.Unlock()
	return m, nil
}

// Error is the Bad status a method call returned.
type Error struct {
	Method string
	Status ua.StatusCode
}

func (e *Error) Error() string { return fmt.Sprintf("remote: %s: %v", e.Method, e.Status) }

// Unwrap returns the status, so errors.Is(err, ua.StatusBadXxx) holds.
func (e *Error) Unwrap() error { return e.Status }

func (r *Client) call(ctx context.Context, obj *ua.NodeID, name string, fallback uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	m, err := r.method(ctx, obj, name, fallback)
	if err != nil {
		return nil, err
	}
	res, err := r.c.Call(ctx, &ua.CallMethodRequest{ObjectID: obj, MethodID: m, InputArguments: args})
	if err != nil {
		return nil, err
	}
	if res.StatusCode != ua.StatusOK {
		return nil, &Error{Method: name, Status: res.StatusCode}
	}
	if len(res.OutputArguments) < outputs {
		return nil, fmt.Errorf("remote: %s: %d output arguments, want %d", name, len(res.OutputArguments), outputs)
	}
	return res.OutputArguments, nil
}

func structArg(v any) *ua.Variant { return ua.MustVariant(ua.NewExtensionObject(v)) }

func structsArg[T any](xs []*T) *ua.Variant {
	out := make([]*ua.ExtensionObject, len(xs))
	for i, x := range xs {
		out[i] = ua.NewExtensionObject(x)
	}
	return ua.MustVariant(out)
}

func nodeIDOut(name string, v *ua.Variant) (*ua.NodeID, error) {
	n, ok := v.Value().(*ua.NodeID)
	if !ok {
		return nil, fmt.Errorf("remote: %s returned %T, want a NodeId", name, v.Value())
	}
	return n, nil
}

func (r *Client) addCall(ctx context.Context, obj *ua.NodeID, name string, fallback uint32, cfg any) (*ua.NodeID, error) {
	out, err := r.call(ctx, obj, name, fallback, 1, structArg(cfg))
	if err != nil {
		return nil, err
	}
	return nodeIDOut(name, out[0])
}

// AddConnection adds a PubSubConnection (with its groups, writers and
// readers) and returns the NodeId of its object.
func (r *Client) AddConnection(ctx context.Context, cfg *ua.PubSubConnectionDataType) (*ua.NodeID, error) {
	return r.addCall(ctx, PublishSubscribe, "AddConnection", id.PublishSubscribeAddConnection, cfg)
}

// RemoveConnection removes a PubSubConnection.
func (r *Client) RemoveConnection(ctx context.Context, conn *ua.NodeID) error {
	_, err := r.call(ctx, PublishSubscribe, "RemoveConnection", id.PublishSubscribeRemoveConnection, 0, ua.MustVariant(conn))
	return err
}

// AddWriterGroup adds a WriterGroup to the connection conn.
func (r *Client) AddWriterGroup(ctx context.Context, conn *ua.NodeID, cfg *ua.WriterGroupDataType) (*ua.NodeID, error) {
	return r.addCall(ctx, conn, "AddWriterGroup", id.PubSubConnectionTypeAddWriterGroup, cfg)
}

// AddReaderGroup adds a ReaderGroup to the connection conn.
func (r *Client) AddReaderGroup(ctx context.Context, conn *ua.NodeID, cfg *ua.ReaderGroupDataType) (*ua.NodeID, error) {
	return r.addCall(ctx, conn, "AddReaderGroup", id.PubSubConnectionTypeAddReaderGroup, cfg)
}

// RemoveGroup removes a WriterGroup or ReaderGroup of the connection conn.
func (r *Client) RemoveGroup(ctx context.Context, conn, group *ua.NodeID) error {
	_, err := r.call(ctx, conn, "RemoveGroup", id.PubSubConnectionTypeRemoveGroup, 0, ua.MustVariant(group))
	return err
}

// AddDataSetWriter adds a DataSetWriter to the WriterGroup group.
func (r *Client) AddDataSetWriter(ctx context.Context, group *ua.NodeID, cfg *ua.DataSetWriterDataType) (*ua.NodeID, error) {
	return r.addCall(ctx, group, "AddDataSetWriter", id.WriterGroupTypeAddDataSetWriter, cfg)
}

// RemoveDataSetWriter removes a DataSetWriter of the WriterGroup group.
func (r *Client) RemoveDataSetWriter(ctx context.Context, group, writer *ua.NodeID) error {
	_, err := r.call(ctx, group, "RemoveDataSetWriter", id.WriterGroupTypeRemoveDataSetWriter, 0, ua.MustVariant(writer))
	return err
}

// AddDataSetReader adds a DataSetReader to the ReaderGroup group.
func (r *Client) AddDataSetReader(ctx context.Context, group *ua.NodeID, cfg *ua.DataSetReaderDataType) (*ua.NodeID, error) {
	return r.addCall(ctx, group, "AddDataSetReader", id.ReaderGroupTypeAddDataSetReader, cfg)
}

// RemoveDataSetReader removes a DataSetReader of the ReaderGroup group.
func (r *Client) RemoveDataSetReader(ctx context.Context, group, reader *ua.NodeID) error {
	_, err := r.call(ctx, group, "RemoveDataSetReader", id.ReaderGroupTypeRemoveDataSetReader, 0, ua.MustVariant(reader))
	return err
}

// PublishedDataItemsResult is the result of AddPublishedDataItems.
type PublishedDataItemsResult struct {
	DataSetNodeID        *ua.NodeID
	ConfigurationVersion *ua.ConfigurationVersionDataType
	// AddResults has one status per variable; variables with a Bad status
	// were not added.
	AddResults []ua.StatusCode
}

// AddPublishedDataItems adds a PublishedDataItems data set. aliases are the
// field names, one per variable; flags may be nil or one per variable
// (ua.DataSetFieldFlagsPromotedField).
func (r *Client) AddPublishedDataItems(ctx context.Context, name string, aliases []string, flags []ua.DataSetFieldFlags, vars []*ua.PublishedVariableDataType) (*PublishedDataItemsResult, error) {
	if aliases == nil {
		aliases = []string{}
	}
	fl := make([]uint16, len(flags))
	for i, f := range flags {
		fl[i] = uint16(f)
	}
	out, err := r.call(ctx, PublishedDataSets, "AddPublishedDataItems", id.DataSetFolderTypeAddPublishedDataItems, 3,
		ua.MustVariant(name), ua.MustVariant(aliases), ua.MustVariant(fl), structsArg(vars))
	if err != nil {
		return nil, err
	}
	res := &PublishedDataItemsResult{}
	if res.DataSetNodeID, err = nodeIDOut("AddPublishedDataItems", out[0]); err != nil {
		return nil, err
	}
	if e, ok := out[1].Value().(*ua.ExtensionObject); ok && e != nil {
		res.ConfigurationVersion, _ = e.Value.(*ua.ConfigurationVersionDataType)
	}
	res.AddResults, _ = out[2].Value().([]ua.StatusCode)
	return res, nil
}

// AddPublishedDataItemsTemplate adds a PublishedDataItems data set with
// given DataSetMetaData (one field per variable). It returns the NodeId of
// the data set and one status per variable.
func (r *Client) AddPublishedDataItemsTemplate(ctx context.Context, name string, md *ua.DataSetMetaDataType, vars []*ua.PublishedVariableDataType) (*ua.NodeID, []ua.StatusCode, error) {
	out, err := r.call(ctx, PublishedDataSets, "AddPublishedDataItemsTemplate", id.DataSetFolderTypeAddPublishedDataItemsTemplate, 2,
		ua.MustVariant(name), structArg(md), structsArg(vars))
	if err != nil {
		return nil, nil, err
	}
	n, err := nodeIDOut("AddPublishedDataItemsTemplate", out[0])
	if err != nil {
		return nil, nil, err
	}
	results, _ := out[1].Value().([]ua.StatusCode)
	return n, results, nil
}

// RemovePublishedDataSet removes a published data set (and its writers).
func (r *Client) RemovePublishedDataSet(ctx context.Context, dataSet *ua.NodeID) error {
	_, err := r.call(ctx, PublishedDataSets, "RemovePublishedDataSet", id.DataSetFolderTypeRemovePublishedDataSet, 0, ua.MustVariant(dataSet))
	return err
}

// child returns the target of a forward hierarchical reference of obj with
// the given BrowseName.
func (r *Client) child(ctx context.Context, obj *ua.NodeID, name string) (*ua.NodeID, error) {
	refs, err := r.c.Node(obj).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if ref.BrowseName != nil && ref.BrowseName.Name == name && ref.NodeID != nil {
			return ref.NodeID.NodeID, nil
		}
	}
	return nil, fmt.Errorf("remote: %v has no child %q: %w", obj, name, ua.StatusBadNotFound)
}

func (r *Client) status(ctx context.Context, component *ua.NodeID) (*ua.NodeID, error) {
	if component == nil {
		component = PublishSubscribe
	}
	return r.child(ctx, component, "Status")
}

// Enable enables a component (connection, group, writer, reader, or the
// PublishSubscribe object itself) with the Enable method of its Status.
func (r *Client) Enable(ctx context.Context, component *ua.NodeID) error {
	st, err := r.status(ctx, component)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, st, "Enable", id.PubSubStatusTypeEnable, 0)
	return err
}

// Disable disables a component with the Disable method of its Status.
func (r *Client) Disable(ctx context.Context, component *ua.NodeID) error {
	st, err := r.status(ctx, component)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, st, "Disable", id.PubSubStatusTypeDisable, 0)
	return err
}

// State reads the Status.State of a component (nil: PublishSubscribe).
func (r *Client) State(ctx context.Context, component *ua.NodeID) (ua.PubSubState, error) {
	st, err := r.status(ctx, component)
	if err != nil {
		return 0, err
	}
	state, err := r.child(ctx, st, "State")
	if err != nil {
		return 0, err
	}
	v, err := r.c.Node(state).Value(ctx)
	if err != nil {
		return 0, err
	}
	switch x := v.Value().(type) {
	case int32:
		return ua.PubSubState(x), nil
	case uint32:
		return ua.PubSubState(x), nil
	}
	return 0, fmt.Errorf("remote: State is %T", v.Value())
}

// Property reads a property (or variable component) of a component, for
// example "PublisherId" of a connection or "DataSetMetaData" of a reader.
func (r *Client) Property(ctx context.Context, component *ua.NodeID, name string) (*ua.Variant, error) {
	n, err := r.child(ctx, component, name)
	if err != nil {
		return nil, err
	}
	return r.c.Node(n).Value(ctx)
}

func (r *Client) children(ctx context.Context, parent *ua.NodeID, refType uint32, typeDef uint32) ([]Component, error) {
	refs, err := r.c.Node(parent).References(ctx, refType, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	if err != nil {
		return nil, err
	}
	var out []Component
	for _, ref := range refs {
		if ref.NodeID == nil || ref.BrowseName == nil {
			continue
		}
		if typeDef != 0 && ref.TypeDefinition != nil && ref.TypeDefinition.NodeID != nil && ref.TypeDefinition.NodeID.IntID() != typeDef {
			continue
		}
		out = append(out, Component{NodeID: ref.NodeID.NodeID, Name: ref.BrowseName.Name})
	}
	return out, nil
}

// Connections lists the PubSubConnections of the server.
func (r *Client) Connections(ctx context.Context) ([]Component, error) {
	return r.children(ctx, PublishSubscribe, id.HasComponent, id.PubSubConnectionType)
}

// WriterGroups lists the WriterGroups of a connection.
func (r *Client) WriterGroups(ctx context.Context, conn *ua.NodeID) ([]Component, error) {
	return r.children(ctx, conn, id.HasComponent, id.WriterGroupType)
}

// ReaderGroups lists the ReaderGroups of a connection.
func (r *Client) ReaderGroups(ctx context.Context, conn *ua.NodeID) ([]Component, error) {
	return r.children(ctx, conn, id.HasComponent, id.ReaderGroupType)
}

// DataSetWriters lists the DataSetWriters of a WriterGroup.
func (r *Client) DataSetWriters(ctx context.Context, group *ua.NodeID) ([]Component, error) {
	return r.children(ctx, group, id.HasComponent, id.DataSetWriterType)
}

// DataSetReaders lists the DataSetReaders of a ReaderGroup.
func (r *Client) DataSetReaders(ctx context.Context, group *ua.NodeID) ([]Component, error) {
	return r.children(ctx, group, id.HasComponent, id.DataSetReaderType)
}

// PublishedDataSets lists the published data sets of the server.
func (r *Client) PublishedDataSets(ctx context.Context) ([]Component, error) {
	return r.children(ctx, PublishedDataSets, id.HasComponent, 0)
}
