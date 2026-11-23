// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// endpoint is a PubSubConnectionEndpoint (Part 81 §6.6.3) the connections
// manage.
type endpoint struct {
	id     *ua.NodeID
	fe     *ua.NodeID // the FunctionalEntity of its ConnectionEndpoints folder
	folder *ua.NodeID
	name   string

	// created: EstablishConnections created it; CloseConnections with
	// Remove deletes it and the nodes below. A preconfigured one stays.
	created bool
	nodes   []*ua.NodeID // the nodes created for it, the endpoint last

	mode    uafx.PubSubConnectionEndpointMode
	inputs  []*ua.NodeID
	outputs []*ua.NodeID
	cleanup time.Duration // < 0: no cleanup (Part 81 §6.6.2)

	// The DataSetReader and DataSetWriter of the endpoint (ToDataSetReader,
	// ToDataSetWriter), nil when it references none.
	reader, writer *ua.NodeID
	// ownReader, ownWriter: the configuration of the reader or writer came
	// with the EstablishConnections call that set the reference, so
	// CloseConnections with Remove removes it unless another endpoint
	// references it (Part 81 §6.2.5.2).
	ownReader, ownWriter bool

	status atomic.Int32 // uafx.ConnectionEndpointStatus

	// cleanupOff: CloseConnections disabled the CleanupTimeout processing
	// (Part 81 §6.2.5.2) until EnableCommunicationCmd enables it again.
	cleanupOff bool
	// deadline is when the CleanupTimeout expires; zero when it does not
	// run.
	deadline time.Time
}

// Status returns the Status of e.
func (e *endpoint) Status() uafx.ConnectionEndpointStatus {
	return uafx.ConnectionEndpointStatus(e.status.Load())
}

// adopt starts managing the PubSubConnectionEndpoints of the
// ConnectionEndpoints folder of fe that exist already (preconfigured, Part
// 81 §5.5.5).
func (c *Connections) adopt(fe *ua.NodeID) {
	folder := c.childID(fe, "ConnectionEndpoints")
	if folder == nil {
		return
	}
	for _, r := range c.children(folder, id.HierarchicalReferences) {
		n := r.NodeID.NodeID
		if !c.isA(n, fxacid.PubSubConnectionEndpointType) {
			continue
		}
		e := &endpoint{id: n, fe: fe, folder: folder, name: r.BrowseName.Name, cleanup: -1}
		if v, ok := val(c.value(c.childID(n, "Mode"))).(int32); ok {
			e.mode = uafx.PubSubConnectionEndpointMode(v)
		}
		if v, ok := val(c.value(c.childID(n, "CleanupTimeout"))).(float64); ok && v >= 0 {
			e.cleanup = time.Duration(v * float64(time.Millisecond))
		}
		e.inputs, _ = val(c.value(c.childID(n, "InputVariables"))).([]*ua.NodeID)
		e.outputs, _ = val(c.value(c.childID(n, "OutputVariables"))).([]*ua.NodeID)
		e.reader = c.target(n, fxacid.ToDataSetReader)
		e.writer = c.target(n, fxacid.ToDataSetWriter)
		e.status.Store(int32(c.derive(e)))
		c.ownStatus(e)
		c.mu.Lock()
		c.endpoints[n.String()] = e
		c.mu.Unlock()
	}
}

// target returns the target of the reference of the AC type refType of n.
func (c *Connections) target(n *ua.NodeID, refType uint32) *ua.NodeID {
	for _, r := range c.browse(n, ua.NewNumericNodeID(c.ns.AC, refType), ua.BrowseDirectionForward) {
		return r.NodeID.NodeID
	}
	return nil
}

// ownStatus makes the Status variable of e show the Status the connections
// derive.
func (c *Connections) ownStatus(e *endpoint) {
	if n := c.node(c.childID(e.id, "Status")); n != nil {
		n.SetValueFunc(func() *ua.DataValue { return server.DataValueFromValue(int32(e.Status())) })
	}
}

// pubsubState maps a DataSetReader or DataSetWriter to the Status of an
// endpoint (Part 81 §6.6.3, Figures 32 and 33): a component that is not
// referenced or does not exist is Initial, a Disabled or Paused one Ready.
func (c *Connections) pubsubState(n *ua.NodeID) uafx.ConnectionEndpointStatus {
	if n == nil {
		return uafx.ConnectionEndpointInitial
	}
	cid, ok := c.srv.PubSubComponentID(n)
	if !ok {
		return uafx.ConnectionEndpointInitial
	}
	st, err := c.srv.PubSub().State(cid)
	if err != nil {
		return uafx.ConnectionEndpointInitial
	}
	switch st {
	case ua.PubSubStateOperational:
		return uafx.ConnectionEndpointOperational
	case ua.PubSubStatePreOperational:
		return uafx.ConnectionEndpointPreOperational
	case ua.PubSubStateError:
		return uafx.ConnectionEndpointError
	case ua.PubSubStateDisabled, ua.PubSubStatePaused:
		return uafx.ConnectionEndpointReady
	}
	return uafx.ConnectionEndpointReady
}

// derive returns the Status of e from its DataSetReader and DataSetWriter
// (Part 81 §6.6.3): of the one its Mode requires, or for
// PublisherSubscriber both as in Figure 31.
func (c *Connections) derive(e *endpoint) uafx.ConnectionEndpointStatus {
	c.mu.Lock()
	reader, writer := e.reader, e.writer
	c.mu.Unlock()
	switch e.mode {
	case uafx.PubSubPublisher:
		return c.pubsubState(writer)
	case uafx.PubSubSubscriber:
		return c.pubsubState(reader)
	case uafx.PubSubPublisherSubscriber:
		r, w := c.pubsubState(reader), c.pubsubState(writer)
		switch {
		case r == uafx.ConnectionEndpointInitial || w == uafx.ConnectionEndpointInitial:
			return uafx.ConnectionEndpointInitial
		case r == uafx.ConnectionEndpointError || w == uafx.ConnectionEndpointError:
			return uafx.ConnectionEndpointError
		case r == uafx.ConnectionEndpointReady || w == uafx.ConnectionEndpointReady:
			return uafx.ConnectionEndpointReady
		case r == uafx.ConnectionEndpointOperational && w == uafx.ConnectionEndpointOperational:
			return uafx.ConnectionEndpointOperational
		}
		return uafx.ConnectionEndpointPreOperational
	}
	return uafx.ConnectionEndpointInitial
}

// monitor updates the Status of the endpoints until Close.
func (c *Connections) monitor() {
	defer close(c.done)
	t := time.NewTicker(c.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.refresh(false)
			c.expireDue()
		}
	}
}

// refreshAll updates the Status of every endpoint, starts and stops their
// CleanupTimeouts and updates the health. It does not close endpoints, so
// that it can run while a call holds c.call; expireDue does.
func (c *Connections) refreshAll() { c.refresh(true) }

// refresh is refreshAll; without health it updates the health only when a
// Status changed, which is all the monitor needs between calls.
func (c *Connections) refresh(health bool) {
	now := time.Now()
	var changed []*ua.NodeID
	c.mu.Lock()
	eps := make([]*endpoint, 0, len(c.endpoints))
	for _, e := range c.endpoints {
		eps = append(eps, e)
	}
	c.mu.Unlock()
	for _, e := range eps {
		old, st := e.Status(), c.derive(e)
		c.mu.Lock()
		if st != old {
			e.status.Store(int32(st))
			if s := c.childID(e.id, "Status"); s != nil {
				changed = append(changed, s)
			}
			// The CleanupTimeout starts when the Status leaves Operational
			// and stops when it returns (Part 81 §6.6.2).
			switch {
			case st == uafx.ConnectionEndpointOperational:
				e.deadline = time.Time{}
			case old == uafx.ConnectionEndpointOperational && e.cleanup >= 0 && !e.cleanupOff:
				e.deadline = now.Add(e.cleanup)
			}
		}
		c.mu.Unlock()
	}
	for _, n := range changed {
		c.srv.ChangeNotification(n)
	}
	if health || len(changed) > 0 {
		c.refreshHealth()
	}
}

// due returns the endpoints whose CleanupTimeout has expired.
func (c *Connections) due(now time.Time) []*endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*endpoint
	for _, e := range c.endpoints {
		if !e.cleanupOff && !e.deadline.IsZero() && !now.Before(e.deadline) {
			out = append(out, e)
		}
	}
	return out
}

// expireDue closes the endpoints whose CleanupTimeout has expired. It
// decides under c.call, after the calls that ran before it: an endpoint a
// CloseConnections closed meanwhile has its cleanup off, one an
// EstablishConnections took again has a new deadline or none, and one that
// is Operational again is not closed (Part 81 §6.2.5.2, §6.6.2).
func (c *Connections) expireDue() {
	if len(c.due(time.Now())) == 0 {
		return
	}
	c.mu.Lock()
	hook := c.beforeExpire
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	c.call.Lock()
	defer c.call.Unlock()
	// due reads the endpoints again: one a call removed is not there.
	for _, e := range c.due(time.Now()) {
		if c.derive(e) == uafx.ConnectionEndpointOperational {
			c.mu.Lock()
			e.deadline = timeZero
			c.mu.Unlock()
			continue
		}
		c.expire(e)
	}
}

// expire closes e as CloseConnections with Remove does when its
// CleanupTimeout expires, and reports an AuditConnectionCleanupEventType
// event when the server audits (Part 81 §6.6.2, §8.3), with Status false
// when the close failed; the close is then tried again after another
// CleanupTimeout, c.retryCleanup at the earliest.
//
// The caller holds c.call.
func (c *Connections) expire(e *endpoint) {
	c.log.Info("uafx: CleanupTimeout of a ConnectionEndpoint expired", "endpoint", e.id, "timeout", e.cleanup)
	rel := c.value(c.childID(e.id, "RelatedEndpoint"))
	if rel == nil {
		rel = &ua.Variant{}
	}
	ok := c.closeEndpoint(e, true) == ua.StatusOK
	if !ok {
		// The endpoint stays with what could not be removed; try again
		// after another CleanupTimeout, at the earliest after a second.
		c.log.Warn("uafx: the cleanup of a ConnectionEndpoint failed; it is retried", "endpoint", e.id)
		c.mu.Lock()
		e.cleanupOff = false
		e.deadline = time.Now().Add(max(e.cleanup, c.retryCleanup))
		c.mu.Unlock()
	}
	if c.srv.Auditing() {
		// The server's own action: no Method call, so no caller in the
		// context. SourceNode is the FunctionalEntity (Part 81 §8.3).
		c.srv.ReportAuditEvent(context.Background(), &server.BaseEvent{
			EventType:  ua.NewNumericNodeID(c.ns.AC, fxacid.AuditConnectionCleanupEventType),
			SourceNode: e.fe,
			SourceName: "UAFX/CleanupTimeout",
			Message:    ua.NewLocalizedText("CleanupTimeout of the ConnectionEndpoint " + e.name + " expired"),
			Severity:   500,
			Fields: map[string]*ua.Variant{
				"Status":          ua.MustVariant(ok),
				"RemovedEndpoint": ua.MustVariant(e.name),
				"RelatedEndpoint": rel,
			},
		}, e.fe)
	}
	c.refreshHealth()
}

var timeZero time.Time

// commHealth bits (Part 81 §10.9).
const (
	commInitial        = 1 << 0
	commPreOperational = 1 << 1
	commError          = 1 << 2
)

// refreshHealth updates the CommHealth of the ConnectionEndpoints folders
// (Part 81 §6.4.8), bits 0 to 15 of the OperationalHealth of the
// FunctionalEntities (§10.34) and the AggregatedOperationalHealth of the
// AutomationComponents (§9.1.2).
func (c *Connections) refreshHealth() {
	comm := map[string]uint16{}
	folders := map[string]*ua.NodeID{}
	c.mu.Lock()
	for _, e := range c.endpoints {
		k := e.fe.String()
		folders[k] = e.folder
		switch e.Status() {
		case uafx.ConnectionEndpointInitial:
			comm[k] |= commInitial
		case uafx.ConnectionEndpointPreOperational:
			comm[k] |= commPreOperational
		case uafx.ConnectionEndpointError:
			comm[k] |= commError
		case uafx.ConnectionEndpointReady, uafx.ConnectionEndpointOperational:
		}
	}
	acs := c.acs
	c.mu.Unlock()
	for _, ac := range acs {
		var agg uint32
		for _, r := range c.children(ac.feFolder, id.HierarchicalReferences) {
			if !c.isA(r.NodeID.NodeID, fxacid.FunctionalEntityType) {
				continue
			}
			agg |= c.feHealth(r.NodeID.NodeID, comm, folders)
		}
		c.setAggregated(ac, agg)
	}
}

// feHealth updates the CommHealth and OperationalHealth of fe and its
// SubFunctionalEntities and returns the OperationalHealth of fe.
func (c *Connections) feHealth(fe *ua.NodeID, comm map[string]uint16, folders map[string]*ua.NodeID) uint32 {
	for _, x := range c.feScope(fe)[1:] {
		c.feHealth1(x, comm, folders)
	}
	return c.feHealth1(fe, comm, folders)
}

func (c *Connections) feHealth1(fe *ua.NodeID, comm map[string]uint16, folders map[string]*ua.NodeID) uint32 {
	bits := comm[fe.String()]
	if f := folders[fe.String()]; f != nil {
		c.setIfChanged(c.childID(f, "CommHealth"), bits)
	}
	oh := c.childID(fe, "OperationalHealth")
	if oh == nil {
		return uint32(bits)
	}
	cur, _ := val(c.value(oh)).(uint32)
	next := cur&^0xffff | uint32(bits)
	c.setIfChanged(oh, next)
	return next
}

// setIfChanged writes v to the Variable n unless it has that value.
func (c *Connections) setIfChanged(n *ua.NodeID, v any) {
	if n == nil {
		return
	}
	if cur := c.value(n); cur != nil && cur.Value() == v {
		return
	}
	c.write(n, v)
}

// setAggregated writes the AggregatedOperationalHealth of ac, keeping its
// AggregatedDeviceHealth.
func (c *Connections) setAggregated(ac *automationComponent, op uint32) {
	if ac.health == nil {
		return
	}
	enc := ua.NewNumericNodeID(c.ns.AC, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary)
	var device uint16
	if v := c.value(ac.health.ID()); v != nil {
		if eo, ok := v.Value().(*ua.ExtensionObject); ok && eo != nil && eo.TypeID != nil && eo.TypeID.NodeID.Equal(enc) {
			body, _ := eo.Value.([]byte)
			if body == nil {
				body = eo.RawBody
			}
			if len(body) == 6 {
				device = binary.LittleEndian.Uint16(body)
				if binary.LittleEndian.Uint32(body[2:]) == op {
					return
				}
			}
		}
	}
	body := binary.LittleEndian.AppendUint16(nil, device)
	body = binary.LittleEndian.AppendUint32(body, op)
	eo := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(c.ns.AC, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary), Value: body}
	c.write(ac.health.ID(), eo)
}

// setAttrs sets the attributes of the new node n.
func setAttrs(n *server.Node, attrs map[ua.AttributeID]any) error {
	for a, v := range attrs {
		if err := n.SetAttribute(a, server.DataValueFromValue(v)); err != nil {
			return err
		}
	}
	return nil
}

// --- creation and removal -------------------------------------------------

// createEndpoint adds a PubSubConnectionEndpoint named p.Name to the
// ConnectionEndpoints folder of fe (Part 81 §6.2.4.3.5), creating the
// folder if fe has none.
func (c *Connections) createEndpoint(fe *ua.NodeID, p *uafx.PubSubConnectionEndpointParameter, cmURI string) (*endpoint, ua.StatusCode) {
	feNode := c.node(fe)
	ns, err := c.srv.Namespace(int(fe.Namespace()))
	if feNode == nil || err != nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	e := &endpoint{fe: fe, name: p.Name, created: true, mode: p.Mode, inputs: p.InputVariableIDs, outputs: p.OutputVariableIDs, cleanup: -1}
	if d, ok := p.CleanupTimeoutDuration(); ok {
		e.cleanup = d
	}
	folder := c.childID(fe, "ConnectionEndpoints")
	if folder == nil {
		// The folder stays when its endpoints go: other endpoints may be
		// created in it.
		f := server.NewFolderNode(c.newNodeID(fe.Namespace()), "ConnectionEndpoints")
		if err := setAttrs(f, map[ua.AttributeID]any{ua.AttributeIDBrowseName: &ua.QualifiedName{NamespaceIndex: c.ns.AC, Name: "ConnectionEndpoints"}}); err != nil {
			return nil, ua.StatusBadInternalError
		}
		ns.AddNode(f)
		f.AddReference(c.node(ua.NewNumericNodeID(c.ns.AC, fxacid.ConnectionEndpointsFolderType)), ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		feNode.AddRef(f, server.RefTypeIDHasComponent, true)
		folder = f.ID()
	}
	e.folder = folder

	relEO := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(c.ns.Data, fxdataid.RelatedEndpointDataTypeEncodingDefaultBinary)}
	body, err := ua.Encode(p.RelatedEndpoint)
	if err != nil {
		return nil, ua.StatusBadInvalidArgument
	}
	relEO.Value = body

	obj := server.NewFolderNode(c.newNodeID(fe.Namespace()), p.Name)
	if err := setAttrs(obj, map[ua.AttributeID]any{ua.AttributeIDBrowseName: &ua.QualifiedName{NamespaceIndex: fe.Namespace(), Name: p.Name}}); err != nil {
		return nil, ua.StatusBadInternalError
	}
	e.id = obj.ID()
	ns.AddNode(obj)
	e.nodes = append(e.nodes, e.id)
	obj.AddReference(c.node(ua.NewNumericNodeID(c.ns.AC, fxacid.PubSubConnectionEndpointType)), ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
	type member struct {
		name     string
		dataType *ua.NodeID
		rank     int32
		value    any
	}
	members := []member{
		{"Status", ua.NewNumericNodeID(c.ns.AC, fxacid.ConnectionEndpointStatusEnum), -1, nil},
		{"RelatedEndpoint", ua.NewNumericNodeID(c.ns.Data, fxdataid.RelatedEndpointDataType), -1, relEO},
		{"IsPersistent", ua.NewNumericNodeID(0, id.Boolean), -1, p.IsPersistent},
		{"CleanupTimeout", ua.NewNumericNodeID(0, id.Duration), -1, p.CleanupTimeout},
		{"Mode", ua.NewNumericNodeID(c.ns.Data, fxdataid.PubSubConnectionEndpointModeEnum), -1, int32(p.Mode)},
		{"InputVariables", ua.NewNumericNodeID(0, id.NodeID), 1, nonNil(p.InputVariableIDs)},
		{"OutputVariables", ua.NewNumericNodeID(0, id.NodeID), 1, nonNil(p.OutputVariableIDs)},
		{"ConnectionManagerApplicationUri", ua.NewNumericNodeID(0, id.String), -1, cmURI},
	}
	baseVar := c.node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	for _, m := range members {
		v := m.value
		if m.name == "Status" {
			v = server.ValueFunc(func() *ua.DataValue { return server.DataValueFromValue(int32(e.Status())) })
		}
		n := server.NewVariableNode(c.newNodeID(fe.Namespace()), m.name, v)
		if err := setAttrs(n, map[ua.AttributeID]any{
			ua.AttributeIDBrowseName:      &ua.QualifiedName{NamespaceIndex: c.ns.AC, Name: m.name},
			ua.AttributeIDDataType:        ua.NewExpandedNodeID(m.dataType, "", 0),
			ua.AttributeIDValueRank:       m.rank,
			ua.AttributeIDAccessLevel:     byte(ua.AccessLevelTypeCurrentRead),
			ua.AttributeIDUserAccessLevel: byte(ua.AccessLevelTypeCurrentRead),
		}); err != nil {
			c.dropNodes(e)
			return nil, ua.StatusBadInternalError
		}
		ns.AddNode(n)
		obj.AddRef(n, server.RefTypeIDHasComponent, true)
		if baseVar != nil {
			n.AddReference(baseVar, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		}
		e.nodes = append(e.nodes, n.ID())
	}
	// CreationTime and ModificationTime (Part 81 Table 74) are optional:
	// the endpoint has no Diagnostics object.
	c.node(folder).AddReference(obj, ua.NewNumericNodeID(c.ns.AC, fxacid.HasConnectionEndpoint), true)
	e.status.Store(int32(uafx.ConnectionEndpointInitial))
	c.mu.Lock()
	c.endpoints[e.id.String()] = e
	c.mu.Unlock()
	return e, ua.StatusOK
}

// nonNil returns s, or an empty array for nil: a Variable of ValueRank 1
// holds an array.
func nonNil(s []*ua.NodeID) []*ua.NodeID {
	if s == nil {
		return []*ua.NodeID{}
	}
	return s
}

// deleteEndpoint removes the nodes created for e.
// The endpoint leaves the connections after its nodes: who sees it gone
// sees its nodes gone.
func (c *Connections) deleteEndpoint(e *endpoint) {
	if e.created {
		if f := c.node(e.folder); f != nil {
			f.RemoveRef(ua.NewExpandedNodeID(e.id, "", 0), ua.NewNumericNodeID(c.ns.AC, fxacid.HasConnectionEndpoint), true)
		}
		c.dropNodes(e)
		c.srv.ChangeNotification(e.folder)
	}
	c.mu.Lock()
	delete(c.endpoints, e.id.String())
	c.mu.Unlock()
}

// dropNodes deletes the nodes created for e, the last first.
func (c *Connections) dropNodes(e *endpoint) {
	for i := len(e.nodes) - 1; i >= 0; i-- {
		n := e.nodes[i]
		if ns, err := c.srv.Namespace(int(n.Namespace())); err == nil {
			if sc := ns.DeleteNode(n); sc != ua.StatusOK {
				c.log.Debug("uafx: node not deleted", "node", n, "status", sc)
			}
		}
	}
}

// setLink sets the ToDataSetReader or ToDataSetWriter Reference of e to the
// DataSetReader or DataSetWriter node, own when this call configured it.
func (c *Connections) setLink(e *endpoint, reader bool, node *ua.NodeID, own bool) {
	refType := uint32(fxacid.ToDataSetWriter)
	cur := &e.writer
	if reader {
		refType = fxacid.ToDataSetReader
		cur = &e.reader
	}
	en := c.node(e.id)
	if en == nil {
		return
	}
	if *cur != nil {
		en.RemoveRef(ua.NewExpandedNodeID(*cur, "", 0), ua.NewNumericNodeID(c.ns.AC, refType), true)
	}
	*cur = node
	if reader {
		e.ownReader = own
	} else {
		e.ownWriter = own
	}
	if node == nil {
		return
	}
	if t := c.node(node); t != nil {
		en.AddReference(t, ua.NewNumericNodeID(c.ns.AC, refType), true)
	}
}

// shared reports whether an endpoint other than e references the
// DataSetReader or DataSetWriter n.
func (c *Connections) shared(e *endpoint, n *ua.NodeID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, o := range c.endpoints {
		if o != e && (o.reader != nil && o.reader.Equal(n) || o.writer != nil && o.writer.Equal(n)) {
			return true
		}
	}
	return false
}

// componentOf returns the PubSub component of the node n.
func (c *Connections) componentOf(n *ua.NodeID) (pubsub.ComponentID, bool) {
	if n == nil {
		return 0, false
	}
	return c.srv.PubSubComponentID(n)
}
