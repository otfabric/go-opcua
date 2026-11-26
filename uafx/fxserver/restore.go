// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// ErrQuarantine reports a quarantined record that cannot be restored or
// discarded as asked.
var ErrQuarantine = errors.New("fxserver: quarantine")

// QuarantinedEndpoint is a record of a persistent ConnectionEndpoint that
// the server did not restore (design §4.7, C3-D10). It is kept, and what it
// reserves stays reserved, until RetryRestore restores it or Discard
// deletes it.
type QuarantinedEndpoint struct {
	// ID names the record for RetryRestore and Discard.
	ID string
	// AutomationComponent, Endpoint, FunctionalEntity and Name are the
	// identities of the record, nil and "" when its identity cannot be
	// read.
	AutomationComponent, Endpoint, FunctionalEntity *ua.NodeID
	Name                                            string
	// Reason is why it was not restored.
	Reason string
	// Retryable: the cause can go away (a component conflict, a
	// ControlGroup in use, a namespace not loaded yet).
	Retryable bool
	// Fences: the identities cannot be read, so the record fences the
	// EstablishConnections of its AutomationComponent (of every one when
	// its key cannot be read) and the allocation of PubSub identifiers of
	// the server.
	Fences bool
	// Component: the record is a component record that does not decode.
	Component bool
	// WriterGroupIDs and DataSetWriterIDs are the PubSub identifiers it
	// reserves.
	WriterGroupIDs, DataSetWriterIDs []uint16
	// MissingNamespaces are the namespace URIs of the record that the
	// server does not have: its NodeIds in them keep the namespace index
	// they were written with. The record is restored once they are there
	// (RetryRestore, or the next start); until then it reserves its
	// NodeIds by namespace URI.
	MissingNamespaces []string
}

// quarantined is a quarantined record.
type quarantined struct {
	key       string // where the record is in the store
	value     []byte // the original record
	id        *epIdentity
	reason    string
	retryable bool
	component bool
	acHash    string // of an unreadable identity; "*" for an unreadable key
	// nodes and fe are the NodeIds the record reserves and its
	// FunctionalEntity, qualified by namespace URI (qualified), so that
	// they stay reserved while a namespace is missing.
	nodes []string
	fe    string
	// missing are the namespace URIs of the record the server does not
	// have.
	missing []string
}

// withIdentity sets the identity of q from the decoded identity idn,
// written with idn.Namespaces, for the server's NamespaceArray cur.
func (q *quarantined) withIdentity(idn *epIdentity, cur []string) *quarantined {
	q.id = remapped(idn, cur)
	q.nodes = qualifiedNodes(idn)
	q.fe = qualified(idn.FunctionalEntity, idn.Namespaces)
	cp := *idn
	cp.Nodes = slices.Clone(idn.Nodes)
	q.missing = usedMissing(idn.Namespaces, cur, &cp)
	if q.value != nil {
		if m := missingOf(q.value, cur); m != nil {
			q.missing = m
		}
	}
	return q
}

// qualifiedNodes returns the nodes of the identity idn qualified by
// namespace URI.
func qualifiedNodes(idn *epIdentity) []string {
	out := make([]string, 0, len(idn.Nodes))
	for _, n := range idn.Nodes {
		if k := qualified(n, idn.Namespaces); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// reserveLocked rebuilds the NodeIds the quarantined records reserve. The
// caller holds p.mu.
func (p *persistence) reserveLocked() {
	p.nodes = map[string]bool{}
	for _, q := range p.quar {
		for _, n := range q.nodes {
			p.nodes[n] = true
		}
	}
}

// qRecord is the value of a q/ key: a quarantined record with its reason.
type qRecord struct {
	Key       string
	Reason    string
	Retryable bool
	Value     []byte
}

// openPersistence opens the store of the connections and decodes its
// records, before any node is created: the NodeIds of the records stay
// reserved until the restore (restoreAll) has run.
func (c *Connections) openPersistence() error {
	timeout := c.opts.StoreTimeout
	if timeout <= 0 {
		timeout = defaultStoreTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d, err := fxstore.OpenDomain(ctx, c.opts.Store, fxstore.DomainOptions{Namespace: "ac", Owner: c.srv.ApplicationURI(), Schema: recordSchema})
	if err != nil {
		return fmt.Errorf("%w: the persistent ConnectionEndpoints store: %w", ErrConnections, err)
	}
	if d.Schema() > recordSchema {
		return fmt.Errorf("%w: the persistent ConnectionEndpoints store has schema %d; this version knows %d", ErrConnections, d.Schema(), recordSchema)
	}
	// A restore links endpoints to the Objects of their components, which
	// the information model of the runtime gives before Start too.
	if err := c.srv.BuildPubSubModel(); err != nil {
		return fmt.Errorf("%w: %w", ErrConnections, err)
	}
	p := &persistence{c: c, d: d, strict: c.opts.StrictNotPersisted, timeout: timeout,
		quar: map[string]*quarantined{}, nodes: map[string]bool{}}
	cur := c.namespaces()
	for k, v := range d.State() {
		switch {
		case strings.HasPrefix(k, "ep/") && validKey(strings.TrimPrefix(k, "ep/")):
			idn, _, err := decodeEndpoint(v)
			switch {
			case idn == nil:
				p.quar[k] = &quarantined{key: k, value: v, reason: "the identity of the record does not decode: " + errText(err), acHash: acOfKey(strings.TrimPrefix(k, "ep/"))}
			case err != nil:
				p.quar[k] = (&quarantined{key: k, value: v, reason: "the record does not decode: " + err.Error()}).withIdentity(idn, cur)
			}
			if idn != nil {
				for _, n := range qualifiedNodes(idn) {
					p.nodes[n] = true
				}
			}
		case strings.HasPrefix(k, "pc/") && validHash(strings.TrimPrefix(k, "pc/")):
			if _, err := decodeComponent(v); err != nil {
				p.quar[k] = &quarantined{key: k, value: v, component: true, reason: "the component record does not decode: " + err.Error()}
			}
		case strings.HasPrefix(k, "q/"):
			q := new(qRecord)
			part, rest, err := readPart(v)
			if err == nil && len(rest) == 0 {
				err = decodeExact(part, q)
			}
			if err != nil {
				p.quar[k] = &quarantined{key: k, value: v, reason: "the quarantine record does not decode: " + err.Error(), acHash: "*"}
				continue
			}
			qq := &quarantined{key: k, value: q.Value, reason: q.Reason, retryable: q.Retryable}
			idn, _, _ := decodeEndpoint(q.Value)
			switch {
			case strings.HasPrefix(q.Key, "pc/"):
				qq.component = true
			case idn != nil:
				qq.withIdentity(idn, cur)
				for _, n := range qq.nodes {
					p.nodes[n] = true
				}
			case strings.HasPrefix(q.Key, "ep/"):
				qq.acHash = acOfKey(strings.TrimPrefix(q.Key, "ep/"))
			default:
				qq.acHash = "*"
			}
			p.quar[k] = qq
		default:
			p.quar[k] = &quarantined{key: k, value: v, reason: "the key is not one of the records", acHash: "*"}
		}
	}
	p.reload()
	c.pers = p
	return nil
}

func errText(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

// remapped returns the identity idn in the namespace indexes cur; the
// NodeIds whose namespace is gone stay as they are.
func remapped(idn *epIdentity, cur []string) *epIdentity {
	cp := *idn
	cp.Nodes = slices.Clone(idn.Nodes)
	r := newRemapper(idn.Namespaces, cur)
	if !r.identity() {
		_ = r.remap(&cp)
	}
	return &cp
}

// validKey reports whether k is "<hash>/<hash>".
func validKey(k string) bool {
	a, b, ok := strings.Cut(k, "/")
	return ok && validHash(a) && validHash(b)
}

func validHash(h string) bool {
	if len(h) != 32 {
		return false
	}
	for _, r := range h {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// restoreAll completes the durable removals and restores the persistent
// endpoints (design §4.1, §4.4, §4.6). A record that fails is quarantined.
func (c *Connections) restoreAll() {
	p := c.pers
	p.mu.Lock()
	// Removals first: a RemovePending record is never restored.
	s := p.begin()
	for _, k := range sortedKeys(p.eps) {
		if p.eps[k].body.State != stateActive {
			s.dropEndpoint(k)
		}
	}
	if b, err := s.batch(); err == nil && !b.Empty() {
		ctx, cancel := p.ctx()
		if o, err := p.d.Apply(ctx, b); o == fxstore.Committed {
			p.reload()
		} else {
			c.log.Warn("uafx: the completion of the removal of persistent ConnectionEndpoints is not committed; the next start completes it", "error", err)
		}
		cancel()
	}
	var todo []*epRecord
	for _, k := range sortedKeys(p.eps) {
		if r := p.eps[k]; r.body.State == stateActive {
			todo = append(todo, r)
		}
	}
	comps := p.comps
	p.mu.Unlock()
	for _, r := range todo {
		e, retry, err := c.restoreOne(r, comps)
		if err != nil {
			c.quarantine(r, err.Error(), retry)
			continue
		}
		p.mu.Lock()
		p.restored = append(p.restored, e.id)
		p.mu.Unlock()
	}
	// The NodeIds of the restored records are taken now; the quarantined
	// ones stay reserved.
	p.mu.Lock()
	p.reserveLocked()
	p.mu.Unlock()
	for _, q := range c.Quarantined() {
		c.log.Warn("uafx: a persistent ConnectionEndpoint record is quarantined", "id", q.ID, "endpoint", q.Endpoint, "name", q.Name, "reason", q.Reason, "retryable", q.Retryable)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// quarantine moves the record r to q/ (one Apply; when it does not commit
// the record stays where it is and is quarantined in memory).
func (c *Connections) quarantine(r *epRecord, reason string, retryable bool) {
	p := c.pers
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.d.State()[r.key]
	q := &quarantined{key: r.key, value: v, id: r.id, reason: reason, retryable: retryable,
		nodes: qualifiedNodes(r.id), fe: qualified(r.id.FunctionalEntity, r.id.Namespaces)}
	qk := "q/" + strings.TrimPrefix(r.key, "ep/")
	enc, err := ua.Encode(&qRecord{Key: r.key, Reason: reason, Retryable: retryable, Value: v})
	if err == nil {
		ctx, cancel := p.ctx()
		o, _ := p.d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{qk: appendPart(nil, enc)}, Deletes: []string{r.key}})
		cancel()
		if o == fxstore.Committed {
			q.key = qk
		}
	}
	p.quar[q.key] = q
	p.reload()
}

// restoreOne restores the persistent endpoint of the record r, all or
// nothing (design §4.6). retry tells whether the cause can go away.
func (c *Connections) restoreOne(r *epRecord, comps map[string]*compRecord) (e *endpoint, retry bool, err error) {
	ac := c.acOf(r.id.AC)
	b := r.body
	switch {
	case ac == nil:
		return nil, false, fmt.Errorf("the AutomationComponent %v is not in the server", r.id.AC)
	case !slices.ContainsFunc(c.functionalEntities(ac), r.id.FunctionalEntity.Equal):
		return nil, true, fmt.Errorf("the FunctionalEntity %v is not in the AutomationComponent", r.id.FunctionalEntity)
	}
	ins, outs := c.folderVariables(r.id.FunctionalEntity, "InputData"), c.folderVariables(r.id.FunctionalEntity, "OutputData")
	for _, v := range b.Inputs {
		if !ins[v.String()] {
			return nil, true, fmt.Errorf("the InputVariable %v is not in the FunctionalEntity", v)
		}
	}
	for _, v := range b.Outputs {
		if !outs[v.String()] {
			return nil, true, fmt.Errorf("the OutputVariable %v is not in the FunctionalEntity", v)
		}
	}
	var groups []*controlGroup
	for _, n := range b.ControlGroups {
		c.ctl.mu.Lock()
		g := c.ctl.groups[n.String()]
		c.ctl.mu.Unlock()
		if g == nil {
			return nil, true, fmt.Errorf("the ControlGroup %v is not in the server", n)
		}
		groups = append(groups, g)
	}
	rel, err := relatedOf(b.Related)
	if err != nil {
		return nil, false, fmt.Errorf("the RelatedEndpoint does not decode: %w", err)
	}
	existing := (&call{c: c}).endpointNamed(r.id.FunctionalEntity, r.id.Name)
	if b.Preconfigured {
		c.mu.Lock()
		pe := c.endpoints[r.id.Endpoint.String()]
		c.mu.Unlock()
		if existing == nil || !existing.Equal(r.id.Endpoint) || pe == nil || c.inUse(c.value(c.childID(existing, "RelatedEndpoint"))) {
			return nil, true, errors.New("the preconfigured ConnectionEndpoint is not there, or in use")
		}
	} else if existing != nil || c.node(r.id.Endpoint) != nil {
		return nil, true, fmt.Errorf("a node or a ConnectionEndpoint named %q exists already (Bad_BrowseNameDuplicated)", r.id.Name)
	}

	// From here on the restore changes the server: undo rolls it back.
	rt := c.srv.PubSub()
	var added []pubsub.ComponentID
	var enabled []pubsub.ComponentID
	undo := func() {
		for i := len(enabled) - 1; i >= 0; i-- {
			if err := c.change(func(rt *pubsub.PubSub) error { return rt.Disable(enabled[i]) }); err != nil {
				c.log.Warn("uafx: restore: undo: disable", "component", enabled[i], "error", err)
			}
		}
		if e != nil {
			c.releaseEndpoint(e)
			if b.Preconfigured {
				c.write(c.childID(e.id, "RelatedEndpoint"), &ua.Variant{})
				c.write(c.childID(e.id, "IsPersistent"), false)
				c.mu.Lock()
				e.persistent, e.key = false, ""
				c.mu.Unlock()
				c.setLinkLocked(e, true, nil, false)
				c.setLinkLocked(e, false, nil, false)
			} else {
				c.deleteEndpoint(e)
			}
		}
		for i := len(added) - 1; i >= 0; i-- {
			id := added[i]
			// What is not removed stays created by the endpoints, so
			// that a later removal of what uses it removes it too.
			if err := c.change(func(rt *pubsub.PubSub) error { return removeComponent(rt, id) }); err != nil {
				c.log.Warn("uafx: restore: undo: remove", "component", id, "error", err)
				continue
			}
			c.mu.Lock()
			delete(c.created, id)
			c.mu.Unlock()
		}
		e = nil
	}
	ensure := func(key string, parent pubsub.ComponentID) (pubsub.ComponentID, error) {
		cr := comps[key]
		if cr == nil {
			return 0, fmt.Errorf("the component record %s is missing", key)
		}
		kind := pubsub.ComponentKind(cr.Kind)
		if cid, ok := lookupComponent(rt, cr); ok {
			cur, err := normalizedConfig(rt, kind, cid)
			if err != nil || !sameConfig(cur, cr.Config) {
				return 0, fmt.Errorf("the %v %s differs from its record", kind, strings.Join(cr.Path, "/"))
			}
			return cid, nil
		}
		if cr.Provenance != provCreated {
			return 0, fmt.Errorf("the %v %s, which the endpoint did not create, is not configured", kind, strings.Join(cr.Path, "/"))
		}
		var cid pubsub.ComponentID
		err := c.change(func(rt *pubsub.PubSub) error {
			var err error
			cid, err = addComponent(rt, kind, parent, configValue(cr))
			return err
		})
		if err != nil {
			return 0, fmt.Errorf("the %v %s cannot be added: %w", kind, strings.Join(cr.Path, "/"), err)
		}
		added = append(added, cid)
		if kind != pubsub.KindDataSetReader && kind != pubsub.KindDataSetWriter {
			c.mu.Lock()
			c.created[cid] = true
			c.mu.Unlock()
		}
		return cid, nil
	}
	// chain restores the components of a reader or writer record: those
	// before it in the identity, parents first.
	chain := func(leaf string) (pubsub.ComponentID, error) {
		i := slices.Index(r.id.Components, leaf)
		if i < 0 {
			return 0, fmt.Errorf("the component %s is not in the identity of the record", leaf)
		}
		start := i
		for start > 0 && !isLeaf(comps[r.id.Components[start-1]]) {
			start--
		}
		parent := pubsub.Root
		var cid pubsub.ComponentID
		for _, k := range r.id.Components[start : i+1] {
			cr := comps[k]
			if cr == nil {
				return 0, fmt.Errorf("the component record %s is missing", k)
			}
			if cr.Removed {
				return 0, nil // removed by another mechanism: not re-created
			}
			p := parent
			if pubsub.ComponentKind(cr.Kind) == pubsub.KindPublishedDataSet {
				p = pubsub.Root
			}
			id, err := ensure(k, p)
			if err != nil {
				return 0, err
			}
			switch pubsub.ComponentKind(cr.Kind) {
			case pubsub.KindConnection:
				parent = id
			case pubsub.KindWriterGroup, pubsub.KindReaderGroup:
				parent = id
				gateGroup(rt, configValue(cr))
			case pubsub.KindPublishedDataSet:
			default:
				gateGroup(rt, configValue(cr))
			}
			cid = id
		}
		return cid, nil
	}
	var readerID, writerID pubsub.ComponentID
	if b.Reader != "" {
		if readerID, err = chain(b.Reader); err != nil {
			undo()
			return nil, true, err
		}
	}
	if b.Writer != "" {
		if writerID, err = chain(b.Writer); err != nil {
			undo()
			return nil, true, err
		}
	}

	param := &uafx.PubSubConnectionEndpointParameter{Name: r.id.Name, Mode: uafx.PubSubConnectionEndpointMode(b.Mode),
		InputVariableIDs: b.Inputs, OutputVariableIDs: b.Outputs, IsPersistent: true, CleanupTimeout: b.CleanupTimeout,
		RelatedEndpoint: rel, IsPreconfigured: b.Preconfigured}
	if b.Preconfigured {
		c.mu.Lock()
		e = c.endpoints[r.id.Endpoint.String()]
		c.mu.Unlock()
		c.setPreconfigured(e, param)
	} else {
		ids := slices.Clone(r.id.Nodes)
		alloc := func() *ua.NodeID {
			for len(ids) > 0 {
				n := ids[0]
				ids = ids[1:]
				if c.node(n) == nil {
					return n
				}
			}
			return c.newNodeID(r.id.FunctionalEntity.Namespace())
		}
		var sc ua.StatusCode
		e, sc = c.createEndpointWith(ac, r.id.FunctionalEntity, param, b.ConnectionManagerURI, alloc, b.Folder, b.CreationTime)
		if sc != ua.StatusOK {
			undo()
			return nil, false, fmt.Errorf("the ConnectionEndpoint cannot be created: %v", sc)
		}
		if !e.id.Equal(r.id.Endpoint) {
			undo()
			return nil, false, fmt.Errorf("the ConnectionEndpoint cannot take its NodeId %v", r.id.Endpoint)
		}
	}
	c.mu.Lock()
	e.persistent, e.key, e.ac = true, r.key, ac
	e.demand = b.Enabled
	e.createdAt, e.modifiedAt = b.CreationTime, b.ModificationTime
	mod := e.modNode
	c.mu.Unlock()
	if mod != nil {
		c.write(mod, b.ModificationTime)
	}
	for _, x := range []struct {
		id     pubsub.ComponentID
		own    bool
		reader bool
	}{{readerID, createdComp(comps, b.Reader), true}, {writerID, createdComp(comps, b.Writer), false}} {
		if x.id == 0 {
			continue
		}
		n, ok := c.srv.PubSubNodeID(x.id)
		if !ok {
			undo()
			return nil, false, errors.New("the PubSub component has no node")
		}
		c.setLinkLocked(e, x.reader, n, x.own)
	}
	// The control the endpoint held, with the endpoint as its owner (G4).
	for _, g := range groups {
		if c.control(g, &lockOwner{client: e.id.String(), user: endpointLockingUser, endpoint: e}) != lockOK {
			undo()
			return nil, true, fmt.Errorf("the ControlGroup %v is controlled by another or cannot be locked", g.id)
		}
	}
	if b.Enabled {
		for _, cid := range []pubsub.ComponentID{readerID, writerID} {
			for id := cid; id != pubsub.Root && cid != 0; {
				info, err := rt.Component(id)
				if err != nil {
					undo()
					return nil, true, err
				}
				if !info.Enabled {
					if err := c.change(func(rt *pubsub.PubSub) error { return rt.Enable(id) }); err != nil {
						undo()
						return nil, true, fmt.Errorf("the %v %s cannot be enabled: %w", info.Kind, info.Name, err)
					}
					enabled = append(enabled, id)
				}
				id = info.Parent
			}
		}
	}
	return e, false, nil
}

// isLeaf reports whether a component record is a DataSetReader or
// DataSetWriter.
func isLeaf(cr *compRecord) bool {
	if cr == nil {
		return true
	}
	k := pubsub.ComponentKind(cr.Kind)
	return k == pubsub.KindDataSetReader || k == pubsub.KindDataSetWriter
}

// gateGroup sets the restart gate of the SecurityGroup of a secured group
// or reader (design §4.10): it then neither publishes nor accepts messages
// under a key that may predate the restart.
func gateGroup(rt *pubsub.PubSub, cfg any) {
	var mode ua.MessageSecurityMode
	var group string
	switch g := cfg.(type) {
	case *ua.WriterGroupDataType:
		mode, group = g.SecurityMode, g.SecurityGroupID
	case *ua.ReaderGroupDataType:
		mode, group = g.SecurityMode, g.SecurityGroupID
	case *ua.DataSetReaderDataType:
		mode, group = g.SecurityMode, g.SecurityGroupID
	default:
		return
	}
	if mode > ua.MessageSecurityModeNone && group != "" {
		rt.GateSecurityGroup(group)
	}
}

// addComponent adds the component cfg of kind below parent, disabled.
func addComponent(rt *pubsub.PubSub, kind pubsub.ComponentKind, parent pubsub.ComponentID, cfg any) (pubsub.ComponentID, error) {
	switch v := cfg.(type) {
	case *ua.PubSubConnectionDataType:
		cp := *v
		cp.Enabled = false
		return rt.AddConnection(&cp)
	case *ua.WriterGroupDataType:
		cp := *v
		cp.Enabled = false
		return rt.AddWriterGroup(parent, &cp)
	case *ua.ReaderGroupDataType:
		cp := *v
		cp.Enabled = false
		return rt.AddReaderGroup(parent, &cp)
	case *ua.DataSetWriterDataType:
		cp := *v
		cp.Enabled = false
		return rt.AddDataSetWriter(parent, &cp)
	case *ua.DataSetReaderDataType:
		cp := *v
		cp.Enabled = false
		return rt.AddDataSetReader(parent, &cp)
	case *ua.PublishedDataSetDataType:
		cp := *v
		return rt.AddPublishedDataSet(&cp)
	}
	return 0, fmt.Errorf("fxserver: a %v record holds %T", kind, cfg)
}

// removeComponent removes the component id.
func removeComponent(rt *pubsub.PubSub, id pubsub.ComponentID) error {
	info, err := rt.Component(id)
	if errors.Is(err, ua.StatusBadNotFound) {
		return nil // gone already: nothing to remove
	}
	if err != nil {
		return err
	}
	switch info.Kind {
	case pubsub.KindConnection:
		return rt.RemoveConnection(id)
	case pubsub.KindWriterGroup, pubsub.KindReaderGroup:
		return rt.RemoveGroup(id)
	case pubsub.KindDataSetWriter:
		return rt.RemoveDataSetWriter(id)
	case pubsub.KindDataSetReader:
		return rt.RemoveDataSetReader(id)
	case pubsub.KindPublishedDataSet:
		return rt.RemovePublishedDataSet(id)
	default:
		return nil
	}
}

// acOf returns the AutomationComponent n.
func (c *Connections) acOf(n *ua.NodeID) *automationComponent {
	for _, ac := range c.acs {
		if n != nil && ac.id.Equal(n) {
			return ac
		}
	}
	return nil
}

// Quarantined returns the quarantined records (design §4.7).
func (c *Connections) Quarantined() []QuarantinedEndpoint {
	p := c.pers
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]QuarantinedEndpoint, 0, len(p.quar))
	for _, k := range sortedKeys(p.quar) {
		q := p.quar[k]
		qe := QuarantinedEndpoint{ID: k, Reason: q.reason, Retryable: q.retryable, Component: q.component,
			Fences: q.id == nil && !q.component}
		if q.id != nil {
			qe.AutomationComponent, qe.Endpoint, qe.FunctionalEntity, qe.Name = q.id.AC, q.id.Endpoint, q.id.FunctionalEntity, q.id.Name
			qe.WriterGroupIDs, qe.DataSetWriterIDs = slices.Clone(q.id.WriterGroupIDs), slices.Clone(q.id.DataSetWriterIDs)
			qe.MissingNamespaces = slices.Clone(q.missing)
		}
		out = append(out, qe)
	}
	return out
}

// RetryRestore restores the quarantined record id again: when it is
// restored, its record goes back where the persistent endpoints are, in
// one committed Apply; else it stays quarantined with the new reason.
func (c *Connections) RetryRestore(ctx context.Context, id string) error {
	p := c.pers
	if p == nil {
		return fmt.Errorf("%w: no store", ErrQuarantine)
	}
	c.call.Lock()
	defer c.call.Unlock()
	p.mu.Lock()
	// Namespaces may have been added since: component records that did
	// not map then may now.
	p.reload()
	q := p.quar[id]
	if q == nil {
		p.mu.Unlock()
		return fmt.Errorf("%w: no quarantined record %q", ErrQuarantine, id)
	}
	if q.id == nil || q.component {
		p.mu.Unlock()
		return fmt.Errorf("%w: the record %q does not decode; it can only be discarded", ErrQuarantine, id)
	}
	if p.fenced() {
		p.mu.Unlock()
		return fmt.Errorf("%w: the store is fenced", ErrQuarantine)
	}
	idn, body, err := decodeEndpoint(q.value)
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrQuarantine, err)
	}
	cur := c.namespaces()
	rm := newRemapper(idn.Namespaces, cur)
	if !rm.identity() && (rm.remap(idn) != nil || rm.remap(body) != nil) {
		p.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrQuarantine, errNamespace)
	}
	idn.Namespaces = cur
	key := "ep/" + strings.TrimPrefix(strings.TrimPrefix(id, "q/"), "ep/")
	r := &epRecord{key: key, id: idn, body: body}
	// The record's own reservations do not stand in its way.
	delete(p.quar, id)
	comps := p.comps
	p.mu.Unlock()
	e, retry, err := c.restoreOne(r, comps)
	if err != nil {
		p.mu.Lock()
		q.reason, q.retryable = err.Error(), retry
		p.quar[id] = q
		p.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrQuarantine, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	b := fxstore.Batch{Puts: map[string][]byte{key: q.value}}
	if id != key {
		b.Deletes = []string{id}
	}
	actx, cancel := context.WithTimeout(ctx, p.timeout)
	o, err := p.d.Apply(actx, b)
	cancel()
	if o != fxstore.Committed {
		p.quar[id] = q
		p.mu.Unlock()
		c.undoRestore(e)
		p.mu.Lock()
		if o == fxstore.Unknown {
			// The record goes back to quarantine once the outcome is
			// known; until then the store is fenced.
			rctx, cancel := context.WithTimeout(context.Background(), p.timeout)
			_, _ = p.d.Require(rctx, p.undo(b))
			cancel()
		}
		return fmt.Errorf("%w: the restored record was not committed: %w", ErrQuarantine, err)
	}
	p.reload()
	p.restored = append(p.restored, e.id)
	c.refreshAll()
	return nil
}

// undoRestore removes the endpoint e that RetryRestore restored: as a
// CloseConnections with Remove does, without the store.
func (c *Connections) undoRestore(e *endpoint) {
	c.mu.Lock()
	e.persistent = false
	c.mu.Unlock()
	_ = c.closeEndpoint(e, true)
}

// Discard deletes the quarantined record id and releases what it reserves,
// in one committed Apply. It removes nothing at runtime: a quarantined
// record restored nothing (design §4.7).
func (c *Connections) Discard(ctx context.Context, id string) error {
	p := c.pers
	if p == nil {
		return fmt.Errorf("%w: no store", ErrQuarantine)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.quar[id]
	if q == nil {
		return fmt.Errorf("%w: no quarantined record %q", ErrQuarantine, id)
	}
	s := p.begin()
	if !q.component {
		// The component records lose the references of the record.
		ref := "ep/" + strings.TrimPrefix(strings.TrimPrefix(id, "q/"), "ep/")
		for _, k := range sortedKeys(s.comps) {
			if slices.Contains(s.comps[k].Refs, ref) {
				s.unref(k, ref)
			}
		}
	}
	b, err := s.batch()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrQuarantine, err)
	}
	b.Deletes = append(b.Deletes, id)
	actx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if o, err := p.d.Apply(actx, b); o != fxstore.Committed {
		return fmt.Errorf("%w: the deletion was not committed: %w", ErrQuarantine, err)
	}
	delete(p.quar, id)
	p.reload()
	p.reserveLocked()
	return nil
}

// establishFence returns the reason the EstablishConnections of ac are
// refused, "" when they are not: the store is fenced, or a quarantined
// record whose identities cannot be read may collide with any new one
// (design §3.5, §4.7).
func (p *persistence) establishFence(ac *automationComponent) string {
	if p.fenced() {
		return "the store has a write with an unknown outcome or an owed write"
	}
	h := hashKey(qualified(ac.id, p.c.namespaces()))
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range sortedKeys(p.quar) {
		q := p.quar[k]
		if q.id == nil && !q.component && (q.acHash == "*" || q.acHash == h) {
			return "the quarantined record " + k + " has identities that cannot be read"
		}
	}
	return ""
}

// reserved reports whether a quarantined record reserves the NodeId n or,
// for the FunctionalEntity fe, the Name name.
func (p *persistence) reserved(n *ua.NodeID, fe *ua.NodeID, name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.c.namespaces()
	if k := qualified(n, cur); k != "" && p.nodes[k] {
		return true
	}
	if fe == nil {
		return false
	}
	fk := qualified(fe, cur)
	for _, q := range p.quar {
		if q.id != nil && q.id.Name == name && q.fe != "" && q.fe == fk {
			return true
		}
	}
	return false
}

// setSupportsPersistence sets SupportsPersistence TRUE in the
// ComponentCapabilities of each AutomationComponent (Part 81 §6.2.6 Table
// 26), adding the Variable when the instance has none.
func (c *Connections) setSupportsPersistence() error {
	for _, ac := range c.acs {
		caps := c.childID(ac.id, "ComponentCapabilities")
		if caps == nil {
			// Mandatory in the AutomationComponentType (Part 81 §6.2.1); an
			// instance without it gets one.
			ns, err := c.srv.Namespace(int(ac.id.Namespace()))
			if err != nil {
				return err
			}
			f := server.NewFolderNode(c.newNodeID(ac.id.Namespace()), "ComponentCapabilities")
			if err := setAttrs(f, map[ua.AttributeID]any{ua.AttributeIDBrowseName: &ua.QualifiedName{NamespaceIndex: c.ns.AC, Name: "ComponentCapabilities"}}); err != nil {
				return err
			}
			ns.AddNode(f)
			if t := c.node(ua.NewNumericNodeID(c.ns.AC, fxacid.AutomationComponentCapabilitiesType)); t != nil {
				f.AddReference(t, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
			}
			c.node(ac.id).AddRef(f, server.RefTypeIDHasComponent, true)
			caps = f.ID()
		}
		if n := c.childID(caps, "SupportsPersistence"); n != nil {
			c.write(n, true)
			continue
		}
		ns, err := c.srv.Namespace(int(caps.Namespace()))
		if err != nil {
			return err
		}
		v := server.NewVariableNode(c.newNodeID(caps.Namespace()), "SupportsPersistence", true)
		if err := setAttrs(v, map[ua.AttributeID]any{
			ua.AttributeIDBrowseName:      &ua.QualifiedName{NamespaceIndex: c.ns.AC, Name: "SupportsPersistence"},
			ua.AttributeIDDataType:        ua.NewNumericExpandedNodeID(0, id.Boolean),
			ua.AttributeIDValueRank:       int32(-1),
			ua.AttributeIDAccessLevel:     byte(ua.AccessLevelTypeCurrentRead),
			ua.AttributeIDUserAccessLevel: byte(ua.AccessLevelTypeCurrentRead),
		}); err != nil {
			return err
		}
		ns.AddNode(v)
		c.node(caps).AddReference(v, ua.NewNumericNodeID(c.ns.AC, fxacid.HasCapability), true)
		if pt := c.node(ua.NewNumericNodeID(0, id.PropertyType)); pt != nil {
			v.AddReference(pt, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		}
	}
	return nil
}

// createdComp reports whether the component record key of comps was added
// by an EstablishConnections call: the endpoint restored with it owns it,
// as each endpoint that references it does, so the last of them removes
// it (Part 81 §6.2.5.2). The ownership comes from the component, not from
// the endpoint record, so a hand-over (handOver) needs no record of its
// own to survive a restart.
func createdComp(comps map[string]*compRecord, key string) bool {
	cr := comps[key]
	return cr != nil && cr.Provenance == provCreated
}
