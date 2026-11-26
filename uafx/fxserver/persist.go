// SPDX-License-Identifier: MIT

package fxserver

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// persistence keeps the persistent ConnectionEndpoints of the server in a
// store (design docs/design/uafx-persistent-connections.md §4). The domain
// holds what is committed; the mirror (eps, comps) is it decoded, with the
// NodeIds in the server's namespace indexes.
//
// Lock order: Connections.call, then the PubSub transaction of the server,
// then mu, then Connections.mu and the locks of the controls. Nothing
// holding mu changes the PubSub configuration: its hook takes mu.
type persistence struct {
	c       *Connections
	d       *fxstore.Domain
	strict  bool
	timeout time.Duration

	mu    sync.Mutex
	eps   map[string]*epRecord   // by key ("ep/...")
	comps map[string]*compRecord // by key ("pc/...")
	quar  map[string]*quarantined
	// nodes are NodeIds the records reserve: all of them until the
	// restore is done, those of the quarantined records afterwards.
	nodes map[string]bool
	// restored are the endpoints the start restored.
	restored []*ua.NodeID

	// backoff and next pace the settling of a fenced domain (monitor).
	backoff time.Duration
	next    time.Time
}

// epRecord is a decoded endpoint record.
type epRecord struct {
	key  string // "ep/<ac>/<endpoint>"
	id   *epIdentity
	body *epBody
}

// ownCallKey marks the context of the PubSub changes an EstablishConnections
// call makes itself: their records are written at its commit point.
type ownCallKey struct{}

func ownCall(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(ownCallKey{}).(bool)
	return v
}

// defaultStoreTimeout bounds one store operation.
const defaultStoreTimeout = 10 * time.Second

func (p *persistence) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout)
}

// namespaces returns the NamespaceArray of the server.
func (c *Connections) namespaces() []string {
	nss := c.srv.Namespaces()
	out := make([]string, len(nss))
	for i, n := range nss {
		out[i] = n.Name()
	}
	return out
}

// keyOf returns the record key of the endpoint e of the AutomationComponent
// ac.
func (c *Connections) keyOf(ac *automationComponent, e *endpoint) string {
	return "ep/" + endpointKey(ac.id, e.id, c.namespaces())
}

// reload rebuilds the mirror from the committed state of the domain. The
// caller holds p.mu.
func (p *persistence) reload() {
	cur := p.c.namespaces()
	p.eps, p.comps = map[string]*epRecord{}, map[string]*compRecord{}
	for k, v := range p.d.State() {
		if p.quar[k] != nil {
			continue
		}
		switch {
		case strings.HasPrefix(k, "ep/"):
			id, body, err := decodeEndpoint(v)
			if err != nil {
				continue
			}
			r := newRemapper(id.Namespaces, cur)
			if !r.identity() && (r.remap(id) != nil || r.remap(body) != nil) {
				continue
			}
			id.Namespaces = cur
			p.eps[k] = &epRecord{key: k, id: id, body: body}
		case strings.HasPrefix(k, "pc/"):
			cr, err := decodeComponent(v)
			if err != nil {
				continue
			}
			r := newRemapper(cr.Namespaces, cur)
			if !r.identity() && r.remap(cr) != nil {
				continue
			}
			cr.Namespaces = cur
			p.comps[k] = cr
		}
	}
}

// --- staged batches ---------------------------------------------------------

// staged is a batch being built on a copy of the mirror: the endpoint
// records it writes and the component records whose references follow.
type staged struct {
	p     *persistence
	ns    []string
	eps   map[string]*epRecord
	comps map[string]*compRecord
	put   map[string]bool
	del   map[string]bool
}

func (p *persistence) begin() *staged {
	s := &staged{p: p, ns: p.c.namespaces(), eps: maps.Clone(p.eps), comps: map[string]*compRecord{},
		put: map[string]bool{}, del: map[string]bool{}}
	for k, cr := range p.comps {
		cp := *cr
		cp.Refs = slices.Clone(cr.Refs)
		s.comps[k] = &cp
	}
	return s
}

// putEndpoint stages the record r of an endpoint that references the
// components comps (in their dependency order).
func (s *staged) putEndpoint(r *epRecord, comps []*compRecord) {
	keys, paths := compKeys(comps)
	for i, cr := range comps {
		k := keys[i]
		cur := s.comps[k]
		if cur == nil {
			cp := *cr
			cp.Refs = []string{r.key}
			s.comps[k] = &cp
			s.put[k], s.del[k] = true, false
			continue
		}
		before, _ := encodeComponent(cur)
		cur.Config, cur.Removed = cr.Config, false
		if !slices.Contains(cur.Refs, r.key) {
			cur.Refs = append(cur.Refs, r.key)
		}
		if after, _ := encodeComponent(cur); !bytes.Equal(before, after) {
			s.put[k] = true
		}
	}
	if old := s.eps[r.key]; old != nil {
		for _, k := range old.id.Components {
			if !slices.Contains(keys, k) {
				s.unref(k, r.key)
			}
		}
	}
	r.id.Components, r.id.Paths = keys, paths
	s.eps[r.key] = r
	s.put[r.key], s.del[r.key] = true, false
}

// compKeys returns the record keys and the paths of comps.
func compKeys(comps []*compRecord) (keys, paths []string) {
	keys = make([]string, 0, len(comps))
	paths = make([]string, 0, len(comps))
	for _, cr := range comps {
		path := componentPath(pubsub.ComponentKind(cr.Kind), cr.Path...)
		keys, paths = append(keys, "pc/"+componentKey(path)), append(paths, path)
	}
	return keys, paths
}

// dropEndpoint stages the removal of the record key and of its references.
func (s *staged) dropEndpoint(key string) {
	old := s.eps[key]
	if old == nil {
		return
	}
	for _, k := range old.id.Components {
		s.unref(k, key)
	}
	delete(s.eps, key)
	s.put[key], s.del[key] = false, true
}

// unref drops the reference of the endpoint record ep to the component
// record k, which goes when it has none left (design §4.2: its durable
// references).
func (s *staged) unref(k, ep string) {
	cr := s.comps[k]
	if cr == nil {
		return
	}
	cr.Refs = slices.DeleteFunc(cr.Refs, func(x string) bool { return x == ep })
	if len(cr.Refs) == 0 {
		delete(s.comps, k)
		s.put[k], s.del[k] = false, true
		return
	}
	s.put[k] = true
}

// active reports whether a component record is referenced by an endpoint
// that is not being removed.
func (s *staged) active(cr *compRecord) bool {
	for _, r := range cr.Refs {
		if e := s.eps[r]; e != nil && e.body.State == stateActive {
			return true
		}
	}
	return false
}

// refresh makes the component records follow the runtime: a component
// that changed gets its new configuration, one that is gone is marked
// Removed (design §4.5). Components of endpoints being removed are left.
func (s *staged) refresh() {
	rt := s.p.c.srv.PubSub()
	for k, cr := range s.comps {
		if cr.Removed || !s.active(cr) {
			continue
		}
		before, _ := encodeComponent(cr)
		if cid, ok := lookupComponent(rt, cr); ok {
			if eo, err := normalizedConfig(rt, pubsub.ComponentKind(cr.Kind), cid); err == nil {
				cr.Config = eo
			}
		} else {
			cr.Removed = true
		}
		if after, _ := encodeComponent(cr); !bytes.Equal(before, after) {
			s.put[k] = true
		}
	}
}

// batch encodes what s stages.
func (s *staged) batch() (fxstore.Batch, error) {
	b := fxstore.Batch{Puts: map[string][]byte{}}
	for k, ok := range s.put {
		if !ok {
			continue
		}
		var v []byte
		var err error
		switch {
		case strings.HasPrefix(k, "ep/"):
			r := s.eps[k]
			r.id.Namespaces = s.ns
			v, err = encodeEndpoint(r.id, r.body)
		default:
			cr := s.comps[k]
			cr.Namespaces = s.ns
			v, err = encodeComponent(cr)
		}
		if err != nil {
			return fxstore.Batch{}, err
		}
		b.Puts[k] = v
	}
	for k, ok := range s.del {
		if ok {
			b.Deletes = append(b.Deletes, k)
		}
	}
	slices.Sort(b.Deletes)
	// Drop the puts that change nothing.
	st := s.p.d.State()
	for k, v := range b.Puts {
		if old, ok := st[k]; ok && bytes.Equal(old, v) {
			delete(b.Puts, k)
		}
	}
	b.Deletes = slices.DeleteFunc(b.Deletes, func(k string) bool { _, ok := st[k]; return !ok })
	return b, nil
}

// undo returns the batch that puts the keys of b back as the committed
// state has them.
func (p *persistence) undo(b fxstore.Batch) fxstore.Batch {
	st := p.d.State()
	u := fxstore.Batch{Puts: map[string][]byte{}}
	for _, k := range append(slices.Collect(maps.Keys(b.Puts)), b.Deletes...) {
		if v, ok := st[k]; ok {
			u.Puts[k] = v
		} else {
			u.Deletes = append(u.Deletes, k)
		}
	}
	slices.Sort(u.Deletes)
	return u
}

// --- records from the runtime ------------------------------------------------

// recordOf returns the record of the persistent endpoint e as the runtime
// has it, with the components it references, in their dependency order.
// enabled is its Enabled, state its State.
func (p *persistence) recordOf(e *endpoint, enabled bool, state uint8) (*epRecord, []*compRecord) {
	c := p.c
	c.mu.Lock()
	reader, writer, ownReader, ownWriter := e.reader, e.writer, e.ownReader, e.ownWriter
	nodes := slices.Clone(e.nodes)
	created, modified := e.createdAt, e.modifiedAt
	c.mu.Unlock()
	ns := c.namespaces()
	id := &epIdentity{Namespaces: ns, AC: e.ac.id, Endpoint: e.id, FunctionalEntity: e.fe, Name: e.name, Nodes: nodes}
	body := &epBody{State: state, Enabled: enabled, Preconfigured: !e.created, Folder: e.folder, Mode: int32(e.mode),
		Inputs: e.inputs, Outputs: e.outputs, CleanupTimeout: -1, CreationTime: created, ModificationTime: modified,
		OwnReader: ownReader, OwnWriter: ownWriter}
	if v, ok := val(c.value(c.childID(e.id, "CleanupTimeout"))).(float64); ok {
		body.CleanupTimeout = v
	}
	body.ConnectionManagerURI, _ = val(c.value(c.childID(e.id, "ConnectionManagerApplicationUri"))).(string)
	if eo, ok := val(c.value(c.childID(e.id, "RelatedEndpoint"))).(*ua.ExtensionObject); ok && eo != nil {
		body.Related = binaryBody(eo)
	}
	body.ControlGroups = c.endpointGroups(e)
	slices.SortFunc(body.ControlGroups, func(a, b *ua.NodeID) int { return strings.Compare(a.String(), b.String()) })
	var comps []*compRecord
	rt := c.srv.PubSub()
	add := func(n *ua.NodeID, own, isReader bool) string {
		cid, ok := c.componentOf(n)
		if !ok {
			return ""
		}
		chain := p.chainOf(rt, cid, own, !e.created, isReader)
		for _, cr := range chain {
			switch pubsub.ComponentKind(cr.Kind) {
			case pubsub.KindWriterGroup:
				if g, err := rt.WriterGroupConfig(cr.cid); err == nil {
					id.WriterGroupIDs = append(id.WriterGroupIDs, g.WriterGroupID)
				}
			case pubsub.KindDataSetWriter:
				if w, err := rt.DataSetWriterConfig(cr.cid); err == nil {
					id.DataSetWriterIDs = append(id.DataSetWriterIDs, w.DataSetWriterID)
				}
			default:
			}
		}
		comps = append(comps, chainRecords(chain)...)
		last := chain[len(chain)-1]
		return "pc/" + componentKey(componentPath(pubsub.ComponentKind(last.Kind), last.Path...))
	}
	if reader != nil {
		body.Reader = add(reader, ownReader, true)
	}
	if writer != nil {
		body.Writer = add(writer, ownWriter, false)
	}
	return &epRecord{key: c.keyOf(e.ac, e), id: id, body: body}, comps
}

// chained is a component record with the id of its component.
type chained struct {
	*compRecord
	cid pubsub.ComponentID
}

func chainRecords(ch []chained) []*compRecord {
	out := make([]*compRecord, len(ch))
	for i, c := range ch {
		out[i] = c.compRecord
	}
	return out
}

// chainOf returns the records of the DataSetReader or DataSetWriter cid
// and of what it depends on: its PubSubConnection and group and, for a
// writer, its PublishedDataSet, parents first. own: the endpoint's calls
// created the reader or writer; preset: the endpoint is preconfigured.
func (p *persistence) chainOf(rt *pubsub.PubSub, cid pubsub.ComponentID, own, preset, isReader bool) []chained {
	c := p.c
	info, err := rt.Component(cid)
	if err != nil {
		return nil
	}
	g, err := rt.Component(info.Parent)
	if err != nil {
		return nil
	}
	conn, err := rt.Component(g.Parent)
	if err != nil {
		return nil
	}
	prov := func(id pubsub.ComponentID, created bool) uint8 {
		switch {
		case created:
			return provCreated
		case preset:
			return provPreconfigured
		}
		return provAdopted
	}
	createdByCall := func(id pubsub.ComponentID) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.created[id]
	}
	rec := func(id pubsub.ComponentID, kind pubsub.ComponentKind, created bool, path ...string) (chained, bool) {
		eo, err := normalizedConfig(rt, kind, id)
		if err != nil {
			return chained{}, false
		}
		return chained{compRecord: &compRecord{Kind: uint8(kind), Path: path, Config: eo, Provenance: prov(id, created)}, cid: id}, true
	}
	var out []chained
	if r, ok := rec(conn.ID, pubsub.KindConnection, createdByCall(conn.ID), conn.Name); ok {
		out = append(out, r)
	}
	if r, ok := rec(g.ID, g.Kind, createdByCall(g.ID), conn.Name, g.Name); ok {
		out = append(out, r)
	}
	if !isReader {
		if dw, err := rt.DataSetWriterConfig(cid); err == nil && dw.DataSetName != "" {
			if pid, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, dw.DataSetName); ok {
				if r, ok := rec(pid, pubsub.KindPublishedDataSet, createdByCall(pid), dw.DataSetName); ok {
					out = append(out, r)
				}
			}
		}
	}
	if r, ok := rec(cid, info.Kind, own, conn.Name, g.Name, info.Name); ok {
		out = append(out, r)
	}
	return out
}

// normalizedConfig returns the configuration of the component id as a
// component record keeps it: without its children, and disabled, since
// enablement follows the endpoints (design §4.4).
func normalizedConfig(rt *pubsub.PubSub, kind pubsub.ComponentKind, id pubsub.ComponentID) (*ua.ExtensionObject, error) {
	var v any
	switch kind {
	case pubsub.KindConnection:
		cfg, err := rt.ConnectionConfig(id)
		if err != nil {
			return nil, err
		}
		cfg.WriterGroups, cfg.ReaderGroups, cfg.Enabled = nil, nil, false
		v = cfg
	case pubsub.KindWriterGroup:
		cfg, err := rt.WriterGroupConfig(id)
		if err != nil {
			return nil, err
		}
		cfg.DataSetWriters, cfg.Enabled = nil, false
		v = cfg
	case pubsub.KindReaderGroup:
		cfg, err := rt.ReaderGroupConfig(id)
		if err != nil {
			return nil, err
		}
		cfg.DataSetReaders, cfg.Enabled = nil, false
		v = cfg
	case pubsub.KindDataSetWriter:
		cfg, err := rt.DataSetWriterConfig(id)
		if err != nil {
			return nil, err
		}
		cfg.Enabled = false
		v = cfg
	case pubsub.KindDataSetReader:
		cfg, err := rt.DataSetReaderConfig(id)
		if err != nil {
			return nil, err
		}
		cfg.Enabled = false
		v = cfg
	case pubsub.KindPublishedDataSet:
		cfg, err := rt.PublishedDataSetConfig(id)
		if err != nil {
			return nil, err
		}
		v = cfg
	default:
		return nil, fmt.Errorf("fxserver: component kind %v", kind)
	}
	return ua.NewExtensionObject(v), nil
}

// lookupComponent finds the component of a record in the runtime by its
// path.
func lookupComponent(rt *pubsub.PubSub, cr *compRecord) (pubsub.ComponentID, bool) {
	kind := pubsub.ComponentKind(cr.Kind)
	switch {
	case kind == pubsub.KindPublishedDataSet && len(cr.Path) == 1:
		return rt.Lookup(kind, pubsub.Root, cr.Path[0])
	case kind == pubsub.KindConnection && len(cr.Path) == 1:
		return rt.Lookup(kind, pubsub.Root, cr.Path[0])
	case (kind == pubsub.KindWriterGroup || kind == pubsub.KindReaderGroup) && len(cr.Path) == 2:
		conn, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, cr.Path[0])
		if !ok {
			return 0, false
		}
		return rt.Lookup(kind, conn, cr.Path[1])
	case (kind == pubsub.KindDataSetWriter || kind == pubsub.KindDataSetReader) && len(cr.Path) == 3:
		groupKind := pubsub.KindWriterGroup
		if kind == pubsub.KindDataSetReader {
			groupKind = pubsub.KindReaderGroup
		}
		_, _, id, ok := lookupPath(rt, groupKind, kind, cr.Path[0], cr.Path[1], cr.Path[2])
		return id, ok
	}
	return 0, false
}

// configValue returns the decoded configuration of a component record.
func configValue(cr *compRecord) any {
	if cr == nil || cr.Config == nil {
		return nil
	}
	return cr.Config.Value
}

// sameConfig reports whether two component configurations are equal.
func sameConfig(a, b *ua.ExtensionObject) bool {
	ab, err1 := ua.Encode(a)
	bb, err2 := ua.Encode(b)
	return err1 == nil && err2 == nil && bytes.Equal(ab, bb)
}

// --- the commit point of EstablishConnections ---------------------------------

// persist writes the records of the persistent endpoints the call x
// touched, and the component records that follow the runtime, in one
// Apply: the commit point of design §4.3. It reports whether the call goes
// on; when it does not, it set the results.
func (x *call) persist() bool {
	p := x.c.pers
	if p == nil || x.persisted {
		return true
	}
	x.persisted = true
	enable := x.req.CommandMask&uafx.EnableCommunicationCmd != 0
	if enable {
		// The existing endpoints EnableCommunicationCmd is about to enable,
		// resolved here as the command would.
		for _, el := range x.els {
			if el.ep == nil && el.cfg.ConnectionEndpoint != nil && el.cfg.ConnectionEndpoint.Parameter == nil {
				x.endpointOf(el)
			}
		}
	}
	p.mu.Lock()
	s := p.begin()
	var first *element
	now := time.Now()
	for _, el := range x.els {
		e := el.ep
		if e == nil || !e.persistent {
			continue
		}
		if first == nil {
			first = el
		}
		on := enable
		if old := p.eps[x.c.keyOf(e.ac, e)]; old != nil && !enable {
			on = old.body.Enabled
		}
		r, comps := p.recordOf(e, on, stateActive)
		r.id.Components, r.id.Paths = compKeys(comps)
		if old := p.eps[r.key]; old != nil {
			// The ModificationTime changes only with the record.
			r.body.ModificationTime = old.body.ModificationTime
			ob, _ := encodeEndpoint(old.id, old.body)
			nb, _ := encodeEndpoint(r.id, r.body)
			if !bytes.Equal(ob, nb) {
				r.body.ModificationTime = now
				x.c.touch(e, now)
			}
		}
		s.putEndpoint(r, comps)
	}
	s.refresh()
	b, err := s.batch()
	if err == nil && b.Empty() {
		p.mu.Unlock()
		return true
	}
	if err != nil {
		p.mu.Unlock()
		x.c.log.Error("uafx: the records of a call do not encode", "error", err)
		x.failPersist(first, ua.StatusBadInternalError)
		return false
	}
	undo := p.undo(b)
	x.c.crashPoint("establish.before-commit")
	ctx, cancel := p.ctx()
	o, err := p.d.Apply(ctx, b)
	cancel()
	switch o {
	case fxstore.Committed:
		p.reload()
		p.mu.Unlock()
		x.compensate = &undo
		x.c.crashPoint("establish.after-commit")
		return true
	case fxstore.NotCommitted:
		p.mu.Unlock()
		x.c.log.Warn("uafx: the records of a call were not committed", "error", err)
		x.failPersist(first, ua.StatusBadResourceUnavailable)
		return false
	default:
		// Unknown: the call is rolled back, and the store is made to
		// follow once the outcome is known (design §4.3, §3.3).
		ctx, cancel := p.ctx()
		_, _ = p.d.Require(ctx, undo)
		cancel()
		p.mu.Unlock()
		x.c.log.Warn("uafx: the outcome of the records of a call is unknown; the store is fenced until it is settled", "error", err)
		x.failPersist(first, ua.StatusBadInternalError)
		return false
	}
}

// failPersist sets the results of a call whose commit point failed: sc in
// the ConnectionEndpointResult of the first persistent endpoint,
// Bad_NothingToDo in those of the others (design §4.3, C3-D13).
func (x *call) failPersist(first *element, sc ua.StatusCode) {
	for _, el := range x.els {
		if el.ep == nil || !el.ep.persistent {
			continue
		}
		if el == first {
			el.res.ConnectionEndpointResult = sc
		} else {
			el.res.ConnectionEndpointResult = ua.StatusBadNothingToDo
		}
	}
}

// uncommit puts the records a committed call wrote back as they were: the
// call is rolled back after its commit point (design §4.3). It is owed
// when it does not commit.
func (x *call) uncommit() {
	p := x.c.pers
	if p == nil || x.compensate == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := p.ctx()
	defer cancel()
	if o, err := p.d.Require(ctx, *x.compensate); o != fxstore.Committed {
		x.c.log.Warn("uafx: the records of a rolled back call are owed; the store is fenced until they are written", "error", err)
	}
	p.reload()
	x.compensate = nil
}

// --- CloseConnections of a persistent endpoint ------------------------------

// closePersistent closes the persistent endpoint e: the intent is made
// durable first, then the runtime acts (design §4.4, C3-D8).
func (c *Connections) closePersistent(e *endpoint, remove bool) ua.StatusCode {
	p := c.pers
	if !remove {
		return c.disablePersistent(e)
	}
	unknown := false
	c.mu.Lock()
	pending := e.removePending
	c.mu.Unlock()
	if !pending {
		p.mu.Lock()
		s := p.begin()
		r, comps := p.recordOf(e, false, stateRemovePending)
		if old := p.eps[r.key]; old != nil {
			r.body.ModificationTime = old.body.ModificationTime
		}
		s.putEndpoint(r, comps)
		b, err := s.batch()
		if err != nil {
			p.mu.Unlock()
			return ua.StatusBadInternalError
		}
		c.crashPoint("close.before-intent")
		ctx, cancel := p.ctx()
		o, err := p.d.Apply(ctx, b)
		cancel()
		switch o {
		case fxstore.Committed:
			p.reload()
		case fxstore.NotCommitted:
			p.mu.Unlock()
			c.log.Warn("uafx: CloseConnections: the removal was not committed", "endpoint", e.id, "error", err)
			return ua.StatusBadResourceUnavailable
		default:
			unknown = true
			c.log.Warn("uafx: CloseConnections: the outcome of the removal is unknown; it is completed anyway", "endpoint", e.id, "error", err)
		}
		p.mu.Unlock()
		c.mu.Lock()
		e.removePending = true
		c.mu.Unlock()
		c.crashPoint("close.after-intent")
	}
	if sc := c.closeEndpoint(e, true); sc != ua.StatusOK {
		return sc
	}
	c.crashPoint("close.after-runtime")
	p.mu.Lock()
	s := p.begin()
	key := c.keyOf(e.ac, e)
	if s.eps[key] == nil {
		// The intent is not in the committed state (its outcome is
		// unknown): the record to delete is the one the intent wrote.
		r, comps := p.recordOf(e, false, stateRemovePending)
		s.putEndpoint(r, comps)
	}
	s.dropEndpoint(key)
	b, err := s.batch()
	if err == nil && !b.Empty() {
		ctx, cancel := p.ctx()
		if o, err := p.d.Require(ctx, b); o != fxstore.Committed {
			c.log.Warn("uafx: CloseConnections: the deletion of the record is owed", "endpoint", e.id, "error", err)
		}
		cancel()
	}
	p.reload()
	p.mu.Unlock()
	c.mu.Lock()
	e.persistent, e.removePending = false, false
	c.mu.Unlock()
	if !e.created {
		c.write(c.childID(e.id, "IsPersistent"), false)
	}
	if unknown {
		return ua.StatusBadInternalError
	}
	return ua.StatusOK
}

// disablePersistent is CloseConnections with Remove FALSE of the persistent
// endpoint e: the record gets Enabled FALSE, then the runtime disables
// (design §4.4).
func (c *Connections) disablePersistent(e *endpoint) ua.StatusCode {
	p := c.pers
	p.mu.Lock()
	s := p.begin()
	r, comps := p.recordOf(e, false, stateActive)
	now := time.Now()
	if old := p.eps[r.key]; old != nil {
		r.body.ModificationTime = old.body.ModificationTime
		if old.body.Enabled {
			r.body.ModificationTime = now
		}
	}
	s.putEndpoint(r, comps)
	b, err := s.batch()
	if err != nil {
		p.mu.Unlock()
		return ua.StatusBadInternalError
	}
	unknown := false
	if !b.Empty() {
		c.crashPoint("disable.before-intent")
		ctx, cancel := p.ctx()
		o, err := p.d.Apply(ctx, b)
		cancel()
		switch o {
		case fxstore.Committed:
			p.reload()
		case fxstore.NotCommitted:
			p.mu.Unlock()
			c.log.Warn("uafx: CloseConnections: the disable was not committed", "endpoint", e.id, "error", err)
			return ua.StatusBadResourceUnavailable
		default:
			// Disable anyway (the safe direction); the store follows once
			// the outcome is known.
			unknown = true
			ctx, cancel := p.ctx()
			_, _ = p.d.Require(ctx, b)
			cancel()
			c.log.Warn("uafx: CloseConnections: the outcome of the disable is unknown; disabled anyway", "endpoint", e.id, "error", err)
		}
	}
	p.mu.Unlock()
	if r.body.ModificationTime.Equal(now) {
		c.touch(e, now)
	}
	c.crashPoint("disable.after-intent")
	sc := c.closeEndpoint(e, false)
	if unknown {
		return ua.StatusBadInternalError
	}
	return sc
}

// --- settling ------------------------------------------------------------------

// settle runs one settling attempt of a fenced domain when it is due, with
// a bounded backoff (design §3.3). The monitor calls it.
func (p *persistence) settle(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.d.Status().Fenced || now.Before(p.next) {
		return
	}
	ctx, cancel := p.ctx()
	ok, err := p.d.Settle(ctx)
	cancel()
	if ok {
		p.backoff, p.next = 0, time.Time{}
		p.reload()
		p.c.log.Info("uafx: the persistent ConnectionEndpoints store is settled")
		return
	}
	p.backoff = min(max(2*p.backoff, 100*time.Millisecond), 30*time.Second)
	p.next = now.Add(p.backoff)
	p.c.log.Warn("uafx: the persistent ConnectionEndpoints store is still fenced", "error", err, "retry", p.backoff)
}

// fenced reports whether the domain is fenced.
func (p *persistence) fenced() bool { return p.d.Status().Fenced }

// PersistenceStatus is the state of the persistent ConnectionEndpoints of a
// server.
type PersistenceStatus struct {
	// Enabled: the connections have a store (ConnectionOptions.Store).
	Enabled bool
	// Durability is what the store survives, when it says.
	Durability fxstore.Durability
	// Store is the state of the records in the store: its revision and
	// whether a write with an unknown outcome or an owed write fences it.
	Store fxstore.DomainStatus
	// Restored are the endpoints the start restored.
	Restored []*ua.NodeID
	// Records is the number of persistent endpoints in the store.
	Records int
	// Quarantined is the number of quarantined records.
	Quarantined int
}

// Persistence returns the state of the persistent ConnectionEndpoints.
func (c *Connections) Persistence() PersistenceStatus {
	p := c.pers
	if p == nil {
		return PersistenceStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := PersistenceStatus{Enabled: true, Store: p.d.Status(), Restored: slices.Clone(p.restored),
		Records: len(p.eps), Quarantined: len(p.quar)}
	if d, ok := c.opts.Store.(interface{ Durability() fxstore.Durability }); ok {
		st.Durability = d.Durability()
	}
	return st
}

// touch sets the ModificationTime of e.
func (c *Connections) touch(e *endpoint, t time.Time) {
	c.mu.Lock()
	e.modifiedAt = t
	n := e.modNode
	c.mu.Unlock()
	if n != nil {
		c.write(n, t)
	}
}

// crashPoint runs the crash hook of the tests at a point of the
// protocols.
func (c *Connections) crashPoint(name string) {
	if f := c.crash.Load(); f != nil {
		(*f)(name)
	}
}
