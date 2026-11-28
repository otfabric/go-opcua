// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"hash/fnv"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

const (
	// maxConfigFileSize bounds what a client may write to the
	// PubSubConfiguration file.
	maxConfigFileSize = 16 << 20
	// maxConfigRead is the most one Read returns (MaxByteStringLength).
	maxConfigRead = 1 << 20
	// maxConfigHandles bounds the open handles of the file.
	maxConfigHandles = 32
	// maxReservedIDs bounds the ids one session may hold through ReserveIds.
	maxReservedIDs = 1024
	// reservedIDMin starts the range of ids ReserveIds and CloseAndUpdate
	// assign (Part 14 §9.1.3.7.5).
	reservedIDMin = 0x8000
)

// configFile is the PubSubConfiguration object (Part 14 §9.1.3.7): a FileType
// holding the configuration of the runtime as a UABinaryFileDataType with a
// PubSubConfiguration2DataType Body. A client reads it, or writes a new one
// and applies element operations of it with CloseAndUpdate.
type configFile struct {
	m *pubsubModel
	// file are the handles of the file (OPC 10000-20 §4.2).
	file *FileObject

	mu       sync.Mutex
	reserved map[string]*idReservation // by SessionId

	// beforeReconcile, set by tests only, runs in applyLocked between
	// reading the configuration and applying the update.
	beforeReconcile func()

	modified atomic.Int64 // UnixNano
	obj      *Node
	nodes    []*ua.NodeID // Size, OpenCount, LastModifiedTime
}

// idReservation are the ids ReserveIds gave a session.
type idReservation struct {
	session *ua.NodeID
	groups  map[uint16]bool
	writers map[uint16]bool
}

// buildConfigFile represents the PubSubConfiguration object, if namespace 0
// has it.
func (m *pubsubModel) buildConfigFile() {
	s := m.s
	obj := s.ownNode(id.PublishSubscribePubSubConfiguration)
	if obj == nil {
		return
	}
	f := &configFile{m: m, obj: obj, reserved: map[string]*idReservation{}}
	f.modified.Store(time.Now().UnixNano())
	// Part 14 §9.1.3.7.1: Open takes Read, Write + EraseExisting and
	// Read + Write only; what a client writes is applied by CloseAndUpdate.
	f.file, _ = s.NewFile(FileConfig{ // the configuration is valid
		Backend: &SnapshotFile{
			Content:      func(context.Context) ([]byte, error) { return f.content() },
			MaxSize:      maxConfigFileSize,
			SizeExceeded: ua.StatusBadResourceUnavailable,
		},
		Writable:            true,
		Modes:               []ua.OpenFileMode{fileModeRead, fileModeRead | fileModeWrite, fileModeWrite | fileModeEraseExisting},
		MaxByteStringLength: maxConfigRead,
		MaxHandles:          maxConfigHandles,
		OnChange:            f.changed,
	})
	m.file = f
	set := func(nid uint32, v ValueFunc, dynamic bool) {
		if n := s.ownNode(nid); n != nil {
			n.mu.Lock()
			n.val = v
			n.mu.Unlock()
			if dynamic {
				f.nodes = append(f.nodes, n.ID())
			}
		}
	}
	set(id.PublishSubscribePubSubConfigurationSize, func() *ua.DataValue {
		b, err := f.content()
		if err != nil {
			return badValue(ua.StatusBadInternalError)
		}
		return DataValueFromValue(uint64(len(b)))
	}, true)
	set(id.PublishSubscribePubSubConfigurationOpenCount, func() *ua.DataValue {
		return DataValueFromValue(uint16(f.file.OpenCount()))
	}, true)
	set(id.PublishSubscribePubSubConfigurationLastModifiedTime, func() *ua.DataValue {
		return DataValueFromValue(time.Unix(0, f.modified.Load()).UTC())
	}, true)
	set(id.PublishSubscribePubSubConfigurationWritable, static(true), false)
	set(id.PublishSubscribePubSubConfigurationUserWritable, static(true), false)
	set(id.PublishSubscribePubSubConfigurationMaxByteStringLength, static(uint32(maxConfigRead)), false)

	for _, x := range []struct {
		name   string
		method uint32
		h      func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	}{
		{"Open", id.PublishSubscribePubSubConfigurationOpen, f.fileMethod("Open")},
		{"Close", id.PublishSubscribePubSubConfigurationClose, f.fileMethod("Close")},
		{"Read", id.PublishSubscribePubSubConfigurationRead, f.fileMethod("Read")},
		{"Write", id.PublishSubscribePubSubConfigurationWrite, f.fileMethod("Write")},
		{"GetPosition", id.PublishSubscribePubSubConfigurationGetPosition, f.fileMethod("GetPosition")},
		{"SetPosition", id.PublishSubscribePubSubConfigurationSetPosition, f.fileMethod("SetPosition")},
		{"ReserveIds", id.PublishSubscribePubSubConfigurationReserveIDs, f.reserveIDs},
		{"CloseAndUpdate", id.PublishSubscribePubSubConfigurationCloseAndUpdate, f.closeAndUpdate},
	} {
		s.addMethodRef(obj, x.method)
		s.RegisterMethod(obj.ID(), ua.NewNumericNodeID(0, x.method), m.method(x.name, x.h))
	}
}

// content returns the file as a client reads it: the configuration of the
// runtime in a UABinaryFileDataType.
func (f *configFile) content() ([]byte, error) {
	cfg := f.m.rt.Configuration()
	var uris []string
	for _, ns := range f.m.s.Namespaces() {
		uris = append(uris, ns.Name())
	}
	body := &ua.PubSubConfiguration2DataType{
		PublishedDataSets: cfg.PublishedDataSets,
		Connections:       cfg.Connections,
		Enabled:           cfg.Enabled,
	}
	return ua.Encode(&ua.UABinaryFileDataType{
		Namespaces: uris,
		Body:       ua.MustVariant(ua.NewExtensionObject(body)),
	})
}

// changed notifies the monitored items of the file's properties.
func (f *configFile) changed() {
	for _, n := range f.nodes {
		f.m.s.ChangeNotification(n)
	}
}

func sessionOf(ctx context.Context) *ua.NodeID {
	if c, ok := MethodCallerFromContext(ctx); ok {
		return c.SessionID
	}
	return nil
}

// fileMethod returns a Method of FileType of the file.
func (f *configFile) fileMethod(name string) func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	h := f.file.Method(name)
	return func(ctx context.Context, obj *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return h(ctx, obj, nil, args)
	}
}

// pruneLocked forgets the reservations of sessions that are closed: they
// are valid for the session only (Part 14 §9.1.3.7.5).
func (f *configFile) pruneLocked() {
	for k, r := range f.reserved {
		if !f.m.s.sb.hasID(r.session) {
			delete(f.reserved, k)
		}
	}
}

// defaultPublisherID is the PublisherId ReserveIds returns and an added
// connection without one gets: that of the first connection that has one,
// else a UInt64 derived from the ApplicationUri of the server.
func (f *configFile) defaultPublisherID(conns []*ua.PubSubConnectionDataType) *ua.Variant {
	for _, c := range conns {
		if c != nil && c.PublisherID != nil && c.PublisherID.Value() != nil {
			return c.PublisherID
		}
	}
	h := fnv.New64a()
	h.Write([]byte(f.m.s.cfg.applicationURI))
	return ua.MustVariant(h.Sum64() | 1)
}

// usedIDs returns the WriterGroupIds and DataSetWriterIds of a
// configuration and of all reservations.
func (f *configFile) usedIDsLocked(conns []*ua.PubSubConnectionDataType) (groups, writers map[uint16]bool) {
	groups, writers = map[uint16]bool{}, map[uint16]bool{}
	for _, c := range conns {
		if c == nil {
			continue
		}
		for _, g := range c.WriterGroups {
			if g == nil {
				continue
			}
			groups[g.WriterGroupID] = true
			for _, w := range g.DataSetWriters {
				if w != nil {
					writers[w.DataSetWriterID] = true
				}
			}
		}
	}
	for _, r := range f.reserved {
		for x := range r.groups {
			groups[x] = true
		}
		for x := range r.writers {
			writers[x] = true
		}
	}
	return groups, writers
}

// allocID returns an id of the range for internal assignment that used does
// not have and marks it used.
func allocID(used map[uint16]bool) (uint16, bool) {
	for x := uint32(reservedIDMin); x <= 0xffff; x++ {
		if !used[uint16(x)] {
			used[uint16(x)] = true
			return uint16(x), true
		}
	}
	return 0, false
}

func (f *configFile) reserveIDs(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.PubSubConfigurationTypeReserveIDsInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	r, sc := f.reserve(ctx, in.NumReqWriterGroupIDs, in.NumReqDataSetWriterIDs)
	if sc != ua.StatusOK {
		return nil, sc
	}
	out := uamethod.PubSubConfigurationTypeReserveIDsOutput{
		DefaultPublisherID: r.DefaultPublisherID,
		WriterGroupIDs:     r.WriterGroupIDs,
		DataSetWriterIDs:   r.DataSetWriterIDs,
	}
	return out.Pack(), ua.StatusOK
}

// reserve reserves ng WriterGroupIds and nw DataSetWriterIds for the
// session of ctx (Part 14 §9.1.3.7.5). It runs in the PubSub transaction:
// the ids it reserves are neither used nor reserved (§9.1.3.7.5), so it
// must not read the configuration while a CloseAndUpdate assigns ids that
// it has not applied yet. The lock order is ps.txn, then f.mu.
func (f *configFile) reserve(ctx context.Context, ng, nw uint16) (*PubSubIDReservation, ua.StatusCode) {
	sess := sessionOf(ctx)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	f.m.s.ps.txn.Lock()
	defer f.m.s.ps.txn.Unlock()
	cfg := f.m.rt.Configuration()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLocked()
	r := f.reserved[sess.String()]
	if r == nil {
		r = &idReservation{session: sess, groups: map[uint16]bool{}, writers: map[uint16]bool{}}
	}
	if len(r.groups)+len(r.writers)+int(ng)+int(nw) > maxReservedIDs {
		return nil, ua.StatusBadResourceUnavailable
	}
	usedG, usedW := f.usedIDsLocked(cfg.Connections)
	if f.m.s.heldPubSubIDs(usedG, usedW) {
		return nil, ua.StatusBadResourceUnavailable
	}
	take := func(n uint16, used map[uint16]bool) ([]uint16, bool) {
		out := make([]uint16, 0, n)
		for range n {
			x, ok := allocID(used)
			if !ok {
				return nil, false
			}
			out = append(out, x)
		}
		return out, true
	}
	gs, ok1 := take(ng, usedG)
	ws, ok2 := take(nw, usedW)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadResourceUnavailable
	}
	for _, x := range gs {
		r.groups[x] = true
	}
	for _, x := range ws {
		r.writers[x] = true
	}
	f.reserved[sess.String()] = r
	return &PubSubIDReservation{DefaultPublisherID: f.defaultPublisherID(cfg.Connections), WriterGroupIDs: gs, DataSetWriterIDs: ws}, ua.StatusOK
}

// releaseUsedLocked ends the reservations of the ids a configuration uses.
func (f *configFile) releaseUsedLocked(conns []*ua.PubSubConnectionDataType) {
	for _, c := range conns {
		for _, g := range c.WriterGroups {
			for _, r := range f.reserved {
				delete(r.groups, g.WriterGroupID)
			}
			for _, w := range g.DataSetWriters {
				for _, r := range f.reserved {
					delete(r.writers, w.DataSetWriterID)
				}
			}
		}
	}
}

func (f *configFile) closeAndUpdate(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.m.s.ps.txn.Lock()
	defer f.m.s.ps.txn.Unlock()

	// The handle stays open when the arguments or what was written are
	// refused: the client may close it, or write again.
	var in uamethod.PubSubConfigurationTypeCloseAndUpdateInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	require, refs := in.RequireCompleteUpdate, in.ConfigurationReferences
	// A null element is no PubSubConfigurationRefDataType.
	if slices.Contains(refs, nil) {
		return nil, ua.StatusBadTypeMismatch
	}
	var file *ua.PubSubConfiguration2DataType
	_, sc := f.file.CloseAndTake(ctx, in.FileHandle, func(b []byte) ua.StatusCode {
		var sc ua.StatusCode
		if file, sc = decodeConfigFile(b); sc != ua.StatusOK {
			return sc
		}
		if len(refs) == 0 {
			return ua.StatusBadNothingToDo
		}
		return ua.StatusOK
	})
	if sc != ua.StatusOK {
		return nil, sc
	}
	u, sc := f.applyLocked(ctx, file, require, refs)
	if sc != ua.StatusOK {
		return nil, sc
	}
	out := uamethod.PubSubConfigurationTypeCloseAndUpdateOutput{
		ChangesApplied:       u.ChangesApplied,
		ReferencesResults:    u.ReferenceResults,
		ConfigurationObjects: u.ConfigurationObjects,
	}
	if u.ChangesApplied {
		out.ConfigurationValues = u.ConfigurationValues
		if out.ConfigurationValues == nil {
			out.ConfigurationValues = []*ua.PubSubConfigurationValueDataType{}
		}
	}
	return out.Pack(), ua.StatusOK
}

// applyLocked applies file as CloseAndUpdate does (Part 14 §9.1.3.7.6).
// The caller holds the PubSub transaction (pubsubState.txn).
func (f *configFile) applyLocked(ctx context.Context, file *ua.PubSubConfiguration2DataType, require bool, refs []*ua.PubSubConfigurationRefDataType) (*PubSubConfigurationUpdate, ua.StatusCode) {
	if st := f.m.checkConnectionTargets(ctx, file.Connections...); st != ua.StatusOK {
		return nil, st
	}

	old := f.m.rt.Configuration()
	f.mu.Lock()
	usedG, usedW := f.usedIDsLocked(old.Connections)
	f.mu.Unlock()
	f.m.s.heldPubSubIDs(usedG, usedW)
	u := newConfigUpdate(file, old, f.defaultPublisherID(old.Connections), usedG, usedW)
	results := u.run(refs)
	applied := u.changed && (!require || !u.failed)
	created := map[pubsub.ComponentID]bool{}
	if f.beforeReconcile != nil {
		f.beforeReconcile()
	}
	var moved []PubSubComponentMove
	if applied {
		ids := f.m.s.componentsByPath()
		if err := reconcilePubSubRecord(f.m.rt, u.cfg, func(id pubsub.ComponentID) { created[id] = true }); err != nil {
			f.m.s.cfg.logger.Warn("pubsub: CloseAndUpdate failed, restoring the configuration", "error", err)
			if rerr := reconcilePubSub(f.m.rt, old); rerr != nil {
				f.m.s.cfg.logger.Error("pubsub: restoring the configuration failed", "error", rerr)
			}
			return nil, statusOf(err)
		}
		moved = movesBetween(ids, f.m.s.componentsByPath(), u.removed)
		if h := f.m.s.pubsubHook(); h != nil || f.m.s.cfg.pubsubStore != nil {
			if err := f.m.s.pubsubChanged(h, &PubSubChange{Context: ctx, Before: old, Moved: moved, ids: f.m.s.restorerOnly(h, ids)}); err != nil {
				return nil, statusOf(err)
			}
		}
		f.mu.Lock()
		f.releaseUsedLocked(u.cfg.Connections)
		f.mu.Unlock()
		f.modified.Store(time.Now().UnixNano())
		go f.changed()
	}
	var objs []*ua.NodeID
	for _, p := range u.paths {
		objs = append(objs, f.nodeOfPath(applied, p))
	}
	r := &PubSubConfigurationUpdate{ChangesApplied: applied, ReferenceResults: results, ConfigurationObjects: objs, f: f}
	if applied {
		r.ConfigurationValues, r.created, r.Moved = u.values, created, moved
		r.before, r.after = old, f.m.rt.Configuration()
	}
	return r, ua.StatusOK
}

// decodeConfigFile decodes what a client wrote.
func decodeConfigFile(b []byte) (*ua.PubSubConfiguration2DataType, ua.StatusCode) {
	var fd ua.UABinaryFileDataType
	if _, err := ua.Decode(b, &fd); err != nil || fd.Body == nil {
		return nil, ua.StatusBadTypeMismatch
	}
	eo, ok := fd.Body.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		return nil, ua.StatusBadTypeMismatch
	}
	cfg, ok := eo.Value.(*ua.PubSubConfiguration2DataType)
	if !ok || cfg == nil {
		return nil, ua.StatusBadTypeMismatch
	}
	return cfg, ua.StatusOK
}
