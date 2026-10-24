// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The modes of FileType.Open (Part 20 §4.2.2).
const (
	fileModeRead          = 0x01
	fileModeWrite         = 0x02
	fileModeEraseExisting = 0x04
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

	mu       sync.Mutex
	handles  map[uint32]*configHandle
	next     uint32
	reserved map[string]*idReservation // by SessionId

	// update serialises CloseAndUpdate.
	update sync.Mutex

	openCount atomic.Int32
	modified  atomic.Int64 // UnixNano
	obj       *Node
	nodes     []*ua.NodeID // Size, OpenCount, LastModifiedTime
}

// configHandle is an open handle of the file. Reads see the configuration at
// Open; writes are kept until CloseAndUpdate.
type configHandle struct {
	session *ua.NodeID
	mode    byte
	buf     []byte
	pos     int
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
	f := &configFile{m: m, obj: obj, handles: map[uint32]*configHandle{}, reserved: map[string]*idReservation{}}
	f.modified.Store(time.Now().UnixNano())
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
		return DataValueFromValue(uint16(f.openCount.Load()))
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
		{"Open", id.PublishSubscribePubSubConfigurationOpen, f.open},
		{"Close", id.PublishSubscribePubSubConfigurationClose, f.close},
		{"Read", id.PublishSubscribePubSubConfigurationRead, f.read},
		{"Write", id.PublishSubscribePubSubConfigurationWrite, f.write},
		{"GetPosition", id.PublishSubscribePubSubConfigurationGetPosition, f.getPosition},
		{"SetPosition", id.PublishSubscribePubSubConfigurationSetPosition, f.setPosition},
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

// pruneLocked forgets the handles and the reservations of sessions that are
// closed: they are valid for the session only (Part 20 §4.2.1, Part 14
// §9.1.3.7.5).
func (f *configFile) pruneLocked() {
	alive := map[string]bool{}
	live := func(sid *ua.NodeID) bool {
		k := sid.String()
		ok, seen := alive[k]
		if !seen {
			ok = f.m.s.sb.hasID(sid)
			alive[k] = ok
		}
		return ok
	}
	for h, x := range f.handles {
		if !live(x.session) {
			delete(f.handles, h)
			f.openCount.Add(-1)
		}
	}
	for k, r := range f.reserved {
		if !live(r.session) {
			delete(f.reserved, k)
		}
	}
}

func (f *configFile) open(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	mode, ok := argValue[byte](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	sess := sessionOf(ctx)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	// Part 14 §9.1.3.7.1: Read, Write + EraseExisting and Read + Write only.
	switch mode {
	case fileModeRead, fileModeRead | fileModeWrite, fileModeWrite | fileModeEraseExisting:
	default:
		return nil, ua.StatusBadInvalidArgument
	}
	var buf []byte
	if mode&fileModeRead != 0 {
		b, err := f.content()
		if err != nil {
			return nil, ua.StatusBadInternalError
		}
		buf = b
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLocked()
	// Reading may be shared, writing is exclusive.
	for _, h := range f.handles {
		if mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotWritable
		}
		if h.mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotReadable
		}
	}
	if len(f.handles) >= maxConfigHandles {
		return nil, ua.StatusBadTooManyOperations
	}
	for {
		f.next++
		if _, used := f.handles[f.next]; f.next != 0 && !used {
			break
		}
	}
	f.handles[f.next] = &configHandle{session: sess, mode: mode, buf: buf}
	f.openCount.Add(1)
	go f.changed()
	return []*ua.Variant{ua.MustVariant(f.next)}, ua.StatusOK
}

// handleLocked returns the handle of argument 0, which must be one of the
// calling session.
func (f *configFile) handleLocked(ctx context.Context, args []*ua.Variant) (uint32, *configHandle, ua.StatusCode) {
	h, ok := argValue[uint32](args, 0)
	if !ok {
		return 0, nil, ua.StatusBadTypeMismatch
	}
	x := f.handles[h]
	if x == nil || !x.session.Equal(sessionOf(ctx)) {
		return 0, nil, ua.StatusBadInvalidArgument
	}
	return h, x, ua.StatusOK
}

func (f *configFile) closeLocked(h uint32) {
	delete(f.handles, h)
	f.openCount.Add(-1)
	go f.changed()
}

func (f *configFile) close(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, _, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	f.closeLocked(h)
	return nil, ua.StatusOK
}

func (f *configFile) read(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, x, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	n, ok := argValue[int32](args, 1)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	if n < 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	if x.mode&fileModeRead == 0 {
		return nil, ua.StatusBadInvalidState
	}
	end := min(x.pos+min(int(n), maxConfigRead), len(x.buf))
	b := append([]byte{}, x.buf[x.pos:end]...)
	x.pos = end
	return []*ua.Variant{ua.MustVariant(b)}, ua.StatusOK
}

func (f *configFile) write(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, x, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	var b []byte
	if len(args) > 1 && args[1] != nil && args[1].Value() != nil {
		var ok bool
		if b, ok = args[1].Value().([]byte); !ok {
			return nil, ua.StatusBadTypeMismatch
		}
	}
	if x.mode&fileModeWrite == 0 {
		return nil, ua.StatusBadInvalidState
	}
	if x.pos+len(b) > maxConfigFileSize {
		return nil, ua.StatusBadResourceUnavailable
	}
	if end := x.pos + len(b); end > len(x.buf) {
		x.buf = append(x.buf, make([]byte, end-len(x.buf))...)
	}
	x.pos += copy(x.buf[x.pos:], b)
	return nil, ua.StatusOK
}

func (f *configFile) getPosition(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, x, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(uint64(x.pos))}, ua.StatusOK
}

func (f *configFile) setPosition(ctx context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, x, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	pos, ok := argValue[uint64](args, 1)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	// A position past the end sets it to the end (Part 20 §4.2.8).
	x.pos = int(min(pos, uint64(len(x.buf))))
	return nil, ua.StatusOK
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
	if _, ok := argValue[string](args, 0); !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	ng, ok1 := argValue[uint16](args, 1)
	nw, ok2 := argValue[uint16](args, 2)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	sess := sessionOf(ctx)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
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
	return []*ua.Variant{f.defaultPublisherID(cfg.Connections), ua.MustVariant(gs), ua.MustVariant(ws)}, ua.StatusOK
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
	f.update.Lock()
	defer f.update.Unlock()

	f.mu.Lock()
	h, x, sc := f.handleLocked(ctx, args)
	if sc != ua.StatusOK {
		f.mu.Unlock()
		return nil, sc
	}
	if x.mode&fileModeWrite == 0 {
		f.mu.Unlock()
		return nil, ua.StatusBadInvalidState
	}
	require, ok := argValue[bool](args, 1)
	refs, ok2 := argStructs[ua.PubSubConfigurationRefDataType](args, 2)
	if !ok || !ok2 {
		f.mu.Unlock()
		return nil, ua.StatusBadTypeMismatch
	}
	file, sc := decodeConfigFile(x.buf)
	if sc != ua.StatusOK {
		f.mu.Unlock()
		return nil, sc
	}
	if len(refs) == 0 {
		f.mu.Unlock()
		return nil, ua.StatusBadNothingToDo
	}
	f.closeLocked(h)
	f.mu.Unlock()

	old := f.m.rt.Configuration()
	f.mu.Lock()
	usedG, usedW := f.usedIDsLocked(old.Connections)
	f.mu.Unlock()
	u := newConfigUpdate(file, old, f.defaultPublisherID(old.Connections), usedG, usedW)
	results := u.run(refs)
	applied := u.changed && (!require || !u.failed)
	if applied {
		if err := reconcilePubSub(f.m.rt, u.cfg); err != nil {
			f.m.s.cfg.logger.Warn("pubsub: CloseAndUpdate failed, restoring the configuration", "error", err)
			if rerr := reconcilePubSub(f.m.rt, old); rerr != nil {
				f.m.s.cfg.logger.Error("pubsub: restoring the configuration failed", "error", rerr)
			}
			return nil, statusOf(err)
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
	values := make([]*ua.ExtensionObject, len(u.values))
	for i, v := range u.values {
		values[i] = ua.NewExtensionObject(v)
	}
	if !applied {
		values = nil
	}
	return []*ua.Variant{ua.MustVariant(applied), ua.MustVariant(results), ua.MustVariant(values), ua.MustVariant(objs)}, ua.StatusOK
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
