// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// ConnectionManagerConfiguration (Annex F.3): a FileType whose content is a
// UABinaryFileDataType with the sets of the Manager (F.2). Open supports
// Read (0x01) and Write with EraseExisting (0x06) only (F.3.2); a writer
// needs the CMAuthorizer (ConfigureAdmin by default). CloseAndUpdate
// applies the written sets with the operations given (F.3.3).

// cmFile is the state of ConnectionManagerConfiguration.
type cmFile struct {
	id      *ua.NodeID
	mu      sync.Mutex
	next    uint32
	handles map[uint32]*fileHandle
}

type fileHandle struct {
	session fxcm.LockOwner
	write   bool
	data    []byte
	pos     int
}

// File open modes (OPC 10000-20 §4.2.2 Table 4).
const (
	fileRead          = 0x01
	fileWrite         = 0x02
	fileEraseExisting = 0x04
)

// maxFileSize bounds what a client may write (library interpretation: the
// file holds configuration, not bulk data).
const maxFileSize = 16 << 20

func (c *ConnectionManager) addFile() (*cmFile, error) {
	cmNS := c.ns.CM
	b := c.builder(&c.nodes)
	obj, err := b.object("cm.File", qn(cmNS, "ConnectionManagerConfiguration"), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionManagerConfigurationType))
	if err != nil {
		return nil, err
	}
	c.srv.Node(c.id).AddRef(obj, server.RefTypeIDHasComponent, true)
	f := &cmFile{id: obj.ID(), handles: map[uint32]*fileHandle{}}
	props := []struct {
		name string
		dt   uint32
		get  func() any
	}{
		{"Size", id.UInt64, func() any {
			b, err := c.fileContent()
			if err != nil {
				return uint64(0)
			}
			return uint64(len(b))
		}},
		{"Writable", id.Boolean, func() any { return true }},
		{"UserWritable", id.Boolean, func() any { return true }},
		{"OpenCount", id.UInt16, func() any {
			f.mu.Lock()
			defer f.mu.Unlock()
			return uint16(len(f.handles))
		}},
	}
	for _, p := range props {
		get := p.get
		n, err := b.variableOf("cm.File."+p.name, qn(0, p.name), dt0(p.dt), -1, dt0(id.PropertyType), false,
			func() *ua.DataValue { return server.DataValueFromValue(get()) })
		if err != nil {
			return nil, err
		}
		obj.AddReference(n, dt0(id.HasProperty), true)
	}
	methods := []struct {
		name string
		ns   uint16
		decl uint32
		h    func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	}{
		{"Open", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationOpen, f.open(c)},
		{"Close", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationClose, f.close},
		{"Read", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationRead, f.read},
		{"Write", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationWrite, f.writeData},
		{"GetPosition", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationGetPosition, f.getPosition},
		{"SetPosition", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationSetPosition, f.setPosition},
		{"CloseAndUpdate", cmNS, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationCloseAndUpdate, f.closeAndUpdate(c)},
	}
	for _, m := range methods {
		n, err := c.methodOf(b, obj, "cm.File."+m.name, qn(m.ns, m.name), ua.NewNumericNodeID(cmNS, m.decl))
		if err != nil {
			return nil, err
		}
		h := m.h
		c.srv.RegisterMethod(obj.ID(), n.ID(), func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if c.isClosed() {
				return nil, ua.StatusBadShutdown
			}
			return h(ctx, args)
		})
	}
	return f, nil
}

// fileContent is the content of the file: the sets of the Manager (F.2).
func (c *ConnectionManager) fileContent() ([]byte, error) {
	var sets []*uafx.ConnectionConfigurationSetConf
	for _, k := range c.m.Keys() {
		if cfg, ok := c.m.Config(k); ok {
			sets = append(sets, cfg.Conf())
		}
	}
	return fxcm.EncodeFile(sets)
}

func callerSession(ctx context.Context) fxcm.LockOwner {
	if mc, ok := server.MethodCallerFromContext(ctx); ok {
		return ownerOf(mc.SessionID)
	}
	return ""
}

// handle returns the open handle h of the caller's session.
func (f *cmFile) handle(ctx context.Context, v *ua.Variant) (uint32, *fileHandle, ua.StatusCode) {
	h, ok := v.Value().(uint32)
	if !ok {
		return 0, nil, ua.StatusBadTypeMismatch
	}
	fh := f.handles[h]
	if fh == nil || fh.session != callerSession(ctx) {
		return 0, nil, ua.StatusBadInvalidArgument
	}
	return h, fh, ua.StatusGood
}

// open is Open (OPC 10000-20 §4.2.2): F.3.2 allows Read and
// Write+EraseExisting only.
func (f *cmFile) open(c *ConnectionManager) func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) != 1 {
			return nil, ua.StatusBadArgumentsMissing
		}
		mode, ok := args[0].Value().(uint8)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		fh := &fileHandle{session: callerSession(ctx)}
		switch mode {
		case fileRead:
			b, err := c.fileContent()
			if err != nil {
				return nil, ua.StatusBadInternalError
			}
			fh.data = b
		case fileWrite | fileEraseExisting:
			if sc := c.authorize(ctx, CMRequest{Operation: CMFileWrite}); sc != ua.StatusOK {
				return nil, sc
			}
			fh.write = true
		default:
			return nil, ua.StatusBadInvalidArgument
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, o := range f.handles {
			// One writer, and no reader beside it (OPC 10000-20 §4.2.2).
			if o.write || fh.write {
				return nil, ua.StatusBadInvalidState
			}
		}
		f.next++
		f.handles[f.next] = fh
		return []*ua.Variant{ua.MustVariant(f.next)}, ua.StatusGood
	}
}

func (f *cmFile) close(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 1 {
		return nil, ua.StatusBadArgumentsMissing
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h, _, sc := f.handle(ctx, args[0])
	if sc != ua.StatusGood {
		return nil, sc
	}
	delete(f.handles, h)
	return nil, ua.StatusGood
}

func (f *cmFile) read(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 2 {
		return nil, ua.StatusBadArgumentsMissing
	}
	n, ok := args[1].Value().(int32)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, fh, sc := f.handle(ctx, args[0])
	if sc != ua.StatusGood {
		return nil, sc
	}
	if fh.write || n < 0 {
		return nil, ua.StatusBadInvalidState
	}
	end := min(fh.pos+int(n), len(fh.data))
	out := append([]byte{}, fh.data[fh.pos:end]...)
	fh.pos = end
	return []*ua.Variant{ua.MustVariant(out)}, ua.StatusGood
}

func (f *cmFile) writeData(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 2 {
		return nil, ua.StatusBadArgumentsMissing
	}
	data, ok := args[1].Value().([]byte)
	if !ok && args[1].Value() != nil {
		return nil, ua.StatusBadTypeMismatch
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, fh, sc := f.handle(ctx, args[0])
	if sc != ua.StatusGood {
		return nil, sc
	}
	if !fh.write {
		return nil, ua.StatusBadInvalidState
	}
	if fh.pos+len(data) > maxFileSize {
		return nil, ua.StatusBadOutOfRange
	}
	if end := fh.pos + len(data); end > len(fh.data) {
		fh.data = append(fh.data, make([]byte, end-len(fh.data))...)
	}
	copy(fh.data[fh.pos:], data)
	fh.pos += len(data)
	return nil, ua.StatusGood
}

func (f *cmFile) getPosition(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 1 {
		return nil, ua.StatusBadArgumentsMissing
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, fh, sc := f.handle(ctx, args[0])
	if sc != ua.StatusGood {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(uint64(fh.pos))}, ua.StatusGood
}

func (f *cmFile) setPosition(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 2 {
		return nil, ua.StatusBadArgumentsMissing
	}
	pos, ok := args[1].Value().(uint64)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, fh, sc := f.handle(ctx, args[0])
	if sc != ua.StatusGood {
		return nil, sc
	}
	fh.pos = int(min(pos, uint64(len(fh.data))))
	return nil, ua.StatusGood
}

// closeAndUpdate is CloseAndUpdate (F.3.3, Tables F.39 to F.41): it closes
// the file and applies its sets, one operation per Body element.
func (f *cmFile) closeAndUpdate(c *ConnectionManager) func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) != 3 {
			return nil, ua.StatusBadArgumentsMissing
		}
		require, ok := args[1].Value().(bool)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		var ops []uafx.ConnectionConfigurationSetOperation
		switch v := args[2].Value().(type) {
		case []byte:
			for _, b := range v {
				ops = append(ops, uafx.ConnectionConfigurationSetOperation(b))
			}
		case nil:
		default:
			return nil, ua.StatusBadTypeMismatch
		}
		f.mu.Lock()
		h, fh, sc := f.handle(ctx, args[0])
		if sc == ua.StatusGood {
			if !fh.write {
				sc = ua.StatusBadInvalidState
			} else {
				delete(f.handles, h)
			}
		}
		f.mu.Unlock()
		if sc != ua.StatusGood {
			return nil, sc
		}
		sets, err := fxcm.DecodeFile(fh.data)
		if err != nil {
			return nil, ua.StatusBadTypeMismatch
		}
		if len(sets) == 0 {
			return nil, ua.StatusBadNothingToDo
		}
		if len(ops) != len(sets) {
			// Library interpretation: F.3.3 gives one operation per Body
			// element.
			return nil, ua.StatusBadInvalidArgument
		}
		in := make([]fxcm.Operation, len(sets))
		for i := range sets {
			in[i] = fxcm.Operation{Op: ops[i], Conf: sets[i]}
		}
		applied, errs := c.m.Update(ctx, in, require)
		c.Flush()
		results := make([]ua.StatusCode, len(errs))
		objects := make([]*ua.NodeID, len(errs))
		for i, e := range errs {
			results[i] = statusOr(e, ua.StatusBadInvalidState)
			objects[i] = ua.NewTwoByteNodeID(0)
			if e == nil && ops[i] != uafx.ElementRemove {
				if n, ok := c.SetNode(fxcm.KeyOf(sets[i])); ok {
					objects[i] = n
				}
			}
		}
		return []*ua.Variant{ua.MustVariant(applied), ua.MustVariant(results), ua.MustVariant(objects)}, ua.StatusGood
	}
}
