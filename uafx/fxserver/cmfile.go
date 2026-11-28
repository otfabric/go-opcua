// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"math"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// ConnectionManagerConfiguration (Annex F.3): a FileType whose content is a
// UABinaryFileDataType with the sets of the Manager (F.2), a
// server.FileObject with a SnapshotFile. Open supports Read (0x01) and
// Write with EraseExisting (0x06) only (F.3.2); a writer needs the
// CMAuthorizer (ConfigureAdmin by default). CloseAndUpdate applies the
// written sets with the operations given (F.3.3).

// cmFile is the state of ConnectionManagerConfiguration: its handles
// (OPC 10000-20 §4.2), which end with their session.
type cmFile struct {
	id   *ua.NodeID
	file *server.FileObject
}

// cmFileModes are the modes of Open: "Only Read (0x01) and Write with
// EraseExisting (0x06) are allowed" (F.3.2).
var cmFileModes = []ua.OpenFileMode{ua.OpenFileModeRead, ua.OpenFileModeWrite | ua.OpenFileModeEraseExisting}

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
	file, err := c.srv.NewFile(server.FileConfig{
		Backend: &server.SnapshotFile{
			Content:      func(context.Context) ([]byte, error) { return c.fileContent() },
			MaxSize:      maxFileSize,
			SizeExceeded: ua.StatusBadOutOfRange,
		},
		Writable: true,
		Modes:    cmFileModes,
		// No bound on a Read beyond its length, and on the handles.
		MaxByteStringLength: math.MaxInt32,
		MaxHandles:          math.MaxInt,
		// A writer needs the CMAuthorizer (F.3.2).
		Authorize: func(ctx context.Context, _ *server.MethodCaller, mode ua.OpenFileMode) ua.StatusCode {
			if mode&ua.OpenFileModeWrite == 0 {
				return ua.StatusOK
			}
			return c.authorize(ctx, CMRequest{Operation: CMFileWrite})
		},
	})
	if err != nil {
		return nil, err
	}
	f := &cmFile{id: obj.ID(), file: file}
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
		{"OpenCount", id.UInt16, func() any { return uint16(min(file.OpenCount(), math.MaxUint16)) }},
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
		{"Open", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationOpen, f.method("Open")},
		{"Close", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationClose, f.method("Close")},
		{"Read", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationRead, f.method("Read")},
		{"Write", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationWrite, f.method("Write")},
		{"GetPosition", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationGetPosition, f.method("GetPosition")},
		{"SetPosition", 0, fxcmid.ConnectionManagerTypeConnectionManagerConfigurationSetPosition, f.method("SetPosition")},
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

// method returns a Method of FileType of the file (OPC 10000-20 §4.2.2 to
// §4.2.7).
func (f *cmFile) method(name string) func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	h := f.file.Method(name)
	return func(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return h(ctx, f.id, nil, args)
	}
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
		// Operations is an array of ConnectionConfigurationSetOperation, an
		// OptionSet of Byte (Table F.39): an array of Byte. A ByteString is
		// taken for it as well (OPC 10000-4 §5.12.2.4).
		var raw []byte
		switch v := args[2].Value().(type) {
		case ua.ByteArray:
			raw = v
		case []byte:
			raw = v
		case nil:
		default:
			return nil, ua.StatusBadTypeMismatch
		}
		for _, b := range raw {
			ops = append(ops, uafx.ConnectionConfigurationSetOperation(b))
		}
		h, ok := args[0].Value().(uint32)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		data, sc := f.file.CloseAndTake(ctx, h, nil)
		if sc != ua.StatusGood {
			return nil, sc
		}
		// F.3.3: the Client shall be authorized when it calls
		// CloseAndUpdate, not only when it opened the file. A refused call
		// closes the handle and changes nothing, as Close does.
		if sc := c.authorize(ctx, CMRequest{Operation: CMFileWrite}); sc != ua.StatusOK {
			return nil, sc
		}
		sets, err := fxcm.DecodeFile(data)
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
