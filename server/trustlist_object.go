// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
	"github.com/otfabric/go-opcua/uapolicy"
)

// TrustListConfig configures a TrustList object served by
// [Server.ServeTrustList].
type TrustListConfig struct {
	// Load returns the trust list the object serves (all four lists). It
	// is called for every Open, OpenWithMasks and change and must not
	// return nil.
	Load func() *ua.TrustListDataType

	// Authorize decides whether the caller may call a method of the object:
	// the method name ("Open", "OpenWithMasks", "Read", "Close",
	// "CloseAndUpdate", "AddCertificate", ...). write reports a call that
	// opens the file for writing or changes the trust list. It returns
	// ua.StatusOK to allow the call, otherwise the status the call fails
	// with. nil allows every call of a session.
	Authorize func(ctx context.Context, caller *MethodCaller, method string, write bool) ua.StatusCode

	// Update, if set, makes the trust list writable: it is called with the
	// complete new trust list (SpecifiedLists TrustListMasksAll) that
	// CloseAndUpdate, AddCertificate or RemoveCertificate made, after the
	// list was validated. The change takes effect when it returns
	// ua.StatusOK; CloseAndUpdate then reports applyChangesRequired false.
	// nil makes the object read-only: the writing methods return
	// Bad_NotWritable.
	Update func(ctx context.Context, caller *MethodCaller, tl *ua.TrustListDataType) ua.StatusCode

	// MaxSize is the most bytes the encoded trust list may have. Zero
	// selects 1 MiB.
	MaxSize uint32
}

// TrustListObject is a TrustList object (Part 12 §7.8.2) that a server
// serves with [Server.ServeTrustList].
type TrustListObject struct {
	s   *Server
	obj *ua.NodeID
	cfg TrustListConfig

	lastUpdate atomic.Int64 // UnixNano

	// file are the handles of the TrustList file (Part 12 §7.8.2.1).
	file *FileObject
	// mu is held by Open, OpenWithMasks, CloseAndUpdate, AddCertificate
	// and RemoveCertificate: no handle is opened while one of the last
	// two checks that none is.
	mu    sync.Mutex
	props []*ua.NodeID // the properties that change
}

// ServeTrustList serves the TrustList object obj of the address space: an
// object of the TrustListType (Part 12 §7.8.2.1) whose methods and
// properties are its HasComponent and HasProperty children, for example a
// TrustList of a NodeSet that was imported. The methods are found by their
// BrowseName. It returns an error if obj or one of the methods Open, Read,
// Close and OpenWithMasks is missing.
//
// Each handle of the file belongs to the session that opened it. A reader
// sees the trust list at the time of the Open; writes are kept until
// CloseAndUpdate.
func (s *Server) ServeTrustList(obj *ua.NodeID, cfg TrustListConfig) (*TrustListObject, error) {
	n := s.Node(obj)
	if n == nil {
		return nil, fmt.Errorf("server: ServeTrustList: node %v not found", obj)
	}
	if cfg.Load == nil {
		return nil, fmt.Errorf("server: ServeTrustList: Load is required")
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = defaultMaxTrustListSize
	}
	t := &TrustListObject{s: s, obj: obj, cfg: cfg}
	t.lastUpdate.Store(time.Now().UnixNano())
	t.file, _ = s.NewFile(FileConfig{ // the configuration is valid
		Backend: &SnapshotFile{
			Content: func(context.Context) ([]byte, error) {
				return encodeTrustList(maskTrustList(t.load(), ua.TrustListMasksAll))
			},
			MaxSize:      int(cfg.MaxSize),
			SizeExceeded: ua.StatusBadEncodingLimitsExceeded,
		},
		Writable:            cfg.Update != nil,
		Modes:               trustListModes,
		MaxByteStringLength: maxTrustListRead,
		MaxHandles:          maxTrustListHandles,
		OnChange:            t.notify,
	})

	methods := map[string]func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode){
		"Open":              t.open,
		"OpenWithMasks":     t.openWithMasks,
		"Read":              t.fileMethod("Read"),
		"Write":             t.fileMethod("Write"),
		"Close":             t.fileMethod("Close"),
		"GetPosition":       t.fileMethod("GetPosition"),
		"SetPosition":       t.fileMethod("SetPosition"),
		"CloseAndUpdate":    t.closeAndUpdate,
		"AddCertificate":    t.addCertificate,
		"RemoveCertificate": t.removeCertificate,
	}
	writes := map[string]bool{"Write": true, "CloseAndUpdate": true, "AddCertificate": true, "RemoveCertificate": true}
	found := map[string]bool{}
	for _, ref := range n.refsSnapshot() {
		if ref == nil || !ref.IsForward || ref.NodeID == nil || ref.ReferenceTypeID == nil {
			continue
		}
		target := ref.NodeID.NodeID
		// The references of an imported NodeSet carry no browse name: it
		// is that of the target node.
		bn := ref.BrowseName
		if tn := s.Node(target); tn != nil {
			bn = tn.BrowseName()
		}
		if bn == nil {
			continue
		}
		switch ref.ReferenceTypeID.IntID() {
		case id.HasComponent:
			name := bn.Name
			f := methods[name]
			if f == nil || bn.NamespaceIndex != 0 {
				continue
			}
			found[name] = true
			write := writes[name]
			s.RegisterMethod(obj, target, func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				c, ok := MethodCallerFromContext(ctx)
				if !ok || c.SessionID == nil {
					return nil, ua.StatusBadUserAccessDenied
				}
				if a := t.cfg.Authorize; a != nil {
					// Open decides by its mode whether it writes.
					w := write || (name == "Open" && len(args) > 0 && args[0] != nil && args[0].Value() != any(byte(fileModeRead)))
					if sc := a(ctx, c, name, w); sc != ua.StatusOK {
						return nil, sc
					}
				}
				return f(ctx, c, args)
			})
		case id.HasProperty:
			t.setProperty(bn.Name, target)
		}
	}
	for _, m := range []string{"Open", "Read", "Close", "OpenWithMasks"} {
		if !found[m] {
			s.files.remove(t.file)
			return nil, fmt.Errorf("server: ServeTrustList: %v has no method %s", obj, m)
		}
	}
	return t, nil
}

// setProperty serves one property of the TrustList object.
func (t *TrustListObject) setProperty(name string, nid *ua.NodeID) {
	var v ValueFunc
	dynamic := false
	switch name {
	case "Size":
		v, dynamic = func() *ua.DataValue { return DataValueFromValue(uint64(t.size())) }, true
	case "OpenCount":
		v, dynamic = func() *ua.DataValue { return DataValueFromValue(uint16(t.file.OpenCount())) }, true
	case "LastUpdateTime":
		v, dynamic = func() *ua.DataValue { return DataValueFromValue(time.Unix(0, t.lastUpdate.Load()).UTC()) }, true
	case "Writable", "UserWritable":
		v = static(t.cfg.Update != nil)
	case "MaxByteStringLength":
		v = static(uint32(maxTrustListRead))
	default:
		return
	}
	n := t.s.Node(nid)
	if n == nil {
		return
	}
	n.mu.Lock()
	n.val = v
	n.mu.Unlock()
	if dynamic {
		t.props = append(t.props, nid)
	}
}

// Changed tells the object that the trust list Load returns changed: the
// LastUpdateTime and Size properties are updated.
func (t *TrustListObject) Changed() {
	t.lastUpdate.Store(time.Now().UnixNano())
	go t.notify()
}

func (t *TrustListObject) notify() {
	for _, n := range t.props {
		t.s.ChangeNotification(n)
	}
}

// size is the encoded size of the trust list.
func (t *TrustListObject) size() int {
	b, err := encodeTrustList(t.load())
	if err != nil {
		return 0
	}
	return len(b)
}

func (t *TrustListObject) load() *ua.TrustListDataType {
	d := t.cfg.Load()
	if d == nil {
		return emptyTrustListData()
	}
	return d
}

func (t *TrustListObject) readContent(masks ua.TrustListMasks) ([]byte, ua.StatusCode) {
	b, err := encodeTrustList(maskTrustList(t.load(), masks))
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	return b, ua.StatusOK
}

// open is Open: Read, or Write with EraseExisting on a writable list.
func (t *TrustListObject) open(ctx context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.file.Method("Open")(ctx, nil, nil, args)
}

func (t *TrustListObject) openWithMasks(ctx context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.TrustListTypeOpenWithMasksInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	b, sc := t.readContent(ua.TrustListMasks(in.Masks))
	if sc != ua.StatusOK {
		return nil, sc
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h, sc := t.file.OpenBytes(ctx, b)
	if sc != ua.StatusOK {
		return nil, sc
	}
	out := uamethod.TrustListTypeOpenWithMasksOutput{FileHandle: h}
	return out.Pack(), ua.StatusOK
}

// fileMethod returns a Method of FileType of the TrustList.
func (t *TrustListObject) fileMethod(name string) func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	h := t.file.Method(name)
	return func(ctx context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return h(ctx, nil, nil, args)
	}
}

// updateLocked validates and hands a new trust list to Update.
func (t *TrustListObject) updateLocked(ctx context.Context, c *MethodCaller, d *ua.TrustListDataType) ua.StatusCode {
	if t.cfg.Update == nil {
		return ua.StatusBadNotWritable
	}
	tl, sc := newTrustList(d, t.cfg.MaxSize)
	if sc != ua.StatusOK {
		return sc
	}
	if sc := t.cfg.Update(ctx, c, cloneTrustListData(tl.data)); sc != ua.StatusOK {
		return sc
	}
	t.Changed()
	return ua.StatusOK
}

func (t *TrustListObject) closeAndUpdate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.TrustListTypeCloseAndUpdateInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b, sc := t.file.CloseAndTake(ctx, in.FileHandle, nil)
	if sc != ua.StatusOK {
		return nil, sc
	}
	upd, sc := decodeTrustList(b)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if sc := t.updateLocked(ctx, c, mergeTrustList(t.load(), upd)); sc != ua.StatusOK {
		return nil, sc
	}
	out := uamethod.TrustListTypeCloseAndUpdateOutput{ApplyChangesRequired: false}
	return out.Pack(), ua.StatusOK
}

func (t *TrustListObject) addCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.TrustListTypeAddCertificateInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	der, trusted := in.Certificate, in.IsTrustedCertificate
	if t.cfg.Update == nil {
		return nil, ua.StatusBadNotWritable
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil || !bytes.Equal(cert.Raw, der) {
		return nil, ua.StatusBadCertificateInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file.OpenCount() > 0 {
		return nil, ua.StatusBadInvalidState
	}
	d := cloneTrustListData(t.load())
	if trusted {
		d.TrustedCertificates = append(d.TrustedCertificates, slices.Clone(der))
	} else {
		d.IssuerCertificates = append(d.IssuerCertificates, slices.Clone(der))
	}
	return nil, t.updateLocked(ctx, c, d)
}

func (t *TrustListObject) removeCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.TrustListTypeRemoveCertificateInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	thumb, trusted := in.Thumbprint, in.IsTrustedCertificate
	if t.cfg.Update == nil {
		return nil, ua.StatusBadNotWritable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file.OpenCount() > 0 {
		return nil, ua.StatusBadInvalidState
	}
	d := cloneTrustListData(t.load())
	certs, crls := &d.TrustedCertificates, &d.TrustedCrls
	if !trusted {
		certs, crls = &d.IssuerCertificates, &d.IssuerCrls
	}
	i := slices.IndexFunc(*certs, func(der []byte) bool {
		return strings.EqualFold(hex.EncodeToString(uapolicy.Thumbprint(der)), strings.TrimSpace(thumb))
	})
	if i < 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	cert, err := uapolicy.ParseCertificate((*certs)[i])
	*certs = slices.Delete(*certs, i, i+1)
	if err == nil {
		*crls = slices.DeleteFunc(*crls, func(der []byte) bool {
			return bytes.Equal(crlIssuer(der), cert.RawSubject)
		})
	}
	return nil, t.updateLocked(ctx, c, d)
}
