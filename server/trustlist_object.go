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
	openCount  atomic.Int32

	mu      sync.Mutex
	handles map[uint32]*trustListHandle
	next    uint32
	props   []*ua.NodeID // the properties that change
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
	t := &TrustListObject{s: s, obj: obj, cfg: cfg, handles: map[uint32]*trustListHandle{}}
	t.lastUpdate.Store(time.Now().UnixNano())

	methods := map[string]func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode){
		"Open":              t.open,
		"OpenWithMasks":     t.openWithMasks,
		"Read":              t.read,
		"Write":             t.write,
		"Close":             t.closeHandle,
		"GetPosition":       t.getPosition,
		"SetPosition":       t.setPosition,
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
		v, dynamic = func() *ua.DataValue { return DataValueFromValue(uint16(t.openCount.Load())) }, true
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

// pruneLocked forgets the handles of sessions that are closed.
func (t *TrustListObject) pruneLocked() {
	for h, x := range t.handles {
		if !t.s.sb.hasID(x.session) {
			delete(t.handles, h)
			t.openCount.Add(-1)
		}
	}
}

func (t *TrustListObject) addHandleLocked(x *trustListHandle) ([]*ua.Variant, ua.StatusCode) {
	t.pruneLocked()
	for _, h := range t.handles {
		if x.mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotWritable
		}
		if h.mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotReadable
		}
	}
	if len(t.handles) >= maxTrustListHandles {
		return nil, ua.StatusBadTooManyOperations
	}
	for {
		t.next++
		if _, used := t.handles[t.next]; t.next != 0 && !used {
			break
		}
	}
	t.handles[t.next] = x
	t.openCount.Add(1)
	go t.notify()
	return []*ua.Variant{ua.MustVariant(t.next)}, ua.StatusOK
}

func (t *TrustListObject) readContent(masks ua.TrustListMasks) ([]byte, ua.StatusCode) {
	b, err := encodeTrustList(maskTrustList(t.load(), masks))
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	return b, ua.StatusOK
}

// open is Open: Read, or Write with EraseExisting on a writable list.
func (t *TrustListObject) open(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	mode, ok := argValue[byte](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	x := &trustListHandle{session: c.SessionID, mode: mode}
	switch mode {
	case fileModeRead:
		b, sc := t.readContent(ua.TrustListMasksAll)
		if sc != ua.StatusOK {
			return nil, sc
		}
		x.buf = b
	case fileModeWrite | fileModeEraseExisting:
		if t.cfg.Update == nil {
			return nil, ua.StatusBadNotWritable
		}
	default:
		return nil, ua.StatusBadInvalidArgument
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addHandleLocked(x)
}

func (t *TrustListObject) openWithMasks(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	masks, ok := argValue[uint32](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	b, sc := t.readContent(ua.TrustListMasks(masks))
	if sc != ua.StatusOK {
		return nil, sc
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addHandleLocked(&trustListHandle{session: c.SessionID, mode: fileModeRead, buf: b})
}

func (t *TrustListObject) handleLocked(c *MethodCaller, args []*ua.Variant) (uint32, *trustListHandle, ua.StatusCode) {
	h, ok := argValue[uint32](args, 0)
	if !ok {
		return 0, nil, ua.StatusBadTypeMismatch
	}
	x := t.handles[h]
	if x == nil || !x.session.Equal(c.SessionID) {
		return 0, nil, ua.StatusBadInvalidArgument
	}
	return h, x, ua.StatusOK
}

func (t *TrustListObject) closeLocked(h uint32) {
	delete(t.handles, h)
	t.openCount.Add(-1)
	go t.notify()
}

func (t *TrustListObject) closeHandle(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h, _, sc := t.handleLocked(c, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	t.closeLocked(h)
	return nil, ua.StatusOK
}

func (t *TrustListObject) read(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, x, sc := t.handleLocked(c, args)
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
	end := min(x.pos+min(int(n), maxTrustListRead), len(x.buf))
	b := append([]byte{}, x.buf[x.pos:end]...)
	x.pos = end
	return []*ua.Variant{ua.MustVariant(b)}, ua.StatusOK
}

func (t *TrustListObject) write(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, x, sc := t.handleLocked(c, args)
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
	if x.pos+len(b) > int(t.cfg.MaxSize) {
		return nil, ua.StatusBadEncodingLimitsExceeded
	}
	if end := x.pos + len(b); end > len(x.buf) {
		x.buf = append(x.buf, make([]byte, end-len(x.buf))...)
	}
	x.pos += copy(x.buf[x.pos:], b)
	return nil, ua.StatusOK
}

func (t *TrustListObject) getPosition(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, x, sc := t.handleLocked(c, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(uint64(x.pos))}, ua.StatusOK
}

func (t *TrustListObject) setPosition(_ context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, x, sc := t.handleLocked(c, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	pos, ok := argValue[uint64](args, 1)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	x.pos = int(min(pos, uint64(len(x.buf))))
	return nil, ua.StatusOK
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
	t.mu.Lock()
	defer t.mu.Unlock()
	h, x, sc := t.handleLocked(c, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if x.mode&fileModeWrite == 0 {
		return nil, ua.StatusBadInvalidState
	}
	t.closeLocked(h)
	upd, sc := decodeTrustList(x.buf)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if sc := t.updateLocked(ctx, c, mergeTrustList(t.load(), upd)); sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(false)}, ua.StatusOK
}

func (t *TrustListObject) addCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	der, ok1 := argValue[[]byte](args, 0)
	trusted, ok2 := argValue[bool](args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	if t.cfg.Update == nil {
		return nil, ua.StatusBadNotWritable
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil || !bytes.Equal(cert.Raw, der) {
		return nil, ua.StatusBadCertificateInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked()
	if len(t.handles) > 0 {
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
	thumb, ok1 := argValue[string](args, 0)
	trusted, ok2 := argValue[bool](args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	if t.cfg.Update == nil {
		return nil, ua.StatusBadNotWritable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked()
	if len(t.handles) > 0 {
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
