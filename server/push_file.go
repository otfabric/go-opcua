// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	// maxTrustListRead is the most one Read of the trust list returns.
	maxTrustListRead = 1 << 20
	// maxTrustListHandles bounds the open handles of the trust list.
	maxTrustListHandles = 32
)

// trustListHandle is an open handle of the TrustList file (Part 12
// §7.8.2): reads see the trust list at Open, writes are kept until
// CloseAndUpdate.
type trustListHandle struct {
	session *ua.NodeID
	mode    byte
	buf     []byte
	pos     int
}

// encodeTrustList returns the content of the TrustList file: the
// TrustListDataType in the OPC UA Binary encoding (Part 12 §7.8.2.1).
func encodeTrustList(d *ua.TrustListDataType) ([]byte, error) {
	return ua.Encode(d)
}

// decodeTrustList decodes what a client wrote to the TrustList file. The
// file must hold exactly one TrustListDataType.
func decodeTrustList(b []byte) (*ua.TrustListDataType, ua.StatusCode) {
	d := new(ua.TrustListDataType)
	n, err := ua.Decode(b, d)
	if err != nil || n != len(b) {
		return nil, ua.StatusBadDecodingError
	}
	if d.SpecifiedLists&^uint32(ua.TrustListMasksAll) != 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	return d, ua.StatusOK
}

// pruneLocked forgets the handles of sessions that are closed: a handle is
// valid for its session only (Part 20 §4.2.1).
func (m *pushManager) pruneLocked(g *certGroup) {
	for h, x := range g.handles {
		if m.s != nil && !m.s.sb.hasID(x.session) {
			delete(g.handles, h)
			g.openCount.Add(-1)
		}
	}
}

// addHandleLocked opens a handle.
func (m *pushManager) addHandleLocked(g *certGroup, x *trustListHandle) ([]*ua.Variant, ua.StatusCode) {
	m.pruneLocked(g)
	// Reading may be shared, writing is exclusive.
	for _, h := range g.handles {
		if x.mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotWritable
		}
		if h.mode&fileModeWrite != 0 {
			return nil, ua.StatusBadNotReadable
		}
	}
	if len(g.handles) >= maxTrustListHandles {
		return nil, ua.StatusBadTooManyOperations
	}
	for {
		m.next++
		if _, used := g.handles[m.next]; m.next != 0 && !used {
			break
		}
	}
	g.handles[m.next] = x
	g.openCount.Add(1)
	go m.changed()
	return []*ua.Variant{ua.MustVariant(m.next)}, ua.StatusOK
}

// readContent returns the lists of the active trust list masks selects.
func (m *pushManager) readContent(g *certGroup, masks ua.TrustListMasks) ([]byte, ua.StatusCode) {
	b, err := encodeTrustList(maskTrustList(g.trust.Load().data, masks))
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	return b, ua.StatusOK
}

// fileOpen is Open (Part 12 §7.8.2.1): Read, or Write with EraseExisting.
func (m *pushManager) fileOpen(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	mode, ok := argValue[byte](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	x := &trustListHandle{session: c.SessionID, mode: mode}
	switch mode {
	case fileModeRead:
		b, sc := m.readContent(g, ua.TrustListMasksAll)
		if sc != ua.StatusOK {
			return nil, sc
		}
		x.buf = b
	case fileModeWrite | fileModeEraseExisting:
	default:
		return nil, ua.StatusBadInvalidArgument
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addHandleLocked(g, x)
}

// fileOpenWithMasks is OpenWithMasks (Part 12 §7.8.2.2): reads only the
// lists of the masks.
func (m *pushManager) fileOpenWithMasks(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	masks, ok := argValue[uint32](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	b, sc := m.readContent(g, ua.TrustListMasks(masks))
	if sc != ua.StatusOK {
		return nil, sc
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addHandleLocked(g, &trustListHandle{session: c.SessionID, mode: fileModeRead, buf: b})
}

// handleLocked returns the handle of argument 0, which must be one of the
// calling session.
func (m *pushManager) handleLocked(c *MethodCaller, g *certGroup, args []*ua.Variant) (uint32, *trustListHandle, ua.StatusCode) {
	h, ok := argValue[uint32](args, 0)
	if !ok {
		return 0, nil, ua.StatusBadTypeMismatch
	}
	x := g.handles[h]
	if x == nil || !x.session.Equal(c.SessionID) {
		return 0, nil, ua.StatusBadInvalidArgument
	}
	return h, x, ua.StatusOK
}

func (m *pushManager) closeLocked(g *certGroup, h uint32) {
	delete(g.handles, h)
	g.openCount.Add(-1)
	go m.changed()
}

func (m *pushManager) fileClose(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, _, sc := m.handleLocked(c, g, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	m.closeLocked(g, h)
	return nil, ua.StatusOK
}

func (m *pushManager) fileRead(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, x, sc := m.handleLocked(c, g, args)
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

func (m *pushManager) fileWrite(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, x, sc := m.handleLocked(c, g, args)
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
	if x.pos+len(b) > int(m.cfg.MaxTrustListSize) {
		return nil, ua.StatusBadEncodingLimitsExceeded
	}
	if end := x.pos + len(b); end > len(x.buf) {
		x.buf = append(x.buf, make([]byte, end-len(x.buf))...)
	}
	x.pos += copy(x.buf[x.pos:], b)
	return nil, ua.StatusOK
}

func (m *pushManager) fileGetPosition(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, x, sc := m.handleLocked(c, g, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(uint64(x.pos))}, ua.StatusOK
}

func (m *pushManager) fileSetPosition(_ context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, x, sc := m.handleLocked(c, g, args)
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

// fileCloseAndUpdate is CloseAndUpdate (Part 12 §7.8.2.3): closes a handle
// opened for writing and replaces the lists the written TrustListDataType
// specifies. The output tells whether ApplyChanges is required.
func (m *pushManager) fileCloseAndUpdate(ctx context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, x, sc := m.handleLocked(c, g, args)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if x.mode&fileModeWrite == 0 {
		return nil, ua.StatusBadInvalidState
	}
	// The handle is closed whatever the outcome: the client cannot fix
	// what it wrote.
	m.closeLocked(g, h)
	upd, sc := decodeTrustList(x.buf)
	if sc != ua.StatusOK {
		return nil, sc
	}
	tl, sc := newTrustList(mergeTrustList(m.baseTrustLocked(g, c.SessionID).data, upd), m.cfg.MaxTrustListSize)
	if sc != ua.StatusOK {
		return nil, sc
	}
	required, sc := m.changeTrustLocked(ctx, c.SessionID, g, tl)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(required)}, ua.StatusOK
}

// openLocked reports whether the trust list has open handles, during which
// AddCertificate and RemoveCertificate are refused.
func (m *pushManager) openLocked(g *certGroup) bool {
	m.pruneLocked(g)
	return len(g.handles) > 0
}

// addCertificate is AddCertificate (Part 12 §7.8.2.4): adds one certificate
// to the trusted or to the issuer certificates.
func (m *pushManager) addCertificate(ctx context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	der, ok1 := argValue[[]byte](args, 0)
	trusted, ok2 := argValue[bool](args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil || !bytes.Equal(cert.Raw, der) {
		return nil, ua.StatusBadCertificateInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.openLocked(g) {
		return nil, ua.StatusBadInvalidState
	}
	d := cloneTrustListData(m.baseTrustLocked(g, c.SessionID).data)
	if trusted {
		d.TrustedCertificates = append(d.TrustedCertificates, slices.Clone(der))
	} else {
		d.IssuerCertificates = append(d.IssuerCertificates, slices.Clone(der))
	}
	tl, sc := newTrustList(d, m.cfg.MaxTrustListSize)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if _, sc := m.changeTrustLocked(ctx, c.SessionID, g, tl); sc != ua.StatusOK {
		return nil, sc
	}
	return nil, ua.StatusOK
}

// removeCertificate is RemoveCertificate (Part 12 §7.8.2.5): removes the
// certificate with the thumbprint (hexadecimal SHA-1) from the trusted or
// the issuer certificates, with the CRLs it issued.
func (m *pushManager) removeCertificate(ctx context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	thumb, ok1 := argValue[string](args, 0)
	trusted, ok2 := argValue[bool](args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.openLocked(g) {
		return nil, ua.StatusBadInvalidState
	}
	base := m.baseTrustLocked(g, c.SessionID)
	d := cloneTrustListData(base.data)
	certs, crls, parsed := &d.TrustedCertificates, &d.TrustedCrls, base.trusted
	if !trusted {
		certs, crls, parsed = &d.IssuerCertificates, &d.IssuerCrls, base.issuers
	}
	i := slices.IndexFunc(*certs, func(der []byte) bool {
		return strings.EqualFold(hex.EncodeToString(uapolicy.Thumbprint(der)), strings.TrimSpace(thumb))
	})
	if i < 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	subject := parsed[i].RawSubject
	*certs = slices.Delete(*certs, i, i+1)
	*crls = slices.DeleteFunc(*crls, func(der []byte) bool {
		return bytes.Equal(crlIssuer(der), subject)
	})
	tl, sc := newTrustList(d, m.cfg.MaxTrustListSize)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if _, sc := m.changeTrustLocked(ctx, c.SessionID, g, tl); sc != ua.StatusOK {
		return nil, sc
	}
	return nil, ua.StatusOK
}
