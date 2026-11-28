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

// initFiles gives every group the TrustList file of Part 12 §7.8.2.1: Open
// takes Read and Write with EraseExisting only, a reader sees the trust
// list at the time of the Open, and what a client writes stays with its
// handle until CloseAndUpdate.
func (m *pushManager) initFiles() {
	for _, g := range m.groups {
		g.file, _ = m.s.NewFile(FileConfig{ // the configuration is valid
			Backend: &SnapshotFile{
				Content: func(context.Context) ([]byte, error) {
					return encodeTrustList(maskTrustList(g.trust.Load().data, ua.TrustListMasksAll))
				},
				MaxSize:      int(m.cfg.MaxTrustListSize),
				SizeExceeded: ua.StatusBadEncodingLimitsExceeded,
			},
			Writable:            true,
			Modes:               trustListModes,
			MaxByteStringLength: maxTrustListRead,
			MaxHandles:          maxTrustListHandles,
			OnChange:            m.changed,
		})
	}
}

// trustListModes are the modes Open of a TrustList takes: "Only Read and
// Write with EraseExisting is allowed" (Part 12 §7.8.2.1).
var trustListModes = []ua.OpenFileMode{fileModeRead, fileModeWrite | fileModeEraseExisting}

// readContent returns the lists of the active trust list masks selects.
func (m *pushManager) readContent(g *certGroup, masks ua.TrustListMasks) ([]byte, ua.StatusCode) {
	b, err := encodeTrustList(maskTrustList(g.trust.Load().data, masks))
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	return b, ua.StatusOK
}

// fileOpen is Open (Part 12 §7.8.2.1). It holds m.mu, so that no handle is
// opened while AddCertificate or RemoveCertificate checks that none is.
func (m *pushManager) fileOpen(ctx context.Context, _ *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return g.file.Method("Open")(ctx, nil, nil, args)
}

// fileOpenWithMasks is OpenWithMasks (Part 12 §7.8.2.2): reads only the
// lists of the masks.
func (m *pushManager) fileOpenWithMasks(ctx context.Context, _ *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
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
	h, sc := g.file.OpenBytes(ctx, b)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(h)}, ua.StatusOK
}

// fileMethod returns a Method of FileType of the TrustList of a group.
func (m *pushManager) fileMethod(name string) func(context.Context, *MethodCaller, *certGroup, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(ctx context.Context, _ *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return g.file.Method(name)(ctx, nil, nil, args)
	}
}

// fileCloseAndUpdate is CloseAndUpdate (Part 12 §7.8.2.3): closes a handle
// opened for writing and replaces the lists the written TrustListDataType
// specifies. The output tells whether ApplyChanges is required.
func (m *pushManager) fileCloseAndUpdate(ctx context.Context, c *MethodCaller, g *certGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	h, ok := argValue[uint32](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// The handle is closed whatever the outcome: the client cannot fix
	// what it wrote.
	b, sc := g.file.CloseAndTake(ctx, h, nil)
	if sc != ua.StatusOK {
		return nil, sc
	}
	upd, sc := decodeTrustList(b)
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
	return g.file.OpenCount() > 0
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
