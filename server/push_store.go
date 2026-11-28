// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// CertificateBatchStore is a CertificateStore that persists all the changes
// of one ApplyChanges, or of one ResetToServerDefaults, in one atomic write.
// The server calls StoreChanges instead of the other methods of the store
// and of CertificateGroupStore and CertificateDeleteStore. Package
// server/pushstore implements it on a directory.
type CertificateBatchStore interface {
	CertificateStore
	// StoreChanges persists c, all or nothing. It returns nil when c is
	// durable. On an error the server does not apply c: ApplyChanges
	// fails with Bad_InternalError and its transaction is discarded (Part
	// 12 §7.10.2). After an error the store must hold the state it held
	// before, or refuse later writes until it does, so that a restarted
	// server never starts with changes it did not apply.
	StoreChanges(ctx context.Context, c CertificateChanges) error
}

// CertificateLoadStore is a CertificateStore that restores what it
// persisted. New calls LoadCertificates once and applies what it returns
// on top of the configuration: the trust lists replace those of
// PushManagement, the certificates those of the options of the server (or
// are added), and a deleted certificate is removed. What the server was
// configured with stays the target of ResetToServerDefaults. An error of
// LoadCertificates, or a trust list or certificate that is not valid, fails
// New: a server does not start with a trust list other than the one it
// was told to have.
type CertificateLoadStore interface {
	CertificateStore
	LoadCertificates(ctx context.Context) (CertificateChanges, error)
}

// CertificateChanges are the trust lists and certificates of certificate
// groups that one ApplyChanges or ResetToServerDefaults applies, or that a
// CertificateLoadStore restores.
type CertificateChanges struct {
	// Reset marks the changes of ResetToServerDefaults (Part 12 §7.10.13):
	// they are the trust lists and certificates of the configuration of
	// the server. A store may then forget what it holds instead of storing
	// them, so that a restarted server starts with its configuration again.
	Reset bool
	// TrustLists are the trust lists that change, at most one per group.
	TrustLists []CertificateGroupTrustList
	// Certificates are the certificates that change, at most one per group
	// and certificate type.
	Certificates []CertificateGroupChange
}

// CertificateGroupTrustList is the trust list of a certificate group.
type CertificateGroupTrustList struct {
	// Group is the BrowseName of the certificate group:
	// "DefaultApplicationGroup", "DefaultHttpsGroup",
	// "DefaultUserTokenGroup" or the Name of a CertificateGroup of
	// PushManagement.CertificateGroups. Unlike its NodeId it does not
	// depend on the namespace table.
	Group string
	// TrustList is the whole trust list (SpecifiedLists is All).
	TrustList *ua.TrustListDataType
	// LastUpdateTime is when it took effect, its LastUpdateTime (Part 12
	// §7.8.2.1). On a restore the zero time keeps the start of the server.
	LastUpdateTime time.Time
}

// CertificateGroupChange is a certificate of a certificate group that is
// added, replaced or deleted.
type CertificateGroupChange struct {
	// Group is the BrowseName of the certificate group, as in
	// CertificateGroupTrustList.
	Group string
	// CertificateType is the type of the certificate (Part 12 §7.8.4), a
	// numeric NodeId of namespace 0.
	CertificateType *ua.NodeID
	// Certificate is the DER encoded certificate; nil deletes the
	// certificate of the type (DeleteCertificate).
	Certificate []byte
	// Issuers are the DER encoded certificates of its issuer chain.
	Issuers [][]byte
	// PrivateKey is the key of the certificate.
	PrivateKey crypto.Signer
}

// Deleted reports whether the change deletes the certificate.
func (c CertificateGroupChange) Deleted() bool { return c.Certificate == nil }

// changesOf returns the changes of trust lists and certificates for a
// CertificateBatchStore, in the order of the groups.
func (m *pushManager) changesOf(trust map[groupKind]*trustList, certs []*pendingCert, reset bool, now time.Time) CertificateChanges {
	c := CertificateChanges{Reset: reset}
	for _, g := range m.groups {
		if tl := trust[g.kind]; tl != nil {
			c.TrustLists = append(c.TrustLists, CertificateGroupTrustList{Group: g.name, TrustList: cloneTrustListData(tl.data), LastUpdateTime: now})
		}
	}
	for _, p := range certs {
		c.Certificates = append(c.Certificates, CertificateGroupChange{
			Group:           m.groups[p.key.group].name,
			CertificateType: ua.NewNumericNodeID(0, p.key.certType),
			Certificate:     slices.Clone(p.cert),
			Issuers:         slices.Clone(p.issuers),
			PrivateKey:      p.priv,
		})
	}
	return c
}

// storeBatchLocked persists the changes with a CertificateBatchStore. A
// failure is recorded against every trust list and group of the changes:
// none of them is stored.
func (m *pushManager) storeBatchLocked(ctx context.Context, bs CertificateBatchStore, trust map[groupKind]*trustList, certs []*pendingCert, reset bool, now time.Time) ua.StatusCode {
	err := bs.StoreChanges(ctx, m.changesOf(trust, certs, reset, now))
	if err == nil {
		return ua.StatusOK
	}
	m.logger().Warn("push management: storing the changes failed", "error", err)
	for _, g := range m.groups {
		if trust[g.kind] != nil {
			m.recordError(g.trustListID(), ua.StatusBadInternalError, "storing the trust list failed")
		}
	}
	for _, p := range certs {
		m.recordError(m.groups[p.key.group].nodeID(), ua.StatusBadInternalError, "storing the certificate failed")
	}
	return ua.StatusBadInternalError
}

// restore applies what a CertificateLoadStore kept (see
// CertificateLoadStore). It runs in New, before the server serves.
func (m *pushManager) restore(ctx context.Context) error {
	ls, ok := m.cfg.Store.(CertificateLoadStore)
	if !ok {
		return nil
	}
	c, err := ls.LoadCertificates(ctx)
	if err != nil {
		return fmt.Errorf("server: push management: load the certificate store: %w", err)
	}
	byName := make(map[string]*certGroup, len(m.groups))
	for _, g := range m.groups {
		byName[g.name] = g
	}
	for _, x := range c.TrustLists {
		g := byName[x.Group]
		if g == nil {
			m.logger().Warn("push management: the certificate store has a trust list of an unknown certificate group; it is ignored", "group", x.Group)
			continue
		}
		tl, sc := newTrustList(x.TrustList, m.cfg.MaxTrustListSize)
		if sc != ua.StatusOK {
			return fmt.Errorf("server: push management: the stored trust list of %s: %w", g.name, sc)
		}
		g.trust.Store(tl)
		if !x.LastUpdateTime.IsZero() {
			g.lastUpdate.Store(x.LastUpdateTime.UnixNano())
		}
	}
	for _, x := range c.Certificates {
		g := byName[x.Group]
		if g == nil {
			m.logger().Warn("push management: the certificate store has a certificate of an unknown certificate group; it is ignored", "group", x.Group)
			continue
		}
		p, ok, err := m.restoredCert(g, x)
		if err != nil {
			return fmt.Errorf("server: push management: the stored certificate of %s: %w", g.name, err)
		}
		if !ok {
			m.logger().Warn("push management: the certificate store has a certificate of a type the group does not have; it is ignored",
				"group", g.name, "type", x.CertificateType.String())
			continue
		}
		m.applyCert(p)
	}
	return nil
}

// restoredCert checks a stored certificate of a group and returns the
// change that puts it in place. It reports false for a type the group does
// not have.
func (m *pushManager) restoredCert(g *certGroup, x CertificateGroupChange) (*pendingCert, bool, error) {
	if x.CertificateType == nil || x.CertificateType.Namespace() != 0 || !isNumericNodeID(x.CertificateType) {
		return nil, false, nil
	}
	t := x.CertificateType.IntID()
	var old []byte
	switch {
	case g.kind == groupApplication:
		if !isAppType(t) {
			return nil, false, nil
		}
		for _, c := range m.s.cfg.identityCerts() {
			if ct, ok := certTypeOf(c.certificate); ok && ct == t {
				old = c.certificate
				break
			}
		}
		if !slices.Contains(m.appTypes, t) {
			m.appTypes = append(m.appTypes, t)
		}
	case g.kind == groupHTTPS:
		if t != id.HTTPSCertificateType {
			return nil, false, nil
		}
		if cur := m.https.Load(); cur != nil {
			old = cur.cert
		}
	case g.custom != nil && slices.Contains(g.custom.types, t):
		if cur, ok := g.custom.get(t); ok {
			old = cur.cert
		}
	default:
		return nil, false, nil
	}
	p := &pendingCert{key: certKey{g.kind, t}, old: old}
	if x.Deleted() {
		return p, true, nil
	}
	cert, err := uapolicy.ParseCertificate(x.Certificate)
	if err != nil || !certFitsType(t, cert, x.Certificate) {
		return nil, false, fmt.Errorf("not a certificate of type %d", t)
	}
	if x.PrivateKey == nil || !uapolicy.KeyMatchesCertificate(x.PrivateKey, x.Certificate) {
		return nil, false, fmt.Errorf("the private key does not match the certificate of type %d", t)
	}
	if _, isRSA := x.PrivateKey.(*rsa.PrivateKey); isRSAType(t) && !isRSA {
		return nil, false, fmt.Errorf("the private key of the certificate of type %d is not an RSA key", t)
	}
	p.cert, p.issuers, p.priv = slices.Clone(x.Certificate), slices.Clone(x.Issuers), x.PrivateKey
	return p, true, nil
}
