// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	stderrors "errors"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// Certificate groups of the application (PushManagement.CertificateGroups):
// CertificateGroupType objects in the CertificateGroups folder of
// ServerConfiguration (CertificateGroupFolderType, Part 12 §7.8.3.3, which
// organizes additional groups), with String NodeIds in the namespace
// CertificateAlarmsNamespaceURI.

// customGroupTypes are the certificate types a group of the application
// may have: the concrete types of Part 12 §7.8.4.
var customGroupTypes = []uint32{
	id.RsaMinApplicationCertificateType,
	id.RsaSha256ApplicationCertificateType,
	id.EccNistP256ApplicationCertificateType,
	id.EccNistP384ApplicationCertificateType,
	id.EccBrainpoolP256r1ApplicationCertificateType,
	id.EccBrainpoolP384r1ApplicationCertificateType,
	id.EccCurve25519ApplicationCertificateType,
	id.EccCurve448ApplicationCertificateType,
	id.HTTPSCertificateType,
	id.UserCertificateType,
	id.TLSServerCertificateType,
	id.TLSClientCertificateType,
}

// isAppType reports whether t is a concrete application instance
// certificate type.
func isAppType(t uint32) bool {
	_, ecc := keyBits[t]
	return isRSAType(t) || ecc
}

// isTLSType reports whether t is a certificate type of TLS connections.
func isTLSType(t uint32) bool {
	return t == id.HTTPSCertificateType || t == id.TLSServerCertificateType || t == id.TLSClientCertificateType
}

// groupTypeMatches reports whether a certificate of the concrete type have
// serves the requested type want (0: any) of a group of the application:
// the type, a supertype of it, or for the application certificate types
// what typeMatches accepts.
func groupTypeMatches(want, have uint32) bool {
	if isAppType(have) {
		return typeMatches(want, have)
	}
	switch want {
	case 0, have, id.CertificateType:
		return true
	case id.TLSCertificateType:
		return have == id.TLSServerCertificateType || have == id.TLSClientCertificateType
	}
	return false
}

// certFitsType reports whether a certificate fits a certificate type: the
// key of an application instance certificate type, a key crypto/tls can
// serve for the TLS types; a UserCertificateType may have any key.
func certFitsType(certType uint32, cert *x509.Certificate, der []byte) bool {
	switch {
	case isAppType(certType):
		t, ok := certTypeOf(der)
		return ok && typeMatches(certType, t)
	case isTLSType(certType):
		return tlsKeySupported(cert.PublicKey)
	}
	return true
}

// groupCert is a certificate of a group of the application.
type groupCert struct {
	cert    []byte
	issuers [][]byte
	key     crypto.Signer
}

// customGroup holds the certificates of a group of the application.
type customGroup struct {
	types   []uint32
	initial map[uint32]groupCert
	// certs is replaced, never changed, under pushManager.mu.
	certs atomic.Pointer[map[uint32]groupCert]
}

func newCustomGroup(cg CertificateGroup) *certGroup {
	c := &customGroup{initial: map[uint32]groupCert{}}
	for _, t := range cg.CertificateTypes {
		c.types = append(c.types, t.IntID())
	}
	for _, x := range cg.Certificates {
		c.initial[x.CertificateType.IntID()] = groupCert{cert: x.Certificate, issuers: x.Issuers, key: x.PrivateKey}
	}
	certs := maps.Clone(c.initial)
	c.certs.Store(&certs)
	return &certGroup{name: cg.Name, initialTrust: cg.TrustList, custom: c}
}

// get returns the certificate of a type.
func (c *customGroup) get(t uint32) (groupCert, bool) {
	x, ok := (*c.certs.Load())[t]
	return x, ok
}

// set applies a change of a certificate.
func (c *customGroup) set(p *pendingCert) {
	certs := maps.Clone(*c.certs.Load())
	if p.deletes() {
		delete(certs, p.key.certType)
	} else {
		certs[p.key.certType] = groupCert{cert: p.cert, issuers: p.issuers, key: p.priv}
	}
	c.certs.Store(&certs)
}

// restore puts back the certificates the group started with.
func (c *customGroup) restore() {
	certs := maps.Clone(c.initial)
	c.certs.Store(&certs)
}

// checkCertificateGroups checks the groups of the application and returns
// copies of them.
func checkCertificateGroups(groups []CertificateGroup, maxTrustListSize uint32) ([]CertificateGroup, error) {
	var out []CertificateGroup
	names := map[string]bool{}
	for _, d := range groupDefs {
		names[d.name] = true
	}
	for _, g := range groups {
		if g.Name == "" || names[g.Name] {
			return nil, fmt.Errorf("certificate group %q: the name is empty or not unique", g.Name)
		}
		names[g.Name] = true
		if _, sc := newTrustList(g.TrustList, maxTrustListSize); sc != ua.StatusOK {
			return nil, fmt.Errorf("certificate group %q: invalid trust list: %w", g.Name, sc)
		}
		cp := CertificateGroup{Name: g.Name}
		if g.TrustList != nil {
			cp.TrustList = cloneTrustListData(g.TrustList)
		}
		for _, t := range g.CertificateTypes {
			if t == nil || t.Namespace() != 0 || !isNumericNodeID(t) || !slices.Contains(customGroupTypes, t.IntID()) ||
				slices.ContainsFunc(cp.CertificateTypes, t.Equal) {
				return nil, fmt.Errorf("certificate group %q: certificate type %v is not supported or repeated", g.Name, t)
			}
			cp.CertificateTypes = append(cp.CertificateTypes, ua.NewNumericNodeID(0, t.IntID()))
		}
		for _, x := range g.Certificates {
			if err := checkGroupCertificate(cp.CertificateTypes, x); err != nil {
				return nil, fmt.Errorf("certificate group %q: %w", g.Name, err)
			}
			if slices.ContainsFunc(cp.Certificates, func(y GroupCertificate) bool { return y.CertificateType.Equal(x.CertificateType) }) {
				return nil, fmt.Errorf("certificate group %q: two certificates of type %v", g.Name, x.CertificateType)
			}
			cp.Certificates = append(cp.Certificates, GroupCertificate{
				CertificateType: ua.NewNumericNodeID(0, x.CertificateType.IntID()),
				Certificate:     slices.Clone(x.Certificate),
				Issuers:         cloneByteStrings(x.Issuers),
				PrivateKey:      x.PrivateKey,
			})
		}
		out = append(out, cp)
	}
	return out, nil
}

var errGroupCertificate = stderrors.New("invalid certificate")

// checkGroupCertificate checks a certificate a group of the application
// starts with.
func checkGroupCertificate(types []*ua.NodeID, x GroupCertificate) error {
	if x.CertificateType == nil || !slices.ContainsFunc(types, x.CertificateType.Equal) {
		return fmt.Errorf("%w: type %v is not one of the group", errGroupCertificate, x.CertificateType)
	}
	t := x.CertificateType.IntID()
	cert, err := uapolicy.ParseCertificate(x.Certificate)
	if err != nil || !bytes.Equal(cert.Raw, x.Certificate) {
		return fmt.Errorf("%w of type %v: %v", errGroupCertificate, x.CertificateType, err)
	}
	if !certFitsType(t, cert, x.Certificate) {
		return fmt.Errorf("%w: the key does not fit type %v", errGroupCertificate, x.CertificateType)
	}
	if x.PrivateKey == nil || !uapolicy.KeyMatchesCertificate(x.PrivateKey, x.Certificate) {
		return fmt.Errorf("%w: the private key does not belong to the certificate of type %v", errGroupCertificate, x.CertificateType)
	}
	if _, ok := x.PrivateKey.(*rsa.PrivateKey); isRSAType(t) && !ok {
		return fmt.Errorf("%w: type %v needs an *rsa.PrivateKey", errGroupCertificate, x.CertificateType)
	}
	for _, b := range x.Issuers {
		if _, err := uapolicy.ParseCertificate(b); err != nil {
			return fmt.Errorf("%w: issuer of type %v: %v", errGroupCertificate, x.CertificateType, err)
		}
	}
	return nil
}

func cloneByteStrings(xs [][]byte) [][]byte {
	var out [][]byte
	for _, x := range xs {
		out = append(out, slices.Clone(x))
	}
	return out
}

// certNamespace returns the namespace of the nodes of the certificate
// groups of the application and the certificate alarms.
func (m *pushManager) certNamespace() *NodeNameSpace {
	for _, x := range m.s.Namespaces() {
		if nns, ok := x.(*NodeNameSpace); ok && x.Name() == CertificateAlarmsNamespaceURI {
			return nns
		}
	}
	return NewNodeNameSpace(m.s, CertificateAlarmsNamespaceURI)
}

// The TrustList methods of CertificateGroupType, which the TrustList
// objects of the groups of the application reference, as the instances of
// the PubSub model do.
var trustListDecls = []struct {
	name   string
	method uint32
}{
	{"Open", id.CertificateGroupTypeTrustListOpen},
	{"Close", id.CertificateGroupTypeTrustListClose},
	{"Read", id.CertificateGroupTypeTrustListRead},
	{"Write", id.CertificateGroupTypeTrustListWrite},
	{"GetPosition", id.CertificateGroupTypeTrustListGetPosition},
	{"SetPosition", id.CertificateGroupTypeTrustListSetPosition},
	{"OpenWithMasks", id.CertificateGroupTypeTrustListOpenWithMasks},
	{"CloseAndUpdate", id.CertificateGroupTypeTrustListCloseAndUpdate},
	{"AddCertificate", id.CertificateGroupTypeTrustListAddCertificate},
	{"RemoveCertificate", id.CertificateGroupTypeTrustListRemoveCertificate},
}

// buildCustomGroups adds the nodes of the groups of the application to the
// CertificateGroups folder.
func (m *pushManager) buildCustomGroups() {
	s := m.s
	if len(m.groups) == int(numDefaultGroups) {
		return
	}
	folder := s.ownNode(id.ServerConfigurationCertificateGroups)
	if folder == nil {
		return
	}
	ns := m.certNamespace()
	idx := ns.ID()
	for _, g := range m.groups[numDefaultGroups:] {
		base := "CertificateGroups." + g.name
		g.node = ua.NewStringNodeID(idx, base)
		g.trustList = ua.NewStringNodeID(idx, base+".TrustList")
		gn := pushObject(s, ns, g.node, &ua.QualifiedName{NamespaceIndex: idx, Name: g.name}, id.CertificateGroupType)
		linkChild(folder, gn, id.Organizes)
		tn := pushObject(s, ns, g.trustList, &ua.QualifiedName{Name: "TrustList"}, id.TrustListType)
		linkChild(gn, tn, id.HasComponent)

		prop := func(parent *Node, name string, dataType uint32, valueRank int32, v ValueFunc, dynamic bool) {
			n := pushProperty(s, ns, ua.NewStringNodeID(idx, parent.ID().StringID()+"."+name), name, dataType, valueRank, v)
			linkChild(parent, n, id.HasProperty)
			if dynamic {
				g.nodes = append(g.nodes, n.ID())
			}
		}
		prop(gn, "CertificateTypes", id.NodeID, 1, func() *ua.DataValue { return DataValueFromValue(m.groupTypes(g)) }, false)
		prop(tn, "Size", id.UInt64, -1, func() *ua.DataValue { return DataValueFromValue(uint64(g.trust.Load().size)) }, true)
		prop(tn, "Writable", id.Boolean, -1, static(true), false)
		prop(tn, "UserWritable", id.Boolean, -1, static(true), false)
		prop(tn, "OpenCount", id.UInt16, -1, func() *ua.DataValue { return DataValueFromValue(uint16(g.openCount.Load())) }, true)
		prop(tn, "LastUpdateTime", id.UtcTime, -1, func() *ua.DataValue {
			return DataValueFromValue(time.Unix(0, g.lastUpdate.Load()).UTC())
		}, true)
		prop(tn, "MaxByteStringLength", id.UInt32, -1, static(uint32(maxTrustListRead)), false)
		if f := m.cfg.TrustListUpdateFrequency; f > 0 {
			prop(tn, "UpdateFrequency", id.Duration, -1, static(float64(f)/float64(time.Millisecond)), false)
		}
		for _, d := range trustListDecls {
			s.addMethodRef(tn, d.method)
		}
	}
}

// pushObject adds an object node of a type.
func pushObject(s *Server, ns *NodeNameSpace, nid *ua.NodeID, name *ua.QualifiedName, typeDef uint32) *Node {
	n := NewNode(nid, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(name),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name.Name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	ns.AddNode(n)
	if t := s.Node(ua.NewNumericNodeID(0, typeDef)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	return n
}

// pushProperty adds a read-only Property node.
func pushProperty(s *Server, ns *NodeNameSpace, nid *ua.NodeID, name string, dataType uint32, valueRank int32, v ValueFunc) *Node {
	n := NewNode(nid, Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, dataType)),
		ua.AttributeIDValueRank:       DataValueFromValue(valueRank),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, v)
	ns.AddNode(n)
	if t := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	return n
}

// CertificateGroupID returns the NodeId of the certificate group with the
// BrowseName name: one of the default groups or of
// PushManagement.CertificateGroups. It returns nil without push management
// or for another name.
func (s *Server) CertificateGroupID(name string) *ua.NodeID {
	if s.push == nil {
		return nil
	}
	for _, g := range s.push.groups {
		if g.name == name {
			return g.nodeID()
		}
	}
	return nil
}

// GroupCertificate returns the certificate of a certificate group of the
// type (null or nil: the first the group has), its issuers and private
// key, nil if the group has none. Changes take effect when the push
// management applies them.
func (s *Server) GroupCertificate(certificateGroup, certificateType *ua.NodeID) ([]byte, [][]byte, crypto.Signer) {
	if s.push == nil {
		return nil, nil, nil
	}
	g, ok := s.push.group(certificateGroup)
	if !ok {
		return nil, nil, nil
	}
	var want uint32
	if !isNullNodeID(certificateType) {
		if certificateType.Namespace() != 0 || !isNumericNodeID(certificateType) {
			return nil, nil, nil
		}
		want = certificateType.IntID()
	}
	x, _, ok := s.push.slot(g, want)
	if !ok || x.cert == nil {
		return nil, nil, nil
	}
	return slices.Clone(x.cert), cloneByteStrings(x.issuers), x.key
}

// VerifyGroupCertificate validates a certificate, or a certificate chain
// (concatenated DER, the certificate first), against the trust list of a
// certificate group. A rejected certificate goes to the list
// GetRejectedList returns. It is how the application uses the trust list
// of a group of PushManagement.CertificateGroups.
func (s *Server) VerifyGroupCertificate(certificateGroup *ua.NodeID, chain []byte) error {
	if s.push == nil {
		return ua.StatusBadNotSupported
	}
	g, ok := s.push.group(certificateGroup)
	if !ok {
		return ua.StatusBadInvalidArgument
	}
	if sc := s.push.validateWith(g.kind, chain); sc != ua.StatusOK {
		return sc
	}
	return nil
}
