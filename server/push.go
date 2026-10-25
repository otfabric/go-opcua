// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	stderrors "errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// PushManagement configures certificate management by the push model of
// OPC UA Part 12 §7: a client with the SecurityAdmin role manages the trust
// lists and the certificates of the server through the ServerConfiguration
// object (Part 12 §7.10.3).
//
// The server has the three certificate groups of Part 12 §7.8.3:
//
//   - DefaultApplicationGroup: the application instance certificates and
//     the trust list the application certificates of the clients are
//     validated against, which replaces WithClientCertificateTrustList.
//   - DefaultHttpsGroup: the TLS certificate of the opc.https and opc.wss
//     endpoints and the trust list for the TLS client certificates of
//     HTTPSClientCertificates.
//   - DefaultUserTokenGroup: the trust list X.509 user identity tokens are
//     validated against, before a WithX509UserValidator is asked.
type PushManagement struct {
	// TrustList is the trust list of the DefaultApplicationGroup the server
	// starts with (nil: an empty one, which rejects every client
	// certificate). It should hold the certificate, or the CA, of the
	// client that manages the server. SpecifiedLists is ignored: all four
	// lists are taken.
	TrustList *ua.TrustListDataType

	// HTTPSTrustList and UserTokenTrustList are the trust lists of the
	// DefaultHttpsGroup and the DefaultUserTokenGroup the server starts
	// with (nil: empty ones).
	HTTPSTrustList     *ua.TrustListDataType
	UserTokenTrustList *ua.TrustListDataType

	// HTTPSClientCertificates selects what the opc.https and opc.wss
	// endpoints do with TLS client certificates. The default leaves the
	// TLS configuration alone.
	HTTPSClientCertificates HTTPSClientAuth

	// MaxTrustListSize is the most bytes an encoded trust list may have,
	// published as MaxTrustListSize. Zero selects 1 MiB.
	MaxTrustListSize uint32

	// MaxRejectedCertificates bounds the list GetRejectedList returns: the
	// most recently rejected certificates. Zero selects 64.
	MaxRejectedCertificates int

	// ApplyImmediately makes every change take effect when its method
	// returns, without ApplyChanges: CloseAndUpdate and UpdateCertificate
	// then return applyChangesRequired false. By default changes are
	// collected in a transaction of the calling session and take effect
	// with ApplyChanges (Part 12 §7.10.2).
	ApplyImmediately bool

	// Authorizer decides who may call the certificate management methods
	// (nil: sessions with the SecurityAdmin role, Part 12 §7.2). Whatever it
	// decides, the methods are refused on channels that are not
	// SignAndEncrypt.
	Authorizer PushAuthorizer

	// Store, if set, persists what ApplyChanges and ResetToServerDefaults
	// apply. The server does not write files on its own. A Store that also
	// implements CertificateGroupStore persists the changes of every
	// certificate group; otherwise only those of the
	// DefaultApplicationGroup are persisted.
	Store CertificateStore

	// PFXPassword returns the password of a PKCS #12 (PFX) private key that
	// UpdateCertificate receives for the certificate group and type (Part
	// 12 §7.10.4 carries no password: it is a secret of the server). Nil
	// or an empty password reads PFX files without a password.
	PFXPassword func(ctx context.Context, certificateGroup, certificateType *ua.NodeID) (string, error)

	// TrustListUpdateFrequency is the UpdateFrequency of the trust lists
	// (Part 12 §7.8.2.1): how often they are expected to be updated. Zero
	// leaves it unset and the TrustListOutOfDate alarms inactive.
	TrustListUpdateFrequency time.Duration

	// Alarms, if set, adds the CertificateExpired and TrustListOutOfDate
	// alarms of the certificate groups (Part 12 §7.8.3).
	Alarms *CertificateAlarms
}

// HTTPSClientAuth selects how the opc.https and opc.wss endpoints of a
// server with push management treat TLS client certificates.
type HTTPSClientAuth int

const (
	// HTTPSClientCertificatesIgnore leaves the TLS configuration (and its
	// ClientAuth) as it is: the trust list of the DefaultHttpsGroup is not
	// used.
	HTTPSClientCertificatesIgnore HTTPSClientAuth = iota
	// HTTPSClientCertificatesVerifyIfGiven requests a TLS client
	// certificate and, if the client presents one, validates it against
	// the trust list of the DefaultHttpsGroup.
	HTTPSClientCertificatesVerifyIfGiven
	// HTTPSClientCertificatesRequire requires a TLS client certificate
	// that the trust list of the DefaultHttpsGroup validates.
	HTTPSClientCertificatesRequire
)

// CertificateAlarms configures the alarms of the certificate groups (Part
// 12 §7.8.3): CertificateExpired (CertificateExpirationAlarmType, Part 12
// §7.8.5) of the DefaultApplicationGroup and the DefaultHttpsGroup, active
// from ExpirationLimit before the certificate of the group that expires
// first until it is replaced, and TrustListOutOfDate
// (TrustListOutOfDateAlarmType, Part 12 §7.8.6) of every group, active
// when the trust list has not been updated for TrustListUpdateFrequency.
//
// The alarms are Alarms & Conditions conditions (Server.AddCondition) with
// the source node of their certificate group, in the namespace
// CertificateAlarmsNamespaceURI. They report their events to the group
// and the Server object.
type CertificateAlarms struct {
	// ExpirationLimit is how long before the expiry the CertificateExpired
	// alarm becomes active (zero: two weeks, the default of Part 12).
	ExpirationLimit time.Duration
	// CheckInterval is how often the server evaluates the alarms (zero:
	// one minute). They are also evaluated whenever a certificate or a
	// trust list changes.
	CheckInterval time.Duration
}

// CertificateAlarmsNamespaceURI is the namespace of the nodes of the
// certificate alarms.
const CertificateAlarmsNamespaceURI = "urn:otfabric:go-opcua:certificates"

// PushAuthorizer decides whether the caller may call a certificate
// management method: the method name ("UpdateCertificate", "ApplyChanges",
// "OpenWithMasks", "AddCertificate", ...). It returns ua.StatusOK to allow
// the call, otherwise the status the call fails with (typically
// ua.StatusBadUserAccessDenied).
type PushAuthorizer func(ctx context.Context, caller *MethodCaller, method string) ua.StatusCode

// CertificateStore persists the changes push certificate management makes,
// so that a restarted server can be configured with them. ApplyChanges
// calls it before the changes take effect; an error fails ApplyChanges with
// Bad_InternalError and keeps the changes pending.
type CertificateStore interface {
	// StoreTrustList persists the trust list of the DefaultApplicationGroup.
	StoreTrustList(ctx context.Context, tl *ua.TrustListDataType) error
	// StoreCertificate persists a new application instance certificate of
	// the certificate type (for example
	// RsaSha256ApplicationCertificateType), its issuer chain and its key.
	StoreCertificate(ctx context.Context, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error
}

// CertificateGroupStore is a CertificateStore that persists the trust lists
// and certificates of every certificate group. The server calls these
// methods instead of those of CertificateStore.
type CertificateGroupStore interface {
	CertificateStore
	// StoreGroupTrustList persists the trust list of a certificate group.
	StoreGroupTrustList(ctx context.Context, certificateGroup *ua.NodeID, tl *ua.TrustListDataType) error
	// StoreGroupCertificate persists a certificate of a certificate group
	// (for the DefaultHttpsGroup: HttpsCertificateType).
	StoreGroupCertificate(ctx context.Context, certificateGroup, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error
}

// WithPushManagement enables certificate management by the push model of
// Part 12 §7. See [PushManagement].
func WithPushManagement(pm PushManagement) Option {
	return func(s *serverConfig) error {
		if pm.MaxTrustListSize == 0 {
			pm.MaxTrustListSize = defaultMaxTrustListSize
		}
		if pm.MaxRejectedCertificates <= 0 {
			pm.MaxRejectedCertificates = 64
		}
		for _, tl := range []*ua.TrustListDataType{pm.TrustList, pm.HTTPSTrustList, pm.UserTokenTrustList} {
			if _, sc := newTrustList(tl, pm.MaxTrustListSize); sc != ua.StatusOK {
				return fmt.Errorf("server: WithPushManagement: invalid trust list: %w", sc)
			}
		}
		if pm.HTTPSClientCertificates < HTTPSClientCertificatesIgnore || pm.HTTPSClientCertificates > HTTPSClientCertificatesRequire {
			return fmt.Errorf("server: WithPushManagement: invalid HTTPSClientCertificates %d", pm.HTTPSClientCertificates)
		}
		if pm.TrustListUpdateFrequency < 0 {
			return fmt.Errorf("server: WithPushManagement: negative TrustListUpdateFrequency")
		}
		if a := pm.Alarms; a != nil {
			if a.ExpirationLimit < 0 || a.CheckInterval < 0 {
				return fmt.Errorf("server: WithPushManagement: negative alarm durations")
			}
			cp := *a
			if cp.ExpirationLimit == 0 {
				cp.ExpirationLimit = 14 * 24 * time.Hour
			}
			if cp.CheckInterval == 0 {
				cp.CheckInterval = time.Minute
			}
			pm.Alarms = &cp
		}
		s.push = &pm
		return nil
	}
}

// groupKind is one of the certificate groups of the server.
type groupKind int

const (
	groupApplication groupKind = iota
	groupHTTPS
	groupUserToken
	numGroups
)

// certGroup is a certificate group (Part 12 §7.8.3) with its trust list.
type certGroup struct {
	kind groupKind
	def  *groupDef

	trust      atomic.Pointer[trustList]
	lastUpdate atomic.Int64 // UnixNano of the last change of the trust list
	openCount  atomic.Int32

	// handles are the open handles of the TrustList file; pushManager.mu.
	handles map[uint32]*trustListHandle

	// nodes are the properties that change.
	nodes []*ua.NodeID
}

func (g *certGroup) nodeID() *ua.NodeID      { return ua.NewNumericNodeID(0, g.def.node) }
func (g *certGroup) trustListID() *ua.NodeID { return ua.NewNumericNodeID(0, g.def.trustList) }

// tlsIdentity is the certificate of the DefaultHttpsGroup: the TLS
// certificate of the opc.https and opc.wss endpoints.
type tlsIdentity struct {
	cert    []byte
	issuers [][]byte
	key     crypto.Signer
	tls     *tlsCertificate
}

// identitySnapshot is what ResetToServerDefaults restores.
type identitySnapshot struct {
	certificate []byte
	privateKey  *rsa.PrivateKey
	identities  []applicationIdentity
	https       *tlsIdentity
}

// certs returns the application instance certificates of the snapshot as
// identityCerts does.
func (snap identitySnapshot) certs() []applicationIdentity {
	var out []applicationIdentity
	if len(snap.certificate) > 0 && snap.privateKey != nil {
		out = append(out, applicationIdentity{certificate: snap.certificate, key: snap.privateKey})
	}
	for _, id := range snap.identities {
		if !slices.ContainsFunc(out, func(x applicationIdentity) bool { return string(x.certificate) == string(id.certificate) }) {
			out = append(out, id)
		}
	}
	return out
}

// pushManager is the state of push certificate management.
type pushManager struct {
	s   *Server
	cfg PushManagement

	groups [numGroups]*certGroup

	// https is the certificate of the DefaultHttpsGroup (nil: none).
	https atomic.Pointer[tlsIdentity]

	// initial is the configuration the server started with.
	initial identitySnapshot

	mu   sync.Mutex
	next uint32 // the last trust list file handle
	tx   *pushTx
	// csrKeys are the keys CreateSigningRequest generated, by group and
	// certificate type, for the certificate UpdateCertificate brings.
	csrKeys map[certKey]crypto.Signer

	diagMu sync.Mutex
	diag   txDiagnostics

	rejMu    sync.Mutex
	rejected [][]byte

	// nodes are the properties of ServerConfiguration that change.
	nodes []*ua.NodeID

	alarms *certAlarms
	// now is the clock of the alarms and the transaction diagnostics.
	now func() time.Time
}

// certKey names a certificate of a group.
type certKey struct {
	group    groupKind
	certType uint32
}

// pushTx is a transaction (Part 12 §7.10.2): the changes of one session
// that ApplyChanges applies together.
type pushTx struct {
	session *ua.NodeID
	trust   map[groupKind]*trustList // the trust lists that change
	certs   map[certKey]*pendingCert
}

// pendingCert is a certificate UpdateCertificate or
// CreateSelfSignedCertificate brought.
type pendingCert struct {
	key      certKey
	old      []byte // the certificate it replaces
	cert     []byte
	issuers  [][]byte
	priv     crypto.Signer
	isTLSKey bool
}

func newPushManager(cfg *PushManagement, sc *serverConfig) *pushManager {
	m := &pushManager{
		cfg:     *cfg,
		csrKeys: map[certKey]crypto.Signer{},
		now:     time.Now,
	}
	m.diag.result = ua.StatusOK
	initial := [numGroups]*ua.TrustListDataType{cfg.TrustList, cfg.HTTPSTrustList, cfg.UserTokenTrustList}
	for k := range numGroups {
		g := &certGroup{kind: k, def: &groupDefs[k], handles: map[uint32]*trustListHandle{}}
		tl, _ := newTrustList(initial[k], cfg.MaxTrustListSize) // checked by the option
		g.trust.Store(tl)
		g.lastUpdate.Store(time.Now().UnixNano())
		m.groups[k] = g
	}
	m.initial = identitySnapshot{
		certificate: sc.certificate,
		privateKey:  sc.privateKey,
		identities:  slices.Clone(sc.identities),
		https:       initialTLSIdentity(sc),
	}
	m.https.Store(m.initial.https)
	return m
}

// group returns the group of a CertificateGroupId: a null NodeId is the
// DefaultApplicationGroup (Part 12 §7.10.4).
func (m *pushManager) group(n *ua.NodeID) (*certGroup, bool) {
	if isNullNodeID(n) {
		return m.groups[groupApplication], true
	}
	if n.Namespace() != 0 || !isNumericNodeID(n) {
		return nil, false
	}
	for _, g := range m.groups {
		if g.def.node == n.IntID() {
			return g, true
		}
	}
	return nil, false
}

// verifyStatus is the status of a certificate the trust list rejects.
func verifyStatus(err error) ua.StatusCode {
	switch {
	case stderrors.Is(err, errRevoked):
		return ua.StatusBadCertificateRevoked
	case stderrors.Is(err, errIssuerRevoked):
		return ua.StatusBadCertificateIssuerRevoked
	}
	return ua.StatusBadCertificateUntrusted
}

// validateWith validates a certificate (chain) against the trust list of a
// group; a rejected certificate goes to the rejected list.
func (m *pushManager) validateWith(k groupKind, der []byte) ua.StatusCode {
	certs, err := uapolicy.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		m.reject(der)
		return ua.StatusBadCertificateInvalid
	}
	if err := m.groups[k].trust.Load().verify(certs); err != nil {
		m.reject(certs[0].Raw)
		return verifyStatus(err)
	}
	return ua.StatusOK
}

// validateClient is the ClientCertificateValidator of a server with push
// management: the client certificate (chain) against the trust list of the
// DefaultApplicationGroup.
func (m *pushManager) validateClient(der []byte) error {
	if len(der) == 0 {
		return nil // no certificate presented; non-certificate channel
	}
	if sc := m.validateWith(groupApplication, der); sc != ua.StatusOK {
		return sc
	}
	return nil
}

// userValidator returns the X509UserValidator of a server with push
// management: the certificate of an X.509 user identity token must be
// trusted by the DefaultUserTokenGroup, and then by next if set.
func (m *pushManager) userValidator(next X509UserValidator) X509UserValidator {
	return func(der []byte) error {
		if sc := m.validateWith(groupUserToken, der); sc != ua.StatusOK {
			return fmt.Errorf("server: user certificate rejected by the DefaultUserTokenGroup: %w", sc)
		}
		if next != nil {
			return next(der)
		}
		return nil
	}
}

// reject adds a certificate to the rejected list, the latest last.
func (m *pushManager) reject(der []byte) {
	m.rejMu.Lock()
	defer m.rejMu.Unlock()
	m.rejected = slices.DeleteFunc(m.rejected, func(x []byte) bool { return string(x) == string(der) })
	m.rejected = append(m.rejected, slices.Clone(der))
	if over := len(m.rejected) - m.cfg.MaxRejectedCertificates; over > 0 {
		m.rejected = slices.Delete(m.rejected, 0, over)
	}
}

func (m *pushManager) rejectedList() [][]byte {
	m.rejMu.Lock()
	defer m.rejMu.Unlock()
	return slices.Clone(m.rejected)
}

// authorize checks the caller of a certificate management method: a
// session on a SignAndEncrypt channel (Bad_SecurityModeInsufficient
// otherwise) with the SecurityAdmin role or what the Authorizer allows
// (Bad_UserAccessDenied otherwise).
func (m *pushManager) authorize(ctx context.Context, method string) (*MethodCaller, ua.StatusCode) {
	c, ok := MethodCallerFromContext(ctx)
	if !ok || c.SessionID == nil {
		return nil, ua.StatusBadUserAccessDenied
	}
	if c.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		return nil, ua.StatusBadSecurityModeInsufficient
	}
	if a := m.cfg.Authorizer; a != nil {
		if sc := a(ctx, c, method); sc != ua.StatusOK {
			return nil, sc
		}
		return c, ua.StatusOK
	}
	admin := ua.RoleSecurityAdmin.NodeID()
	if !slices.ContainsFunc(c.Roles, func(r *ua.NodeID) bool { return r.Equal(admin) }) {
		return nil, ua.StatusBadUserAccessDenied
	}
	return c, ua.StatusOK
}

// method wraps a certificate management method with authorize.
func (m *pushManager) method(name string, f func(ctx context.Context, caller *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		c, sc := m.authorize(ctx, name)
		if sc != ua.StatusOK {
			return nil, sc
		}
		return f(ctx, c, args)
	}
}

// txLocked returns the transaction of the session, which it starts if
// needed. A transaction of another session that is still open makes it
// fail with Bad_TransactionPending; one of a closed session is dropped.
func (m *pushManager) txLocked(session *ua.NodeID) (*pushTx, ua.StatusCode) {
	if m.tx != nil && !m.tx.session.Equal(session) {
		if m.s != nil && m.s.sb.hasID(m.tx.session) {
			return nil, ua.StatusBadTransactionPending
		}
		m.tx = nil
		m.endDiagnostics(ua.StatusBadSessionClosed)
	}
	if m.tx == nil {
		m.tx = &pushTx{session: session, trust: map[groupKind]*trustList{}, certs: map[certKey]*pendingCert{}}
		m.startDiagnostics()
	}
	return m.tx, ua.StatusOK
}

// otherTxLocked reports whether a session other than session, which is
// still open, has a transaction.
func (m *pushManager) otherTxLocked(session *ua.NodeID) bool {
	return m.tx != nil && !m.tx.session.Equal(session) && m.s != nil && m.s.sb.hasID(m.tx.session)
}

// baseTrustLocked is the trust list of the group a change of the session
// starts from: that of its transaction or the active one.
func (m *pushManager) baseTrustLocked(g *certGroup, session *ua.NodeID) *trustList {
	if m.tx != nil && m.tx.session.Equal(session) {
		if tl := m.tx.trust[g.kind]; tl != nil {
			return tl
		}
	}
	return g.trust.Load()
}

// changeTrustLocked records a new trust list of the group for the session:
// in its transaction, or at once with ApplyImmediately. It reports whether
// ApplyChanges is required.
func (m *pushManager) changeTrustLocked(ctx context.Context, session *ua.NodeID, g *certGroup, tl *trustList) (bool, ua.StatusCode) {
	tx, sc := m.txLocked(session)
	if sc != ua.StatusOK {
		return false, sc
	}
	tx.trust[g.kind] = tl
	m.affected(g.trustListID(), nil)
	if m.cfg.ApplyImmediately {
		return false, m.applyLocked(ctx)
	}
	return true, ua.StatusOK
}

// addCertLocked records a new certificate for the session: in its
// transaction, or at once with ApplyImmediately. It reports whether
// ApplyChanges is required.
func (m *pushManager) addCertLocked(ctx context.Context, session *ua.NodeID, g *certGroup, p *pendingCert) (bool, ua.StatusCode) {
	tx, sc := m.txLocked(session)
	if sc != ua.StatusOK {
		return false, sc
	}
	tx.certs[p.key] = p
	m.affected(nil, g.nodeID())
	if m.cfg.ApplyImmediately {
		return false, m.applyLocked(ctx)
	}
	return true, ua.StatusOK
}

// storeLocked persists the trust lists and certificates.
func (m *pushManager) storeLocked(ctx context.Context, trust map[groupKind]*trustList, certs []*pendingCert) ua.StatusCode {
	st := m.cfg.Store
	if st == nil {
		return ua.StatusOK
	}
	gs, all := st.(CertificateGroupStore)
	fail := func(target *ua.NodeID, what string, err error) ua.StatusCode {
		m.logger().Warn("push management: storing "+what+" failed", "error", err)
		m.recordError(target, ua.StatusBadInternalError, "storing "+what+" failed")
		return ua.StatusBadInternalError
	}
	for k := range numGroups {
		tl := trust[k]
		if tl == nil {
			continue
		}
		g := m.groups[k]
		var err error
		switch {
		case all:
			err = gs.StoreGroupTrustList(ctx, g.nodeID(), cloneTrustListData(tl.data))
		case k == groupApplication:
			err = st.StoreTrustList(ctx, cloneTrustListData(tl.data))
		}
		if err != nil {
			return fail(g.trustListID(), "the trust list", err)
		}
	}
	for _, p := range certs {
		g := m.groups[p.key.group]
		typ := ua.NewNumericNodeID(0, p.key.certType)
		var err error
		switch {
		case all:
			err = gs.StoreGroupCertificate(ctx, g.nodeID(), typ, slices.Clone(p.cert), slices.Clone(p.issuers), p.priv)
		case p.key.group == groupApplication:
			err = st.StoreCertificate(ctx, typ, slices.Clone(p.cert), slices.Clone(p.issuers), p.priv)
		}
		if err != nil {
			return fail(g.nodeID(), "the certificate", err)
		}
	}
	return ua.StatusOK
}

// applyLocked applies the transaction (ApplyChanges, Part 12 §7.10.6): the
// trust lists for the validation of new channels, sessions and TLS
// connections, and the certificates for new channels and TLS connections.
// Channels that are open keep their certificate until they are closed.
func (m *pushManager) applyLocked(ctx context.Context) ua.StatusCode {
	tx := m.tx
	if tx == nil {
		return ua.StatusOK
	}
	certs := sortedCerts(tx.certs)
	if sc := m.storeLocked(ctx, tx.trust, certs); sc != ua.StatusOK {
		m.setDiagnosticsResult(sc)
		return sc
	}
	m.tx = nil
	now := time.Now().UnixNano()
	for k, tl := range tx.trust {
		m.groups[k].trust.Store(tl)
		m.groups[k].lastUpdate.Store(now)
	}
	appCerts := false
	for _, p := range certs {
		switch p.key.group {
		case groupApplication:
			m.s.cfg.replaceIdentity(p.old, p.cert, p.priv)
			appCerts = true
		case groupHTTPS:
			m.https.Store(newTLSIdentity(p.cert, p.issuers, p.priv))
		case groupUserToken, numGroups:
		}
		delete(m.csrKeys, p.key)
	}
	if appCerts {
		m.s.initEndpoints()
	}
	m.endDiagnostics(ua.StatusOK)
	m.evaluateAlarms()
	go m.changed()
	return ua.StatusOK
}

func sortedCerts(certs map[certKey]*pendingCert) []*pendingCert {
	out := make([]*pendingCert, 0, len(certs))
	for _, p := range certs {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *pendingCert) int {
		if a.key.group != b.key.group {
			return int(a.key.group) - int(b.key.group)
		}
		return int(a.key.certType) - int(b.key.certType)
	})
	return out
}

func (m *pushManager) logger() *slog.Logger { return m.s.cfg.logger }

// changed notifies the monitored items of the properties that changed.
func (m *pushManager) changed() {
	for _, n := range m.nodes {
		m.s.ChangeNotification(n)
	}
	for _, g := range m.groups {
		for _, n := range g.nodes {
			m.s.ChangeNotification(n)
		}
	}
}

// replaceIdentity replaces the application instance certificate old, with
// its key, by cert and key, wherever the server has it.
func (s *serverConfig) replaceIdentity(old, cert []byte, key crypto.Signer) {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	if string(s.certificate) == string(old) {
		s.certificate = cert
		if rk, ok := key.(*rsa.PrivateKey); ok && s.privateKey != nil {
			s.privateKey = rk
		}
	}
	for i := range s.identities {
		if string(s.identities[i].certificate) == string(old) {
			s.identities[i] = applicationIdentity{certificate: cert, key: key}
		}
	}
}

// restoreIdentities puts back the application instance certificates of a
// snapshot.
func (s *serverConfig) restoreIdentities(snap identitySnapshot) {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	s.certificate = snap.certificate
	s.privateKey = snap.privateKey
	s.identities = slices.Clone(snap.identities)
}

// identityCerts returns the application instance certificates of the
// server with their keys: the Certificate / PrivateKey pair first.
func (s *serverConfig) identityCerts() []applicationIdentity {
	s.idMu.RLock()
	defer s.idMu.RUnlock()
	var out []applicationIdentity
	if len(s.certificate) > 0 && s.privateKey != nil {
		out = append(out, applicationIdentity{certificate: s.certificate, key: s.privateKey})
	}
	for _, id := range s.identities {
		if !slices.ContainsFunc(out, func(x applicationIdentity) bool { return string(x.certificate) == string(id.certificate) }) {
			out = append(out, id)
		}
	}
	return out
}

// TrustList returns the trust list the server validates client
// certificates against (that of the DefaultApplicationGroup), nil without
// push management.
func (s *Server) TrustList() *ua.TrustListDataType {
	if s.push == nil {
		return nil
	}
	return cloneTrustListData(s.push.groups[groupApplication].trust.Load().data)
}

// GroupTrustList returns the trust list of a certificate group
// (DefaultApplicationGroup, DefaultHttpsGroup or DefaultUserTokenGroup of
// ServerConfiguration), nil without push management or for another node.
func (s *Server) GroupTrustList(certificateGroup *ua.NodeID) *ua.TrustListDataType {
	if s.push == nil || isNullNodeID(certificateGroup) {
		return nil
	}
	g, ok := s.push.group(certificateGroup)
	if !ok {
		return nil
	}
	return cloneTrustListData(g.trust.Load().data)
}

// HTTPSCertificate returns the certificate of the DefaultHttpsGroup, the
// TLS certificate of the opc.https and opc.wss endpoints of a server with
// push management (nil without one).
func (s *Server) HTTPSCertificate() []byte {
	if s.push == nil {
		return nil
	}
	if x := s.push.https.Load(); x != nil {
		return slices.Clone(x.cert)
	}
	return nil
}

// RejectedCertificates returns the certificates the server rejected most
// recently (what GetRejectedList returns), nil without push management.
func (s *Server) RejectedCertificates() [][]byte {
	if s.push == nil {
		return nil
	}
	return s.push.rejectedList()
}

// groupDef holds the NodeIds of a certificate group of ServerConfiguration.
type groupDef struct {
	name                                                                 string
	node, trustList, certTypes                                           uint32
	size, writable, userWritable, openCount, lastUpdate, updateFrequency uint32
	open, close, read, write, getPosition, setPosition, openWithMasks    uint32
	closeAndUpdate, addCertificate, removeCertificate                    uint32
}

var groupDefs = [numGroups]groupDef{
	groupApplication: {
		name:              "DefaultApplicationGroup",
		node:              id.ServerConfigurationCertificateGroupsDefaultApplicationGroup,
		trustList:         id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		certTypes:         id.ServerConfigurationCertificateGroupsDefaultApplicationGroupCertificateTypes,
		size:              id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize,
		writable:          id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWritable,
		userWritable:      id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListUserWritable,
		openCount:         id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenCount,
		lastUpdate:        id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListLastUpdateTime,
		updateFrequency:   id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListUpdateFrequency,
		open:              id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen,
		close:             id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose,
		read:              id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead,
		write:             id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite,
		getPosition:       id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListGetPosition,
		setPosition:       id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSetPosition,
		openWithMasks:     id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks,
		closeAndUpdate:    id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate,
		addCertificate:    id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListAddCertificate,
		removeCertificate: id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRemoveCertificate,
	},
	groupHTTPS: {
		name:              "DefaultHttpsGroup",
		node:              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup,
		trustList:         id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustList,
		certTypes:         id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupCertificateTypes,
		size:              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListSize,
		writable:          id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListWritable,
		userWritable:      id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListUserWritable,
		openCount:         id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpenCount,
		lastUpdate:        id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListLastUpdateTime,
		updateFrequency:   id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListUpdateFrequency,
		open:              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpen,
		close:             id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListClose,
		read:              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListRead,
		write:             id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListWrite,
		getPosition:       id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListGetPosition,
		setPosition:       id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListSetPosition,
		openWithMasks:     id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpenWithMasks,
		closeAndUpdate:    id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListCloseAndUpdate,
		addCertificate:    id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListAddCertificate,
		removeCertificate: id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListRemoveCertificate,
	},
	groupUserToken: {
		name:              "DefaultUserTokenGroup",
		node:              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup,
		trustList:         id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustList,
		certTypes:         id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupCertificateTypes,
		size:              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListSize,
		writable:          id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListWritable,
		userWritable:      id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListUserWritable,
		openCount:         id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListOpenCount,
		lastUpdate:        id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListLastUpdateTime,
		updateFrequency:   id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListUpdateFrequency,
		open:              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListOpen,
		close:             id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListClose,
		read:              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListRead,
		write:             id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListWrite,
		getPosition:       id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListGetPosition,
		setPosition:       id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListSetPosition,
		openWithMasks:     id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListOpenWithMasks,
		closeAndUpdate:    id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListCloseAndUpdate,
		addCertificate:    id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListAddCertificate,
		removeCertificate: id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListRemoveCertificate,
	},
}
