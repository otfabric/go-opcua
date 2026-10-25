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

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// PushManagement configures certificate management by the push model of
// OPC UA Part 12 §7: a client with the SecurityAdmin role manages the trust
// list and the application instance certificates of the server through the
// ServerConfiguration object (Part 12 §7.10.3).
//
// The server then validates the application certificates of its clients
// against the trust list of the DefaultApplicationGroup, which replaces
// WithClientCertificateTrustList.
type PushManagement struct {
	// TrustList is the trust list the server starts with (nil: an empty
	// one, which rejects every client certificate). It should hold the
	// certificate, or the CA, of the client that manages the server.
	// SpecifiedLists is ignored: all four lists are taken.
	TrustList *ua.TrustListDataType

	// MaxTrustListSize is the most bytes the encoded trust list may have,
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

	// Store, if set, persists what ApplyChanges applies. The server does not
	// write files on its own.
	Store CertificateStore
}

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
		if _, sc := newTrustList(pm.TrustList, pm.MaxTrustListSize); sc != ua.StatusOK {
			return fmt.Errorf("server: WithPushManagement: invalid trust list: %w", sc)
		}
		s.push = &pm
		return nil
	}
}

// pushManager is the state of push certificate management.
type pushManager struct {
	s   *Server
	cfg PushManagement

	trust      atomic.Pointer[trustList]
	lastUpdate atomic.Int64 // UnixNano of the last change of the trust list

	mu      sync.Mutex
	handles map[uint32]*trustListHandle
	next    uint32
	tx      *pushTx
	// csrKeys are the keys CreateSigningRequest generated, by certificate
	// type, for the certificate UpdateCertificate brings.
	csrKeys map[uint32]crypto.Signer

	rejMu    sync.Mutex
	rejected [][]byte

	openCount atomic.Int32
	nodes     []*ua.NodeID // properties that change
}

// pushTx is a transaction (Part 12 §7.10.2): the changes of one session
// that ApplyChanges applies together.
type pushTx struct {
	session *ua.NodeID
	trust   *trustList              // nil: the trust list is not changed
	certs   map[uint32]*pendingCert // by certificate type
}

// pendingCert is an application instance certificate UpdateCertificate
// brought.
type pendingCert struct {
	certType uint32
	old      []byte // the certificate it replaces
	cert     []byte
	issuers  [][]byte
	key      crypto.Signer
}

func newPushManager(cfg *PushManagement) *pushManager {
	m := &pushManager{
		cfg:     *cfg,
		handles: map[uint32]*trustListHandle{},
		csrKeys: map[uint32]crypto.Signer{},
	}
	tl, _ := newTrustList(cfg.TrustList, cfg.MaxTrustListSize) // checked by the option
	m.trust.Store(tl)
	m.lastUpdate.Store(time.Now().UnixNano())
	return m
}

// validateClient is the ClientCertificateValidator of a server with push
// management: the client certificate (chain) against the trust list.
func (m *pushManager) validateClient(der []byte) error {
	if len(der) == 0 {
		return nil // no certificate presented; non-certificate channel
	}
	tl := m.trust.Load()
	certs, err := uapolicy.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		m.reject(der)
		return ua.StatusBadCertificateInvalid
	}
	if err := tl.verify(certs); err != nil {
		m.reject(certs[0].Raw)
		switch {
		case stderrors.Is(err, errRevoked):
			return ua.StatusBadCertificateRevoked
		case stderrors.Is(err, errIssuerRevoked):
			return ua.StatusBadCertificateIssuerRevoked
		}
		return ua.StatusBadCertificateUntrusted
	}
	return nil
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
	}
	if m.tx == nil {
		m.tx = &pushTx{session: session, certs: map[uint32]*pendingCert{}}
	}
	return m.tx, ua.StatusOK
}

// baseTrustLocked is the trust list a change of the session starts from:
// that of its transaction or the active one.
func (m *pushManager) baseTrustLocked(session *ua.NodeID) *trustList {
	if m.tx != nil && m.tx.trust != nil && m.tx.session.Equal(session) {
		return m.tx.trust
	}
	return m.trust.Load()
}

// changeTrustLocked records a new trust list for the session: in its
// transaction, or at once with ApplyImmediately. It reports whether
// ApplyChanges is required.
func (m *pushManager) changeTrustLocked(ctx context.Context, session *ua.NodeID, tl *trustList) (bool, ua.StatusCode) {
	tx, sc := m.txLocked(session)
	if sc != ua.StatusOK {
		return false, sc
	}
	tx.trust = tl
	if m.cfg.ApplyImmediately {
		return false, m.applyLocked(ctx)
	}
	return true, ua.StatusOK
}

// applyLocked applies the transaction (ApplyChanges, Part 12 §7.10.6): the
// trust list for the validation of new channels and sessions, and the
// certificates for new channels. Channels that are open keep their
// certificate until they are closed.
func (m *pushManager) applyLocked(ctx context.Context) ua.StatusCode {
	tx := m.tx
	if tx == nil {
		return ua.StatusOK
	}
	if st := m.cfg.Store; st != nil {
		if tx.trust != nil {
			if err := st.StoreTrustList(ctx, cloneTrustListData(tx.trust.data)); err != nil {
				m.logger().Warn("push management: storing the trust list failed", "error", err)
				return ua.StatusBadInternalError
			}
		}
		for _, p := range sortedCerts(tx.certs) {
			if err := st.StoreCertificate(ctx, ua.NewNumericNodeID(0, p.certType), slices.Clone(p.cert), slices.Clone(p.issuers), p.key); err != nil {
				m.logger().Warn("push management: storing the certificate failed", "error", err)
				return ua.StatusBadInternalError
			}
		}
	}
	m.tx = nil
	if tx.trust != nil {
		m.trust.Store(tx.trust)
		m.lastUpdate.Store(time.Now().UnixNano())
	}
	if len(tx.certs) > 0 {
		for _, p := range sortedCerts(tx.certs) {
			m.s.cfg.replaceIdentity(p.old, p.cert, p.key)
			delete(m.csrKeys, p.certType)
		}
		m.s.initEndpoints()
	}
	go m.changed()
	return ua.StatusOK
}

func sortedCerts(certs map[uint32]*pendingCert) []*pendingCert {
	out := make([]*pendingCert, 0, len(certs))
	for _, p := range certs {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *pendingCert) int { return int(a.certType) - int(b.certType) })
	return out
}

func (m *pushManager) logger() *slog.Logger { return m.s.cfg.logger }

// changed notifies the monitored items of the properties that changed.
func (m *pushManager) changed() {
	for _, n := range m.nodes {
		m.s.ChangeNotification(n)
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
// certificates against, nil without push management.
func (s *Server) TrustList() *ua.TrustListDataType {
	if s.push == nil {
		return nil
	}
	return cloneTrustListData(s.push.trust.Load().data)
}

// RejectedCertificates returns the client certificates the server rejected
// most recently (what GetRejectedList returns), nil without push
// management.
func (s *Server) RejectedCertificates() [][]byte {
	if s.push == nil {
		return nil
	}
	return s.push.rejectedList()
}
