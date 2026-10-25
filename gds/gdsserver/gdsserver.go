// SPDX-License-Identifier: MIT

package gdsserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Defaults of Config.
const (
	DefaultCALifetime          = 10 * 365 * 24 * time.Hour
	DefaultCertificateLifetime = 365 * 24 * time.Hour
	DefaultCRLLifetime         = 30 * 24 * time.Hour
	DefaultRequestLifetime     = 24 * time.Hour
	DefaultMaxRequests         = 8
	DefaultMaxApplications     = 10_000
	defaultCARSABits           = 3072
	defaultRSABits             = 2048
)

// DefaultCertificateTypes are the certificate types of the
// DefaultApplicationGroup of a GDS whose Config sets none: every
// application certificate type of Part 12 §7.8.4 this module has security
// policies for, RSA first.
var DefaultCertificateTypes = []*ua.NodeID{
	ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccNistP384ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccBrainpoolP256r1ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccBrainpoolP384r1ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccCurve25519ApplicationCertificateType),
	ua.NewNumericNodeID(0, id.EccCurve448ApplicationCertificateType),
}

// Config configures a GDS.
type Config struct {
	// Store persists the state (nil: a new MemoryStore).
	Store Store

	// CertificateTypes are the certificate types the
	// DefaultApplicationGroup issues (nil: DefaultCertificateTypes). The
	// first one is used when a request names none.
	CertificateTypes []*ua.NodeID

	// Issuers are certificate authorities to use instead of generating
	// them: Issuer.Name selects the key type ("RSA", "NistP256",
	// "NistP384", "Curve25519", "Curve448"), Certificate and PrivateKey
	// are required, the rest is ignored. An issuer given here replaces the
	// one of the Store, whose revocations it keeps only if it is the same
	// certificate. A CA the GDS needs and neither Issuers nor the Store
	// have is generated and stored.
	Issuers []*Issuer

	// CAName is the common name of the CAs the GDS generates, followed by
	// the key type (default "go-opcua GDS CA").
	CAName string

	// CALifetime, CertificateLifetime and CRLLifetime are the validity of
	// a generated CA, of an issued certificate (at most until the CA
	// expires) and the time from one CRL to its NextUpdate.
	CALifetime          time.Duration
	CertificateLifetime time.Duration
	CRLLifetime         time.Duration

	// RSAKeySize is the size of the RSA keys of StartNewKeyPairRequest
	// (default 2048). A generated RSA CA has 3072 bits.
	RSAKeySize int

	// AutoApprove approves every certificate request when it is made. By
	// default a request waits until GDS.ApproveRequest approves or rejects
	// it, and FinishRequest returns Bad_NothingToDo until then.
	AutoApprove bool

	// RequestLifetime is how long a request that FinishRequest did not
	// complete is kept (default 24 h).
	RequestLifetime time.Duration

	// MaxRequests bounds the open requests of one application (default
	// 8), MaxApplications the registered applications (default 10000).
	MaxRequests     int
	MaxApplications int

	// SelfAdmin decides whether the application whose record is given may
	// manage itself (the ApplicationSelfAdmin privilege of Part 12 §6.2)
	// when it connects with cert, a certificate whose application URI is
	// that of the record but that the GDS did not issue — typically the
	// self-signed certificate of an application that asks for its first
	// certificate. nil allows only the certificates the GDS issued to the
	// application and did not revoke.
	SelfAdmin func(app *gds.ApplicationRecord, cert *x509.Certificate) bool

	// Now returns the current time (nil: time.Now).
	Now func() time.Time

	// Logger receives the log of the GDS (nil: slog.Default()).
	Logger *slog.Logger
}

// GDS is a Global Discovery Server (OPC UA Part 12 §6 and §7.9, the pull
// model): the Directory object, an instance of the CertificateDirectoryType,
// on a server.Server.
type GDS struct {
	srv   *server.Server
	cfg   Config
	ns    uint16
	store Store
	now   func() time.Time
	log   *slog.Logger
	types []uint32 // the certificate types of the DefaultApplicationGroup
	// groups are the certificate groups of the Directory: the
	// DefaultApplicationGroup, the DefaultHttpsGroup and the
	// DefaultUserTokenGroup.
	groups []*group

	mu      sync.Mutex
	apps    map[string]*Application
	byURI   map[string]string // ApplicationURI → ID
	reqs    map[string]*Request
	issuing map[string]bool // requests FinishRequest is issuing
	cas     map[string]*ca
	meta    *Meta
	closed  bool           // Close was called
	calls   sync.WaitGroup // the method calls in progress
}

// group is a certificate group of the Directory (Part 12 §7.8.3).
type group struct {
	key       string // GroupApplication, GroupHTTPS or GroupUserToken
	node      uint32
	trustNode uint32
	typesNode uint32
	types     []uint32 // the certificate types it issues
	// issuers are the names of the CAs whose certificates and CRLs are in
	// its trust list.
	issuers []string
	trust   *server.TrustListObject
}

// errAttach wraps the errors of Attach.
var errAttach = errors.New("gdsserver")

// Attach makes srv a GDS: it imports the GDS information model (namespace
// gdsid.NamespaceURI, which it adds to srv) with the Directory object,
// loads the state from cfg.Store and serves the methods of the Directory
// and the TrustLists of its certificate groups. Call it once, before
// srv.Start.
//
// The GDS namespace gets the next free namespace index: 1 when Attach is
// the first to add a namespace to srv. The roles of Part 12 §6.2 are in
// that namespace; give them to sessions with server.WithRoleMapper, see
// GDS.DiscoveryAdminRole and GDS.CertificateAuthorityAdminRole.
//
// The methods need a session over a secured channel; srv should offer
// SignAndEncrypt endpoints and validate client certificates.
func Attach(srv *server.Server, cfg Config) (*GDS, error) {
	for _, ns := range srv.Namespaces() {
		if ns.Name() == gdsid.NamespaceURI {
			return nil, fmt.Errorf("%w: the server has the namespace %s already", errAttach, gdsid.NamespaceURI)
		}
	}
	g := &GDS{
		srv:     srv,
		cfg:     cfg,
		store:   cfg.Store,
		now:     cfg.Now,
		log:     cfg.Logger,
		apps:    map[string]*Application{},
		byURI:   map[string]string{},
		reqs:    map[string]*Request{},
		issuing: map[string]bool{},
		cas:     map[string]*ca{},
	}
	if g.store == nil {
		g.store = NewMemoryStore()
	}
	if g.now == nil {
		g.now = time.Now
	}
	if g.log == nil {
		g.log = slog.Default()
	}
	g.setDefaults()
	types := cfg.CertificateTypes
	if len(types) == 0 {
		types = DefaultCertificateTypes
	}
	for _, t := range types {
		if t == nil || t.Namespace() != 0 || certTypes[t.IntID()] == nil || certTypes[t.IntID()].issuer == "" {
			return nil, fmt.Errorf("%w: certificate type %v is not supported", errAttach, t)
		}
		if !slices.Contains(g.types, t.IntID()) {
			g.types = append(g.types, t.IntID())
		}
	}

	ctx := context.Background()
	if err := g.load(ctx); err != nil {
		return nil, err
	}
	g.makeGroups()

	g.ns = server.NewNodeNameSpace(srv, gdsid.NamespaceURI).ID()
	if err := srv.ImportNodeSetXML(nodeSet(g.ns)); err != nil {
		return nil, fmt.Errorf("%w: import the GDS information model: %w", errAttach, err)
	}
	if err := g.buildModel(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *GDS) setDefaults() {
	c := &g.cfg
	if c.CAName == "" {
		c.CAName = "go-opcua GDS CA"
	}
	if c.CALifetime <= 0 {
		c.CALifetime = DefaultCALifetime
	}
	if c.CertificateLifetime <= 0 {
		c.CertificateLifetime = DefaultCertificateLifetime
	}
	if c.CRLLifetime <= 0 {
		c.CRLLifetime = DefaultCRLLifetime
	}
	if c.RSAKeySize < 2048 {
		c.RSAKeySize = defaultRSABits
	}
	if c.RequestLifetime <= 0 {
		c.RequestLifetime = DefaultRequestLifetime
	}
	if c.MaxRequests <= 0 {
		c.MaxRequests = DefaultMaxRequests
	}
	if c.MaxApplications <= 0 {
		c.MaxApplications = DefaultMaxApplications
	}
}

// nodeSets caches nodeSet by namespace index.
var nodeSets sync.Map // uint16 → []byte

// nodeSet returns the GDS NodeSet with namespace index 1 of the file
// replaced by ns, the index the namespace has on the server, and without
// its NamespaceUris, whose namespace Attach adds itself. A browse name
// without a namespace prefix (namespace 0 in a NodeSet, "Open") gets the
// prefix 0: the importer would put it in the namespace of the node.
func nodeSet(ns uint16) []byte {
	if b, ok := nodeSets.Load(ns); ok {
		return b.([]byte)
	}
	src := schema.OpcUaGdsNodeSet2
	if i, j := bytes.Index(src, []byte("<NamespaceUris>")), bytes.Index(src, []byte("</NamespaceUris>")); i >= 0 && j > i {
		src = append(slices.Clip(src[:i]), src[j+len("</NamespaceUris>"):]...)
	}
	n := strconv.Itoa(int(ns))
	b := bytes.ReplaceAll(src, []byte(`"ns=1;`), []byte(`"ns=`+n+`;`))
	b = bytes.ReplaceAll(b, []byte(`>ns=1;`), []byte(`>ns=`+n+`;`))
	b = bytes.ReplaceAll(b, []byte(`Name="1:`), []byte(`Name="`+n+`:`))
	// BrowseName="Open" → BrowseName="0:Open".
	const attr = ` BrowseName="`
	var out bytes.Buffer
	out.Grow(len(b) + 4096)
	for {
		i := bytes.Index(b, []byte(attr))
		if i < 0 {
			out.Write(b)
			break
		}
		i += len(attr)
		out.Write(b[:i])
		b = b[i:]
		if len(b) > 0 && (b[0] < '0' || b[0] > '9') {
			out.WriteString("0:")
		}
	}
	nodeSets.Store(ns, out.Bytes())
	return out.Bytes()
}

// load reads the state of the store and prepares the CAs.
func (g *GDS) load(ctx context.Context) error {
	st, err := g.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("%w: load the store: %w", errAttach, err)
	}
	for _, a := range st.Applications {
		if a == nil || a.Record == nil || a.ID == "" {
			continue
		}
		g.apps[a.ID] = a
		g.byURI[a.Record.ApplicationURI] = a.ID
	}
	for _, r := range st.Requests {
		if r != nil && r.ID != "" {
			g.reqs[r.ID] = r
		}
	}
	g.meta = st.Meta
	if g.meta == nil {
		g.meta = &Meta{NextRecordID: 1, CounterResetTime: g.now().UTC()}
		if err := g.store.PutMeta(ctx, g.meta); err != nil {
			return fmt.Errorf("%w: store: %w", errAttach, err)
		}
	}
	stored := map[string]*Issuer{}
	for _, i := range st.Issuers {
		if i != nil {
			stored[i.Name] = i
		}
	}
	for _, i := range g.cfg.Issuers {
		if i == nil {
			continue
		}
		rec := cloneIssuer(i)
		rec.CRL, rec.CRLNumber, rec.Revoked = nil, 0, nil
		if old := stored[i.Name]; old != nil && bytes.Equal(old.Certificate, i.Certificate) {
			rec.CRL, rec.CRLNumber, rec.Revoked = old.CRL, old.CRLNumber, old.Revoked
		}
		stored[i.Name] = rec
	}
	for _, t := range g.types {
		name := certTypes[t].issuer
		if g.cas[name] != nil {
			continue
		}
		rec := stored[name]
		if rec == nil {
			if rec, err = newCA(name, g.cfg.CAName+" "+name, g.now(), g.cfg.CALifetime, defaultCARSABits); err != nil {
				return fmt.Errorf("%w: create the %s CA: %w", errAttach, name, err)
			}
		}
		c, err := loadCA(rec)
		if err != nil {
			return fmt.Errorf("%w: %w", errAttach, err)
		}
		if c.crl == nil || !bytes.Equal(c.crl.RawIssuer, c.cert.RawSubject) {
			if err := c.makeCRL(g.now(), g.cfg.CRLLifetime); err != nil {
				return fmt.Errorf("%w: the CRL of the %s CA: %w", errAttach, name, err)
			}
		}
		if err := g.store.PutIssuer(ctx, rec); err != nil {
			return fmt.Errorf("%w: store: %w", errAttach, err)
		}
		g.cas[name] = c
	}
	return nil
}

// buildModel serves the methods and properties of the Directory object.
func (g *GDS) buildModel() error {
	dir := g.node(gdsid.Directory)
	type method struct {
		id uint32
		h  func(context.Context, *caller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	}
	for _, m := range []method{
		{gdsid.DirectoryFindApplications, g.findApplications},
		{gdsid.DirectoryRegisterApplication, g.registerApplication},
		{gdsid.DirectoryUpdateApplication, g.updateApplication},
		{gdsid.DirectoryUnregisterApplication, g.unregisterApplication},
		{gdsid.DirectoryGetApplication, g.getApplication},
		{gdsid.DirectoryQueryApplications, g.queryApplications},
		{gdsid.DirectoryQueryServers, g.queryServers},
		{gdsid.DirectoryStartSigningRequest, g.startSigningRequest},
		{gdsid.DirectoryStartNewKeyPairRequest, g.startNewKeyPairRequest},
		{gdsid.DirectoryFinishRequest, g.finishRequest},
		{gdsid.DirectoryRevokeCertificate, g.revokeCertificate},
		{gdsid.DirectoryGetCertificateGroups, g.getCertificateGroups},
		{gdsid.DirectoryGetCertificates, g.getCertificates},
		{gdsid.DirectoryGetTrustList, g.getTrustList},
		{gdsid.DirectoryGetCertificateStatus, g.getCertificateStatus},
		{gdsid.DirectoryCheckRevocationStatus, g.checkRevocationStatus},
	} {
		mid, h := m.id, m.h
		perms := g.rolePermissions(g.node(mid))
		g.srv.RegisterMethod(dir, g.node(mid), func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if !g.enter() {
				return nil, ua.StatusBadShutdown
			}
			defer g.calls.Done()
			c, sc := g.identify(ctx)
			if sc != ua.StatusOK {
				return nil, sc
			}
			// The RolePermissions of the NodeSet apply besides the checks of
			// the handler; an application may call the self methods for
			// itself without a role.
			var out []*ua.Variant
			if !c.permits(perms) && !selfMethods[mid] {
				sc = ua.StatusBadUserAccessDenied
			} else {
				out, sc = h(ctx, c, args)
			}
			g.audit(ctx, c, mid, args, out, sc)
			return out, sc
		})
	}

	for _, gr := range g.groups {
		if n := g.srv.Node(g.node(gr.typesNode)); n != nil {
			types := make([]*ua.NodeID, len(gr.types))
			for i, t := range gr.types {
				types[i] = ua.NewNumericNodeID(0, t)
			}
			dv := server.DataValueFromValue(types)
			n.SetValueFunc(func() *ua.DataValue { return dv })
		}
		tl, err := g.srv.ServeTrustList(g.node(gr.trustNode), server.TrustListConfig{
			Load:      func() *ua.TrustListDataType { return g.trustListOf(gr) },
			Authorize: g.authorizeTrustList,
			Update: func(ctx context.Context, _ *server.MethodCaller, tl *ua.TrustListDataType) ua.StatusCode {
				return g.updateTrustList(ctx, gr, tl)
			},
		})
		if err != nil {
			return fmt.Errorf("%w: %w", errAttach, err)
		}
		gr.trust = tl
	}
	return nil
}

// enter counts a method call in, unless the GDS is closed.
func (g *GDS) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.calls.Add(1)
	return true
}

// Close stops the GDS: its methods return Bad_ShutDown from then on, and
// Close returns when the calls in progress completed. The GDS then no
// longer writes to its Store, which another GDS may take over. Close the
// server separately.
func (g *GDS) Close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.calls.Wait()
}

// node returns the NodeId of a node of the GDS namespace.
func (g *GDS) node(i uint32) *ua.NodeID { return ua.NewNumericNodeID(g.ns, i) }

// Namespace returns the namespace index of the GDS information model on
// the server.
func (g *GDS) Namespace() uint16 { return g.ns }

// DiscoveryAdminRole returns the NodeId of the DiscoveryAdmin role of Part
// 12 §6.2: a session with it may register, update and unregister
// applications.
func (g *GDS) DiscoveryAdminRole() *ua.NodeID { return g.node(gdsid.WellKnownRoleDiscoveryAdmin) }

// CertificateAuthorityAdminRole returns the NodeId of the
// CertificateAuthorityAdmin role of Part 12 §7.2: a session with it may
// request, revoke and read the certificates of every application and
// change the trust list.
func (g *GDS) CertificateAuthorityAdminRole() *ua.NodeID {
	return g.node(gdsid.WellKnownRoleCertificateAuthorityAdmin)
}

// DefaultApplicationGroup returns the NodeId of the DefaultApplicationGroup
// of the Directory.
func (g *GDS) DefaultApplicationGroup() *ua.NodeID {
	return g.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroup)
}

// DefaultHTTPSGroup returns the NodeId of the DefaultHttpsGroup of the
// Directory: it issues HttpsCertificateType certificates to servers.
func (g *GDS) DefaultHTTPSGroup() *ua.NodeID {
	return g.node(gdsid.DirectoryCertificateGroupsDefaultHTTPSGroup)
}

// DefaultUserTokenGroup returns the NodeId of the DefaultUserTokenGroup of
// the Directory: its trust list holds the issuers of user certificates.
func (g *GDS) DefaultUserTokenGroup() *ua.NodeID {
	return g.node(gdsid.DirectoryCertificateGroupsDefaultUserTokenGroup)
}

// GroupTrustList returns the trust list of a certificate group (by its
// NodeId; nil for the DefaultApplicationGroup), nil for an unknown group.
func (g *GDS) GroupTrustList(group *ua.NodeID) *ua.TrustListDataType {
	gr := g.groupOf(group)
	if gr == nil {
		return nil
	}
	return g.trustListOf(gr)
}

// IssuerCertificates returns the certificates of the CAs of the GDS (DER).
func (g *GDS) IssuerCertificates() [][]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out [][]byte
	for _, name := range g.caNamesLocked() {
		out = append(out, slices.Clone(g.cas[name].rec.Certificate))
	}
	return out
}

// caNamesLocked returns the names of the CAs, sorted.
func (g *GDS) caNamesLocked() []string {
	names := make([]string, 0, len(g.cas))
	for n := range g.cas {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// TrustList returns the trust list of the DefaultApplicationGroup: the
// certificates and CRLs of the CAs of the GDS and what a
// CertificateAuthorityAdmin added.
func (g *GDS) TrustList() *ua.TrustListDataType { return g.trustList() }

// trustList builds the trust list. A CRL whose NextUpdate is near is
// renewed first.
func (g *GDS) trustList() *ua.TrustListDataType {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshCRLsLocked()
	return g.trustListLocked()
}

func (g *GDS) trustListLocked() *ua.TrustListDataType {
	return g.groupTrustListLocked(g.groups[0])
}

// trustListOf builds the trust list of a group.
func (g *GDS) trustListOf(gr *group) *ua.TrustListDataType {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshCRLsLocked()
	return g.groupTrustListLocked(gr)
}

// groupTrustListLocked builds the trust list of a group: the certificates
// and CRLs of its CAs, then what a CertificateAuthorityAdmin added.
func (g *GDS) groupTrustListLocked(gr *group) *ua.TrustListDataType {
	tl := &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll)}
	for _, name := range gr.issuers {
		c := g.cas[name]
		tl.TrustedCertificates = append(tl.TrustedCertificates, slices.Clone(c.rec.Certificate))
		tl.TrustedCrls = append(tl.TrustedCrls, slices.Clone(c.rec.CRL))
	}
	if extra := g.extraTrustLocked(gr); extra != nil {
		add := func(dst *[][]byte, src [][]byte) {
			for _, x := range src {
				if !slices.ContainsFunc(*dst, func(y []byte) bool { return bytes.Equal(x, y) }) {
					*dst = append(*dst, slices.Clone(x))
				}
			}
		}
		add(&tl.TrustedCertificates, extra.TrustedCertificates)
		add(&tl.TrustedCrls, extra.TrustedCrls)
		add(&tl.IssuerCertificates, extra.IssuerCertificates)
		add(&tl.IssuerCrls, extra.IssuerCrls)
	}
	return tl
}

// refreshCRLsLocked renews the CRLs that passed half their lifetime.
func (g *GDS) refreshCRLsLocked() {
	if g.closed {
		return
	}
	now := g.now()
	changed := false
	for _, name := range g.caNamesLocked() {
		c := g.cas[name]
		if c.crl != nil && now.Before(c.crl.ThisUpdate.Add(c.crl.NextUpdate.Sub(c.crl.ThisUpdate)/2)) {
			continue
		}
		if err := g.renewCRLLocked(c); err != nil {
			g.log.Warn("gds: renewing the CRL failed", "issuer", name, "error", err)
			continue
		}
		changed = true
	}
	if changed {
		g.trustChanged()
	}
}

// renewCRLLocked signs a new CRL of the CA and stores it.
func (g *GDS) renewCRLLocked(c *ca) error {
	old, oldNumber, oldCRL := c.rec.CRL, c.rec.CRLNumber, c.crl
	if err := c.makeCRL(g.now(), g.cfg.CRLLifetime); err != nil {
		return err
	}
	if err := g.store.PutIssuer(context.Background(), c.rec); err != nil {
		c.rec.CRL, c.rec.CRLNumber, c.crl = old, oldNumber, oldCRL
		return err
	}
	return nil
}

// updateTrustList is the Update of the TrustList object of a group: the
// certificates and CRLs besides those of the CAs are kept in the Meta.
func (g *GDS) updateTrustList(ctx context.Context, gr *group, tl *ua.TrustListDataType) ua.StatusCode {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ua.StatusBadShutdown
	}
	own := map[string]bool{}
	for _, c := range g.cas {
		own[string(c.rec.Certificate)] = true
		own[string(c.rec.CRL)] = true
	}
	keep := func(xs [][]byte) [][]byte {
		var out [][]byte
		for _, x := range xs {
			if !own[string(x)] {
				out = append(out, slices.Clone(x))
			}
		}
		return out
	}
	meta := cloneMeta(g.meta)
	extra := &ua.TrustListDataType{
		SpecifiedLists:      uint32(ua.TrustListMasksAll),
		TrustedCertificates: keep(tl.TrustedCertificates),
		TrustedCrls:         keep(tl.TrustedCrls),
		IssuerCertificates:  keep(tl.IssuerCertificates),
		IssuerCrls:          keep(tl.IssuerCrls),
	}
	if gr.key == GroupApplication {
		meta.TrustList = extra
	} else {
		if meta.GroupTrustLists == nil {
			meta.GroupTrustLists = map[string]*ua.TrustListDataType{}
		}
		meta.GroupTrustLists[gr.key] = extra
	}
	if err := g.store.PutMeta(ctx, meta); err != nil {
		g.log.Warn("gds: storing the trust list failed", "error", err)
		return ua.StatusBadInternalError
	}
	g.meta = meta
	return ua.StatusOK
}

// guidOf returns the GUID of a NodeId of the GDS namespace, "" for any
// other NodeId.
func (g *GDS) guidOf(n *ua.NodeID) string {
	if n == nil || n.Namespace() != g.ns || n.Type() != ua.NodeIDTypeGUID {
		return ""
	}
	return strings.ToLower(n.StringID())
}

// guidNode returns the NodeId of an application or request.
func (g *GDS) guidNode(guid string) *ua.NodeID { return ua.NewGUIDNodeID(g.ns, guid) }
