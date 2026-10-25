// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// Store persists the state of a GDS: the application directory, the
// certificate requests, the certificate authorities and the trust list.
//
// The GDS reads the whole state when it is attached to a server and keeps
// it in memory; it then writes every change through to the Store before
// the change takes effect. A failing write fails the method call with
// Bad_InternalError and leaves the state as it was. Only one GDS may use a
// Store at a time.
//
// A Store holds secrets: the private keys of the certificate authorities
// (Issuer.PrivateKey) and the passwords of pending new key pair requests
// (Request.PrivateKeyPassword). A persistent implementation must protect
// them.
//
// The values passed to a Store and returned by it are not shared with the
// GDS afterwards: an implementation may keep them as they are, and must
// not change them.
type Store interface {
	// Load returns the complete state, the zero State for a new store.
	Load(ctx context.Context) (*State, error)

	// PutApplication inserts or replaces the application with its ID.
	PutApplication(ctx context.Context, app *Application) error
	// DeleteApplication removes the application with the ID.
	DeleteApplication(ctx context.Context, id string) error

	// PutRequest inserts or replaces the request with its ID.
	PutRequest(ctx context.Context, req *Request) error
	// DeleteRequest removes the request with the ID.
	DeleteRequest(ctx context.Context, id string) error

	// PutIssuer inserts or replaces the certificate authority with its
	// Name.
	PutIssuer(ctx context.Context, iss *Issuer) error

	// PutMeta replaces the counters and the trust list additions.
	PutMeta(ctx context.Context, meta *Meta) error
}

// State is everything a Store holds.
type State struct {
	Applications []*Application
	Requests     []*Request
	Issuers      []*Issuer
	Meta         *Meta // nil for a new store
}

// Application is an application of the directory.
type Application struct {
	// ID identifies the application: the GUID of its ApplicationId
	// NodeId.
	ID string
	// RecordID is the record identifier QueryApplications pages with.
	RecordID uint32
	// Record is the registered ApplicationRecordDataType (ApplicationID
	// nil).
	Record *gds.ApplicationRecord
	// EndpointIDs are the record identifiers of QueryServers, one for each
	// of Record.DiscoveryURLs.
	EndpointIDs []uint32
	// Certificates are the certificates the GDS issued to the application.
	Certificates []*IssuedCertificate
}

// IssuedCertificate is a certificate the GDS issued.
type IssuedCertificate struct {
	// CertificateType is the numeric id of the certificate type in
	// namespace 0, for example id.EccNistP256ApplicationCertificateType.
	CertificateType uint32
	// Certificate is the certificate (DER).
	Certificate []byte
	// Revoked tells that RevokeCertificate or UnregisterApplication
	// revoked it.
	Revoked bool
}

// RequestState is the state of a certificate request.
type RequestState int

// The states of a certificate request (Part 12 §7.9.5): a new request
// waits for the approval of a CertificateAuthorityAdmin (or is approved at
// once with Config.AutoApprove); FinishRequest issues the certificate of an
// approved request and removes the request.
const (
	RequestPending RequestState = iota
	RequestApproved
	RequestRejected
)

func (s RequestState) String() string {
	switch s {
	case RequestPending:
		return "Pending"
	case RequestApproved:
		return "Approved"
	case RequestRejected:
		return "Rejected"
	}
	return "Unknown"
}

// Request is a certificate request of StartSigningRequest or
// StartNewKeyPairRequest.
type Request struct {
	// ID identifies the request: the GUID of its RequestId NodeId.
	ID string
	// ApplicationID is the ID of the application that made it.
	ApplicationID string
	// CertificateType is the numeric id of the certificate type in
	// namespace 0.
	CertificateType uint32
	State           RequestState
	Created         time.Time

	// CertificateRequest is the PKCS #10 request of StartSigningRequest.
	CertificateRequest []byte

	// The arguments of StartNewKeyPairRequest.
	SubjectName        string
	DomainNames        []string
	PrivateKeyFormat   string
	PrivateKeyPassword string
}

// Issuer is a certificate authority of the GDS.
type Issuer struct {
	// Name is the key type of the CA: "RSA", "NistP256", "NistP384",
	// "Curve25519" or "Curve448".
	Name string
	// Certificate is the CA certificate (DER).
	Certificate []byte
	// PrivateKey is the key of the CA (PKCS #8, DER).
	PrivateKey []byte
	// CRL is the current certificate revocation list (DER).
	CRL []byte
	// CRLNumber is the number of the current CRL.
	CRLNumber uint64
	// Revoked are the certificates the CA revoked.
	Revoked []*RevokedCertificate
}

// RevokedCertificate is an entry of a CRL.
type RevokedCertificate struct {
	// SerialNumber is the serial number (big-endian, unsigned).
	SerialNumber []byte
	RevokedAt    time.Time
}

// Meta holds the counters of the directory and the certificates and CRLs
// a CertificateAuthorityAdmin added to the trust list.
type Meta struct {
	// NextRecordID is the next record identifier for QueryApplications
	// and QueryServers.
	NextRecordID uint32
	// CounterResetTime is when the record identifiers started.
	CounterResetTime time.Time
	// TrustList holds the entries of the trust list besides the CA
	// certificates and CRLs of the GDS.
	TrustList *ua.TrustListDataType
}

// MemoryStore is a Store that keeps the state in memory: it lives as long
// as the process and survives a restart of the GDS (a new server with the
// same MemoryStore).
type MemoryStore struct {
	mu    sync.Mutex
	apps  map[string]*Application
	reqs  map[string]*Request
	iss   map[string]*Issuer
	meta  *Meta
	fails func(op string) error
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{apps: map[string]*Application{}, reqs: map[string]*Request{}, iss: map[string]*Issuer{}}
}

// failWith makes the writes fail with what f returns for the operation
// ("PutApplication", ...), for tests.
func (m *MemoryStore) failWith(f func(op string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fails = f
}

func (m *MemoryStore) fail(op string) error {
	if m.fails == nil {
		return nil
	}
	return m.fails(op)
}

// Load returns a copy of the state.
func (m *MemoryStore) Load(context.Context) (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Load"); err != nil {
		return nil, err
	}
	st := &State{}
	for _, a := range m.apps {
		st.Applications = append(st.Applications, cloneApplication(a))
	}
	sort.Slice(st.Applications, func(i, j int) bool { return st.Applications[i].RecordID < st.Applications[j].RecordID })
	for _, r := range m.reqs {
		st.Requests = append(st.Requests, cloneRequest(r))
	}
	sort.Slice(st.Requests, func(i, j int) bool { return st.Requests[i].ID < st.Requests[j].ID })
	for _, i := range m.iss {
		st.Issuers = append(st.Issuers, cloneIssuer(i))
	}
	sort.Slice(st.Issuers, func(i, j int) bool { return st.Issuers[i].Name < st.Issuers[j].Name })
	if m.meta != nil {
		st.Meta = cloneMeta(m.meta)
	}
	return st, nil
}

// PutApplication stores a copy of app.
func (m *MemoryStore) PutApplication(_ context.Context, app *Application) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("PutApplication"); err != nil {
		return err
	}
	m.apps[app.ID] = cloneApplication(app)
	return nil
}

// DeleteApplication removes an application.
func (m *MemoryStore) DeleteApplication(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteApplication"); err != nil {
		return err
	}
	delete(m.apps, id)
	return nil
}

// PutRequest stores a copy of req.
func (m *MemoryStore) PutRequest(_ context.Context, req *Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("PutRequest"); err != nil {
		return err
	}
	m.reqs[req.ID] = cloneRequest(req)
	return nil
}

// DeleteRequest removes a request.
func (m *MemoryStore) DeleteRequest(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteRequest"); err != nil {
		return err
	}
	delete(m.reqs, id)
	return nil
}

// PutIssuer stores a copy of iss.
func (m *MemoryStore) PutIssuer(_ context.Context, iss *Issuer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("PutIssuer"); err != nil {
		return err
	}
	m.iss[iss.Name] = cloneIssuer(iss)
	return nil
}

// PutMeta stores a copy of meta.
func (m *MemoryStore) PutMeta(_ context.Context, meta *Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("PutMeta"); err != nil {
		return err
	}
	m.meta = cloneMeta(meta)
	return nil
}

func cloneRecord(r *gds.ApplicationRecord) *gds.ApplicationRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.ApplicationNames = make([]*ua.LocalizedText, len(r.ApplicationNames))
	for i, n := range r.ApplicationNames {
		if n != nil {
			c := *n
			out.ApplicationNames[i] = &c
		}
	}
	out.DiscoveryURLs = slices.Clone(r.DiscoveryURLs)
	out.ServerCapabilities = slices.Clone(r.ServerCapabilities)
	return &out
}

func cloneApplication(a *Application) *Application {
	out := *a
	out.Record = cloneRecord(a.Record)
	out.EndpointIDs = slices.Clone(a.EndpointIDs)
	out.Certificates = make([]*IssuedCertificate, len(a.Certificates))
	for i, c := range a.Certificates {
		x := *c
		x.Certificate = slices.Clone(c.Certificate)
		out.Certificates[i] = &x
	}
	return &out
}

func cloneRequest(r *Request) *Request {
	out := *r
	out.CertificateRequest = slices.Clone(r.CertificateRequest)
	out.DomainNames = slices.Clone(r.DomainNames)
	return &out
}

func cloneIssuer(i *Issuer) *Issuer {
	out := *i
	out.Certificate = slices.Clone(i.Certificate)
	out.PrivateKey = slices.Clone(i.PrivateKey)
	out.CRL = slices.Clone(i.CRL)
	out.Revoked = make([]*RevokedCertificate, len(i.Revoked))
	for k, r := range i.Revoked {
		x := *r
		x.SerialNumber = slices.Clone(r.SerialNumber)
		out.Revoked[k] = &x
	}
	return &out
}

func cloneTrustList(d *ua.TrustListDataType) *ua.TrustListDataType {
	if d == nil {
		return nil
	}
	cl := func(xs [][]byte) [][]byte {
		out := make([][]byte, len(xs))
		for i, x := range xs {
			out[i] = slices.Clone(x)
		}
		return out
	}
	return &ua.TrustListDataType{
		SpecifiedLists:      d.SpecifiedLists,
		TrustedCertificates: cl(d.TrustedCertificates),
		TrustedCrls:         cl(d.TrustedCrls),
		IssuerCertificates:  cl(d.IssuerCertificates),
		IssuerCrls:          cl(d.IssuerCrls),
	}
}

func cloneMeta(m *Meta) *Meta {
	out := *m
	out.TrustList = cloneTrustList(m.TrustList)
	return &out
}
