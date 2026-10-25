// SPDX-License-Identifier: MIT

package gds

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// DefaultPollInterval is the interval at which WaitForCertificate calls
// FinishRequest when none is given.
const DefaultPollInterval = 5 * time.Second

// PullClient calls the methods of the Directory object of a Global
// Discovery Server (the pull model of OPC UA Part 12 §6 and §7.9) over the
// session of an opcua.Client.
//
// The node ids of the GDS information model lie in the namespace
// gdsid.NamespaceURI; PullClient looks up its index on the server at the
// first call.
type PullClient struct {
	c *opcua.Client

	mu sync.Mutex
	ns uint16
	ok bool
}

// NewPullClient returns a PullClient that uses the session of c.
func NewPullClient(c *opcua.Client) *PullClient { return &PullClient{c: c} }

// Namespace returns the index of the GDS namespace on the server.
func (p *PullClient) Namespace(ctx context.Context) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ok {
		return p.ns, nil
	}
	ns, err := p.c.FindNamespace(ctx, gdsid.NamespaceURI)
	if err != nil {
		return 0, fmt.Errorf("gds: the server has no GDS namespace: %w", err)
	}
	p.ns, p.ok = ns, true
	return ns, nil
}

// node returns a node of the GDS namespace.
func (p *PullClient) node(ctx context.Context, i uint32) (*ua.NodeID, error) {
	ns, err := p.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	return ua.NewNumericNodeID(ns, i), nil
}

// DefaultApplicationGroup returns the NodeId of the DefaultApplicationGroup
// of the Directory.
func (p *PullClient) DefaultApplicationGroup(ctx context.Context) (*ua.NodeID, error) {
	return p.node(ctx, gdsid.DirectoryCertificateGroupsDefaultApplicationGroup)
}

func (p *PullClient) call(ctx context.Context, name string, method uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	ns, err := p.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	res, err := p.c.Call(ctx, &ua.CallMethodRequest{
		ObjectID:       ua.NewNumericNodeID(ns, gdsid.Directory),
		MethodID:       ua.NewNumericNodeID(ns, method),
		InputArguments: args,
	})
	if err != nil {
		return nil, err
	}
	if res.StatusCode != ua.StatusOK {
		return nil, &Error{Method: name, Status: res.StatusCode}
	}
	if len(res.OutputArguments) < outputs {
		return nil, fmt.Errorf("gds: %s: %d output arguments, want %d", name, len(res.OutputArguments), outputs)
	}
	return res.OutputArguments, nil
}

func outValue[T any](name string, v *ua.Variant) (T, error) {
	x, ok := v.Value().(T)
	if !ok && v.Value() != nil {
		return x, fmt.Errorf("gds: %s returned %T, want %T", name, v.Value(), x)
	}
	return x, nil
}

// RegisterApplication registers an application (Part 12 §6.6.5; the
// DiscoveryAdmin role) and returns its ApplicationId.
func (p *PullClient) RegisterApplication(ctx context.Context, r *ApplicationRecord) (*ua.NodeID, error) {
	ns, err := p.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	rec := *r
	rec.ApplicationID = nil
	eo, err := EncodeApplicationRecord(ns, &rec)
	if err != nil {
		return nil, err
	}
	out, err := p.call(ctx, "RegisterApplication", gdsid.DirectoryRegisterApplication, 1, ua.MustVariant(eo))
	if err != nil {
		return nil, err
	}
	return outValue[*ua.NodeID]("RegisterApplication", out[0])
}

// UpdateApplication replaces the record with r.ApplicationID (Part 12
// §6.6.6).
func (p *PullClient) UpdateApplication(ctx context.Context, r *ApplicationRecord) error {
	ns, err := p.Namespace(ctx)
	if err != nil {
		return err
	}
	eo, err := EncodeApplicationRecord(ns, r)
	if err != nil {
		return err
	}
	_, err = p.call(ctx, "UpdateApplication", gdsid.DirectoryUpdateApplication, 0, ua.MustVariant(eo))
	return err
}

// UnregisterApplication removes an application (Part 12 §6.6.7); the GDS
// revokes the certificates it issued to it.
func (p *PullClient) UnregisterApplication(ctx context.Context, applicationID *ua.NodeID) error {
	_, err := p.call(ctx, "UnregisterApplication", gdsid.DirectoryUnregisterApplication, 0, ua.MustVariant(nodeOrNull(applicationID)))
	return err
}

func (p *PullClient) records(ctx context.Context, name string, v *ua.Variant) ([]*ApplicationRecord, error) {
	ns, err := p.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	var eos []*ua.ExtensionObject
	switch x := v.Value().(type) {
	case nil:
	case []*ua.ExtensionObject:
		eos = x
	case *ua.ExtensionObject:
		eos = []*ua.ExtensionObject{x}
	default:
		return nil, fmt.Errorf("gds: %s returned %T", name, x)
	}
	out := make([]*ApplicationRecord, 0, len(eos))
	for _, eo := range eos {
		r, err := DecodeApplicationRecord(ns, eo)
		if err != nil {
			return nil, fmt.Errorf("gds: %s: %w", name, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// FindApplications returns the records with the ApplicationUri (Part 12
// §6.6.4).
func (p *PullClient) FindApplications(ctx context.Context, applicationURI string) ([]*ApplicationRecord, error) {
	out, err := p.call(ctx, "FindApplications", gdsid.DirectoryFindApplications, 1, ua.MustVariant(applicationURI))
	if err != nil {
		return nil, err
	}
	return p.records(ctx, "FindApplications", out[0])
}

// GetApplication returns the record of an application (Part 12 §6.6.8).
func (p *PullClient) GetApplication(ctx context.Context, applicationID *ua.NodeID) (*ApplicationRecord, error) {
	out, err := p.call(ctx, "GetApplication", gdsid.DirectoryGetApplication, 1, ua.MustVariant(nodeOrNull(applicationID)))
	if err != nil {
		return nil, err
	}
	rs, err := p.records(ctx, "GetApplication", out[0])
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		return nil, fmt.Errorf("gds: GetApplication returned %d records", len(rs))
	}
	return rs[0], nil
}

// ApplicationQuery is the filter of QueryApplications (Part 12 §6.6.10).
// The names and URIs are patterns of the Like operator; empty matches
// everything.
type ApplicationQuery struct {
	StartingRecordID   uint32
	MaxRecordsToReturn uint32 // 0: no limit
	ApplicationName    string
	ApplicationURI     string
	// ApplicationType is 0 or 3 for all applications, 1 for servers and 2
	// for clients.
	ApplicationType    uint32
	ProductURI         string
	ServerCapabilities []string
}

// ApplicationQueryResult is the result of QueryApplications.
type ApplicationQueryResult struct {
	LastCounterResetTime time.Time
	// NextRecordID is where the next page starts, 0 at the end.
	NextRecordID uint32
	Applications []*ua.ApplicationDescription
}

// QueryApplications returns the registered applications that match the
// query (Part 12 §6.6.10).
func (p *PullClient) QueryApplications(ctx context.Context, q *ApplicationQuery) (*ApplicationQueryResult, error) {
	if q == nil {
		q = &ApplicationQuery{}
	}
	out, err := p.call(ctx, "QueryApplications", gdsid.DirectoryQueryApplications, 3,
		ua.MustVariant(q.StartingRecordID), ua.MustVariant(q.MaxRecordsToReturn),
		ua.MustVariant(q.ApplicationName), ua.MustVariant(q.ApplicationURI),
		ua.MustVariant(q.ApplicationType), ua.MustVariant(q.ProductURI), ua.MustVariant(strs(q.ServerCapabilities)))
	if err != nil {
		return nil, err
	}
	res := &ApplicationQueryResult{}
	if res.LastCounterResetTime, err = outValue[time.Time]("QueryApplications", out[0]); err != nil {
		return nil, err
	}
	if res.NextRecordID, err = outValue[uint32]("QueryApplications", out[1]); err != nil {
		return nil, err
	}
	res.Applications, err = eosAs[ua.ApplicationDescription]("QueryApplications", out[2])
	return res, err
}

// ServerQuery is the filter of QueryServers (Part 12 §6.6.9).
type ServerQuery struct {
	StartingRecordID   uint32
	MaxRecordsToReturn uint32 // 0: no limit
	ApplicationName    string
	ApplicationURI     string
	ProductURI         string
	ServerCapabilities []string
}

// ServerQueryResult is the result of QueryServers.
type ServerQueryResult struct {
	LastCounterResetTime time.Time
	Servers              []*ua.ServerOnNetwork
}

// QueryServers returns the discovery URLs of the registered servers that
// match the query, one record each (Part 12 §6.6.9).
func (p *PullClient) QueryServers(ctx context.Context, q *ServerQuery) (*ServerQueryResult, error) {
	if q == nil {
		q = &ServerQuery{}
	}
	out, err := p.call(ctx, "QueryServers", gdsid.DirectoryQueryServers, 2,
		ua.MustVariant(q.StartingRecordID), ua.MustVariant(q.MaxRecordsToReturn),
		ua.MustVariant(q.ApplicationName), ua.MustVariant(q.ApplicationURI),
		ua.MustVariant(q.ProductURI), ua.MustVariant(strs(q.ServerCapabilities)))
	if err != nil {
		return nil, err
	}
	res := &ServerQueryResult{}
	if res.LastCounterResetTime, err = outValue[time.Time]("QueryServers", out[0]); err != nil {
		return nil, err
	}
	res.Servers, err = eosAs[ua.ServerOnNetwork]("QueryServers", out[1])
	return res, err
}

func strs(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func eosAs[T any](name string, v *ua.Variant) ([]*T, error) {
	eos, err := outValue[[]*ua.ExtensionObject](name, v)
	if err != nil {
		return nil, err
	}
	out := make([]*T, 0, len(eos))
	for _, eo := range eos {
		x, ok := eo.Value.(*T)
		if !ok {
			return nil, fmt.Errorf("gds: %s returned %T, want %T", name, eo.Value, x)
		}
		out = append(out, x)
	}
	return out, nil
}

// StartSigningRequest asks the GDS to sign a PKCS #10 request (Part 12
// §7.9.4) of the application for a certificate of the group (nil: the
// DefaultApplicationGroup of the GDS) and type (nil: the first type of the
// group). It returns the RequestId for FinishRequest.
func (p *PullClient) StartSigningRequest(ctx context.Context, applicationID, group, certificateType *ua.NodeID, csr []byte) (*ua.NodeID, error) {
	if group == nil {
		var err error
		if group, err = p.DefaultApplicationGroup(ctx); err != nil {
			return nil, err
		}
	}
	out, err := p.call(ctx, "StartSigningRequest", gdsid.DirectoryStartSigningRequest, 1,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(group), ua.MustVariant(nodeOrNull(certificateType)), ua.MustVariant(byteString(csr)))
	if err != nil {
		return nil, err
	}
	return outValue[*ua.NodeID]("StartSigningRequest", out[0])
}

func byteString(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// NewKeyPairRequest is the input of StartNewKeyPairRequest (Part 12
// §7.9.5).
type NewKeyPairRequest struct {
	// CertificateGroup (nil: the DefaultApplicationGroup) and
	// CertificateType (nil: the first type of the group).
	CertificateGroup *ua.NodeID
	CertificateType  *ua.NodeID
	// SubjectName is the subject as X.500 name value pairs separated by
	// '/' ("CN=App/O=Company"); empty lets the GDS choose.
	SubjectName string
	// DomainNames are the host names and IP addresses of the certificate;
	// empty lets the GDS take those of the discovery URLs.
	DomainNames []string
	// PrivateKeyFormat is PrivateKeyFormatPEM (empty selects it) or
	// PrivateKeyFormatPFX.
	PrivateKeyFormat string
	// PrivateKeyPassword protects the private key FinishRequest returns
	// (DecodePrivateKey decodes it).
	PrivateKeyPassword string
}

// StartNewKeyPairRequest asks the GDS to generate a key pair and a
// certificate for the application (Part 12 §7.9.5). It returns the
// RequestId for FinishRequest.
func (p *PullClient) StartNewKeyPairRequest(ctx context.Context, applicationID *ua.NodeID, r *NewKeyPairRequest) (*ua.NodeID, error) {
	if r == nil {
		r = &NewKeyPairRequest{}
	}
	group := r.CertificateGroup
	if group == nil {
		var err error
		if group, err = p.DefaultApplicationGroup(ctx); err != nil {
			return nil, err
		}
	}
	format := r.PrivateKeyFormat
	if format == "" {
		format = PrivateKeyFormatPEM
	}
	out, err := p.call(ctx, "StartNewKeyPairRequest", gdsid.DirectoryStartNewKeyPairRequest, 1,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(group), ua.MustVariant(nodeOrNull(r.CertificateType)),
		ua.MustVariant(r.SubjectName), ua.MustVariant(strs(r.DomainNames)), ua.MustVariant(format), ua.MustVariant(r.PrivateKeyPassword))
	if err != nil {
		return nil, err
	}
	return outValue[*ua.NodeID]("StartNewKeyPairRequest", out[0])
}

// IssuedCertificate is the result of FinishRequest.
type IssuedCertificate struct {
	// Certificate is the new certificate (DER).
	Certificate []byte
	// PrivateKey is the new private key of a StartNewKeyPairRequest in the
	// requested format, nil for a StartSigningRequest.
	PrivateKey []byte
	// IssuerCertificates is the chain of CA certificates (DER).
	IssuerCertificates [][]byte
}

// FinishRequest completes a certificate request (Part 12 §7.9.6). While
// the request waits for approval the error is Bad_NothingToDo
// (errors.Is(err, ua.StatusBadNothingToDo)); a rejected request fails with
// Bad_RequestNotAllowed.
func (p *PullClient) FinishRequest(ctx context.Context, applicationID, requestID *ua.NodeID) (*IssuedCertificate, error) {
	out, err := p.call(ctx, "FinishRequest", gdsid.DirectoryFinishRequest, 3,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(nodeOrNull(requestID)))
	if err != nil {
		return nil, err
	}
	res := &IssuedCertificate{}
	if res.Certificate, err = outValue[[]byte]("FinishRequest", out[0]); err != nil {
		return nil, err
	}
	if res.PrivateKey, err = outValue[[]byte]("FinishRequest", out[1]); err != nil {
		return nil, err
	}
	if res.IssuerCertificates, err = outValue[[][]byte]("FinishRequest", out[2]); err != nil {
		return nil, err
	}
	if len(res.Certificate) == 0 {
		return nil, errors.New("gds: FinishRequest returned no certificate")
	}
	return res, nil
}

// WaitForCertificate calls FinishRequest until the GDS issues the
// certificate, every interval (DefaultPollInterval if zero) while the
// request waits for approval, and returns when ctx ends or the request
// fails otherwise.
func (p *PullClient) WaitForCertificate(ctx context.Context, applicationID, requestID *ua.NodeID, interval time.Duration) (*IssuedCertificate, error) {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := p.FinishRequest(ctx, applicationID, requestID)
		if !errors.Is(err, ua.StatusBadNothingToDo) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// RevokeCertificate revokes a certificate the GDS issued to the application
// (Part 12 §7.9.9; the CertificateAuthorityAdmin role).
func (p *PullClient) RevokeCertificate(ctx context.Context, applicationID *ua.NodeID, cert []byte) error {
	_, err := p.call(ctx, "RevokeCertificate", gdsid.DirectoryRevokeCertificate, 0,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(byteString(cert)))
	return err
}

// GetCertificateGroups returns the certificate groups of the application
// (Part 12 §7.9.10).
func (p *PullClient) GetCertificateGroups(ctx context.Context, applicationID *ua.NodeID) ([]*ua.NodeID, error) {
	out, err := p.call(ctx, "GetCertificateGroups", gdsid.DirectoryGetCertificateGroups, 1, ua.MustVariant(nodeOrNull(applicationID)))
	if err != nil {
		return nil, err
	}
	return outValue[[]*ua.NodeID]("GetCertificateGroups", out[0])
}

// GetCertificates returns the certificates the GDS issued to the
// application in the group (nil: all groups) with their types (Part 12
// §7.9.11).
func (p *PullClient) GetCertificates(ctx context.Context, applicationID, group *ua.NodeID) (types []*ua.NodeID, certs [][]byte, err error) {
	out, err := p.call(ctx, "GetCertificates", gdsid.DirectoryGetCertificates, 2,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(nodeOrNull(group)))
	if err != nil {
		return nil, nil, err
	}
	if types, err = outValue[[]*ua.NodeID]("GetCertificates", out[0]); err != nil {
		return nil, nil, err
	}
	certs, err = outValue[[][]byte]("GetCertificates", out[1])
	return types, certs, err
}

// GetTrustList returns the NodeId of the TrustList object of the group
// (nil: the DefaultApplicationGroup) for the application (Part 12
// §7.9.12).
func (p *PullClient) GetTrustList(ctx context.Context, applicationID, group *ua.NodeID) (*ua.NodeID, error) {
	if group == nil {
		var err error
		if group, err = p.DefaultApplicationGroup(ctx); err != nil {
			return nil, err
		}
	}
	out, err := p.call(ctx, "GetTrustList", gdsid.DirectoryGetTrustList, 1,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(group))
	if err != nil {
		return nil, err
	}
	return outValue[*ua.NodeID]("GetTrustList", out[0])
}

// ReadTrustList reads the trust list of the group (nil: the
// DefaultApplicationGroup) for the application: GetTrustList, then the
// TrustList file (Part 12 §7.8.2).
func (p *PullClient) ReadTrustList(ctx context.Context, applicationID, group *ua.NodeID) (*ua.TrustListDataType, error) {
	tl, err := p.GetTrustList(ctx, applicationID, group)
	if err != nil {
		return nil, err
	}
	c := New(p.c)
	c.TrustList = tl
	return c.ReadTrustList(ctx, ua.TrustListMasksAll)
}

// GetCertificateStatus reports whether the application should ask for a
// new certificate of the type (nil: any type of the group) in the group
// (nil: the DefaultApplicationGroup) (Part 12 §7.9.13).
func (p *PullClient) GetCertificateStatus(ctx context.Context, applicationID, group, certificateType *ua.NodeID) (bool, error) {
	if group == nil {
		var err error
		if group, err = p.DefaultApplicationGroup(ctx); err != nil {
			return false, err
		}
	}
	out, err := p.call(ctx, "GetCertificateStatus", gdsid.DirectoryGetCertificateStatus, 1,
		ua.MustVariant(nodeOrNull(applicationID)), ua.MustVariant(group), ua.MustVariant(nodeOrNull(certificateType)))
	if err != nil {
		return false, err
	}
	return boolOut("GetCertificateStatus", out[0])
}

// CheckRevocationStatus asks the GDS whether a certificate is valid (Part
// 12 §7.9.14): status is Good or why it is not (for example
// Bad_CertificateRevoked); validUntil is when to ask again.
func (p *PullClient) CheckRevocationStatus(ctx context.Context, cert []byte) (status ua.StatusCode, validUntil time.Time, err error) {
	out, err := p.call(ctx, "CheckRevocationStatus", gdsid.DirectoryCheckRevocationStatus, 2, ua.MustVariant(byteString(cert)))
	if err != nil {
		return 0, time.Time{}, err
	}
	if status, err = outValue[ua.StatusCode]("CheckRevocationStatus", out[0]); err != nil {
		return 0, time.Time{}, err
	}
	validUntil, err = outValue[time.Time]("CheckRevocationStatus", out[1])
	return status, validUntil, err
}

// NewCertificateRequest returns a PKCS #10 request for StartSigningRequest:
// the key of the application with its ApplicationUri, the subject (name
// value pairs separated by '/' or ',', or empty for CN=the host of the
// URI) and the host names and IP addresses. The key may be of any
// certificate type: RSA, ECDSA (NIST and Brainpool curves), Ed25519 or
// Ed448 (uapolicy.CreateCertificateRequest).
func NewCertificateRequest(key crypto.Signer, applicationURI, subject string, hosts []string) ([]byte, error) {
	u, err := url.Parse(applicationURI)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("gds: invalid application URI %q", applicationURI)
	}
	name, err := parseName(subject)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: name, URIs: []*url.URL{u}}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return uapolicy.CreateCertificateRequest(rand.Reader, tmpl, key)
}

var oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

// parseName parses "CN=App/O=Company" or "CN=App, O=Company".
func parseName(s string) (pkix.Name, error) {
	var n pkix.Name
	sep := "/"
	if !strings.Contains(s, "/") {
		sep = ","
	}
	for part := range strings.SplitSeq(s, sep) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return n, fmt.Errorf("gds: invalid subject name %q", s)
		}
		switch v = strings.TrimSpace(v); strings.ToUpper(strings.TrimSpace(k)) {
		case "CN":
			n.CommonName = v
		case "O":
			n.Organization = append(n.Organization, v)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, v)
		case "C":
			n.Country = append(n.Country, v)
		case "ST", "S":
			n.Province = append(n.Province, v)
		case "L":
			n.Locality = append(n.Locality, v)
		case "DC":
			n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidDomainComponent, Value: v})
		default:
			return n, fmt.Errorf("gds: unsupported attribute %q in subject name", k)
		}
	}
	return n, nil
}

// Enrollment is what Enroll obtained: the certificate, its private key,
// the issuer chain and the trust list of the group.
type Enrollment struct {
	ApplicationID      *ua.NodeID
	Certificate        []byte
	PrivateKey         crypto.Signer
	IssuerCertificates [][]byte
	TrustList          *ua.TrustListDataType
}

// EnrollRequest is the input of Enroll.
type EnrollRequest struct {
	// Record registers the application when ApplicationID is nil and no
	// application with its ApplicationUri is registered (registering needs
	// the DiscoveryAdmin role).
	Record        *ApplicationRecord
	ApplicationID *ua.NodeID

	CertificateGroup *ua.NodeID
	CertificateType  *ua.NodeID

	// Key, if set, is the key the certificate is for: Enroll sends a
	// StartSigningRequest with a request NewCertificateRequest makes.
	// Otherwise the GDS generates the key (StartNewKeyPairRequest).
	Key         crypto.Signer
	SubjectName string
	DomainNames []string

	// PrivateKeyFormat (PrivateKeyFormatPEM or PrivateKeyFormatPFX) and
	// PrivateKeyPassword are those of the key the GDS generates (no Key):
	// the format the key travels in.
	PrivateKeyFormat   string
	PrivateKeyPassword string

	// PollInterval is the interval of WaitForCertificate.
	PollInterval time.Duration
}

// Enroll obtains an application instance certificate from the GDS: it
// finds or registers the application, asks for a certificate, waits until
// the GDS issues it and reads the trust list of the group.
func (p *PullClient) Enroll(ctx context.Context, r *EnrollRequest) (*Enrollment, error) {
	appID := r.ApplicationID
	if appID == nil {
		if r.Record == nil {
			return nil, errors.New("gds: Enroll needs an ApplicationID or a Record")
		}
		found, err := p.FindApplications(ctx, r.Record.ApplicationURI)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			appID = found[0].ApplicationID
		} else if appID, err = p.RegisterApplication(ctx, r.Record); err != nil {
			return nil, err
		}
	}
	var reqID *ua.NodeID
	var err error
	if r.Key != nil {
		uri := ""
		if r.Record != nil {
			uri = r.Record.ApplicationURI
		} else {
			rec, err := p.GetApplication(ctx, appID)
			if err != nil {
				return nil, err
			}
			uri = rec.ApplicationURI
		}
		csr, err := NewCertificateRequest(r.Key, uri, r.SubjectName, r.DomainNames)
		if err != nil {
			return nil, err
		}
		reqID, err = p.StartSigningRequest(ctx, appID, r.CertificateGroup, r.CertificateType, csr)
		if err != nil {
			return nil, err
		}
	} else {
		reqID, err = p.StartNewKeyPairRequest(ctx, appID, &NewKeyPairRequest{
			CertificateGroup: r.CertificateGroup, CertificateType: r.CertificateType,
			SubjectName: r.SubjectName, DomainNames: r.DomainNames,
			PrivateKeyFormat: r.PrivateKeyFormat, PrivateKeyPassword: r.PrivateKeyPassword,
		})
		if err != nil {
			return nil, err
		}
	}
	res, err := p.WaitForCertificate(ctx, appID, reqID, r.PollInterval)
	if err != nil {
		return nil, err
	}
	e := &Enrollment{ApplicationID: appID, Certificate: res.Certificate, IssuerCertificates: res.IssuerCertificates, PrivateKey: r.Key}
	if e.PrivateKey == nil {
		format := r.PrivateKeyFormat
		if format == "" {
			format = PrivateKeyFormatPEM
		}
		if e.PrivateKey, err = DecodePrivateKey(format, res.PrivateKey, r.PrivateKeyPassword); err != nil {
			return nil, err
		}
	}
	if !uapolicy.KeyMatchesCertificate(e.PrivateKey, e.Certificate) {
		return nil, errors.New("gds: the issued certificate is not for the key")
	}
	if e.TrustList, err = p.ReadTrustList(ctx, appID, r.CertificateGroup); err != nil {
		return nil, err
	}
	return e, nil
}

// trustedCertificates returns the CA and trusted certificates of the trust
// list, parsed.
func (e *Enrollment) trustedCertificates() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	if e.TrustList == nil {
		return nil, nil
	}
	for _, der := range e.TrustList.TrustedCertificates {
		c, err := uapolicy.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ClientOptions configures an opcua.Client with the enrollment: the
// certificate and key, and the trusted certificates of the trust list for
// the validation of server certificates.
func (e *Enrollment) ClientOptions() ([]opcua.Option, error) {
	trusted, err := e.trustedCertificates()
	if err != nil {
		return nil, err
	}
	return []opcua.Option{
		opcua.Certificate(e.Certificate),
		opcua.PrivateKeySigner(e.PrivateKey),
		opcua.TrustedCertificates(trusted...),
	}, nil
}

// ServerOptions configures a server.Server with the enrollment: the
// application identity, and push management (server.WithPushManagement)
// with the trust list, so that the server validates client certificates
// against the trust list and its CRLs and can be managed by the push model
// afterwards.
func (e *Enrollment) ServerOptions() []server.Option {
	tl := e.TrustList
	if tl == nil {
		tl = &ua.TrustListDataType{}
	}
	return []server.Option{
		server.ApplicationIdentity(e.Certificate, e.PrivateKey),
		server.WithPushManagement(server.PushManagement{TrustList: tl}),
	}
}
