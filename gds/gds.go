// SPDX-License-Identifier: MIT

// Package gds manages the certificates of an OPC UA server by the push
// model of OPC UA Part 12 §7: a client with the SecurityAdmin role reads and
// writes the trust list of the server (the TrustList file of a certificate
// group, Part 12 §7.8.2), asks the server for a certificate signing request
// (CreateSigningRequest), installs the certificate a CA issued for it
// (UpdateCertificate), reads the certificates the server rejected
// (GetRejectedList) and makes the changes take effect (ApplyChanges).
//
// It works with any server that implements the ServerConfiguration object
// (Part 12 §7.10.3): this module's server with server.WithPushManagement,
// open62541 built with UA_ENABLE_GDS_PUSHMANAGEMENT, UA-.NETStandard and
// node-opcua. Part 12 requires a session with the SecurityAdmin role over a
// SignAndEncrypt channel; servers refuse the methods otherwise.
//
// Beyond the methods of Part 12 1.04 it calls GetCertificates,
// CreateSelfSignedCertificate, DeleteCertificate and ResetToServerDefaults
// (Part 12 1.05 §7.10) and reads the TransactionDiagnostics.
// CertificateGroups lists the certificate groups of a server, the default
// ones and those of the application; their trust lists, like those of the
// DefaultHttpsGroup and the DefaultUserTokenGroup, are reached with
// WithTrustList. A private key for UpdateCertificate may be PEM or PFX
// (uapolicy.EncodePFX).
//
// PullClient is the client of the pull model (Part 12 §6 and §7.9): it
// registers an application with a Global Discovery Server, asks it for a
// certificate (StartSigningRequest, StartNewKeyPairRequest), waits for it
// (FinishRequest), reads the trust list and checks revocation. Enroll does
// all of it, and an Enrollment configures an opcua.Client or a
// server.Server. Package gdsserver is the server side.
package gds

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the thumbprint of Part 6 §6.2.3 is SHA-1
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Well-known nodes of the ServerConfiguration object.
var (
	// ServerConfiguration is the ServerConfiguration object (i=12637).
	ServerConfiguration = ua.NewNumericNodeID(0, id.ServerConfiguration)
	// DefaultApplicationGroup is the certificate group of the application
	// instance certificates (i=14156).
	DefaultApplicationGroup = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroup)
	// DefaultTrustList is the TrustList of the DefaultApplicationGroup
	// (i=12642).
	DefaultTrustList = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList)
	// DefaultHTTPSGroup is the certificate group of the TLS certificate of
	// the HTTPS endpoints (DefaultHttpsGroup, i=14088).
	DefaultHTTPSGroup = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup)
	// HTTPSTrustList is the TrustList of the DefaultHttpsGroup (i=14089).
	HTTPSTrustList = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustList)
	// DefaultUserTokenGroup is the certificate group whose trust list
	// validates X.509 user identity tokens (i=14122).
	DefaultUserTokenGroup = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup)
	// UserTokenTrustList is the TrustList of the DefaultUserTokenGroup
	// (i=14123).
	UserTokenTrustList = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustList)
)

// HTTPSCertificateType is the certificate type of the DefaultHttpsGroup
// (Part 12 §7.8.4).
var HTTPSCertificateType = ua.NewNumericNodeID(0, id.HTTPSCertificateType)

// Certificate types of application instance certificates (Part 12 §7.8.4).
var (
	RsaSha256ApplicationCertificateType          = ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType)
	RsaMinApplicationCertificateType             = ua.NewNumericNodeID(0, id.RsaMinApplicationCertificateType)
	EccNistP256ApplicationCertificateType        = ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)
	EccNistP384ApplicationCertificateType        = ua.NewNumericNodeID(0, id.EccNistP384ApplicationCertificateType)
	EccBrainpoolP256r1ApplicationCertificateType = ua.NewNumericNodeID(0, id.EccBrainpoolP256r1ApplicationCertificateType)
	EccBrainpoolP384r1ApplicationCertificateType = ua.NewNumericNodeID(0, id.EccBrainpoolP384r1ApplicationCertificateType)
	EccCurve25519ApplicationCertificateType      = ua.NewNumericNodeID(0, id.EccCurve25519ApplicationCertificateType)
	EccCurve448ApplicationCertificateType        = ua.NewNumericNodeID(0, id.EccCurve448ApplicationCertificateType)
)

// Client calls the push management methods of a server over the session of
// an opcua.Client.
type Client struct {
	c *opcua.Client

	// TrustList is the TrustList object the trust list methods use
	// (default DefaultTrustList).
	TrustList *ua.NodeID

	mu      sync.Mutex
	methods map[string]*ua.NodeID
}

// New returns a Client that uses the session of c.
func New(c *opcua.Client) *Client {
	return &Client{c: c, TrustList: DefaultTrustList, methods: map[string]*ua.NodeID{}}
}

// WithTrustList returns a Client over the same session whose trust list
// methods use the TrustList object tl, for example HTTPSTrustList or
// UserTokenTrustList.
func (g *Client) WithTrustList(tl *ua.NodeID) *Client {
	return &Client{c: g.c, TrustList: tl, methods: map[string]*ua.NodeID{}}
}

// Error is the Bad status a method call returned.
type Error struct {
	Method string
	Status ua.StatusCode
}

func (e *Error) Error() string { return fmt.Sprintf("gds: %s: %v", e.Method, e.Status) }

// Unwrap returns the status, so errors.Is(err, ua.StatusBadXxx) holds.
func (e *Error) Unwrap() error { return e.Status }

// badStatus reports whether err is a Bad ua.StatusCode.
func badStatus(err error) bool {
	var sc ua.StatusCode
	return errors.As(err, &sc) && sc&ua.StatusBad != 0
}

// method finds the method name of an object: a forward HasComponent
// reference to a Method with that BrowseName, or the fallback.
func (g *Client) method(ctx context.Context, obj *ua.NodeID, name string, fallback uint32) (*ua.NodeID, error) {
	key := obj.String() + "\x00" + name
	g.mu.Lock()
	m := g.methods[key]
	g.mu.Unlock()
	if m != nil {
		return m, nil
	}
	refs, err := g.c.Node(obj).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassMethod, true)
	if badStatus(err) {
		// The object cannot be browsed (e.g. Bad_NodeIdUnknown or
		// Bad_UserAccessDenied as the Browse result, Part 4 §5.8.2.2): call
		// the standard method and let the Call service report the status.
		// Not cached, the next call browses again.
		return ua.NewNumericNodeID(0, fallback), nil
	}
	if err != nil {
		return nil, err
	}
	m = ua.NewNumericNodeID(0, fallback)
	for _, ref := range refs {
		if ref.BrowseName != nil && ref.BrowseName.Name == name && ref.NodeID != nil {
			m = ref.NodeID.NodeID
			break
		}
	}
	g.mu.Lock()
	g.methods[key] = m
	g.mu.Unlock()
	return m, nil
}

func (g *Client) call(ctx context.Context, obj *ua.NodeID, name string, fallback uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	m, err := g.method(ctx, obj, name, fallback)
	if err != nil {
		return nil, err
	}
	res, err := g.c.Call(ctx, &ua.CallMethodRequest{ObjectID: obj, MethodID: m, InputArguments: args})
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

func boolOut(name string, v *ua.Variant) (bool, error) {
	b, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("gds: %s returned %T, want a Boolean", name, v.Value())
	}
	return b, nil
}

func nodeOrNull(n *ua.NodeID) *ua.NodeID {
	if n == nil {
		return ua.NewTwoByteNodeID(0)
	}
	return n
}

func groupOrDefault(n *ua.NodeID) *ua.NodeID {
	if n == nil {
		return DefaultApplicationGroup
	}
	return n
}

func byteStrings(xs [][]byte) [][]byte {
	if xs == nil {
		return [][]byte{}
	}
	return xs
}

// SigningRequest is the input of CreateSigningRequest (Part 12 §7.10.7).
type SigningRequest struct {
	// CertificateGroup is the certificate group (nil: the
	// DefaultApplicationGroup).
	CertificateGroup *ua.NodeID
	// CertificateType is the type of the certificate to replace, for
	// example RsaSha256ApplicationCertificateType (nil: a null NodeId,
	// which some servers take as their first certificate).
	CertificateType *ua.NodeID
	// SubjectName is the subject of the request, as X.500 name value pairs
	// separated by '/' ("CN=App/O=Company"); empty keeps the subject of the
	// current certificate.
	SubjectName string
	// RegeneratePrivateKey asks the server for a new key.
	RegeneratePrivateKey bool
	// Nonce is the entropy for the new key (at least 32 bytes); nil with
	// RegeneratePrivateKey generates 32 random bytes.
	Nonce []byte
}

// CreateSigningRequest asks the server for a PKCS #10 certificate signing
// request (DER) for a new application instance certificate. A CA issues the
// certificate, which UpdateCertificate installs.
func (g *Client) CreateSigningRequest(ctx context.Context, req *SigningRequest) ([]byte, error) {
	nonce := req.Nonce
	if req.RegeneratePrivateKey && nonce == nil {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	if nonce == nil {
		nonce = []byte{}
	}
	out, err := g.call(ctx, ServerConfiguration, "CreateSigningRequest", id.ServerConfigurationCreateSigningRequest, 1,
		ua.MustVariant(groupOrDefault(req.CertificateGroup)), ua.MustVariant(nodeOrNull(req.CertificateType)),
		ua.MustVariant(req.SubjectName), ua.MustVariant(req.RegeneratePrivateKey), ua.MustVariant(nonce))
	if err != nil {
		return nil, err
	}
	csr, ok := out[0].Value().([]byte)
	if !ok || len(csr) == 0 {
		return nil, fmt.Errorf("gds: CreateSigningRequest returned no certificate request")
	}
	return csr, nil
}

// CertificateUpdate is the input of UpdateCertificate (Part 12 §7.10.4).
type CertificateUpdate struct {
	// CertificateGroup is the certificate group (nil: the
	// DefaultApplicationGroup).
	CertificateGroup *ua.NodeID
	// CertificateType is the type of the certificate to replace (nil: a
	// null NodeId).
	CertificateType *ua.NodeID
	// Certificate is the new application instance certificate (DER).
	Certificate []byte
	// IssuerCertificates are the CA certificates that issued it (DER).
	IssuerCertificates [][]byte
	// PrivateKeyFormat ("PEM" or "PFX") and PrivateKey carry the private
	// key of a certificate the server did not request; both are empty when
	// the certificate was issued for a CreateSigningRequest.
	PrivateKeyFormat string
	PrivateKey       []byte
}

// UpdateCertificate installs a new application instance certificate. It
// reports whether ApplyChanges must be called before the server uses it.
func (g *Client) UpdateCertificate(ctx context.Context, u *CertificateUpdate) (applyChangesRequired bool, err error) {
	key := u.PrivateKey
	if key == nil {
		key = []byte{}
	}
	out, err := g.call(ctx, ServerConfiguration, "UpdateCertificate", id.ServerConfigurationUpdateCertificate, 1,
		ua.MustVariant(groupOrDefault(u.CertificateGroup)), ua.MustVariant(nodeOrNull(u.CertificateType)),
		ua.MustVariant(u.Certificate), ua.MustVariant(byteStrings(u.IssuerCertificates)),
		ua.MustVariant(u.PrivateKeyFormat), ua.MustVariant(key))
	if err != nil {
		return false, err
	}
	return boolOut("UpdateCertificate", out[0])
}

// GetRejectedList returns the certificates the server rejected (DER).
func (g *Client) GetRejectedList(ctx context.Context) ([][]byte, error) {
	out, err := g.call(ctx, ServerConfiguration, "GetRejectedList", id.ServerConfigurationGetRejectedList, 1)
	if err != nil {
		return nil, err
	}
	switch v := out[0].Value().(type) {
	case [][]byte:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("gds: GetRejectedList returned %T, want a ByteString array", v)
	}
}

// ApplyChanges makes the server apply the pending changes (Part 12
// §7.10.6): the new trust list for new connections and the new
// certificates for new SecureChannels.
func (g *Client) ApplyChanges(ctx context.Context) error {
	_, err := g.call(ctx, ServerConfiguration, "ApplyChanges", id.ServerConfigurationApplyChanges, 0)
	return err
}

// CancelChanges drops the pending changes (Part 12 §7.10.10).
func (g *Client) CancelChanges(ctx context.Context) error {
	_, err := g.call(ctx, ServerConfiguration, "CancelChanges", id.ServerConfigurationCancelChanges, 0)
	return err
}

// Properties are the properties of the ServerConfiguration object.
type Properties struct {
	ServerCapabilities         []string
	SupportedPrivateKeyFormats []string
	MaxTrustListSize           uint32
	MulticastDNSEnabled        bool
	// CertificateTypes are the certificate types of the
	// DefaultApplicationGroup.
	CertificateTypes []*ua.NodeID
}

// Properties reads the properties of the ServerConfiguration object and the
// CertificateTypes of the DefaultApplicationGroup.
func (g *Client) Properties(ctx context.Context) (*Properties, error) {
	dvs, err := g.c.ReadValues(ctx,
		ua.NewNumericNodeID(0, id.ServerConfigurationServerCapabilities),
		ua.NewNumericNodeID(0, id.ServerConfigurationSupportedPrivateKeyFormats),
		ua.NewNumericNodeID(0, id.ServerConfigurationMaxTrustListSize),
		ua.NewNumericNodeID(0, id.ServerConfigurationMulticastDNSEnabled),
		ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupCertificateTypes),
	)
	if err != nil {
		return nil, err
	}
	val := func(i int) any {
		if i < len(dvs) && dvs[i] != nil && dvs[i].Status == ua.StatusOK && dvs[i].Value != nil {
			return dvs[i].Value.Value()
		}
		return nil
	}
	p := &Properties{}
	p.ServerCapabilities, _ = val(0).([]string)
	p.SupportedPrivateKeyFormats, _ = val(1).([]string)
	p.MaxTrustListSize, _ = val(2).(uint32)
	p.MulticastDNSEnabled, _ = val(3).(bool)
	p.CertificateTypes, _ = val(4).([]*ua.NodeID)
	return p, nil
}

// Thumbprint returns the thumbprint of a DER certificate as
// RemoveCertificate takes it: the SHA-1 of the certificate in upper-case
// hexadecimal. Part 12 §7.8.2.6 does not fix the case; UA-.NETStandard
// compares it case-sensitively with upper-case thumbprints, the go-opcua,
// open62541 and node-opcua servers accept either.
func Thumbprint(cert []byte) string {
	sum := sha1.Sum(cert) //nolint:gosec // the thumbprint of Part 6 §6.2.3 is SHA-1
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// errNoTrustList reports a TrustList file that does not hold a trust list.
var errNoTrustList = errors.New("gds: the TrustList file does not hold a TrustListDataType")
