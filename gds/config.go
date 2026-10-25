// SPDX-License-Identifier: MIT

package gds

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// trustListMethods are the NodeIds of the TrustList methods of the
// certificate groups of ServerConfiguration, the fallback where a server
// does not browse them.
var trustListMethods = map[uint32]map[string]uint32{
	id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustList: {
		"Open":              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpen,
		"OpenWithMasks":     id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpenWithMasks,
		"Close":             id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListClose,
		"Read":              id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListRead,
		"Write":             id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListWrite,
		"CloseAndUpdate":    id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListCloseAndUpdate,
		"AddCertificate":    id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListAddCertificate,
		"RemoveCertificate": id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListRemoveCertificate,
	},
	id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustList: {
		"Open":              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListOpen,
		"OpenWithMasks":     id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListOpenWithMasks,
		"Close":             id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListClose,
		"Read":              id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListRead,
		"Write":             id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListWrite,
		"CloseAndUpdate":    id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListCloseAndUpdate,
		"AddCertificate":    id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListAddCertificate,
		"RemoveCertificate": id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListRemoveCertificate,
	},
}

// trustListFallback returns the fallback NodeId of a TrustList method of
// the client's TrustList; fallback is that of the DefaultApplicationGroup.
func (g *Client) trustListFallback(name string, fallback uint32) uint32 {
	if tl := g.TrustList; tl != nil && tl.Namespace() == 0 {
		if m, ok := trustListMethods[tl.IntID()][name]; ok {
			return m
		}
	}
	return fallback
}

// GetCertificates returns the certificate types and the certificates (DER)
// of a certificate group that the server uses (Part 12 §7.10.8); nil is
// the DefaultApplicationGroup.
func (g *Client) GetCertificates(ctx context.Context, group *ua.NodeID) ([]*ua.NodeID, [][]byte, error) {
	out, err := g.call(ctx, ServerConfiguration, "GetCertificates", id.ServerConfigurationGetCertificates, 2, ua.MustVariant(groupOrDefault(group)))
	if err != nil {
		return nil, nil, err
	}
	var (
		types []*ua.NodeID
		certs [][]byte
		ok1   = out[0].Value() == nil
		ok2   = out[1].Value() == nil
	)
	if !ok1 {
		types, ok1 = out[0].Value().([]*ua.NodeID)
	}
	if !ok2 {
		certs, ok2 = out[1].Value().([][]byte)
	}
	if !ok1 || !ok2 || len(types) != len(certs) {
		return nil, nil, fmt.Errorf("gds: GetCertificates returned %T and %T, want NodeId and ByteString arrays of the same length", out[0].Value(), out[1].Value())
	}
	return types, certs, nil
}

// SelfSignedCertificate is the input of CreateSelfSignedCertificate (Part
// 12 §7.10.5).
type SelfSignedCertificate struct {
	// CertificateGroup is the certificate group (nil: the
	// DefaultApplicationGroup).
	CertificateGroup *ua.NodeID
	// CertificateType is the type of the certificate to replace (nil: a
	// null NodeId).
	CertificateType *ua.NodeID
	// SubjectName is the subject as X.500 name value pairs separated by
	// '/'; empty keeps the subject of the current certificate.
	SubjectName string
	// DNSNames and IPAddresses are the names of the certificate; with both
	// empty the server keeps those of the current certificate.
	DNSNames    []string
	IPAddresses []string
	// LifetimeInDays is the validity (0: the server's default).
	LifetimeInDays uint16
	// KeySizeInBits is the size of the new key (0: the server's default).
	KeySizeInBits uint16
}

func stringsOrEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// CreateSelfSignedCertificate has the server create a new key and a
// self-signed certificate for it, which replaces the current certificate
// of the type when the changes are applied. It returns the certificate.
func (g *Client) CreateSelfSignedCertificate(ctx context.Context, req *SelfSignedCertificate) ([]byte, error) {
	out, err := g.call(ctx, ServerConfiguration, "CreateSelfSignedCertificate", id.ServerConfigurationCreateSelfSignedCertificate, 1,
		ua.MustVariant(groupOrDefault(req.CertificateGroup)), ua.MustVariant(nodeOrNull(req.CertificateType)),
		ua.MustVariant(req.SubjectName), ua.MustVariant(stringsOrEmpty(req.DNSNames)), ua.MustVariant(stringsOrEmpty(req.IPAddresses)),
		ua.MustVariant(req.LifetimeInDays), ua.MustVariant(req.KeySizeInBits))
	if err != nil {
		return nil, err
	}
	cert, ok := out[0].Value().([]byte)
	if !ok || len(cert) == 0 {
		return nil, fmt.Errorf("gds: CreateSelfSignedCertificate returned no certificate")
	}
	return cert, nil
}

// ResetToServerDefaults has the server go back to the trust lists and
// certificates of its default configuration (Part 12 §7.10.13).
func (g *Client) ResetToServerDefaults(ctx context.Context) error {
	_, err := g.call(ctx, ServerConfiguration, "ResetToServerDefaults", id.ServerConfigurationResetToServerDefaults, 0)
	return err
}

// TransactionDiagnostics are the diagnostics of the last transaction of
// the server, or of the one in progress (TransactionDiagnosticsType, Part
// 12 §7.10.11).
type TransactionDiagnostics struct {
	StartTime, EndTime        time.Time
	Result                    ua.StatusCode
	AffectedTrustLists        []*ua.NodeID
	AffectedCertificateGroups []*ua.NodeID
	Errors                    []*ua.TransactionErrorType
}

// TransactionDiagnostics reads the TransactionDiagnostics object of
// ServerConfiguration, which servers show to SecurityAdmin only.
func (g *Client) TransactionDiagnostics(ctx context.Context) (*TransactionDiagnostics, error) {
	ids := []uint32{
		id.ServerConfigurationTransactionDiagnosticsStartTime,
		id.ServerConfigurationTransactionDiagnosticsEndTime,
		id.ServerConfigurationTransactionDiagnosticsResult,
		id.ServerConfigurationTransactionDiagnosticsAffectedTrustLists,
		id.ServerConfigurationTransactionDiagnosticsAffectedCertificateGroups,
		id.ServerConfigurationTransactionDiagnosticsErrors,
	}
	nodes := make([]*ua.NodeID, len(ids))
	for i, n := range ids {
		nodes[i] = ua.NewNumericNodeID(0, n)
	}
	dvs, err := g.c.ReadValues(ctx, nodes...)
	if err != nil {
		return nil, err
	}
	if len(dvs) != len(ids) {
		return nil, fmt.Errorf("gds: TransactionDiagnostics: %d values, want %d", len(dvs), len(ids))
	}
	vals := make([]any, len(dvs))
	for i, dv := range dvs {
		switch {
		case dv == nil:
			return nil, &Error{Method: "TransactionDiagnostics", Status: ua.StatusBad}
		case dv.Status != ua.StatusOK:
			return nil, &Error{Method: "TransactionDiagnostics", Status: dv.Status}
		case dv.Value != nil:
			vals[i] = dv.Value.Value()
		}
	}
	d := &TransactionDiagnostics{}
	d.StartTime, _ = vals[0].(time.Time)
	d.EndTime, _ = vals[1].(time.Time)
	d.Result, _ = vals[2].(ua.StatusCode)
	d.AffectedTrustLists, _ = vals[3].([]*ua.NodeID)
	d.AffectedCertificateGroups, _ = vals[4].([]*ua.NodeID)
	if eos, ok := vals[5].([]*ua.ExtensionObject); ok {
		for _, eo := range eos {
			if e, ok := eo.Value.(*ua.TransactionErrorType); ok {
				d.Errors = append(d.Errors, e)
			}
		}
	}
	return d, nil
}

// DeleteCertificate has the server delete the certificate of a type of a
// certificate group (nil: the DefaultApplicationGroup) when the changes are
// applied (DeleteCertificate, Part 12 1.05 §7.10); certType nil is a null
// NodeId. A server refuses it with Bad_InvalidState if the group has no
// certificate of the type, and ApplyChanges fails with Bad_InvalidState
// for a certificate one of its endpoints uses. Deleting a certificate and
// then creating or updating one of the type in the same transaction
// replaces it, which servers that refuse to overwrite a certificate
// require.
func (g *Client) DeleteCertificate(ctx context.Context, group, certType *ua.NodeID) error {
	_, err := g.call(ctx, ServerConfiguration, "DeleteCertificate", id.ServerConfigurationDeleteCertificate, 0,
		ua.MustVariant(groupOrDefault(group)), ua.MustVariant(nodeOrNull(certType)))
	return err
}

// CertificateGroup is a certificate group of a server's CertificateGroups
// folder.
type CertificateGroup struct {
	// Name is its BrowseName.
	Name string
	// Group is its NodeId, the CertificateGroupId of the methods.
	Group *ua.NodeID
	// TrustList is the NodeId of its TrustList object, for WithTrustList.
	TrustList *ua.NodeID
}

// CertificateGroups browses the certificate groups of the server: the
// default ones and those the application added (Part 12 §7.8.3.3).
func (g *Client) CertificateGroups(ctx context.Context) ([]CertificateGroup, error) {
	folder := ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroups)
	refs, err := g.c.Node(folder).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	if err != nil {
		return nil, err
	}
	var out []CertificateGroup
	for _, ref := range refs {
		if ref.NodeID == nil || ref.BrowseName == nil {
			continue
		}
		cg := CertificateGroup{Name: ref.BrowseName.Name, Group: ref.NodeID.NodeID}
		children, err := g.c.Node(cg.Group).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, true)
		if err != nil {
			return nil, err
		}
		for _, c := range children {
			if c.NodeID != nil && c.BrowseName != nil && c.BrowseName.Name == "TrustList" {
				cg.TrustList = c.NodeID.NodeID
			}
		}
		if cg.TrustList != nil {
			out = append(out, cg)
		}
	}
	return out, nil
}
