// SPDX-License-Identifier: MIT

package certmgmt

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestGDSPush_DeleteCertificate: Part 12 1.05 §7.10, DeleteCertificate.
// The method is a component of ServerConfiguration with the arguments of
// ServerConfigurationType. A certificate no endpoint advertises goes with
// ApplyChanges; a type without a certificate is Bad_InvalidState; the
// certificate of the endpoints is refused at ApplyChanges ("Certificates
// that are referenced by EndpointDescriptions shall not be deleted"),
// which the TransactionDiagnostics record. Deleting and creating in one
// transaction replaces a certificate.
func TestGDSPush_DeleteCertificate(t *testing.T) {
	p := pki(t)
	src, err := testpki.Get()
	require.NoError(t, err)
	p384 := src.ECC.Server[testpki.CurveP384]
	_, url := pushServerWith(t, server.PushManagement{}, server.ApplicationIdentity(p384.Cert, p384.Key))
	c, g := pushAdminClient(t, url)
	ctx := context.Background()

	m, err := c.Node(gds.ServerConfiguration).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "DeleteCertificate"}})
	require.NoError(t, err)
	require.True(t, m.Equal(ua.NewNumericNodeID(0, id.ServerConfigurationDeleteCertificate)))
	args, err := c.Node(m).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "InputArguments"}})
	require.NoError(t, err)
	dv, err := c.ReadValue(ctx, args)
	require.NoError(t, err)
	var names []string
	for _, eo := range dv.Value.Value().([]*ua.ExtensionObject) {
		names = append(names, eo.Value.(*ua.Argument).Name)
	}
	require.Equal(t, []string{"CertificateGroupId", "CertificateTypeId"}, names)

	p384Type := gds.EccNistP384ApplicationCertificateType
	require.NoError(t, g.DeleteCertificate(ctx, nil, p384Type))
	_, certs, err := g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Contains(t, certs, p384.Cert, "not before ApplyChanges")
	require.ErrorIs(t, g.DeleteCertificate(ctx, nil, p384Type), ua.StatusBadInvalidState)
	require.NoError(t, g.ApplyChanges(ctx))
	types, certs, err := g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.RsaSha256ApplicationCertificateType}, types)
	require.Equal(t, [][]byte{p.serverCert}, certs)
	require.ErrorIs(t, g.DeleteCertificate(ctx, nil, p384Type), ua.StatusBadInvalidState)

	// The type can be filled again, and delete-then-create replaces.
	cert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateType: p384Type, SubjectName: "CN=p384/O=otfabric"})
	require.NoError(t, err)
	require.NoError(t, g.ApplyChanges(ctx))
	require.NoError(t, g.DeleteCertificate(ctx, nil, p384Type))
	cert2, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateType: p384Type})
	require.NoError(t, err)
	require.NoError(t, g.ApplyChanges(ctx))
	_, certs, err = g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.serverCert, cert2}, certs)
	parsed, err := x509.ParseCertificate(cert2)
	require.NoError(t, err)
	require.Equal(t, "p384", parsed.Subject.CommonName, "the subject of the deleted certificate")
	require.NotEqual(t, cert, cert2)

	// The certificate of the endpoints stays.
	require.NoError(t, g.DeleteCertificate(ctx, nil, gds.RsaSha256ApplicationCertificateType))
	require.ErrorIs(t, g.ApplyChanges(ctx), ua.StatusBadInvalidState)
	d, err := g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadInvalidState, d.Result)
	require.Len(t, d.Errors, 1)
	require.True(t, d.Errors[0].TargetID.Equal(gds.DefaultApplicationGroup))
	require.NoError(t, g.CancelChanges(ctx))
	require.Equal(t, p.serverCert, endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt).ServerCertificate)
}

// TestGDSPush_ApplicationGroups: Part 12 §7.8.3.3, a CertificateGroupFolder
// with a certificate group of the application beside the default ones: a
// CertificateGroupType object with its TrustList, CertificateTypes and
// alarms, whose certificates and trust list the methods of
// ServerConfiguration manage in the transactions.
func TestGDSPush_ApplicationGroups(t *testing.T) {
	p := pki(t)
	src, err := testpki.Get()
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(src.CACert)
	require.NoError(t, err)
	tlsClient := ua.NewNumericNodeID(0, id.TLSClientCertificateType)
	srv, url := pushServerWith(t, server.PushManagement{
		CertificateGroups: []server.CertificateGroup{{Name: "Outgoing", CertificateTypes: []*ua.NodeID{tlsClient, gds.RsaSha256ApplicationCertificateType}}},
		Alarms:            &server.CertificateAlarms{ExpirationLimit: 48 * time.Hour},
	})
	c, g := pushAdminClient(t, url)
	ctx := context.Background()

	groups, err := g.CertificateGroups(ctx)
	require.NoError(t, err)
	require.Len(t, groups, 4)
	out := groups[3]
	require.Equal(t, "Outgoing", out.Name)
	require.True(t, out.Group.Equal(srv.CertificateGroupID("Outgoing")))
	typeDef, err := c.Node(out.Group).References(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, typeDef, 1)
	require.Equal(t, uint32(id.CertificateGroupType), typeDef[0].NodeID.NodeID.IntID())
	child := func(names ...string) *ua.NodeID {
		t.Helper()
		qn := make([]*ua.QualifiedName, len(names))
		for i, n := range names {
			qn[i] = &ua.QualifiedName{Name: n}
		}
		nid, err := c.Node(out.Group).TranslateBrowsePathsToNodeIDs(ctx, qn)
		require.NoError(t, err, "%v", names)
		return nid
	}
	read := func(n *ua.NodeID) any {
		t.Helper()
		dv, err := c.ReadValue(ctx, n)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, dv.Status)
		return dv.Value.Value()
	}
	require.Equal(t, []*ua.NodeID{tlsClient, gds.RsaSha256ApplicationCertificateType}, read(child("CertificateTypes")))
	require.True(t, child("TrustList").Equal(out.TrustList))
	// Without a certificate the expiry alarm is inactive.
	require.Equal(t, false, read(child("CertificateExpired", "ActiveState", "Id")))

	// The trust list.
	tl := g.WithTrustList(out.TrustList)
	required, err := tl.WriteTrustList(ctx, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll), TrustedCertificates: [][]byte{src.CACert}})
	require.NoError(t, err)
	require.True(t, required)
	require.ErrorIs(t, srv.VerifyGroupCertificate(out.Group, src.IssuedCert), ua.StatusBadCertificateUntrusted)

	// An RSA certificate the CA issues for a signing request, and a
	// self-signed TLS client certificate, in the same transaction.
	csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{
		CertificateGroup: out.Group, CertificateType: gds.RsaSha256ApplicationCertificateType,
		SubjectName: "CN=outgoing/O=otfabric", RegeneratePrivateKey: true,
	})
	require.NoError(t, err)
	issued, err := testpki.IssueFromCSR(csr, ca, src.CAKey)
	require.NoError(t, err)
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateGroup: out.Group, CertificateType: gds.RsaSha256ApplicationCertificateType,
		Certificate: issued, IssuerCertificates: [][]byte{src.CACert},
	})
	require.NoError(t, err)
	tlsCert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateGroup: out.Group, CertificateType: tlsClient, SubjectName: "CN=tls-client"})
	require.NoError(t, err)
	d, err := g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{out.TrustList}, d.AffectedTrustLists)
	require.Equal(t, []*ua.NodeID{out.Group}, d.AffectedCertificateGroups)
	require.NoError(t, g.ApplyChanges(ctx))

	types, certs, err := g.GetCertificates(ctx, out.Group)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{tlsClient, gds.RsaSha256ApplicationCertificateType}, types)
	require.Equal(t, [][]byte{tlsCert, issued}, certs)
	require.NoError(t, srv.VerifyGroupCertificate(out.Group, src.IssuedCert))
	cert, issuers, key := srv.GroupCertificate(out.Group, gds.RsaSha256ApplicationCertificateType)
	require.Equal(t, issued, cert)
	require.Equal(t, [][]byte{src.CACert}, issuers)
	require.NotNil(t, key)
	// The certificates of the PKI are valid for a day: the alarm of the
	// group becomes active (evaluated by the server's goroutine).
	require.Eventually(t, func() bool {
		dv, err := c.ReadValue(ctx, child("CertificateExpired", "ActiveState", "Id"))
		return err == nil && dv.Value != nil && dv.Value.Value() == true
	}, 10*time.Second, 5*time.Millisecond)
	// The default groups are unchanged.
	_, certs, err = g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.serverCert}, certs)

	// ResetToServerDefaults empties the group again.
	require.NoError(t, g.ResetToServerDefaults(ctx))
	types, _, err = g.GetCertificates(ctx, out.Group)
	require.NoError(t, err)
	require.Empty(t, types)
	got, err := tl.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Empty(t, got.TrustedCertificates)
}
