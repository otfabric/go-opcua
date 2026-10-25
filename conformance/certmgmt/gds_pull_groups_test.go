// SPDX-License-Identifier: MIT

package certmgmt

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

func gdsServerRecord(uri string) *gds.ApplicationRecord {
	return &gds.ApplicationRecord{
		ApplicationURI:   uri,
		ApplicationType:  ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("GDS app")},
		ProductURI:       "urn:otfabric:conformance",
		DiscoveryURLs:    []string{"opc.tcp://host.example:4841"},
	}
}

// TestGDSPull_HTTPSGroup: the DefaultHttpsGroup (Part 12 §7.9.12) of a
// server issues TLS certificates; a request for it may leave out the
// ApplicationUri.
func TestGDSPull_HTTPSGroup(t *testing.T) {
	g, url := gdsPullServer(t, gdsserver.Config{AutoApprove: true})
	_, admin := gdsPullClient(t, url, true)
	ctx := context.Background()
	appID, err := admin.RegisterApplication(ctx, gdsServerRecord("urn:otfabric:conformance:https"))
	require.NoError(t, err)
	groups, err := admin.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Len(t, groups, 3)
	require.True(t, groups[1].Equal(g.DefaultHTTPSGroup()))

	key, err := testpki.NewKey(testpki.CurveP256)
	require.NoError(t, err)
	csr, err := uapolicy.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "host.example"}, DNSNames: []string{"host.example"}}, key)
	require.NoError(t, err)
	reqID, err := admin.StartSigningRequest(ctx, appID, g.DefaultHTTPSGroup(), ua.NewNumericNodeID(0, id.HTTPSCertificateType), csr)
	require.NoError(t, err)
	res, err := admin.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	require.Equal(t, []string{"host.example"}, cert.DNSNames)
	issuer, err := x509.ParseCertificate(res.IssuerCertificates[0])
	require.NoError(t, err)
	require.NoError(t, cert.CheckSignatureFrom(issuer))

	tl, err := admin.ReadTrustList(ctx, appID, g.DefaultHTTPSGroup())
	require.NoError(t, err)
	require.Contains(t, tl.TrustedCertificates, res.IssuerCertificates[0])
	update, err := admin.GetCertificateStatus(ctx, appID, g.DefaultHTTPSGroup(), nil)
	require.NoError(t, err)
	require.False(t, update)
}

// TestGDSPull_BrainpoolPFXFileStore: a Brainpool certificate from a
// request, a key pair delivered as PFX (Part 12 §7.9.5) and the state in a
// FileStore across a restart of the GDS.
func TestGDSPull_BrainpoolPFXFileStore(t *testing.T) {
	store, err := gdsserver.NewFileStore(t.TempDir())
	require.NoError(t, err)
	bp := gds.EccBrainpoolP256r1ApplicationCertificateType
	g, url := gdsPullServer(t, gdsserver.Config{Store: store, AutoApprove: true,
		CertificateTypes: []*ua.NodeID{gds.EccNistP256ApplicationCertificateType, bp}})
	_, admin := gdsPullClient(t, url, true)
	ctx := context.Background()
	uri := "urn:otfabric:conformance:bp"
	appID, err := admin.RegisterApplication(ctx, gdsServerRecord(uri))
	require.NoError(t, err)

	key, err := testpki.NewKey(testpki.CurveBrainpoolP256r1)
	require.NoError(t, err)
	csr, err := gds.NewCertificateRequest(key, uri, "CN=bp", nil)
	require.NoError(t, err)
	reqID, err := admin.StartSigningRequest(ctx, appID, nil, bp, csr)
	require.NoError(t, err)
	res, err := admin.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate))
	cert, err := uapolicy.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	ca, err := uapolicy.ParseCertificate(res.IssuerCertificates[0])
	require.NoError(t, err)
	require.Equal(t, cert.Issuer.String(), ca.Subject.String())

	reqID, err = admin.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{
		CertificateType: gds.EccNistP256ApplicationCertificateType, PrivateKeyFormat: gds.PrivateKeyFormatPFX, PrivateKeyPassword: "pfx-pw"})
	require.NoError(t, err)
	res, err = admin.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	k, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPFX, res.PrivateKey, "pfx-pw")
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(k, res.Certificate))
	issuers := g.IssuerCertificates()

	// A second GDS on the same directory has the application, its
	// certificates and the CAs.
	g2, url2 := gdsPullServer(t, gdsserver.Config{Store: store,
		CertificateTypes: []*ua.NodeID{gds.EccNistP256ApplicationCertificateType, bp}})
	require.Equal(t, issuers, g2.IssuerCertificates())
	_, admin2 := gdsPullClient(t, url2, true)
	_, certs, err := admin2.GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, certs, 2)
}

// TestGDSPull_AuditEvents: the audit events of the GDS NodeSet (Part 12
// §6.6.x, §7.9.x) through the auditing of the server, without the
// password of StartNewKeyPairRequest and the key FinishRequest returns.
func TestGDSPull_AuditEvents(t *testing.T) {
	g, url := gdsPullServer(t, gdsserver.Config{AutoApprove: true}, server.WithAuditing(true))
	c, admin := gdsPullClient(t, url, true)
	ctx := context.Background()
	ns := g.Namespace()

	f := ua.NewEventFilter().TypeDefinition(ua.NewNumericNodeID(0, id.BaseEventType)).
		Select("EventType", "SourceName", "Status", "InputArguments", "OutputArguments", "CertificateGroup", "CertificateType")
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(f.Build(), ua.NewNumericNodeID(ns, gdsid.Directory)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	var got [][]*ua.Variant
	next := func() []*ua.Variant {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for len(got) == 0 {
			select {
			case msg := <-ch:
				require.NoError(t, msg.Error)
				if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
					for _, ev := range enl.Events {
						got = append(got, ev.EventFields)
					}
				}
			case <-deadline:
				t.Fatal("no audit event")
			}
		}
		ev := got[0]
		got = got[1:]
		return ev
	}

	appID, err := admin.RegisterApplication(ctx, gdsServerRecord("urn:otfabric:conformance:audit"))
	require.NoError(t, err)
	ev := next()
	require.True(t, ev[0].Value().(*ua.NodeID).Equal(ua.NewNumericNodeID(ns, gdsid.ApplicationRegistrationChangedAuditEventType)))
	require.Equal(t, true, ev[2].Value())

	reqID, err := admin.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{
		CertificateType: gds.EccNistP256ApplicationCertificateType, PrivateKeyPassword: "secret"})
	require.NoError(t, err)
	ev = next()
	require.True(t, ev[0].Value().(*ua.NodeID).Equal(ua.NewNumericNodeID(ns, gdsid.CertificateRequestedAuditEventType)))
	require.Nil(t, ev[3].Value().([]*ua.Variant)[6].Value(), "no password")
	require.True(t, ev[5].Value().(*ua.NodeID).Equal(g.DefaultApplicationGroup()))
	require.True(t, ev[6].Value().(*ua.NodeID).Equal(gds.EccNistP256ApplicationCertificateType))

	res, err := admin.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	ev = next()
	require.True(t, ev[0].Value().(*ua.NodeID).Equal(ua.NewNumericNodeID(ns, gdsid.CertificateDeliveredAuditEventType)))
	require.Nil(t, ev[4].Value().([]*ua.Variant)[1].Value(), "no private key")

	require.NoError(t, admin.RevokeCertificate(ctx, appID, res.Certificate))
	ev = next()
	require.True(t, ev[0].Value().(*ua.NodeID).Equal(ua.NewNumericNodeID(ns, gdsid.CertificateRevokedAuditEventType)))
	require.Equal(t, "Method/RevokeCertificate", ev[1].Value())
}
