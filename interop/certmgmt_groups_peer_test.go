//go:build interop

// SPDX-License-Identifier: MIT

// The Part 12 (1.05) push management methods and objects beyond the trust
// list and the certificate update of the DefaultApplicationGroup, from
// package gds against the peer servers of pushPeers: GetCertificates,
// CreateSelfSignedCertificate, the TransactionDiagnostics, the trust lists
// of the DefaultHTTPSGroup and DefaultUserTokenGroup, a PFX private key in
// UpdateCertificate, the certificate alarms and ResetToServerDefaults. A
// peer that does not implement one refuses it; the subtest then skips with
// the status the peer answered.

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// peerRefuses skips when err is the refusal of a method or node that the
// peer does not implement, and reports whether it did.
func peerRefuses(t *testing.T, what string, err error) {
	t.Helper()
	for _, sc := range []ua.StatusCode{ua.StatusBadMethodInvalid, ua.StatusBadNodeIDUnknown, ua.StatusBadNotImplemented,
		ua.StatusBadNotSupported, ua.StatusBadServiceUnsupported, ua.StatusBadNoMatch, ua.StatusBadAttributeIDInvalid} {
		if errors.Is(err, sc) {
			t.Skipf("the peer does not implement %s: %v", what, err)
		}
	}
}

// refusal reports whether err is the refusal of a method the peer does not
// implement (see peerRefuses).
func refusal(err error) bool {
	for _, sc := range []ua.StatusCode{ua.StatusBadMethodInvalid, ua.StatusBadNodeIDUnknown, ua.StatusBadNotImplemented,
		ua.StatusBadNotSupported, ua.StatusBadServiceUnsupported} {
		if errors.Is(err, sc) {
			return true
		}
	}
	return false
}

// emptySlot returns a certificate group and type of the peer without a
// certificate: a type of the CertificateTypes of the
// DefaultApplicationGroup or the DefaultHttpsGroup that GetCertificates
// does not return. It returns nils if there is none.
func emptySlot(t *testing.T, ctx context.Context, c *opcua.Client, g *gds.Client) (*ua.NodeID, *ua.NodeID) {
	t.Helper()
	for _, group := range []*ua.NodeID{gds.DefaultApplicationGroup, gds.DefaultHTTPSGroup} {
		nid, err := c.Node(group).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "CertificateTypes"}})
		if err != nil {
			continue
		}
		dv, err := c.ReadValue(ctx, nid)
		if err != nil || dv.Value == nil {
			continue
		}
		types, _ := dv.Value.Value().([]*ua.NodeID)
		used, _, err := g.GetCertificates(ctx, group)
		if err != nil {
			continue
		}
		t.Logf("%v: CertificateTypes %v, GetCertificates %v", group, types, used)
		for _, typ := range types {
			if !slices.ContainsFunc(used, typ.Equal) {
				return group, typ
			}
		}
	}
	return nil, nil
}

// endpointCertificate returns the leaf certificate a new Basic256Sha256
// channel presents.
func endpointCertificate(t *testing.T, endpoint string) *x509.Certificate {
	t.Helper()
	c := pushClient(t, endpoint, false)
	defer func() { _ = c.Close(context.Background()) }()
	chain, err := x509.ParseCertificates(c.SecureChannel().RemoteCertificate())
	if err != nil || len(chain) == 0 {
		t.Fatalf("server certificate: %v", err)
	}
	return chain[0]
}

// TestCertMgmtPushGroups_GoClient_PeerServers: package gds against the
// ServerConfiguration of each peer server.
func TestCertMgmtPushGroups_GoClient_PeerServers(t *testing.T) {
	for _, p := range pushPeers {
		t.Run(p.name, func(t *testing.T) {
			requirePushFeature(t, p.env, p.image, "serverFeatures", "push-management")
			h := startSecureAdapterServerIn(t, p.env, p.image, p.pki, pushFixtureDir(t))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			t.Run("coverage/certmgmt.push.get-certificates/"+p.direction, func(t *testing.T) {
				types, certs, err := gds.New(pushClient(t, h.endpoint, true)).GetCertificates(ctx, gds.DefaultApplicationGroup)
				peerRefuses(t, "GetCertificates", err)
				if err != nil {
					t.Fatalf("GetCertificates: %v", err)
				}
				t.Logf("%s: GetCertificates types %v", p.name, types)
				cur := endpointCertificate(t, h.endpoint)
				if !slices.ContainsFunc(certs, func(c []byte) bool {
					x, err := x509.ParseCertificates(c)
					return err == nil && len(x) > 0 && x[0].Equal(cur)
				}) {
					t.Fatalf("GetCertificates (%d certificates) does not return the certificate of the endpoints", len(certs))
				}
			})

			t.Run("coverage/certmgmt.push.transaction-diagnostics/"+p.direction, func(t *testing.T) {
				extra, _, err := testpki.SelfSigned("go-opcua interop diagnostics "+p.name, "urn:otfabric:interop:diagnostics")
				if err != nil {
					t.Fatal(err)
				}
				g := gds.New(pushClient(t, h.endpoint, true))
				if err := g.AddCertificate(ctx, extra, true); err != nil {
					t.Fatalf("AddCertificate: %v", err)
				}
				applyChanges(t, ctx, g, p, true)
				d, err := gds.New(pushClient(t, h.endpoint, true)).TransactionDiagnostics(ctx)
				peerRefuses(t, "TransactionDiagnostics", err)
				if errors.Is(err, ua.StatusBadDataTypeIDUnknown) {
					t.Skipf("the peer cannot encode a variable of its TransactionDiagnostics: %v", err)
				}
				if err != nil {
					t.Fatalf("TransactionDiagnostics: %v", err)
				}
				t.Logf("%s: TransactionDiagnostics %+v", p.name, d)
				if d.StartTime.IsZero() || d.EndTime.Before(d.StartTime) || d.Result != ua.StatusOK {
					t.Fatalf("TransactionDiagnostics of the applied transaction: %+v", d)
				}
				if len(d.AffectedTrustLists) == 0 {
					t.Fatal("TransactionDiagnostics: no affected trust list")
				}
			})

			groupTrustList := func(t *testing.T, tl *ua.NodeID, name string) {
				extra, _, err := testpki.SelfSigned("go-opcua interop "+name+" "+p.name, "urn:otfabric:interop:"+name)
				if err != nil {
					t.Fatal(err)
				}
				// The transaction is the session's: the change and
				// ApplyChanges go over one session.
				g := gds.New(pushClient(t, h.endpoint, true))
				_, err = g.WithTrustList(tl).ReadTrustList(ctx, ua.TrustListMasksAll)
				peerRefuses(t, "the trust list "+tl.String(), err)
				if errors.Is(err, io.ErrUnexpectedEOF) {
					t.Skipf("the peer serves the trust list %v as an empty file, no TrustListDataType: %v", tl, err)
				}
				if err != nil {
					t.Fatalf("ReadTrustList %v: %v", tl, err)
				}
				if err := g.WithTrustList(tl).AddCertificate(ctx, extra, true); err != nil {
					t.Fatalf("AddCertificate %v: %v", tl, err)
				}
				applyChanges(t, ctx, g, p, true)
				got, err := gds.New(pushClient(t, h.endpoint, true)).WithTrustList(tl).ReadTrustList(ctx, ua.TrustListMasksAll)
				if err != nil {
					t.Fatalf("ReadTrustList %v: %v", tl, err)
				}
				if !containsCert(got.TrustedCertificates, extra) {
					t.Fatalf("the trust list %v does not trust the certificate added to it", tl)
				}
				if containsCert(readTrustList(t, ctx, h.endpoint).TrustedCertificates, extra) {
					t.Fatal("the certificate added to the group trust list is in the application trust list")
				}
			}
			t.Run("coverage/certmgmt.push.usertoken-group/"+p.direction, func(t *testing.T) {
				groupTrustList(t, gds.UserTokenTrustList, "usertoken")
			})
			t.Run("coverage/certmgmt.push.https-group/"+p.direction, func(t *testing.T) {
				groupTrustList(t, gds.HTTPSTrustList, "https")
			})

			t.Run("coverage/certmgmt.push.create-self-signed/"+p.direction, func(t *testing.T) {
				cur := endpointCertificate(t, h.endpoint)
				ips := make([]string, len(cur.IPAddresses))
				for i, ip := range cur.IPAddresses {
					ips[i] = ip.String()
				}
				c := pushClient(t, h.endpoint, true)
				g := gds.New(c)
				create := func(group, typ *ua.NodeID) ([]byte, error) {
					return g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
						CertificateGroup: group,
						CertificateType:  typ,
						SubjectName:      "CN=" + cur.Subject.CommonName,
						DNSNames:         cur.DNSNames,
						IPAddresses:      ips,
						LifetimeInDays:   2,
						KeySizeInBits:    2048,
					})
				}
				group, typ := gds.DefaultApplicationGroup, gds.RsaSha256ApplicationCertificateType
				cert, err := create(group, typ)
				peerRefuses(t, "CreateSelfSignedCertificate", err)
				if errors.Is(err, ua.StatusBadInvalidState) {
					// UA-.NETStandard creates a certificate for an empty
					// slot only (Part 12 1.05 §7.10): DeleteCertificate
					// empties it first, in the same transaction. It does
					// not empty the slot of the only application
					// certificate either; then the test takes a slot of a
					// group that is empty.
					derr := g.DeleteCertificate(ctx, group, typ)
					t.Logf("%s: CreateSelfSignedCertificate for an occupied slot: %v; DeleteCertificate: %v", p.name, err, derr)
					switch {
					case derr == nil:
					case errors.Is(derr, ua.StatusBadInvalidState):
						if group, typ = emptySlot(t, ctx, c, g); group == nil {
							t.Skip("the peer refuses to delete its certificate and has no empty certificate slot")
						}
					default:
						t.Fatalf("DeleteCertificate: %v", derr)
					}
					cert, err = create(group, typ)
				}
				if err != nil {
					t.Fatalf("CreateSelfSignedCertificate %v %v: %v", group, typ, err)
				}
				t.Logf("%s: self-signed certificate for %v %v", p.name, group, typ)
				x, err := x509.ParseCertificate(cert)
				if err != nil {
					t.Fatalf("the certificate does not parse: %v", err)
				}
				// Signed with its own key, issuer = subject. Not
				// CheckSignatureFrom: an application certificate need not
				// be a CA (UA-.NETStandard's has cA false), which Go
				// requires of a parent.
				t.Logf("%s: BasicConstraints valid %v cA %v, KeyUsage %v", p.name, x.BasicConstraintsValid, x.IsCA, x.KeyUsage)
				if !bytes.Equal(x.RawIssuer, x.RawSubject) {
					t.Fatalf("issuer %v is not the subject %v", x.Issuer, x.Subject)
				}
				if err := x.CheckSignature(x.SignatureAlgorithm, x.RawTBSCertificate, x.Signature); err != nil {
					t.Fatalf("not self-signed: %v", err)
				}
				// The endpoints keep their certificate: the change is
				// cancelled (the channel stays trusted by the go client).
				if err := g.CancelChanges(ctx); err != nil {
					t.Fatalf("CancelChanges: %v", err)
				}
			})

			t.Run("coverage/certmgmt.push.alarms/"+p.direction, func(t *testing.T) {
				// The alarms of the DefaultApplicationGroup (Part 12
				// §7.8.3) and the state of each.
				c := pushClient(t, h.endpoint, true)
				for _, name := range []string{"TrustListOutOfDate", "CertificateExpired"} {
					qn := []*ua.QualifiedName{{Name: "CertificateGroups"}, {Name: "DefaultApplicationGroup"}, {Name: name}, {Name: "ActiveState"}, {Name: "Id"}}
					nid, err := c.Node(gds.ServerConfiguration).TranslateBrowsePathsToNodeIDs(ctx, qn)
					peerRefuses(t, "the "+name+" alarm", err)
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					dv, err := c.ReadValue(ctx, nid)
					if err != nil || dv.Status != ua.StatusOK || dv.Value == nil {
						t.Fatalf("%s ActiveState/Id: %v %v", name, dv, err)
					}
					active, ok := dv.Value.Value().(bool)
					if !ok {
						t.Fatalf("%s ActiveState/Id is %T, want Boolean", name, dv.Value.Value())
					}
					t.Logf("%s: %s active %v", p.name, name, active)
				}
			})

			t.Run("coverage/certmgmt.push.pfx/"+p.direction, func(t *testing.T) {
				props, err := gds.New(pushClient(t, h.endpoint, true)).Properties(ctx)
				if err != nil {
					t.Fatalf("Properties: %v", err)
				}
				if !slices.Contains(props.SupportedPrivateKeyFormats, "PFX") {
					t.Skipf("the peer does not support PFX private keys (SupportedPrivateKeyFormats %v)", props.SupportedPrivateKeyFormats)
				}
				cur := endpointCertificate(t, h.endpoint)
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				caCert, caKey := loadTestCA(t)
				tmpl := testpki.CertTemplate(cur.Subject.CommonName, "")
				tmpl.Subject = cur.Subject
				tmpl.URIs, tmpl.DNSNames, tmpl.IPAddresses = cur.URIs, cur.DNSNames, cur.IPAddresses
				newDER, err := uapolicy.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
				if err != nil {
					t.Fatal(err)
				}
				pfx, err := uapolicy.EncodePFX(key, [][]byte{newDER}, "")
				if err != nil {
					t.Fatal(err)
				}
				g := gds.New(pushClient(t, h.endpoint, true))
				required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
					CertificateGroup:   gds.DefaultApplicationGroup,
					CertificateType:    gds.RsaSha256ApplicationCertificateType,
					Certificate:        newDER,
					IssuerCertificates: [][]byte{caCert.Raw},
					PrivateKeyFormat:   "PFX",
					PrivateKey:         pfx,
				})
				if err != nil {
					t.Fatalf("UpdateCertificate with a PFX key: %v", err)
				}
				if required {
					applyChanges(t, ctx, g, p, false)
				}
				deadline := time.Now().Add(20 * time.Second)
				for !endpointCertificate(t, h.endpoint).Equal(mustParse(t, newDER)) {
					if time.Now().After(deadline) {
						t.Fatal("the channels do not present the certificate installed with the PFX key")
					}
					time.Sleep(250 * time.Millisecond)
				}
			})

			t.Run("coverage/certmgmt.push.delete-certificate/"+p.direction, func(t *testing.T) {
				// The certificate the endpoints advertise "shall not be
				// deleted. This determination happens when ApplyChanges is
				// called" (Part 12 1.05 §7.10): the deletion is accepted,
				// ApplyChanges refuses it with Bad_InvalidState and the
				// endpoints keep their certificate.
				// UA-.NETStandard refuses the deletion of the only
				// application certificate at once, with the same status.
				cur := endpointCertificate(t, h.endpoint)
				g := gds.New(pushClient(t, h.endpoint, true))
				err := g.DeleteCertificate(ctx, gds.DefaultApplicationGroup, gds.RsaSha256ApplicationCertificateType)
				peerRefuses(t, "DeleteCertificate", err)
				if err == nil {
					err = g.ApplyChanges(ctx)
					if cerr := g.CancelChanges(ctx); cerr != nil {
						t.Logf("%s: CancelChanges: %v", p.name, cerr)
					}
				}
				t.Logf("%s: deleting the certificate of the endpoints: %v", p.name, err)
				if !errors.Is(err, ua.StatusBadInvalidState) {
					t.Fatalf("the deletion of the certificate of the endpoints: %v, want Bad_InvalidState", err)
				}
				if !endpointCertificate(t, h.endpoint).Equal(cur) {
					t.Fatal("the endpoints changed their certificate")
				}
			})

			t.Run("coverage/certmgmt.push.reset-to-defaults/"+p.direction, func(t *testing.T) {
				err := gds.New(pushClient(t, h.endpoint, true)).ResetToServerDefaults(ctx)
				peerRefuses(t, "ResetToServerDefaults", err)
				if errors.Is(err, ua.StatusBadInternalError) {
					t.Skipf("the peer fails ResetToServerDefaults: %v", err)
				}
				if err != nil {
					t.Fatalf("ResetToServerDefaults: %v", err)
				}
				// The go client is still trusted (the default trust list of
				// the fixture trusts the test CA).
				pushClient(t, h.endpoint, false)
			})
		})
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	x, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return x
}
