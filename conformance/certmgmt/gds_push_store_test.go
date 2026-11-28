// SPDX-License-Identifier: MIT

package certmgmt

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/pushstore"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// Push certificate management with the file store of package
// server/pushstore: every entry point over the wire, a restart, failed
// commits and concurrent changes.

const pushStoreOwner = "urn:otfabric:test:certmgmt"

func openPushStore(t *testing.T, dir string) *pushstore.Store {
	t.Helper()
	st, err := pushstore.OpenDir(context.Background(), dir, pushstore.Options{Owner: pushStoreOwner})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = st.Close() })
	return st
}

func trustListUpdateTime(t *testing.T, c *opcua.Client) time.Time {
	t.Helper()
	v, err := c.ReadValue(context.Background(), ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListLastUpdateTime))
	require.NoError(t, err)
	return v.Value.Value().(time.Time)
}

// TestGDSPush_FileStoreRestart: the changes of CloseAndUpdate,
// AddCertificate, RemoveCertificate, UpdateCertificate and
// CreateSelfSignedCertificate, each applied with ApplyChanges, are in the
// store; a server created again on the directory starts with them and uses
// them, and after ResetToServerDefaults with its configuration.
func TestGDSPush_FileStoreRestart(t *testing.T) {
	p := pki(t)
	src, err := testpki.Get()
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(src.CACert)
	require.NoError(t, err)
	ctx := context.Background()
	dir := t.TempDir()

	st := openPushStore(t, dir)
	srv1, url := pushServerWith(t, server.PushManagement{Store: st})
	c1, g := pushAdminClient(t, url)

	// CloseAndUpdate: the CA of the issued client.
	tl, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	tl.TrustedCertificates = append(tl.TrustedCertificates, p.caCert)
	_, err = g.WriteTrustList(ctx, tl)
	require.NoError(t, err)
	require.NoError(t, g.ApplyChanges(ctx))
	// AddCertificate and RemoveCertificate on the DefaultUserTokenGroup.
	users := g.WithTrustList(gds.UserTokenTrustList)
	require.NoError(t, users.AddCertificate(ctx, p.userCert, true))
	require.NoError(t, users.AddCertificate(ctx, p.issuedCert, true))
	require.NoError(t, g.ApplyChanges(ctx))
	require.NoError(t, users.RemoveCertificate(ctx, gds.Thumbprint(p.issuedCert), true))
	require.NoError(t, g.ApplyChanges(ctx))
	// UpdateCertificate with a certificate the CA issued for a CSR.
	csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateType: gds.RsaSha256ApplicationCertificateType})
	require.NoError(t, err)
	cert, err := testpki.IssueFromCSR(csr, ca, src.CAKey)
	require.NoError(t, err)
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType: gds.RsaSha256ApplicationCertificateType, Certificate: cert, IssuerCertificates: [][]byte{src.CACert},
	})
	require.NoError(t, err)
	require.NoError(t, g.ApplyChanges(ctx))
	// CreateSelfSignedCertificate for the DefaultHttpsGroup.
	tlsCert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
		CertificateGroup: gds.DefaultHTTPSGroup, SubjectName: "CN=tls", DNSNames: []string{"localhost"}, LifetimeInDays: 1,
	})
	require.NoError(t, err)
	require.NoError(t, g.ApplyChanges(ctx))
	updated := trustListUpdateTime(t, c1)
	require.Equal(t, uint64(5), st.Status().Revision, "one write per ApplyChanges")

	// Restart.
	require.NoError(t, srv1.Close())
	require.NoError(t, st.Close())
	st2 := openPushStore(t, dir)
	srv2, url2 := pushServerWith(t, server.PushManagement{Store: st2})
	require.Equal(t, [][]byte{p.clientCert, p.caCert}, srv2.TrustList().TrustedCertificates)
	require.Equal(t, [][]byte{p.userCert}, srv2.GroupTrustList(gds.DefaultUserTokenGroup).TrustedCertificates)
	require.Equal(t, tlsCert, srv2.HTTPSCertificate())
	// The restored trust list admits the issued client, the endpoints
	// present the restored certificate with its key.
	c, err := pushDial(t, url2, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.NoError(t, err)
	require.Equal(t, cert, c.SecureChannel().RemoteCertificate())
	ep := endpointFor(t, url2, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.Equal(t, cert, ep.ServerCertificate)
	c2, g2 := pushAdminClient(t, url2)
	require.True(t, updated.Equal(trustListUpdateTime(t, c2)), "LastUpdateTime survives the restart")

	// ResetToServerDefaults empties the store: the next start has the
	// configuration.
	require.NoError(t, g2.ResetToServerDefaults(ctx))
	require.NoError(t, srv2.Close())
	require.NoError(t, st2.Close())
	st3 := openPushStore(t, dir)
	srv3, url3 := pushServerWith(t, server.PushManagement{Store: st3})
	require.Equal(t, [][]byte{p.clientCert}, srv3.TrustList().TrustedCertificates)
	_, err = pushDial(t, url3, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	ep = endpointFor(t, url3, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.Equal(t, p.serverCert, ep.ServerCertificate)
	got, err := st3.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Empty(t, got.TrustLists)
	require.Empty(t, got.Certificates)
}

// TestGDSPush_FileStoreFailedCommit: an ApplyChanges whose write fails, or
// has an unknown outcome, is Bad_InternalError and applies nothing; the
// transaction is discarded (Part 12 §7.10.2) and the errors are in the
// TransactionDiagnostics. The next ApplyChanges settles the store, and a
// restart starts with what was applied only.
func TestGDSPush_FileStoreFailedCommit(t *testing.T) {
	p := pki(t)
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := fxstore.OpenFile(dir, fxstore.Limits{})
	require.NoError(t, err)
	faulty := storetest.NewFaulty(fs)
	st, err := pushstore.Open(ctx, faulty, pushstore.Options{Owner: pushStoreOwner})
	require.NoError(t, err)
	srv, url := pushServerWith(t, server.PushManagement{Store: st})
	_, g := pushAdminClient(t, url)

	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		require.NoError(t, g.AddCertificate(ctx, p.caCert, true))
		faulty.FailApply(fault)
		require.ErrorIs(t, g.ApplyChanges(ctx), ua.StatusBadInternalError, "fault %d", fault)
		require.Equal(t, [][]byte{p.clientCert}, srv.TrustList().TrustedCertificates)
		_, err = pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
		require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
		d, err := g.TransactionDiagnostics(ctx)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadInternalError, d.Result)
		require.Len(t, d.Errors, 1)
		require.True(t, d.Errors[0].TargetID.Equal(gds.DefaultTrustList))
		// The transaction is gone: there is nothing to apply.
		require.ErrorIs(t, g.ApplyChanges(ctx), ua.StatusBadNothingToDo)
		require.Equal(t, [][]byte{p.clientCert}, srv.TrustList().TrustedCertificates)
	}
	// The store is fenced by the last fault; the next ApplyChanges
	// settles it, writes the state before the fault back and applies.
	require.True(t, st.Status().Fenced)
	require.NoError(t, g.AddCertificate(ctx, p.caCert, true))
	require.NoError(t, g.ApplyChanges(ctx))
	require.False(t, st.Status().Fenced)
	_, err = pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.NoError(t, err)

	// A write that landed with an unknown outcome and is then settled
	// leaves the state that was applied.
	require.NoError(t, g.RemoveCertificate(ctx, gds.Thumbprint(p.caCert), true))
	faulty.FailApply(storetest.FailApplied)
	require.ErrorIs(t, g.ApplyChanges(ctx), ua.StatusBadInternalError)
	ok, err := st.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, srv.Close())
	require.NoError(t, st.Close())
	require.NoError(t, fs.Close())

	st2 := openPushStore(t, dir)
	srv2, _ := pushServerWith(t, server.PushManagement{Store: st2})
	require.Equal(t, [][]byte{p.clientCert, p.caCert}, srv2.TrustList().TrustedCertificates)
}

// gateStore blocks the Apply of a pushstore while gate is set.
type gateStore struct {
	fxstore.Store
	mu      sync.Mutex
	gate    chan struct{}
	entered chan struct{}
}

func (s *gateStore) Apply(ctx context.Context, b fxstore.Batch) error {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		s.entered <- struct{}{}
		<-gate
	}
	return s.Store.Apply(ctx, b)
}

// TestGDSPush_FileStoreConcurrent: a second session is refused while the
// first has a transaction (Bad_TransactionPending, Part 12 §7.10.2); while
// ApplyChanges is writing the store, the trust list in effect, its
// validation and a load of the store are those before it, and after it the
// new ones, which a restart restores.
func TestGDSPush_FileStoreConcurrent(t *testing.T) {
	p := pki(t)
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := fxstore.OpenFile(dir, fxstore.Limits{})
	require.NoError(t, err)
	gs := &gateStore{Store: fs, entered: make(chan struct{})}
	st, err := pushstore.Open(ctx, gs, pushstore.Options{Owner: pushStoreOwner})
	require.NoError(t, err)
	srv, url := pushServerWith(t, server.PushManagement{Store: st})
	_, a := pushAdminClient(t, url)
	_, b := pushAdminClient(t, url)

	require.NoError(t, a.AddCertificate(ctx, p.caCert, true))
	require.ErrorIs(t, b.AddCertificate(ctx, p.userCert, true), ua.StatusBadTransactionPending)
	require.ErrorIs(t, b.ApplyChanges(ctx), ua.StatusBadSessionIDInvalid, "the session is not valid for the active transaction (Part 12 §7.10.9)")

	gate := make(chan struct{})
	gs.mu.Lock()
	gs.gate = gate
	gs.mu.Unlock()
	release := sync.OnceFunc(func() {
		gs.mu.Lock()
		gs.gate = nil
		gs.mu.Unlock()
		close(gate)
	})
	cleanup.Register(t, release) // before the server closes, if the test fails
	done := make(chan error, 1)
	go func() { done <- a.ApplyChanges(ctx) }()
	<-gs.entered
	// The write is in progress: the trust list in effect and the store are
	// those before it. (The server answers requests one at a time: the
	// clients wait for ApplyChanges.)
	require.Equal(t, [][]byte{p.clientCert}, srv.TrustList().TrustedCertificates)
	require.Error(t, srv.VerifyGroupCertificate(gds.DefaultApplicationGroup, p.issuedCert))
	got, err := st.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Empty(t, got.TrustLists)
	release()
	require.NoError(t, <-done)
	require.Equal(t, [][]byte{p.clientCert, p.caCert}, srv.TrustList().TrustedCertificates)
	_, err = pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.NoError(t, err)

	// The transaction is closed: the second session may change now.
	require.NoError(t, b.AddCertificate(ctx, p.userCert, true))
	require.NoError(t, b.ApplyChanges(ctx))
	require.NoError(t, srv.Close())
	require.NoError(t, st.Close())
	require.NoError(t, fs.Close())

	st2 := openPushStore(t, dir)
	srv2, _ := pushServerWith(t, server.PushManagement{Store: st2})
	require.Equal(t, [][]byte{p.clientCert, p.caCert, p.userCert}, srv2.TrustList().TrustedCertificates)
}
