// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

func newFileStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gds")
	s, err := NewFileStore(dir)
	require.NoError(t, err)
	return s, dir
}

// TestFileStore_RoundTrip: what is put is loaded, in RecordID order; the
// files are private.
func TestFileStore_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, dir := newFileStore(t)
	st, err := s.Load(ctx)
	require.NoError(t, err)
	require.Empty(t, st.Applications)
	require.Nil(t, st.Meta)

	rec := &gds.ApplicationRecord{ApplicationURI: "urn:a", ApplicationType: ua.ApplicationTypeServer, ProductURI: "urn:p",
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("A", "en"), nil, ua.NewLocalizedText("B")},
		DiscoveryURLs:    []string{"opc.tcp://a:4840"}, ServerCapabilities: []string{"LDS"}}
	certs := []*IssuedCertificate{{CertificateType: 1, Certificate: []byte{1, 2}, Revoked: true, CertificateGroup: GroupHTTPS}}
	require.NoError(t, s.PutApplication(ctx, &Application{ID: "b", RecordID: 2, Record: rec, EndpointIDs: []uint32{7}, Certificates: certs}))
	require.NoError(t, s.PutApplication(ctx, &Application{ID: "a", RecordID: 1}))
	require.NoError(t, s.PutApplication(ctx, &Application{ID: "c", RecordID: 3}))
	require.NoError(t, s.DeleteApplication(ctx, "c"))
	require.NoError(t, s.DeleteApplication(ctx, "c"), "deleting a missing file is no error")
	created := time.Now().UTC().Truncate(time.Second)
	req := &Request{ID: "r-1", ApplicationID: "b", CertificateType: 2, CertificateGroup: GroupHTTPS, Created: created,
		PrivateKeyFormat: "PFX", PrivateKeyPassword: "secret", DomainNames: []string{"a"}}
	require.NoError(t, s.PutRequest(ctx, req))
	require.NoError(t, s.PutRequest(ctx, &Request{ID: "r-2"}))
	require.NoError(t, s.DeleteRequest(ctx, "r-2"))
	iss := &Issuer{Name: "NistP256", Certificate: []byte{3}, PrivateKey: []byte{4}, CRL: []byte{5}, CRLNumber: 9,
		Revoked: []*RevokedCertificate{{SerialNumber: []byte{6}, RevokedAt: created}}}
	require.NoError(t, s.PutIssuer(ctx, iss))
	meta := &Meta{NextRecordID: 4, GroupTrustLists: map[string]*ua.TrustListDataType{GroupUserToken: {SpecifiedLists: 15, TrustedCertificates: [][]byte{{8}}}}}
	require.NoError(t, s.PutMeta(ctx, meta))

	st, err = s.Load(ctx)
	require.NoError(t, err)
	require.Len(t, st.Applications, 2)
	require.Equal(t, "a", st.Applications[0].ID)
	b := st.Applications[1]
	require.Equal(t, certs, b.Certificates)
	require.Equal(t, []uint32{7}, b.EndpointIDs)
	require.Equal(t, "urn:a", b.Record.ApplicationURI)
	require.Equal(t, ua.ApplicationTypeServer, b.Record.ApplicationType)
	require.Equal(t, []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("A", "en"), ua.NewLocalizedTextWithLocale("B", "")}, b.Record.ApplicationNames)
	require.Equal(t, rec.DiscoveryURLs, b.Record.DiscoveryURLs)
	require.Equal(t, rec.ServerCapabilities, b.Record.ServerCapabilities)
	require.Nil(t, st.Applications[0].Record)
	require.Equal(t, []*Request{req}, st.Requests)
	require.Equal(t, []*Issuer{iss}, st.Issuers)
	require.Equal(t, meta, st.Meta)

	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(dir, "issuers", "NistP256.json"), filepath.Join(dir, "requests", "r-1.json"), filepath.Join(dir, "meta.json")} {
			fi, err := os.Stat(p)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), p)
		}
		fi, err := os.Stat(filepath.Join(dir, "issuers"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	}
}

// TestFileStore_Errors: invalid names, corrupt files, leftovers of an
// interrupted write and a directory that cannot be made.
func TestFileStore_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, dir := newFileStore(t)
	for _, name := range []string{"", "../x", "a/b", "a.b", string(make([]byte, 65))} {
		require.Error(t, s.PutApplication(ctx, &Application{ID: name}), "%q", name)
		require.Error(t, s.DeleteRequest(ctx, name), "%q", name)
	}

	// A temporary file of an interrupted write is removed; other files and
	// directories are skipped.
	tmp := filepath.Join(dir, "requests", tmpPrefix+"123")
	require.NoError(t, os.WriteFile(tmp, []byte("{"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requests", "notes.txt"), []byte("x"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "requests", "sub.json"), 0o700))
	_, err := s.Load(ctx)
	require.NoError(t, err)
	_, err = os.Stat(tmp)
	require.ErrorIs(t, err, os.ErrNotExist)

	for _, sub := range []string{"applications", "requests", "issuers"} {
		bad := filepath.Join(dir, sub, "bad.json")
		require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))
		_, err := s.Load(ctx)
		require.ErrorContains(t, err, filepath.Join(sub, "bad.json"))
		require.NoError(t, os.Remove(bad))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "meta.json"), []byte("["), 0o600))
	_, err = s.Load(ctx)
	require.ErrorContains(t, err, "meta.json")
	require.NoError(t, os.Remove(filepath.Join(dir, "meta.json")))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "meta.json"), 0o700))
	_, err = s.Load(ctx)
	require.Error(t, err, "meta.json is a directory")

	// The directories are gone.
	require.NoError(t, os.RemoveAll(dir))
	_, err = s.Load(ctx)
	require.Error(t, err)
	require.Error(t, s.PutIssuer(ctx, &Issuer{Name: "RSA"}))
	require.Error(t, s.PutMeta(ctx, &Meta{}))
	require.Error(t, s.DeleteApplication(ctx, "x"))

	// A file where the directory should be.
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = NewFileStore(file)
	require.Error(t, err)
}

// TestFileStore_GDS: a GDS on a FileStore keeps nothing in temporary
// files.
func TestFileStore_GDS(t *testing.T) {
	t.Parallel()
	s, dir := newFileStore(t)
	e := newEnv(t, Config{Store: s, SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	reqID, err := e.anonymous().StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	_, err = e.anonymous().FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	for _, sub := range []string{"applications", "requests", "issuers"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		require.NoError(t, err)
		for _, en := range entries {
			require.Equal(t, ".json", filepath.Ext(en.Name()))
		}
	}
	apps, err := os.ReadDir(filepath.Join(dir, "applications"))
	require.NoError(t, err)
	require.Len(t, apps, 1)
	reqs, err := os.ReadDir(filepath.Join(dir, "requests"))
	require.NoError(t, err)
	require.Empty(t, reqs, "the finished request is removed")
}
