// SPDX-License-Identifier: MIT

package pushstore

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// TestRecordErrors: records and keys that do not decode are ErrCorrupt.
func TestRecordErrors(t *testing.T) {
	p := pki(t)
	good, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: rsaType, Certificate: p.ServerCert,
		Issuers: [][]byte{p.CACert}, PrivateKey: p.ServerKey})
	require.NoError(t, err)
	_, err = decodeCert(good)
	require.NoError(t, err)
	other, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: rsaType, Certificate: p.ServerCert, PrivateKey: p.ClientKey})
	require.NoError(t, err)
	notCert, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: rsaType, Certificate: []byte{1, 2}, PrivateKey: p.ServerKey})
	require.NoError(t, err)
	issuerNotCert, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: rsaType, Certificate: p.ServerCert,
		Issuers: [][]byte{{3}}, PrivateKey: p.ServerKey})
	require.NoError(t, err)
	manyIssuers := append([]byte{recordFormat, kindCertificate}, appendBytes(appendBytes(nil, p.ServerCert), []byte{1})...)
	manyIssuers = binary.LittleEndian.AppendUint32(manyIssuers, 3)
	manyIssuers = append(manyIssuers, 0, 0, 0, 0)
	tooManyIssuers := binary.LittleEndian.AppendUint32(append([]byte{recordFormat, kindCertificate}, appendBytes(appendBytes(nil, p.ServerCert), []byte{1})...), 1000)
	noKey := append([]byte{recordFormat, kindCertificate}, appendLen(appendBytes(appendBytes(nil, p.ServerCert), nil), 0)...)
	for name, b := range map[string][]byte{
		"empty":        nil,
		"format":       {2, kindDeleted},
		"kind":         {recordFormat, 7},
		"deleted+data": {recordFormat, kindDeleted, 0},
		"truncated":    good[:len(good)-1],
		"trailing":     append(bytes.Clone(good), 0),
		"short length": {recordFormat, kindCertificate, 1, 0},
		"long length":  {recordFormat, kindCertificate, 0xff, 0xff, 0xff, 0xff},
		"key mismatch": other,
		"not a cert":   notCert,
		"issuer":       issuerNotCert,
		"issuer count": manyIssuers,
		"issuer bytes": tooManyIssuers,
		"no key":       noKey,
	} {
		_, err := decodeCert(b)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, name)
	}

	tl, err := encodeTrustList(server.CertificateGroupTrustList{Group: "g", TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}}})
	require.NoError(t, err)
	_, err = decodeTrustList(tl)
	require.NoError(t, err)
	masks, err := ua.Encode(&ua.TrustListDataType{SpecifiedLists: 1})
	require.NoError(t, err)
	for name, b := range map[string][]byte{
		"empty":    nil,
		"format":   {2, 0},
		"varint":   {recordFormat, 0x80},
		"body":     {recordFormat, 0, 1},
		"trailing": append(bytes.Clone(tl), 0),
		"masks":    append([]byte{recordFormat, 0}, masks...),
	} {
		_, err := decodeTrustList(b)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, name)
	}

	for _, k := range []string{"x", "tl/", "tl/%zz", "tl/a/b", "cert/a", "cert//1", "cert/%zz/1", "cert/a/b/1",
		"cert/a/0", "cert/a/01", "cert/a/x", "cert/a/4294967296"} {
		_, _, _, err := parseKey(k)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, k)
	}
	g, typ, isCert, err := parseKey(certKey("a/b c", 15))
	require.NoError(t, err)
	require.Equal(t, "a/b c", g)
	require.Equal(t, uint32(15), typ)
	require.True(t, isCert)

	// A bad record in a state: the error names it.
	_, err = decodeState(map[string][]byte{"cert/g/1": {9}})
	require.ErrorContains(t, err, `"cert/g/1"`)
	_, err = decodeState(map[string][]byte{"tl/g": {9}})
	require.ErrorContains(t, err, `"tl/g"`)
	_, err = decodeState(map[string][]byte{"other": {9}})
	require.ErrorIs(t, err, fxstore.ErrCorrupt)
}

func TestEncodeError(t *testing.T) {
	defer func(f func(any) ([]byte, error)) { encode = f }(encode)
	encode = func(any) ([]byte, error) { return nil, fxstore.ErrLimit }
	s := openMem(t, &fxstore.MemoryStore{})
	err := s.StoreTrustList(t.Context(), &ua.TrustListDataType{})
	require.ErrorIs(t, err, fxstore.ErrLimit)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
}

func TestAppendLenPanics(t *testing.T) {
	require.PanicsWithValue(t, errLength, func() { appendLen(nil, -1) })
}

// FuzzRecords: the records and keys of a data file are untrusted. What
// decodes encodes to a record that decodes to the same.
func FuzzRecords(f *testing.F) {
	p, err := testpki.Get()
	if err != nil {
		f.Fatal(err)
	}
	cert, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: rsaType, Certificate: p.ServerCert,
		Issuers: [][]byte{p.CACert}, PrivateKey: p.ServerKey})
	if err != nil {
		f.Fatal(err)
	}
	ed := p.ECC.Server[testpki.CurveEd448]
	edCert, err := encodeCert(server.CertificateGroupChange{Group: "g", CertificateType: p256Type, Certificate: ed.Cert, PrivateKey: ed.Key})
	if err != nil {
		f.Fatal(err)
	}
	tl, err := encodeTrustList(server.CertificateGroupTrustList{Group: "g", TrustList: &ua.TrustListDataType{
		TrustedCertificates: [][]byte{p.CACert}, IssuerCrls: [][]byte{{1}}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("tl/DefaultApplicationGroup", tl)
	f.Add("cert/DefaultApplicationGroup/12557", cert)
	f.Add("cert/Ecc/23537", edCert)
	f.Add("cert/DefaultHttpsGroup/12558", []byte{recordFormat, kindDeleted})
	f.Add("cert/a%2Fb/1", []byte{recordFormat, kindCertificate, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, key string, b []byte) {
		if g, typ, isCert, err := parseKey(key); err == nil {
			if isCert && certKey(g, typ) != key || !isCert && trustListKey(g) != key {
				t.Fatalf("key %q parses to %q %d", key, g, typ)
			}
		}
		if x, err := decodeTrustList(b); err == nil {
			x.Group = "g"
			again, err := encodeTrustList(x)
			if err != nil {
				t.Fatal(err)
			}
			y, err := decodeTrustList(again)
			if err != nil || !y.LastUpdateTime.Equal(x.LastUpdateTime) || len(y.TrustList.TrustedCertificates) != len(x.TrustList.TrustedCertificates) {
				t.Fatalf("trust list round trip: %v", err)
			}
		}
		if x, err := decodeCert(b); err == nil {
			x.Group = "g"
			again, err := encodeCert(x)
			if err != nil {
				t.Fatal(err)
			}
			y, err := decodeCert(again)
			if err != nil || !bytes.Equal(y.Certificate, x.Certificate) || len(y.Issuers) != len(x.Issuers) || y.Deleted() != x.Deleted() {
				t.Fatalf("certificate round trip: %v", err)
			}
		}
	})
}
