// SPDX-License-Identifier: MIT

package server

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
)

// TestPushRevocationFollowsVerifiedChain checks that the revocation of the
// issuers is checked along the signature-verified chain: an extra
// certificate in the presented chain that only carries the name of a revoked
// intermediate does not hide it (Part 4 §6.1.3: Bad_CertificateIssuerRevoked).
func TestPushRevocationFollowsVerifiedChain(t *testing.T) {
	p := pushPKI(t)
	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)

	interKey := mustECDSA(t, elliptic.P256())
	interTmpl := testpki.CertTemplate("intermediate", "")
	interTmpl.IsCA = true
	interTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, ca, &interKey.PublicKey, p.CAKey)
	require.NoError(t, err)
	inter, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)

	leafKey := mustECDSA(t, elliptic.P256())
	leafDER, err := x509.CreateCertificate(rand.Reader, testpki.CertTemplate("leaf", testpki.ClientAppURI), inter, &leafKey.PublicKey, interKey)
	require.NoError(t, err)

	// A self-signed certificate with the subject of the intermediate.
	otherKey := mustECDSA(t, elliptic.P256())
	otherTmpl := testpki.CertTemplate("intermediate", "")
	otherTmpl.IsCA = true
	otherTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)
	require.NoError(t, err)

	cat := func(ders ...[]byte) []byte {
		var out []byte
		for _, d := range ders {
			out = append(out, d...)
		}
		return out
	}

	m := newPushManager(&PushManagement{MaxTrustListSize: defaultMaxTrustListSize, MaxRejectedCertificates: 4}, &serverConfig{})
	load := func(d *ua.TrustListDataType) {
		tl, sc := newTrustList(d, 0)
		require.Equal(t, ua.StatusOK, sc)
		m.groups[groupApplication].trust.Store(tl)
	}

	// Not revoked: the chain is accepted, also with the extra certificate.
	load(&ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}, IssuerCertificates: [][]byte{interDER}})
	require.NoError(t, m.validateClient(cat(leafDER, interDER)))
	require.NoError(t, m.validateClient(cat(leafDER, otherDER, interDER)))

	// The CA revokes the intermediate.
	load(&ua.TrustListDataType{
		TrustedCertificates: [][]byte{p.CACert},
		IssuerCertificates:  [][]byte{interDER},
		TrustedCrls:         [][]byte{testCRL(t, ca, p.CAKey, inter.SerialNumber)},
	})
	require.Equal(t, ua.StatusBadCertificateIssuerRevoked, m.validateClient(cat(leafDER, interDER)))
	require.Equal(t, ua.StatusBadCertificateIssuerRevoked, m.validateClient(cat(leafDER, otherDER, interDER)))
	require.Equal(t, ua.StatusBadCertificateIssuerRevoked, m.validateClient(cat(leafDER, otherDER)))
}
