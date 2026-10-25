// SPDX-License-Identifier: MIT

package gdsserver

import (
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

func TestCA_KeyTypes(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, name := range []string{"NistP256", "NistP384", "Curve25519", "Curve448", "RSA"} {
		rec, err := newCA(name, "test "+name, now, time.Hour, 2048)
		require.NoError(t, err, name)
		c, err := loadCA(rec)
		require.NoError(t, err, name)
		rec.Revoked = append(rec.Revoked, &RevokedCertificate{SerialNumber: big.NewInt(42).Bytes(), RevokedAt: now})
		require.NoError(t, c.makeCRL(now, time.Hour), name)
		crl, err := x509.ParseRevocationList(rec.CRL)
		require.NoError(t, err, name)
		require.Equal(t, c.cert.RawSubject, crl.RawIssuer)
		require.Len(t, crl.RevokedCertificateEntries, 1)
		if pub, ok := c.cert.PublicKey.(ed448.PublicKey); ok {
			require.True(t, ed448.Verify(pub, crl.RawTBSRevocationList, crl.Signature, ""), "the Ed448 CRL verifies")
		} else {
			require.NoError(t, crl.CheckSignatureFrom(c.cert), name)
		}
	}
	_, err := newCA("DSA", "x", now, time.Hour, 0)
	require.Error(t, err)
	_, err = newIssuerKey("nope", 0)
	require.Error(t, err)
	_, err = loadCA(&Issuer{Name: "x", Certificate: []byte("junk")})
	require.Error(t, err)
}

func TestParseSubjectName(t *testing.T) {
	t.Parallel()
	n, err := parseSubjectName("CN=App/O=Org/OU=Unit/C=BE/ST=Antwerp/L=Mol/STREET=Main 1/DC=host")
	require.NoError(t, err)
	require.Equal(t, "App", n.CommonName)
	require.Equal(t, []string{"Org"}, n.Organization)
	require.Equal(t, []string{"Unit"}, n.OrganizationalUnit)
	require.Equal(t, []string{"BE"}, n.Country)
	require.Equal(t, []string{"Antwerp"}, n.Province)
	require.Equal(t, []string{"Mol"}, n.Locality)
	require.Equal(t, []string{"Main 1"}, n.StreetAddress)
	require.Len(t, n.ExtraNames, 1)

	n, err = parseSubjectName(`CN="A/B", O=Org, S=X`)
	require.NoError(t, err)
	require.Equal(t, "A/B", n.CommonName)
	require.Equal(t, []string{"X"}, n.Province)

	for _, bad := range []string{"", "/", "CN", "CN=", "X=1"} {
		_, err := parseSubjectName(bad)
		require.Error(t, err, bad)
	}
}

func TestHostsOf(t *testing.T) {
	t.Parallel()
	dns, ips := hostsOf([]string{"opc.tcp://Host:1", "opc.tcp://host:2", "rcp+opc.tcp://other:3", "opc.tcp://[::1]:4", "::bad", "urn:x"})
	require.Equal(t, []string{"Host", "other"}, dns)
	require.Equal(t, []net.IP{net.ParseIP("::1")}, ips)
}

func TestLike(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		pattern, s string
		match      bool
	}{
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"a%", "abcd", true},
		{"a_c", "abc", true},
		{"a_c", "ac", false},
		{`a\%`, "a%", true},
		{`a\%`, "ab", false},
		{`a\`, `a\`, true},
		{"[a-c]x", "bx", true},
		{"[a-c]x", "dx", false},
		{"[^a-c]x", "dx", true},
		{"[-a]x", "-x", true},
		{"[a-]x", "-x", true},
		{`[\]]x`, "]x", true},
		{"[.]", "a", false},
		{"a.b", "axb", false},
		{"%\n%", "a\nb", true},
	} {
		p, err := compileLike(c.pattern)
		require.NoError(t, err, c.pattern)
		require.Equal(t, c.match, p.match(c.s), "%q ~ %q", c.pattern, c.s)
	}
	for _, bad := range []string{"[", "[]", "[^", "a[bc"} {
		_, err := compileLike(bad)
		require.Error(t, err, bad)
	}
	var none *likePattern
	require.True(t, none.match("anything"))
	require.Nil(t, cloneLT(nil))
	require.Equal(t, "x", cloneLT(ua.NewLocalizedText("x")).Text)
}

func TestCertURIs(t *testing.T) {
	t.Parallel()
	require.Nil(t, certURIs(nil))
}
