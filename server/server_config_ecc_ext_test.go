// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
)

// TestServerConfig_ExtendedIdentities: application instance certificates
// with Brainpool and Ed448 keys serve their policies.
func TestServerConfig_ExtendedIdentities(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)
	bp256 := pki.ECC.Server[testpki.CurveBrainpoolP256r1]
	bp384 := pki.ECC.Server[testpki.CurveBrainpoolP384r1]
	ed448 := pki.ECC.Server[testpki.CurveEd448]
	p256 := pki.ECC.Server[testpki.CurveP256]

	cfg := &serverConfig{}
	for _, opt := range []Option{
		ApplicationIdentity(p256.Cert, p256.Key),
		ApplicationIdentity(bp384.Cert, bp384.Key),
		ApplicationIdentity(bp256.Cert, bp256.Key),
		ApplicationIdentity(ed448.Cert, ed448.Key),
	} {
		require.NoError(t, opt(cfg))
	}
	require.Equal(t, testpki.ServerAppURI, cfg.applicationURI)
	for uri, want := range map[string]*testpki.Identity{
		ua.SecurityPolicyURIECCNistP256:        p256,
		ua.SecurityPolicyURIECCBrainpoolP256r1: bp384, // the first one that fits: P384r1 also serves P256r1
		ua.SecurityPolicyURIECCBrainpoolP384r1: bp384,
		ua.SecurityPolicyURIECCCurve448:        ed448,
	} {
		cert, key, ok := cfg.identityFor(uri)
		require.True(t, ok, uri)
		require.Equal(t, want.Cert, cert, uri)
		require.Equal(t, want.Key, key, uri)
	}
	_, _, ok := cfg.identityFor(ua.SecurityPolicyURIECCCurve25519)
	require.False(t, ok)

	// The key has to belong to the certificate.
	require.Error(t, ApplicationIdentity(bp256.Cert, bp384.Key)(&serverConfig{}))
	require.Error(t, ApplicationIdentity(ed448.Cert, pki.ECC.Client[testpki.CurveEd448].Key)(&serverConfig{}))

	// Certificate reads the ApplicationURI of such certificates too.
	c := &serverConfig{}
	require.NoError(t, Certificate(ed448.Cert)(c))
	require.Equal(t, testpki.ServerAppURI, c.applicationURI)
	require.True(t, certificateHasURI(bp256.Cert, testpki.ServerAppURI))
	require.False(t, certificateHasURI(bp256.Cert, "urn:other"))
}

// TestServerOption_WithClientCertificateTrustList_Extended verifies client
// certificates with Brainpool and Ed448 keys against a trust list.
func TestServerOption_WithClientCertificateTrustList_Extended(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)
	for _, curve := range []string{testpki.CurveBrainpoolP256r1, testpki.CurveBrainpoolP384r1, testpki.CurveEd448} {
		t.Run(curve, func(t *testing.T) {
			ca, issued := pki.ECC.CAs[curve], pki.ECC.IssuedByCA[curve]
			self := pki.ECC.Client[curve]

			cfg := &serverConfig{}
			require.NoError(t, WithClientCertificateTrustList(ca.Cert, self.Cert)(cfg))
			validate := cfg.clientCertificateValidator
			require.NoError(t, validate(issued.Cert))
			require.NoError(t, validate(self.Cert), "a trusted self-signed certificate")
			require.NoError(t, validate(append(append([]byte(nil), issued.Cert...), ca.Cert...)), "a chain")
			require.ErrorIs(t, validate(pki.ECC.Server[curve].Cert), ua.StatusBadCertificateUntrusted)
			require.ErrorIs(t, validate([]byte("junk")), ua.StatusBadCertificateInvalid)
		})
	}
}
