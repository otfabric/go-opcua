// SPDX-License-Identifier: MIT

package opcua

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// extCurves are the curves of the certificates crypto/x509 cannot handle.
var extCurves = []string{testpki.CurveBrainpoolP256r1, testpki.CurveBrainpoolP384r1, testpki.CurveEd448}

func TestCertificate_ExtendedKeys(t *testing.T) {
	for _, curve := range extCurves {
		t.Run(curve, func(t *testing.T) {
			id, err := testpki.NewIdentity(curve, "client "+curve, "urn:otfabric:client:"+curve, nil, nil)
			require.NoError(t, err)
			cfg, err := ApplyConfig(Certificate(id.Cert), PrivateKeySigner(id.Key))
			require.NoError(t, err)
			require.Equal(t, "urn:otfabric:client:"+curve, cfg.session.ClientDescription.ApplicationURI)
			require.Equal(t, id.Key, cfg.sechan.LocalPrivateKey)

			// The key file formats.
			der, err := uapolicy.MarshalPrivateKey(id.Key)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "key.pem")
			require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
			cfg, err = ApplyConfig(PrivateKeyFile(path))
			require.NoError(t, err)
			require.True(t, uapolicy.KeyMatchesCertificate(cfg.sechan.LocalPrivateKey, id.Cert))
		})
	}

	// SEC 1 Brainpool keys, as OpenSSL writes them.
	cfg, err := ApplyConfig(PrivateKeyFile(filepath.Join("uapolicy", "testdata", "openssl", "brainpoolP384r1-sec1.pem")))
	require.NoError(t, err)
	require.NotNil(t, cfg.sechan.LocalPrivateKey)
}

// TestValidateServerCertificate_ExtendedKeys validates server certificates
// with Brainpool and Ed448 keys: self-signed and trusted, issued by a trusted
// CA on the same curve, untrusted.
func TestValidateServerCertificate_ExtendedKeys(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)
	trust := func(certs ...*x509.Certificate) *Config {
		c := newConfig()
		for _, cert := range certs {
			require.NoError(t, TrustedCertificates(cert)(c))
		}
		return c
	}
	modes := []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}
	for _, curve := range extCurves {
		t.Run(curve, func(t *testing.T) {
			server := pki.ECC.Server[curve]
			ca, issued := pki.ECC.CAs[curve], pki.ECC.IssuedByCA[curve]
			stranger := pki.ECC.Client[curve]
			for _, mode := range modes {
				require.NoError(t, trust(server.X509).validateServerCertificate(server.Cert, mode))
				require.NoError(t, trust(ca.X509).validateServerCertificate(issued.Cert, mode))
				require.Error(t, trust(stranger.X509).validateServerCertificate(server.Cert, mode))
				require.Error(t, trust().validateServerCertificate(server.Cert, mode))
				// A chain: leaf followed by its issuer, which is not trusted
				// by itself.
				chain := append(append([]byte(nil), issued.Cert...), ca.Cert...)
				require.Error(t, trust(stranger.X509).validateServerCertificate(chain, mode))
			}

			// The ApplicationURI binding.
			c := trust(server.X509)
			c.certValidator.serverApplicationURI = "urn:someone:else"
			require.ErrorContains(t, c.validateServerCertificate(server.Cert, ua.MessageSecurityModeSign), "ApplicationURI")
			c.certValidator.serverApplicationURI = testpki.ServerAppURI
			require.NoError(t, c.validateServerCertificate(server.Cert, ua.MessageSecurityModeSign))

			require.Error(t, trust(server.X509).validateServerCertificate([]byte("junk"), ua.MessageSecurityModeSign))
		})
	}
}
