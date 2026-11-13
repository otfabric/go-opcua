// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
)

// TestVerifyCertificateChains checks that the chains returned run from the
// certificate to a trust anchor through signature-linked issuers only, with
// and without Ed448 signatures.
func TestVerifyCertificateChains(t *testing.T) {
	keys := extKeys(t)
	for _, family := range []string{"p256", "ed448"} {
		t.Run(family, func(t *testing.T) {
			key := keys[family]
			ca := newTestCert(t, caTemplate("ca "+family), key, nil)
			interKey := extKeys(t)[family]
			inter := newTestCert(t, caTemplate("intermediate "+family), interKey, ca)
			leaf := newTestCert(t, certTemplate("leaf "+family), extKeys(t)[family], inter)
			// Same subject as the intermediate, another key, self-signed.
			twin := newTestCert(t, caTemplate("intermediate "+family), extKeys(t)[family], nil)
			anchors := []*x509.Certificate{ca.cert}

			chains, err := VerifyCertificateChains([]*x509.Certificate{leaf.cert, twin.cert, inter.cert}, poolOf(ca.cert), anchors)
			require.NoError(t, err)
			require.Len(t, chains, 1)
			require.Len(t, chains[0], 3)
			require.True(t, chains[0][0].Equal(leaf.cert))
			require.True(t, chains[0][1].Equal(inter.cert))
			require.True(t, chains[0][2].Equal(ca.cert))

			// A trusted leaf is a chain of its own.
			chains, err = VerifyCertificateChains([]*x509.Certificate{leaf.cert}, poolOf(leaf.cert), []*x509.Certificate{leaf.cert})
			require.NoError(t, err)
			require.Len(t, chains, 1)
			require.Len(t, chains[0], 1)

			_, err = VerifyCertificateChains([]*x509.Certificate{leaf.cert, twin.cert}, poolOf(ca.cert), anchors)
			require.Error(t, err)
		})
	}
	_, err := VerifyCertificateChains(nil, nil, nil)
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)

	t.Run("ed448 expired leaf", func(t *testing.T) {
		key := newEd448Key(t)
		ca := newTestCert(t, caTemplate("ed448 ca"), key, nil)
		tmpl := certTemplate("expired")
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		old := newTestCert(t, tmpl, newEd448Key(t), ca)
		_, err := VerifyCertificateChains([]*x509.Certificate{old.cert}, poolOf(ca.cert), []*x509.Certificate{ca.cert})
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	})
	t.Run("ed448 too long", func(t *testing.T) {
		key := newEd448Key(t)
		parent := newTestCert(t, caTemplate("root"), key, nil)
		root := parent
		var inters []*x509.Certificate
		for i := range maxChainLength {
			c := newTestCert(t, caTemplate("inter "+string(rune('a'+i))), newEd448Key(t), parent)
			inters = append(inters, c.cert)
			parent = c
		}
		leaf := newTestCert(t, certTemplate("deep leaf"), newEd448Key(t), parent)
		_, err := VerifyCertificateChains(append([]*x509.Certificate{leaf.cert}, inters...), poolOf(root.cert), []*x509.Certificate{root.cert})
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	})
}
