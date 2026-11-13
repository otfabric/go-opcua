// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
)

// TestVerifyEd448Chain_Bounded checks that the work to look for an Ed448
// chain is bounded, whatever intermediates come with the certificate.
func TestVerifyEd448Chain_Bounded(t *testing.T) {
	unrelated := newTestCert(t, caTemplate("unrelated anchor"), newEd448Key(t), nil)
	anchors := []*x509.Certificate{unrelated.cert}

	t.Run("intermediates with one key", func(t *testing.T) {
		// Many CAs with one name and one key, no path length constraint:
		// each appears to issue the leaf and every other one.
		key := newEd448Key(t)
		var ims []*testCert
		for i := 0; i < 20; i++ {
			ims = append(ims, newTestCert(t, caTemplate("shared ca"), key, nil))
		}
		leaf := newTestCert(t, certTemplate("ed448 leaf"), newEd448Key(t), ims[0])
		certs := []*x509.Certificate{leaf.cert}
		for _, c := range ims {
			certs = append(certs, c.cert, c.cert) // duplicates too
		}
		b := &ed448Builder{intermediates: dedupCertificates(certs[1:]), anchors: anchors, now: time.Now(), sigs: map[sigEdge]error{}}
		require.Len(t, b.intermediates, 20)
		start := time.Now()
		err := b.build(certs[:1])
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
		require.Less(t, time.Since(start), 10*time.Second)
		require.LessOrEqual(t, b.sigChecks, 21, "one signature check per certificate and key")
		require.LessOrEqual(t, b.candidates, maxChainCandidates+1)

		start = time.Now()
		require.ErrorIs(t, VerifyCertificate(certs, poolOf(anchors...), anchors), errors.ErrInvalidCertificate)
		require.Less(t, time.Since(start), 10*time.Second)
	})

	t.Run("cross-certified keys", func(t *testing.T) {
		// CAs with one name and six keys, each key certified by every
		// other: many paths, each edge with a signature of its own.
		tmpl := func() *x509.Certificate {
			tmpl := caTemplate("shared ca")
			tmpl.SubjectKeyId = []byte{1, 2, 3, 4}
			return tmpl
		}
		var keys []*testCert
		for i := 0; i < 6; i++ {
			keys = append(keys, newTestCert(t, tmpl(), newEd448Key(t), nil))
		}
		leaf := newTestCert(t, certTemplate("ed448 leaf"), newEd448Key(t), keys[0])
		certs := []*x509.Certificate{leaf.cert}
		for _, subject := range keys {
			for _, issuer := range keys {
				certs = append(certs, newTestCert(t, tmpl(), subject.key, issuer).cert)
			}
		}
		b := &ed448Builder{intermediates: dedupCertificates(certs[1:]), anchors: anchors, now: time.Now(), sigs: map[sigEdge]error{}}
		err := b.build(certs[:1])
		require.ErrorIs(t, err, errChainWork)
		require.Equal(t, maxChainSignatureChecks+1, b.sigChecks, "stopped at the limit")
		require.ErrorIs(t, VerifyCertificate(certs, poolOf(anchors...), anchors), errors.ErrInvalidCertificate)
	})

	t.Run("valid chain through a crowd", func(t *testing.T) {
		root := newTestCert(t, caTemplate("ed448 root"), newEd448Key(t), nil)
		im := newTestCert(t, caTemplate("ed448 intermediate"), newEd448Key(t), root)
		leaf := newTestCert(t, certTemplate("ed448 leaf"), newEd448Key(t), im)
		certs := []*x509.Certificate{leaf.cert}
		for i := 0; i < 5; i++ {
			certs = append(certs, newTestCert(t, caTemplate("ed448 intermediate"), newEd448Key(t), nil).cert)
		}
		certs = append(certs, im.cert)
		require.NoError(t, VerifyCertificate(certs, poolOf(root.cert), []*x509.Certificate{root.cert}))
	})
}
