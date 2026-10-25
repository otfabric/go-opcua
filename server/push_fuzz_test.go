// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// FuzzTrustListUpdate: whatever a client writes to the TrustList file,
// CloseAndUpdate's decoding and validation never panic, and a trust list
// they accept is within its limits, encodes to what it holds and validates
// certificates.
func FuzzTrustListUpdate(f *testing.F) {
	p, err := testpki.Get()
	if err != nil {
		f.Fatal(err)
	}
	enc := func(d *ua.TrustListDataType) []byte {
		b, err := ua.Encode(d)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	f.Add(enc(&ua.TrustListDataType{SpecifiedLists: 15, TrustedCertificates: [][]byte{p.ClientCert}, IssuerCertificates: [][]byte{p.CACert}}))
	f.Add(enc(&ua.TrustListDataType{SpecifiedLists: 1, TrustedCertificates: [][]byte{p.CACert, p.CACert}}))
	f.Add(enc(&ua.TrustListDataType{SpecifiedLists: 2, TrustedCrls: [][]byte{{0x30, 0x03, 0x02, 0x01, 0x00}}}))
	f.Add(enc(&ua.TrustListDataType{SpecifiedLists: 0xff}))
	f.Add([]byte{0x0f, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f})
	f.Add([]byte("garbage"))
	base, sc := newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}, 0)
	if sc != ua.StatusOK {
		f.Fatal(sc)
	}
	probe, err := uapolicy.ParseCertificates(p.IssuedCert)
	if err != nil {
		f.Fatal(err)
	}
	const limit = 64 << 10
	f.Fuzz(func(t *testing.T, file []byte) {
		upd, sc := decodeTrustList(file)
		if sc != ua.StatusOK {
			return
		}
		tl, sc := newTrustList(mergeTrustList(base.data, upd), limit)
		if sc != ua.StatusOK {
			return
		}
		if tl.size > limit {
			t.Fatalf("trust list of %d bytes accepted, limit %d", tl.size, limit)
		}
		b, err := encodeTrustList(tl.data)
		if err != nil || len(b) != tl.size {
			t.Fatalf("encoding the accepted trust list: %d bytes, %v; want %d", len(b), err, tl.size)
		}
		again, sc := decodeTrustList(b)
		if sc != ua.StatusOK || len(again.TrustedCertificates) != len(tl.trusted) || len(again.IssuerCertificates) != len(tl.issuers) {
			t.Fatalf("the accepted trust list does not decode to itself: %v", sc)
		}
		_ = tl.verify(probe)
		_ = maskTrustList(tl.data, ua.TrustListMasks(len(file)))
	})
}
