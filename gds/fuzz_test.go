// SPDX-License-Identifier: MIT

package gds_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// FuzzDecodeTrustList: DecodeTrustList never panics, and what it decodes
// encodes back to the same bytes.
func FuzzDecodeTrustList(f *testing.F) {
	for _, tl := range []*ua.TrustListDataType{
		{SpecifiedLists: 15},
		{SpecifiedLists: 1, TrustedCertificates: [][]byte{{1, 2, 3}}},
		{SpecifiedLists: 15, TrustedCertificates: [][]byte{{1}}, TrustedCrls: [][]byte{{2}}, IssuerCertificates: [][]byte{{3}}, IssuerCrls: [][]byte{{4}}},
	} {
		b, err := gds.EncodeTrustList(tl)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, b []byte) {
		tl, err := gds.DecodeTrustList(b)
		if err != nil {
			return
		}
		out, err := gds.EncodeTrustList(tl)
		if err != nil {
			t.Fatalf("re-encoding: %v", err)
		}
		again, err := gds.DecodeTrustList(out)
		if err != nil {
			t.Fatalf("decoding the re-encoded trust list: %v", err)
		}
		out2, _ := gds.EncodeTrustList(again)
		if !bytes.Equal(out, out2) {
			t.Fatal("the encoding is not stable")
		}
	})
}
