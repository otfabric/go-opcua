// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiagnosticInfo_Resolve(t *testing.T) {
	table := []string{"BadNodeIdUnknown", "http://opcfoundation.org/UA/", "The node id refers to a node that does not exist.", "en", "BadTypeMismatch"}
	d := &DiagnosticInfo{
		EncodingMask: DiagnosticInfoSymbolicID | DiagnosticInfoNamespaceURI | DiagnosticInfoLocalizedText | DiagnosticInfoLocale |
			DiagnosticInfoAdditionalInfo | DiagnosticInfoInnerStatusCode | DiagnosticInfoInnerDiagnosticInfo,
		SymbolicID: 0, NamespaceURI: 1, LocalizedText: 2, Locale: 3,
		AdditionalInfo:  "ns=1;s=x",
		InnerStatusCode: StatusBadTypeMismatch,
		InnerDiagnosticInfo: &DiagnosticInfo{
			EncodingMask: DiagnosticInfoSymbolicID | DiagnosticInfoLocalizedText,
			SymbolicID:   4,
			// out of range: resolves to ""
			LocalizedText: 99,
		},
	}
	r := d.Resolve(table)
	require.Equal(t, &Diagnostic{
		SymbolicID:      "BadNodeIdUnknown",
		NamespaceURI:    "http://opcfoundation.org/UA/",
		LocalizedText:   "The node id refers to a node that does not exist.",
		Locale:          "en",
		AdditionalInfo:  "ns=1;s=x",
		InnerStatusCode: StatusBadTypeMismatch,
		Inner:           &Diagnostic{SymbolicID: "BadTypeMismatch"},
	}, r)
	s := r.String()
	require.Contains(t, s, "BadNodeIdUnknown")
	require.Contains(t, s, `"The node id refers`)
	require.Contains(t, s, "ns=1;s=x")
	require.Contains(t, s, "inner ")
	require.Contains(t, s, "(BadTypeMismatch)")

	// Fields whose bit is not set are ignored.
	r = (&DiagnosticInfo{EncodingMask: DiagnosticInfoLocale, SymbolicID: 0, Locale: -1}).Resolve(table)
	require.Equal(t, &Diagnostic{}, r)
	require.Empty(t, r.String())

	require.Nil(t, (*DiagnosticInfo)(nil).Resolve(table))
	require.Nil(t, (&DiagnosticInfo{}).Resolve(table))
	require.Empty(t, (*Diagnostic)(nil).String())
}

func TestDiagnosticInfo_ResolveDepth(t *testing.T) {
	d := &DiagnosticInfo{EncodingMask: DiagnosticInfoAdditionalInfo, AdditionalInfo: "x"}
	for i := 0; i < 100; i++ {
		d = &DiagnosticInfo{EncodingMask: DiagnosticInfoInnerDiagnosticInfo | DiagnosticInfoAdditionalInfo, AdditionalInfo: "x", InnerDiagnosticInfo: d}
	}
	r := d.Resolve(nil)
	depth := 0
	for ; r != nil; r = r.Inner {
		depth++
	}
	require.Equal(t, maxDiagnosticDepth, depth)
}

func TestResponseHeader_Diagnostics(t *testing.T) {
	h := &ResponseHeader{
		StringTable:        []string{"BadTimeout"},
		ServiceDiagnostics: &DiagnosticInfo{EncodingMask: DiagnosticInfoSymbolicID},
	}
	require.Equal(t, "BadTimeout", h.ServiceDiagnostic().SymbolicID)
	require.Equal(t, "BadTimeout", h.Diagnostic(&DiagnosticInfo{EncodingMask: DiagnosticInfoSymbolicID}).SymbolicID)
	require.Nil(t, (&ResponseHeader{}).ServiceDiagnostic())

	var nilHdr *ResponseHeader
	require.Nil(t, nilHdr.ServiceDiagnostic())
	require.Equal(t, "", nilHdr.Diagnostic(&DiagnosticInfo{EncodingMask: DiagnosticInfoSymbolicID}).SymbolicID)
}

// FuzzDiagnosticInfoResolve decodes arbitrary DiagnosticInfos and string
// tables and resolves them: Resolve must never panic and must stay bounded.
func FuzzDiagnosticInfoResolve(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00}, "a", "b")
	f.Add([]byte{0x7f, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 'x', 0, 0, 0, 0, 0x40, 0x01, 0, 0, 0, 0}, "s", "t")
	f.Fuzz(func(t *testing.T, b []byte, s1, s2 string) {
		d := new(DiagnosticInfo)
		if _, err := d.Decode(b); err != nil {
			return
		}
		r := d.Resolve([]string{s1, s2})
		_ = r.String()
	})
}
