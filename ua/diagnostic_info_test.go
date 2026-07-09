// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestDiagnosticInfo(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "Nothing",
			Struct: &DiagnosticInfo{},
			Bytes: []byte{
				0x00,
			},
		},
		{
			Name: "Has SymbolicID",
			Struct: &DiagnosticInfo{
				EncodingMask: DiagnosticInfoSymbolicID,
				SymbolicID:   1,
			},
			Bytes: []byte{
				0x01, 0x01, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has NamespaceURI",
			Struct: &DiagnosticInfo{
				EncodingMask: DiagnosticInfoNamespaceURI,
				NamespaceURI: 2,
			},
			Bytes: []byte{
				0x02, 0x02, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has LocalizedText",
			Struct: &DiagnosticInfo{
				EncodingMask:  DiagnosticInfoLocalizedText,
				LocalizedText: 3,
			},
			Bytes: []byte{
				0x04, 0x03, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has Locale",
			Struct: &DiagnosticInfo{
				EncodingMask: DiagnosticInfoLocale,
				Locale:       4,
			},
			Bytes: []byte{
				0x08, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has AdditionalInfo",
			Struct: &DiagnosticInfo{
				EncodingMask:   DiagnosticInfoAdditionalInfo,
				AdditionalInfo: "foobar",
			},
			Bytes: []byte{
				0x10, 0x06, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f,
				0x62, 0x61, 0x72,
			},
		},
		{
			Name: "Has InnerStatusCode",
			Struct: &DiagnosticInfo{
				EncodingMask:    DiagnosticInfoInnerStatusCode,
				InnerStatusCode: 6,
			},
			Bytes: []byte{
				0x20, 0x06, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has InnerDiagnosticInfo",
			Struct: &DiagnosticInfo{
				EncodingMask: DiagnosticInfoInnerDiagnosticInfo,
				InnerDiagnosticInfo: &DiagnosticInfo{
					EncodingMask: DiagnosticInfoSymbolicID,
					SymbolicID:   7,
				},
			},
			Bytes: []byte{
				0x40, 0x01, 0x07, 0x00, 0x00, 0x00,
			},
		},
		{
			Name: "Has all",
			Struct: &DiagnosticInfo{
				EncodingMask: DiagnosticInfoSymbolicID |
					DiagnosticInfoNamespaceURI |
					DiagnosticInfoLocalizedText |
					DiagnosticInfoLocale |
					DiagnosticInfoAdditionalInfo |
					DiagnosticInfoInnerStatusCode |
					DiagnosticInfoInnerDiagnosticInfo,

				SymbolicID:      1,
				NamespaceURI:    2,
				Locale:          3,
				LocalizedText:   4,
				AdditionalInfo:  "foobar",
				InnerStatusCode: 6,
				InnerDiagnosticInfo: &DiagnosticInfo{
					EncodingMask: DiagnosticInfoSymbolicID,
					SymbolicID:   7,
				},
			},
			Bytes: []byte{
				0x7f,
				// SymbolicID
				0x01, 0x00, 0x00, 0x00,
				// NamespaceURI
				0x02, 0x00, 0x00, 0x00,
				// Locale
				0x03, 0x00, 0x00, 0x00,
				// LocalizedText
				0x04, 0x00, 0x00, 0x00,
				// AdditionalInfo
				0x06, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
				// InnerStatusCode
				0x06, 0x00, 0x00, 0x00,
				// InnerDiagnostics
				0x01, 0x07, 0x00, 0x00, 0x00,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestDiagnosticInfoUpdateMask(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		d := &DiagnosticInfo{}
		d.UpdateMask()
		if d.EncodingMask != 0 {
			t.Fatalf("want 0, got %d", d.EncodingMask)
		}
	})
	t.Run("all fields", func(t *testing.T) {
		d := &DiagnosticInfo{
			SymbolicID:          1,
			NamespaceURI:        2,
			Locale:              3,
			LocalizedText:       4,
			AdditionalInfo:      "info",
			InnerStatusCode:     StatusBad,
			InnerDiagnosticInfo: &DiagnosticInfo{},
		}
		d.UpdateMask()
		wantBits := byte(DiagnosticInfoSymbolicID | DiagnosticInfoNamespaceURI |
			DiagnosticInfoLocale | DiagnosticInfoLocalizedText |
			DiagnosticInfoAdditionalInfo | DiagnosticInfoInnerStatusCode |
			DiagnosticInfoInnerDiagnosticInfo)
		if d.EncodingMask != wantBits {
			t.Fatalf("encoding mask: got 0x%02x, want 0x%02x", d.EncodingMask, wantBits)
		}
	})
}
