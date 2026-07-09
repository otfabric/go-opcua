// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
	"time"
)

func TestDataValue(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "no value",
			Struct: &DataValue{
				EncodingMask: 0x00,
				Value:        MustVariant(nil),
			},
			Bytes: []byte{
				// EncodingMask
				0x00,
			},
		},
		{
			Name: "value only",
			Struct: &DataValue{
				EncodingMask: 0x01,
				Value:        MustVariant(float32(2.50025)),
			},
			Bytes: []byte{
				// EncodingMask
				0x01,
				// Value
				0x0a,                   // type
				0x19, 0x04, 0x20, 0x40, // value
			},
		},
		{
			Name: "value, source timestamp, server timestamp",
			Struct: &DataValue{
				EncodingMask:    0x0d,
				Value:           MustVariant(float32(2.50017)),
				SourceTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
				ServerTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
			},
			Bytes: []byte{
				// EncodingMask
				0x0d,
				// Value
				0x0a,                   // type
				0xc9, 0x02, 0x20, 0x40, // value
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// SeverTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
			},
		},
		{
			Name: "source timestamp, server timestamp",
			Struct: &DataValue{
				EncodingMask:    0x0c,
				Value:           MustVariant(nil),
				SourceTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
				ServerTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
			},
			Bytes: []byte{
				// EncodingMask
				0x0c,
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// SeverTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
			},
		},
		{
			Name: "value with nil slice, source timestamp, server timestamp",
			Struct: &DataValue{
				EncodingMask:    0x0d,
				Value:           MustVariant([]string(nil)),
				SourceTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
				ServerTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
			},
			Bytes: []byte{
				// EncodingMask
				0x0d,
				// Value
				0x8c,                   // type
				0xff, 0xff, 0xff, 0xff, // value
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// SeverTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestDataValueArray(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "value only; value, source timestamp, server timestamp; source timestamp, server timestamp",
			Struct: []*DataValue{
				{
					EncodingMask: 0x01,
					Value:        MustVariant(float32(2.50025)),
				},
				{
					EncodingMask:    0x0d,
					Value:           MustVariant(float32(2.50017)),
					SourceTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
					ServerTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
				},
				{
					EncodingMask:    0x0c,
					Value:           MustVariant(nil),
					SourceTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
					ServerTimestamp: time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC),
				},
			},
			Bytes: []byte{
				// length
				0x03, 0x00, 0x00, 0x00,

				// EncodingMask
				0x01,
				// Value
				0x0a,
				0x19, 0x04, 0x20, 0x40,

				// EncodingMask
				0x0d,
				// Value
				0x0a,
				0xc9, 0x02, 0x20, 0x40,
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// ServerTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,

				// EncodingMask
				0x0c,
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// ServerTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestGUID(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "ok",
			Struct: NewGUID("AAAABBBB-CCDD-EEFF-0102-0123456789AB"),
			Bytes: []byte{
				// data1 (inverse order)
				0xbb, 0xbb, 0xaa, 0xaa,
				// data2 (inverse order)
				0xdd, 0xcc,
				// data3 (inverse order)
				0xff, 0xee,
				// data4 (same order)
				0x01, 0x02, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
			},
		},
		{
			Name:   "spec",
			Struct: NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"),
			Bytes: []byte{
				// data1 (inverse order)
				0x91, 0x2b, 0x96, 0x72,
				// data2 (inverse order)
				0x75, 0xfa,
				// data3 (inverse order)
				0xe6, 0x4a,
				// data4 (same order)
				0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestLocalizedText(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "nothing",
			Struct: NewLocalizedText(""),
			Bytes:  []byte{0x00},
		},
		{
			Name:   "has-locale",
			Struct: NewLocalizedTextWithLocale("", "foo"),
			Bytes: []byte{
				0x01,
				0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f,
			},
		},
		{
			Name:   "has-text",
			Struct: NewLocalizedText("bar"),
			Bytes: []byte{
				0x02,
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72,
			},
		},
		{
			Name:   "has-both",
			Struct: NewLocalizedTextWithLocale("bar", "foo"),
			Bytes: []byte{
				0x03,
				0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f,
				// second String: "bar"
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestLocalizedText_String(t *testing.T) {
	tests := []struct {
		l    *LocalizedText
		want string
	}{
		{nil, ""},
		{NewLocalizedText("Siemens AG"), "Siemens AG"},
		{NewLocalizedTextWithLocale("Siemens AG", "en-US"), "en-US: Siemens AG"},
		{&LocalizedText{}, ""},
	}
	for _, tt := range tests {
		got := tt.l.String()
		if got != tt.want {
			t.Errorf("LocalizedText.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestDataValueUpdateMask(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("empty", func(t *testing.T) {
		dv := &DataValue{}
		dv.UpdateMask()
		if dv.EncodingMask != 0 {
			t.Fatalf("want 0, got %d", dv.EncodingMask)
		}
	})
	t.Run("value only", func(t *testing.T) {
		dv := &DataValue{Value: MustVariant(int32(1))}
		dv.UpdateMask()
		if dv.EncodingMask&DataValueValue == 0 {
			t.Fatal("DataValueValue bit not set")
		}
	})
	t.Run("all fields", func(t *testing.T) {
		dv := &DataValue{
			Value:             MustVariant(int32(1)),
			Status:            StatusBadUserAccessDenied,
			SourceTimestamp:   ts,
			ServerTimestamp:   ts,
			SourcePicoseconds: 100,
			ServerPicoseconds: 200,
		}
		dv.UpdateMask()
		wantBits := byte(DataValueValue | DataValueStatusCode |
			DataValueSourceTimestamp | DataValueServerTimestamp |
			DataValueSourcePicoseconds | DataValueServerPicoseconds)
		if dv.EncodingMask != wantBits {
			t.Fatalf("encoding mask: got 0x%02x, want 0x%02x", dv.EncodingMask, wantBits)
		}
	})
}

func TestXMLElementCodec(t *testing.T) {
	original := XMLElement("<foo>bar</foo>")
	b, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var decoded XMLElement
	n, err := decoded.Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n == 0 {
		t.Fatal("Decode returned 0 bytes consumed")
	}
	if decoded != original {
		t.Fatalf("round-trip: got %q, want %q", decoded, original)
	}
}
