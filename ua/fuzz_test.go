// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func FuzzVariantDecode(f *testing.F) {
	// seed corpus: a few valid Variant encodings
	f.Add([]byte{0x01, 0x01})                                           // Boolean true
	f.Add([]byte{0x06, 0x2a, 0x00, 0x00, 0x00})                         // Int32(42)
	f.Add([]byte{0x0c, 0x04, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74}) // String "test"
	f.Add([]byte{0x00})                                                 // Null
	f.Fuzz(func(t *testing.T, data []byte) {
		v := new(Variant)
		n, err := v.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzNodeIDDecode(f *testing.F) {
	f.Add([]byte{0x00, 0x0d})                               // TwoByte: i=13
	f.Add([]byte{0x01, 0x00, 0x0d, 0x00})                   // FourByte: i=13
	f.Add([]byte{0x02, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00}) // Numeric
	f.Fuzz(func(t *testing.T, data []byte) {
		n := new(NodeID)
		consumed, err := n.Decode(data)
		if err != nil {
			return
		}
		if consumed > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", consumed, len(data))
		}
	})
}

func FuzzExtensionObjectDecode(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x01, 0x00, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		e := new(ExtensionObject)
		consumed, err := e.Decode(data)
		if err != nil {
			return
		}
		if consumed > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", consumed, len(data))
		}
	})
}

func FuzzParseNodeID(f *testing.F) {
	f.Add("i=2253")
	f.Add("ns=2;s=Temperature")
	f.Add("ns=1;i=42")
	f.Add("ns=2;g=09087e75-8e5e-499b-954f-f2a9603db28a")
	f.Add("ns=3;b=M/RbKBsRVkePCePcx24oRA==")
	f.Add("")
	f.Add("not-a-node-id")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseNodeID(s)
	})
}

func FuzzParseNumericRange(f *testing.F) {
	f.Add("0")
	f.Add("0:5")
	f.Add("1:3,0:1")
	f.Add("")
	f.Add(":-1")
	f.Add("5:1")
	f.Add("999999999999999999999")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseNumericRange(s)
		_, _ = ParseNumericRanges(s)
	})
}

func FuzzEventFilterDecode(f *testing.F) {
	ef := NewEventFilter().
		Select("EventId", "Severity", "Message").
		Where(OfType(NewNumericNodeID(0, id.BaseEventType))).
		Build()
	if b, err := Encode(ef); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		v := new(EventFilter)
		n, err := Decode(data, v)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzContentFilterDecode(f *testing.F) {
	cf := &ContentFilter{
		Elements: []*ContentFilterElement{
			OfType(NewNumericNodeID(0, id.BaseEventType)),
		},
	}
	if b, err := Encode(cf); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		v := new(ContentFilter)
		n, err := Decode(data, v)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzDecodeService(f *testing.F) {
	// FourByte ExpandedNodeID type prefix for ReadResponse (631) + empty-ish body.
	// Encoding: ExpandedNodeID NodeID encoding + service body.
	f.Add([]byte{0x01, 0x00, 0x77, 0x02}) // FourByte ns=0 id=631 ReadResponse type id only
	f.Add([]byte{0x01, 0x00, 0xd4, 0x03}) // PublishResponse type id 980
	f.Add([]byte{0x01, 0x00, 0x8f, 0x01}) // ServiceFault type id 399
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeService(data)
	})
}

func FuzzUABinaryDecode(f *testing.F) {
	// Prefer hand-built seeds; Encode of zero ResponseHeader can panic on nil
	// DiagnosticInfo pointers and is not a decode-path concern.
	if b, err := Encode(&DataValue{}); err == nil {
		f.Add(b)
	}
	if b, err := Encode(&QualifiedName{}); err == nil {
		f.Add(b)
	}
	if b, err := Encode(&LocalizedText{}); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		targets := []interface{}{
			new(DataValue),
			new(DiagnosticInfo),
			new(QualifiedName),
			new(LocalizedText),
			new(NodeID),
		}
		for _, v := range targets {
			n, err := Decode(data, v)
			if err != nil {
				continue
			}
			if n > len(data) {
				t.Fatalf("%T Decode consumed %d bytes but input was %d", v, n, len(data))
			}
		}
	})
}
