// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

func FuzzHeaderDecode(f *testing.F) {
	f.Add([]byte{'M', 'S', 'G', 'F', 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{'O', 'P', 'N', 'F', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{'C', 'L', 'O', 'A'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(Header)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Header.Decode consumed %d bytes but input was %d", n, len(data))
		}
		// Reject absurd MessageSize claims that would blow chunk reassembly budgets.
		if h.MessageSize > 0 && int(h.MessageSize) < n {
			// MessageSize includes the header; values smaller than consumed bytes
			// are malformed but must not panic above.
			return
		}
	})
}

func FuzzSequenceHeaderDecode(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(SequenceHeader)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("SequenceHeader.Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzSymmetricSecurityHeaderDecode(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(SymmetricSecurityHeader)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("SymmetricSecurityHeader.Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzAsymmetricSecurityHeaderDecode(f *testing.F) {
	// Empty strings for security policy / cert / thumbprint lengths.
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, // SecurityPolicyURI length 0
		0x00, 0x00, 0x00, 0x00, // SenderCertificate length 0
		0x00, 0x00, 0x00, 0x00, // ReceiverCertificateThumbprint length 0
	})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(AsymmetricSecurityHeader)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("AsymmetricSecurityHeader.Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

// FuzzDecodeServiceMessageJSON feeds arbitrary bytes to the decoder of the
// JSON messages of https-uajson and wss-uajson. It must never panic, and
// what it decodes must encode and decode again.
func FuzzDecodeServiceMessageJSON(f *testing.F) {
	ns := []string{"http://opcfoundation.org/UA/", "urn:one"}
	for _, v := range []any{
		&ua.ReadRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 1}, NodesToRead: []*ua.ReadValueID{{NodeID: ua.NewStringNodeID(1, "x"), AttributeID: ua.AttributeIDValue}}},
		&ua.CreateSessionRequest{RequestHeader: &ua.RequestHeader{}, ClientNonce: []byte{1, 2}},
		&ua.ServiceFault{ResponseHeader: &ua.ResponseHeader{ServiceResult: ua.StatusBadDecodingError}},
	} {
		b, err := EncodeServiceMessageJSON(v, ns)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"TypeId":{"Id":631},"Body":{}}`))
	f.Add([]byte(`{"UaTypeId":"i=631","UaEncoding":1,"UaBody":"AA=="}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := DecodeServiceMessageJSON(data, ns)
		if err != nil {
			return
		}
		b, err := EncodeServiceMessageJSON(v, ns)
		if err != nil {
			t.Fatalf("decoded %T does not encode: %v", v, err)
		}
		if _, err := DecodeServiceMessageJSON(b, ns); err != nil {
			t.Fatalf("re-encoded %T does not decode: %v\n%s", v, err, b)
		}
	})
}
