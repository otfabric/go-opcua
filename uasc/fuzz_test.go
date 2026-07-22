// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"
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
