// SPDX-License-Identifier: MIT

package uapolicy

import (
	stderrors "errors"
)

// BER (ITU-T X.690) to DER, for the PKCS #12 files of producers that write
// indefinite lengths and constructed OCTET STRINGs (Java keytool before JDK
// 8u301, Windows CryptoAPI, some HSM exports). berToDER rewrites:
//
//   - indefinite lengths (0x80 ... end-of-contents) as definite ones;
//   - non-minimal definite lengths as minimal ones;
//   - constructed OCTET STRINGs (0x24) as primitive ones with the
//     concatenated contents of their segments, which may be constructed
//     themselves.
//
// Primitive contents are copied as they are: the MAC of a PFX is computed
// over the contents of the authSafe OCTET STRING, which this leaves
// unchanged, and certificates keep the bytes their signatures cover. It
// does not sort SET OF elements; nothing ParsePFX reads depends on the
// order.
//
// The input is bounded by maxPFXSize and the nesting by maxBERDepth; the
// output is at most twice the size of the input (an indefinite length costs
// four bytes, a definite one at most six).

// maxBERDepth bounds the nesting of constructed elements.
const maxBERDepth = 64

var errBER = stderrors.New("malformed BER")

// berToDER returns data in DER as described above. It returns data itself
// when it is in DER already.
func berToDER(data []byte) ([]byte, error) {
	if len(data) > 2*maxPFXSize {
		return nil, errBER
	}
	if isDER(data, 0) {
		return data, nil
	}
	out, rest, err := berElement(data, 0, nil)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBER
	}
	return out, nil
}

// isDER reports whether data is a sequence of elements with minimal definite
// lengths and no constructed OCTET STRING, at any depth.
func isDER(data []byte, depth int) bool {
	if depth > maxBERDepth {
		return false
	}
	for len(data) > 0 {
		tag, constructed, hdr, ok := berTag(data)
		if !ok {
			return false
		}
		n, lenLen, ok := berLength(data[hdr:])
		if !ok || n < 0 || !minimalLength(data[hdr:hdr+lenLen], n) || n > len(data)-hdr-lenLen {
			return false
		}
		content := data[hdr+lenLen : hdr+lenLen+n]
		if constructed {
			if tag == tagOctetString || !isDER(content, depth+1) {
				return false
			}
		}
		data = data[hdr+lenLen+n:]
	}
	return true
}

// tagOctetString is the universal OCTET STRING tag (number 4, class bits 0).
const tagOctetString = 4

// berTag reads the identifier octets of an element: the tag (class bits and
// number for low tag numbers, or the whole identifier octets for high ones,
// as an opaque comparable value), whether it is constructed and the size of
// the identifier octets.
func berTag(b []byte) (tag uint64, constructed bool, size int, ok bool) {
	if len(b) == 0 {
		return 0, false, 0, false
	}
	constructed = b[0]&0x20 != 0
	if b[0]&0x1f != 0x1f {
		return uint64(b[0] &^ 0x20), constructed, 1, true
	}
	// High tag number: base-128 octets, the last without bit 8.
	tag = uint64(b[0] &^ 0x20)
	for i := 1; i < len(b) && i <= 5; i++ {
		tag = tag<<8 | uint64(b[i])
		if b[i]&0x80 == 0 {
			return tag, constructed, i + 1, true
		}
	}
	return 0, false, 0, false
}

// berLength reads the length octets: the length, -1 for an indefinite
// length, and the size of the length octets.
func berLength(b []byte) (n, size int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, true
	}
	if b[0] == 0x80 {
		return -1, 1, true
	}
	k := int(b[0] & 0x7f)
	if k > 4 || len(b) < 1+k {
		return 0, 0, false
	}
	for _, c := range b[1 : 1+k] {
		n = n<<8 | int(c)
	}
	if n > 2*maxPFXSize {
		return 0, 0, false
	}
	return n, 1 + k, true
}

// minimalLength reports whether the length octets enc are the DER encoding
// of n.
func minimalLength(enc []byte, n int) bool {
	return len(enc) == len(derLength(nil, n))
}

// derLength appends the DER length octets of n.
func derLength(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n < 0x100:
		return append(b, 0x81, byte(n))
	case n < 0x10000:
		return append(b, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// berElement converts the element at the start of b and appends it to out;
// it returns the rest of b.
func berElement(b []byte, depth int, out []byte) ([]byte, []byte, error) {
	if depth > maxBERDepth {
		return nil, nil, errBER
	}
	tag, constructed, hdr, ok := berTag(b)
	if !ok {
		return nil, nil, errBER
	}
	n, lenLen, ok := berLength(b[hdr:])
	if !ok {
		return nil, nil, errBER
	}
	ident := b[:hdr]
	body := b[hdr+lenLen:]
	if !constructed {
		if n < 0 || n > len(body) {
			return nil, nil, errBER // a primitive element has a definite length
		}
		out = append(out, ident...)
		out = derLength(out, n)
		return append(out, body[:n]...), body[n:], nil
	}

	// The contents of a constructed element: its children up to the
	// definite length, or up to the end-of-contents octets.
	var children, rest []byte
	var conv []byte
	var err error
	if n >= 0 {
		if n > len(body) {
			return nil, nil, errBER
		}
		children, rest = body[:n], body[n:]
		for len(children) > 0 {
			if conv, children, err = berElement(children, depth+1, conv); err != nil {
				return nil, nil, err
			}
		}
	} else {
		rest = body
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]
				break
			}
			if len(rest) == 0 {
				return nil, nil, errBER // no end-of-contents
			}
			if conv, rest, err = berElement(rest, depth+1, conv); err != nil {
				return nil, nil, err
			}
		}
	}

	if tag == tagOctetString {
		// A constructed OCTET STRING: the concatenation of its segments,
		// which are (converted) primitive OCTET STRINGs.
		var s []byte
		for len(conv) > 0 {
			if conv[0] != tagOctetString {
				return nil, nil, errBER
			}
			m, l, ok := berLength(conv[1:])
			if !ok || m < 0 || m > len(conv)-1-l {
				return nil, nil, errBER
			}
			s = append(s, conv[1+l:1+l+m]...)
			conv = conv[1+l+m:]
		}
		out = append(out, tagOctetString)
		out = derLength(out, len(s))
		return append(out, s...), rest, nil
	}
	out = append(out, ident...)
	out = derLength(out, len(conv))
	return append(out, conv...), rest, nil
}
