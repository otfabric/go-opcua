// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// toBER re-encodes DER the way BER producers such as Java keytool before JDK
// 8u301 do: every constructed element with an indefinite length, every
// non-empty OCTET STRING as a constructed one of segments of chunk bytes
// (the first segment again constructed, to nest them), and the contents of
// the OCTET STRINGs that hold DER themselves re-encoded too, down to deep
// levels.
func toBER(t *testing.T, der []byte, deep, chunk int) []byte {
	t.Helper()
	var out []byte
	for len(der) > 0 {
		tag, constructed, hdr, ok := berTag(der)
		require.True(t, ok)
		n, l, ok := berLength(der[hdr:])
		require.True(t, ok)
		content := der[hdr+l : hdr+l+n]
		switch {
		case constructed:
			out = append(out, der[0]|0x20)
			out = append(out, der[1:hdr]...)
			out = append(out, 0x80)
			out = append(out, toBER(t, content, deep, chunk)...)
			out = append(out, 0, 0)
		case tag == tagOctetString && n > 0:
			if deep > 0 && content[0] == 0x30 && isDER(content, 0) {
				content = toBER(t, content, deep-1, chunk)
			}
			out = append(out, 0x24, 0x80)
			// The first segment is itself constructed, with a non-minimal
			// definite length.
			first := min(chunk, len(content))
			inner := append([]byte{0x04}, derLength(nil, first)...)
			inner = append(inner, content[:first]...)
			require.Less(t, len(inner), 1<<16)
			out = append(out, 0x24, 0x82, byte(len(inner)>>8), byte(len(inner)))
			out = append(out, inner...)
			for i := first; i < len(content); i += chunk {
				seg := content[i:min(i+chunk, len(content))]
				out = append(out, 0x04)
				out = derLength(out, len(seg))
				out = append(out, seg...)
			}
			out = append(out, 0, 0)
		default:
			out = append(out, der[:hdr+l+n]...)
		}
		der = der[hdr+l+n:]
	}
	return out
}

// TestParsePFX_BER decodes PKCS #12 files in BER: indefinite lengths,
// constructed and nested OCTET STRINGs, non-minimal lengths.
func TestParsePFX_BER(t *testing.T) {
	// The MAC covers the contents of the authSafe OCTET STRING, so in a file
	// with a MAC only the encoding around them changes.
	for _, tt := range []struct {
		file, password string
	}{
		{"rsa-default.p12", pfxTestPassword},
		{"keytool-p256-legacy.p12", "opcuaopcua"},
		{"ed448-pbmac1-sha512.p12", pfxTestPassword},
	} {
		t.Run(tt.file, func(t *testing.T) {
			der := readPFX(t, tt.file)
			wantKey, wantCerts, err := ParsePFX(der, tt.password)
			require.NoError(t, err)
			ber := toBER(t, der, 0, 100)
			require.NotEqual(t, der, ber)
			require.False(t, isDER(ber, 0))
			key, certs, err := ParsePFX(ber, tt.password)
			require.NoError(t, err)
			require.True(t, keysEqual(key.Public(), wantKey.Public()))
			require.Equal(t, wantCerts[0].Raw, certs[0].Raw)
			_, _, err = ParsePFX(ber, "wrong")
			require.ErrorIs(t, err, ErrPFXPassword)
		})
	}
	// Without MAC and encryption the AuthenticatedSafe and the SafeContents
	// are in BER too.
	t.Run("nested", func(t *testing.T) {
		der := readPFX(t, "p256-noenc-nomac.p12")
		wantKey, _, err := ParsePFX(der, "")
		require.NoError(t, err)
		for _, chunk := range []int{1, 7, 1 << 15} {
			ber := toBER(t, der, 2, chunk)
			key, certs, err := ParsePFX(ber, "")
			require.NoError(t, err, "chunk %d", chunk)
			require.True(t, keysEqual(key.Public(), wantKey.Public()))
			require.True(t, KeyMatchesCertificate(key, certs[0].Raw))
		}
	})
}

func TestBERToDER(t *testing.T) {
	for name, tt := range map[string]struct {
		in, want []byte
	}{
		"DER as is":           {[]byte{0x30, 0x03, 0x02, 0x01, 0x05}, nil},
		"empty":               {[]byte{}, nil},
		"indefinite":          {[]byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00}, []byte{0x30, 0x03, 0x02, 0x01, 0x05}},
		"long form length":    {[]byte{0x30, 0x81, 0x03, 0x02, 0x01, 0x05}, []byte{0x30, 0x03, 0x02, 0x01, 0x05}},
		"long form primitive": {[]byte{0x04, 0x82, 0x00, 0x01, 0xaa}, []byte{0x04, 0x01, 0xaa}},
		"constructed octets": {
			[]byte{0x24, 0x80, 0x04, 0x01, 0xaa, 0x24, 0x03, 0x04, 0x01, 0xbb, 0x04, 0x00, 0x00, 0x00},
			[]byte{0x04, 0x02, 0xaa, 0xbb},
		},
		"empty constructed octets": {[]byte{0x24, 0x80, 0x00, 0x00}, []byte{0x04, 0x00}},
		"context specific":         {[]byte{0xa0, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00}, []byte{0xa0, 0x03, 0x04, 0x01, 0xaa}},
		"high tag number": {
			[]byte{0xbf, 0x81, 0x01, 0x80, 0x05, 0x00, 0x00, 0x00},
			[]byte{0xbf, 0x81, 0x01, 0x02, 0x05, 0x00},
		},
		"long content": {
			append([]byte{0x30, 0x80, 0x04, 0x81, 0x80}, append(bytes.Repeat([]byte{1}, 0x80), 0, 0)...),
			append([]byte{0x30, 0x81, 0x83, 0x04, 0x81, 0x80}, bytes.Repeat([]byte{1}, 0x80)...),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := berToDER(tt.in)
			require.NoError(t, err)
			want := tt.want
			if want == nil {
				want = tt.in
			}
			require.Equal(t, want, got)
			require.True(t, isDER(got, 0))
		})
	}

	nested := func(depth int) []byte {
		var b []byte
		for range depth {
			b = append(b, 0x30, 0x80)
		}
		for range depth {
			b = append(b, 0, 0)
		}
		return b
	}
	_, err := berToDER(nested(maxBERDepth))
	require.NoError(t, err)
	for name, in := range map[string][]byte{
		"no end of contents":      {0x30, 0x80, 0x02, 0x01, 0x05},
		"primitive indefinite":    {0x04, 0x80, 0x00, 0x00},
		"truncated":               {0x30, 0x05, 0x02, 0x01},
		"truncated primitive":     {0x04, 0x05, 0x01},
		"trailing data":           {0x30, 0x80, 0x00, 0x00, 0x01},
		"no length":               {0x30},
		"length too long":         {0x04, 0x85, 0, 0, 0, 0, 1},
		"length truncated":        {0x04, 0x82, 0x01},
		"length too large":        {0x04, 0x84, 0x7f, 0xff, 0xff, 0xff},
		"high tag truncated":      {0x3f, 0x81},
		"high tag too long":       {0x3f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00},
		"octets of other":         {0x24, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00},
		"too deep":                nested(maxBERDepth + 2),
		"bad child":               {0x30, 0x80, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00},
		"bad definite child":      {0x30, 0x02, 0x04, 0x05},
		"octets bad segment len":  {0x24, 0x80, 0x24, 0x80, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00},
		"empty identifier header": {0x24, 0x80},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := berToDER(in)
			require.Error(t, err)
		})
	}
	_, err = berToDER(make([]byte, 2*maxPFXSize+1))
	require.Error(t, err)
}

// FuzzBERToDER: what berToDER returns is DER, and DER is returned as it is.
func FuzzBERToDER(f *testing.F) {
	f.Add([]byte{0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := berToDER(in)
		if err != nil {
			return
		}
		if !isDER(out, 0) {
			t.Fatalf("not DER: %x", out)
		}
		again, err := berToDER(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("DER changed: %x -> %x (%v)", out, again, err)
		}
	})
}
