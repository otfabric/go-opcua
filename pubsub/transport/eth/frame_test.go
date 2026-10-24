// SPDX-License-Identifier: MIT

package eth

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	macA = mustMAC("02-00-00-00-00-0a")
	macB = mustMAC("02-00-00-00-00-0b")
	grp  = mustMAC("01-00-5e-7f-00-01")
)

func TestHeaderUntagged(t *testing.T) {
	h := header(grp, macA, Address{})
	require.Equal(t, "01005e7f0001"+"02000000000a"+"b62c", hex.EncodeToString(h))
}

func TestHeaderTagged(t *testing.T) {
	// TCI: PCP 5 (101), DEI 0, VID 100 (0x064) = 1010 0000 0110 0100.
	h := header(grp, macA, Address{VLAN: true, VID: 100, PCP: 5})
	require.Equal(t, "01005e7f0001"+"02000000000a"+"8100"+"a064"+"b62c", hex.EncodeToString(h))
	// A priority tag: VID 0.
	h = header(grp, macA, Address{VLAN: true, VID: 0, PCP: 7})
	require.Equal(t, "8100e000b62c", hex.EncodeToString(h[12:]))
}

func TestParseFrameRoundTrip(t *testing.T) {
	for _, a := range []Address{{}, {VLAN: true, VID: 4094, PCP: 7}, {VLAN: true}} {
		b := append(header(macB, macA, a), "payload"...)
		f, err := parseFrame(b)
		require.NoError(t, err)
		require.Equal(t, macB, f.dst)
		require.Equal(t, macA, f.src)
		require.Equal(t, a.VLAN, f.tagged)
		require.Equal(t, a.VID, f.vid)
		require.Equal(t, a.PCP, f.pcp)
		require.Equal(t, "payload", string(f.payload))
		src := f.source()
		require.Equal(t, Address{MAC: macA, VLAN: a.VLAN, VID: a.VID, PCP: a.PCP}, src)
		// The source address does not alias the receive buffer.
		b[6] = 0xee
		require.Equal(t, macA, src.MAC)
	}
}

func TestParseFrameErrors(t *testing.T) {
	untagged := header(macB, macA, Address{})
	tagged := header(macB, macA, Address{VLAN: true, VID: 1})
	withType := func(h []byte, et ...byte) []byte {
		b := bytes.Clone(h)
		copy(b[len(b)-2:], et)
		return append(b, 1)
	}
	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"empty":            {nil, errShortFrame},
		"13 bytes":         {untagged[:13], errShortFrame},
		"tag cut":          {tagged[:16], errShortFrame},
		"tag no type":      {tagged[:17], errShortFrame},
		"no payload":       {untagged, errNoPayload},
		"tagged no pay":    {tagged, errNoPayload},
		"IPv4":             {withType(untagged, 0x08, 0x00), errEtherType},
		"tagged IPv4":      {withType(tagged, 0x08, 0x00), errEtherType},
		"length field":     {withType(untagged, 0x00, 0x10), errEtherType},
		"double 802.1Q":    {withType(tagged, 0x81, 0x00), errStacked},
		"inner 802.1ad":    {withType(tagged, 0x88, 0xa8), errStacked},
		"outer 802.1ad":    {withType(untagged, 0x88, 0xa8), errStacked},
		"untagged 8100 ok": {append(bytes.Clone(tagged), 9), nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseFrame(tc.b)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// FuzzParseFrame: parsing never panics and the payload stays inside the
// frame.
func FuzzParseFrame(f *testing.F) {
	f.Add(append(header(macB, macA, Address{}), 1, 2, 3))
	f.Add(append(header(macB, macA, Address{VLAN: true, VID: 7, PCP: 1}), 1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := parseFrame(b)
		if err != nil {
			return
		}
		if len(fr.payload) == 0 || len(fr.payload) > len(b)-headerLen {
			t.Fatalf("payload of %d bytes in a frame of %d", len(fr.payload), len(b))
		}
	})
}
