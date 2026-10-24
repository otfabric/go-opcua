// SPDX-License-Identifier: MIT

package eth

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustMAC(s string) net.HardwareAddr {
	m, err := parseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestParseURL(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want Address
	}{
		{"opc.eth://01-23-45-67-89-ab", Address{MAC: mustMAC("01-23-45-67-89-ab")}},
		{"opc.eth://01-23-45-67-89-AB", Address{MAC: mustMAC("01-23-45-67-89-ab")}},
		{"opc.eth://1-2-3-4-5-6", Address{MAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}}},
		{"opc.eth://ff-ff-ff-ff-ff-ff", Address{MAC: mustMAC("ff-ff-ff-ff-ff-ff")}},
		{"opc.eth://01-00-5e-00-00-01:100", Address{MAC: mustMAC("01-00-5e-00-00-01"), VLAN: true, VID: 100}},
		{"opc.eth://01-00-5e-00-00-01:100.5", Address{MAC: mustMAC("01-00-5e-00-00-01"), VLAN: true, VID: 100, PCP: 5}},
		{"opc.eth://01-00-5e-00-00-01:0.7", Address{MAC: mustMAC("01-00-5e-00-00-01"), VLAN: true, VID: 0, PCP: 7}},
		{"opc.eth://01-00-5e-00-00-01:4094.0", Address{MAC: mustMAC("01-00-5e-00-00-01"), VLAN: true, VID: 4094}},
		{"opc.eth://01-00-5e-00-00-01/path?q#f", Address{MAC: mustMAC("01-00-5e-00-00-01")}},
		{"opc.eth://", Address{}},
		{"opc.eth://:12", Address{VLAN: true, VID: 12}},
	} {
		t.Run(tc.url, func(t *testing.T) {
			a, err := ParseURL(tc.url)
			require.NoError(t, err)
			require.Equal(t, tc.want, a)
		})
	}
}

func TestParseURLErrors(t *testing.T) {
	for _, tc := range []struct{ url, msg string }{
		{"opc.udp://01-23-45-67-89-ab", "not an opc.eth:// URL"},
		{"opc.eth://01:23:45:67:89:ab", "written with hyphens"},
		{"opc.eth://[::1]:4840", "written with hyphens"},
		{"opc.eth://host.example.com", "resolving host names"},
		{"opc.eth://10.0.0.1:5", "resolving host names"},
		{"opc.eth://localhost", "resolving host names"},
		{"opc.eth://01-23-45-67-89", "six hyphen separated groups"},
		{"opc.eth://01-23-45-67-89-ab-cd", "six hyphen separated groups"},
		{"opc.eth://01-23-45-67-89-", "bad group"},
		{"opc.eth://01-23-45-67-89-abc", "bad group"},
		{"opc.eth://01-23-45-67-89-zz", "bad group"},
		{"opc.eth://01-23-45-67-89-ab:", "VLAN id"},
		{"opc.eth://01-23-45-67-89-ab:4095", "out of range 0..4094"},
		{"opc.eth://01-23-45-67-89-ab:99999", "out of range 0..4094"},
		{"opc.eth://01-23-45-67-89-ab:+5", "not a decimal number"},
		{"opc.eth://01-23-45-67-89-ab:0x10", "not a decimal number"},
		{"opc.eth://01-23-45-67-89-ab:10.8", "out of range 0..7"},
		{"opc.eth://01-23-45-67-89-ab:10.", "priority code point"},
		{"opc.eth://01-23-45-67-89-ab:10.1.2", "not a decimal number"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			_, err := ParseURL(tc.url)
			require.ErrorContains(t, err, tc.msg)
		})
	}
}

func TestAddressString(t *testing.T) {
	a := Address{MAC: net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0xab}}
	require.Equal(t, "01-00-5e-00-00-ab", a.String())
	require.Equal(t, "opc.eth://01-00-5e-00-00-ab", a.URL())
	require.Equal(t, Scheme, a.Network())
	a.VLAN, a.VID, a.PCP = true, 100, 3
	require.Equal(t, "opc.eth://01-00-5e-00-00-ab:100.3", a.URL())
	back, err := ParseURL(a.URL())
	require.NoError(t, err)
	require.Equal(t, a, back)
	require.Empty(t, FormatMAC(nil))
}

func TestMACClasses(t *testing.T) {
	require.True(t, isMulticast(mustMAC("01-00-5e-00-00-01")))
	require.True(t, isMulticast(mustMAC("ff-ff-ff-ff-ff-ff")))
	require.False(t, isMulticast(mustMAC("02-00-00-00-00-01")))
	require.False(t, isMulticast(nil))
	require.True(t, isBroadcast(mustMAC("ff-ff-ff-ff-ff-ff")))
	require.False(t, isBroadcast(mustMAC("ff-ff-ff-ff-ff-fe")))
	require.False(t, isBroadcast(nil))
}
