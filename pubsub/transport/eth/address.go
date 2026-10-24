// SPDX-License-Identifier: MIT

package eth

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Address is the address of an Ethernet connection, the part of an
// opc.eth:// URL after the scheme (Part 14 §7.3.3):
//
//	opc.eth://<host>[:<VID>[.<PCP>]]
//
// It is also the [net.Addr] of the sender of a received message.
type Address struct {
	// MAC is the destination (or, for a received message, the source)
	// MAC address; nil for an address without host (receive only).
	MAC net.HardwareAddr
	// VLAN reports whether the address has a VID: frames are sent with an
	// IEEE 802.1Q tag.
	VLAN bool
	// VID is the VLAN identifier, 0 to 4094. VID 0 is a priority tag: the
	// frame belongs to no VLAN and only carries the PCP.
	VID uint16
	// PCP is the priority code point of the tag, 0 to 7.
	PCP uint8
}

var _ net.Addr = Address{}

// MaxVID is the largest VLAN identifier: 4095 (0xFFF) is reserved
// (IEEE 802.1Q §9.6).
const MaxVID = 4094

// ParseURL parses an opc.eth:// URL (Part 14 §7.3.3):
//
//	opc.eth://<host>[:<VID>[.<PCP>]]
//
// host is a MAC address as six groups of hexadecimal digits separated by
// hyphens (01-23-45-67-89-ab), unicast, multicast or broadcast
// (ff-ff-ff-ff-ff-ff), or empty for a connection that only receives. The
// specification also allows a host name or IP address "if the system can
// resolve them to a MAC address"; resolving is not supported, such an
// address is an error. VID is the decimal VLAN identifier (0 to 4094), PCP
// the decimal priority code point (0 to 7). A path, query or fragment is
// ignored.
func ParseURL(url string) (Address, error) {
	rest, ok := strings.CutPrefix(url, Scheme+"://")
	if !ok {
		return Address{}, fmt.Errorf("pubsub/transport/eth: %q is not an %s:// URL", url, Scheme)
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.Count(rest, ":") > 1 {
		return Address{}, fmt.Errorf("pubsub/transport/eth: %q: a MAC address is written with hyphens (01-23-45-67-89-ab)", url)
	}
	host, tag, hasTag := strings.Cut(rest, ":")
	var a Address
	if host != "" {
		mac, err := parseMAC(host)
		if err != nil {
			return Address{}, fmt.Errorf("pubsub/transport/eth: %q: %w", url, err)
		}
		a.MAC = mac
	}
	if !hasTag {
		return a, nil
	}
	vid, pcp, hasPCP := strings.Cut(tag, ".")
	n, err := parseDecimal(vid, MaxVID)
	if err != nil {
		return Address{}, fmt.Errorf("pubsub/transport/eth: %q: VLAN id %q: %w", url, vid, err)
	}
	a.VLAN, a.VID = true, uint16(n)
	if hasPCP {
		p, err := parseDecimal(pcp, 7)
		if err != nil {
			return Address{}, fmt.Errorf("pubsub/transport/eth: %q: priority code point %q: %w", url, pcp, err)
		}
		a.PCP = uint8(p)
	}
	return a, nil
}

// parseDecimal parses a decimal number from 0 to max: digits only, no sign.
func parseDecimal(s string, limit uint64) (uint64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("not a decimal number")
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n > limit {
		return 0, fmt.Errorf("out of range 0..%d", limit)
	}
	return n, nil
}

// parseMAC parses six groups of one or two hexadecimal digits separated by
// hyphens. Part 14 §7.3.3 shows two digits per group (01-23-45-67-89-ab);
// open62541 also accepts a single digit, so do we.
func parseMAC(s string) (net.HardwareAddr, error) {
	groups := strings.Split(s, "-")
	if len(groups) != 6 {
		if strings.ContainsAny(s, ".:[]") || !strings.Contains(s, "-") {
			return nil, fmt.Errorf("host %q is not a MAC address: resolving host names and IP addresses to MAC addresses is not supported", s)
		}
		return nil, fmt.Errorf("MAC address %q needs six hyphen separated groups", s)
	}
	mac := make(net.HardwareAddr, 6)
	for i, g := range groups {
		if len(g) == 0 || len(g) > 2 {
			return nil, fmt.Errorf("MAC address %q: bad group %q", s, g)
		}
		v, err := strconv.ParseUint(g, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("MAC address %q: bad group %q", s, g)
		}
		mac[i] = byte(v)
	}
	return mac, nil
}

// FormatMAC formats a MAC address the way Part 14 §7.3.3 writes it:
// lower-case hexadecimal groups separated by hyphens.
func FormatMAC(mac net.HardwareAddr) string {
	var b strings.Builder
	for i, v := range mac {
		if i > 0 {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%02x", v)
	}
	return b.String()
}

// Network implements [net.Addr].
func (a Address) Network() string { return Scheme }

// String returns the host and tag part of the URL:
// 01-23-45-67-89-ab[:VID.PCP].
func (a Address) String() string {
	s := FormatMAC(a.MAC)
	if a.VLAN {
		s += fmt.Sprintf(":%d.%d", a.VID, a.PCP)
	}
	return s
}

// URL returns the address as an opc.eth:// URL.
func (a Address) URL() string { return Scheme + "://" + a.String() }

// isMulticast reports whether mac is a group address (the I/G bit, the
// least significant bit of the first octet, is set); the broadcast address
// is one too.
func isMulticast(mac net.HardwareAddr) bool { return len(mac) == 6 && mac[0]&1 != 0 }

// isBroadcast reports whether mac is ff-ff-ff-ff-ff-ff.
func isBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}
