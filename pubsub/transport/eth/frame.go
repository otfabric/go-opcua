// SPDX-License-Identifier: MIT

package eth

import (
	"encoding/binary"
	"errors"
	"net"
)

// Frame layout (Part 14 §7.3.3, Table 200; IEEE 802.3 Ethernet II with an
// optional IEEE 802.1Q tag):
//
//	destination MAC   6 bytes
//	source MAC        6 bytes
//	[TPID 0x8100      2 bytes   802.1Q tag, optional
//	 TCI              2 bytes   PCP (3 bits) | DEI (1 bit) | VID (12 bits)]
//	EtherType 0xB62C  2 bytes
//	NetworkMessage    up to 1500 bytes
//
// The frame check sequence is added and removed by the hardware.
const (
	// EtherType is the IANA-registered EtherType of OPC UA UADP
	// NetworkMessages (Part 14 §7.3.3).
	EtherType = 0xB62C
	// tpid8021Q is the EtherType of an IEEE 802.1Q VLAN tag.
	tpid8021Q = 0x8100
	// tpid8021AD is the EtherType of an IEEE 802.1ad (QinQ) service tag.
	tpid8021AD = 0x88A8

	headerLen = 14
	tagLen    = 4

	// MaxPayload is the largest NetworkMessage of a frame: Part 14 §7.3.3
	// limits frames to 1522 bytes, "MaxNetworkMessageSize is typically
	// 1500" once the 22 bytes of addresses, EtherType, VLAN tag and frame
	// check sequence are subtracted. The tag does not reduce it: a tagged
	// frame may be 4 bytes longer than an untagged one.
	MaxPayload = 1500
)

// Reasons a received frame is dropped.
var (
	errShortFrame = errors.New("short frame")
	errEtherType  = errors.New("not an OPC UA frame")
	errStacked    = errors.New("stacked VLAN tags or an 802.1ad service tag")
	errNoPayload  = errors.New("empty payload")
)

// frame is a parsed received frame.
type frame struct {
	dst, src net.HardwareAddr // slices of the received buffer
	tagged   bool
	vid      uint16
	pcp      uint8
	payload  []byte
}

// header returns the header of the frames sent to dst from src: the
// addresses, the 802.1Q tag if a has a VID, and the EtherType.
func header(dst, src net.HardwareAddr, a Address) []byte {
	b := make([]byte, 0, headerLen+tagLen)
	b = append(b, dst[:6]...)
	b = append(b, src[:6]...)
	if a.VLAN {
		b = binary.BigEndian.AppendUint16(b, tpid8021Q)
		b = binary.BigEndian.AppendUint16(b, uint16(a.PCP&7)<<13|a.VID&0x0FFF) // DEI 0
	}
	return binary.BigEndian.AppendUint16(b, EtherType)
}

// parseFrame parses a received frame. Every length is checked: the frame
// comes from the network.
func parseFrame(b []byte) (frame, error) {
	if len(b) < headerLen {
		return frame{}, errShortFrame
	}
	f := frame{dst: net.HardwareAddr(b[0:6:6]), src: net.HardwareAddr(b[6:12:12])}
	et := binary.BigEndian.Uint16(b[12:14])
	off := headerLen
	if et == tpid8021Q {
		if len(b) < headerLen+tagLen {
			return frame{}, errShortFrame
		}
		tci := binary.BigEndian.Uint16(b[14:16])
		f.tagged, f.pcp, f.vid = true, uint8(tci>>13), tci&0x0FFF
		et = binary.BigEndian.Uint16(b[16:18])
		off += tagLen
	}
	switch et {
	case EtherType:
	case tpid8021Q, tpid8021AD:
		return frame{}, errStacked
	default:
		return frame{}, errEtherType
	}
	f.payload = b[off:]
	if len(f.payload) == 0 {
		return frame{}, errNoPayload
	}
	return f, nil
}

// source returns the Address of the sender of f.
func (f frame) source() Address {
	return Address{MAC: append(net.HardwareAddr(nil), f.src...), VLAN: f.tagged, VID: f.vid, PCP: f.pcp}
}
