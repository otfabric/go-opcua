// SPDX-License-Identifier: MIT

package eth

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// runFilter interprets the classic BPF subset of recvFilter: it returns the
// number of bytes the kernel keeps (0: the frame is dropped). A load beyond
// the frame drops it, as in the kernel.
func runFilter(t *testing.T, prog []filterInsn, frame []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.code {
		case bpfLdHAbs:
			if int(in.k)+2 > len(frame) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(frame[in.k:]))
		case bpfJeqK:
			if a == in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfRetK:
			return in.k
		default:
			t.Fatalf("opcode %#x", in.code)
		}
	}
	t.Fatal("program without return")
	return 0
}

func TestRecvFilter(t *testing.T) {
	tagged := frameTo(grp, Address{VLAN: true, VID: 5}, "x")
	ipv4 := frameTo(grp, Address{}, "x")
	binary.BigEndian.PutUint16(ipv4[12:], 0x0800)
	taggedIPv4 := frameTo(grp, Address{VLAN: true, VID: 5}, "x")
	binary.BigEndian.PutUint16(taggedIPv4[16:], 0x0800)
	for name, tc := range map[string]struct {
		frame  []byte
		accept bool
	}{
		"untagged":    {frameTo(grp, Address{}, "x"), true},
		"tagged":      {tagged, true},
		"IPv4":        {ipv4, false},
		"tagged IPv4": {taggedIPv4, false},
		"short":       {tagged[:13], false},
		"short tag":   {tagged[:17], false},
	} {
		got := runFilter(t, recvFilter, tc.frame)
		require.Equal(t, tc.accept, got > 0, name)
	}
}
