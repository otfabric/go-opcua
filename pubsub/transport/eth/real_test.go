// SPDX-License-Identifier: MIT

//go:build linux || darwin || freebsd

package eth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// The tests of this file use real raw sockets (Linux) or BPF devices (macOS,
// FreeBSD). They need CAP_NET_RAW or root (Linux) or access to /dev/bpf*
// and skip without. They send frames, so they only run on interfaces that
// are made for it:
//
//   - GO_OPCUA_ETH_IFACE names an interface for the tests that send to the
//     host itself; on Linux the loopback interface "lo" is the default.
//   - GO_OPCUA_ETH_PAIR names two connected interfaces ("veth0,veth1", a
//     veth pair) for the tests that send from one to the other.
//   - GO_OPCUA_ETH_REQUIRE=1 turns the skips into failures (CI runs the
//     tests as root and must not pass by skipping them).
//
// On macOS a port without link (status inactive) does not work: frames are
// dropped before the BPF devices see them. A vmnet bridge (bridge100 of a
// local VM) does.

// RealIfaceEnv and RealPairEnv are the environment variables of the real
// interface tests.
const (
	RealIfaceEnv   = "GO_OPCUA_ETH_IFACE"
	RealPairEnv    = "GO_OPCUA_ETH_PAIR"
	RealRequireEnv = "GO_OPCUA_ETH_REQUIRE"
)

// SkipReal skips a real interface test, or fails it if RealRequireEnv is
// set.
func SkipReal(t *testing.T, args ...any) {
	t.Helper()
	if os.Getenv(RealRequireEnv) != "" {
		t.Fatal(args...)
	}
	t.Skip(args...)
}

func realIface(t *testing.T) string {
	t.Helper()
	if name := os.Getenv(RealIfaceEnv); name != "" {
		return name
	}
	if runtime.GOOS == "linux" {
		return "lo"
	}
	SkipReal(t, "set "+RealIfaceEnv+" to an Ethernet interface to run the real BPF tests")
	return ""
}

func realPair(t *testing.T) (string, string) {
	t.Helper()
	a, b, ok := strings.Cut(os.Getenv(RealPairEnv), ",")
	if !ok || a == "" || b == "" {
		SkipReal(t, "set "+RealPairEnv+" to two connected interfaces (a,b) to run the real pair tests")
	}
	return a, b
}

// skipWithoutPrivilege skips the test if err says raw access is denied.
func skipWithoutPrivilege(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		SkipReal(t, "no raw Ethernet access:", err)
	}
}

// nonce makes the payloads of a test distinct from anything else on the
// interface.
func nonce(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return []byte("go-opcua-eth-test-" + hex.EncodeToString(b) + ":")
}

func realOpen(t *testing.T, url, iface string, mod func(*transport.Config)) *Conn {
	t.Helper()
	cfg := transport.Config{URL: url, Interface: iface}
	if mod != nil {
		mod(&cfg)
	}
	c, err := Open(context.Background(), cfg)
	skipWithoutPrivilege(t, err)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

// realSubscribe subscribes to the URL on the interface and returns the
// channel of the messages whose payload starts with prefix.
func realSubscribe(t *testing.T, url, iface string, prefix []byte) (*Conn, chan *transport.Message) {
	t.Helper()
	c := realOpen(t, url, iface, nil)
	ch := make(chan *transport.Message, 64)
	_, err := c.Subscribe(context.Background(), "", 0, func(m *transport.Message) {
		if bytes.HasPrefix(m.Payload, prefix) {
			select {
			case ch <- m:
			default:
			}
		}
	})
	skipWithoutPrivilege(t, err)
	require.NoError(t, err)
	return c, ch
}

// sendUntil sends payload every 20 ms until it arrives on ch (a raw frame
// has no delivery guarantee) and returns the message. Other messages are
// skipped; one with the payload reject fails the test.
func sendUntil(t *testing.T, pub *Conn, payload []byte, ch chan *transport.Message, reject []byte) *transport.Message {
	t.Helper()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(10 * time.Second)
	for {
		require.NoError(t, pub.Send(context.Background(), payload, transport.PublishOptions{}))
	wait:
		for {
			select {
			case m := <-ch:
				if reject != nil && bytes.Equal(m.Payload, reject) {
					t.Fatalf("received %q", m.Payload)
				}
				if bytes.Equal(m.Payload, payload) {
					return m
				}
			case <-tick.C:
				break wait
			case <-deadline:
				t.Fatal("no frame received")
			}
		}
	}
}

func macOf(t *testing.T, iface string) net.HardwareAddr {
	t.Helper()
	ifi, err := net.InterfaceByName(iface)
	require.NoError(t, err)
	if len(ifi.HardwareAddr) == 0 {
		return make(net.HardwareAddr, 6)
	}
	return ifi.HardwareAddr
}

// TestRealSelf sends to the host itself on one interface: to its own
// address, to broadcast, to a multicast group and with a VLAN tag.
func TestRealSelf(t *testing.T) {
	iface := realIface(t)
	mac := macOf(t, iface)
	urls := []string{
		"opc.eth://ff-ff-ff-ff-ff-ff",
		"opc.eth://01-00-5e-7f-00-01",
		"opc.eth://ff-ff-ff-ff-ff-ff:100.3",
	}
	if !macHidden(mac) {
		urls = append(urls, "opc.eth://"+FormatMAC(mac), "opc.eth://"+FormatMAC(mac)+":101.1")
	}
	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			prefix := nonce(t)
			sub, ch := realSubscribe(t, url, iface, prefix)
			pub := realOpen(t, url, iface, nil)
			payload := append(bytes.Clone(prefix), "hello"...)
			m := sendUntil(t, pub, payload, ch, nil)
			require.Equal(t, payload, m.Payload)
			if !macHidden(mac) {
				src := m.Source.(Address)
				require.Equal(t, mac, src.MAC)
				require.Equal(t, sub.LocalAddr().(Address).MAC, src.MAC)
			}

			// The largest NetworkMessage goes through in one frame.
			full := append(bytes.Clone(prefix), make([]byte, pub.MaxMessageSize()-len(prefix))...)
			m = sendUntil(t, pub, full, ch, nil)
			require.Equal(t, full, m.Payload)
			err := pub.Send(context.Background(), append(full, 0), transport.PublishOptions{})
			require.ErrorIs(t, err, transport.ErrMessageTooLarge)
		})
	}
}

// TestRealPair sends from one interface of a connected pair to the other.
func TestRealPair(t *testing.T) {
	a, b := realPair(t)
	macB := FormatMAC(macOf(t, b))
	for _, url := range []string{
		"opc.eth://" + macB,
		"opc.eth://01-00-5e-7f-00-02",
		"opc.eth://ff-ff-ff-ff-ff-ff",
		"opc.eth://" + macB + ":42.6",
		"opc.eth://01-00-5e-7f-00-02:0.5", // priority tag
	} {
		t.Run(url, func(t *testing.T) {
			prefix := nonce(t)
			_, ch := realSubscribe(t, url, b, prefix)
			pub := realOpen(t, url, a, nil)
			require.Equal(t, MaxPayload, pub.MaxMessageSize())
			payload := append(bytes.Clone(prefix), make([]byte, MaxPayload-len(prefix))...)
			m := sendUntil(t, pub, payload, ch, nil)
			require.Equal(t, payload, m.Payload)
			require.Equal(t, macOf(t, a), m.Source.(Address).MAC)
		})
	}

	// A frame to another host's unicast address is not delivered: the
	// subscriber on b also gets the frames sent to a, which it drops,
	// and then the ones sent to b.
	t.Run("filter", func(t *testing.T) {
		prefix := nonce(t)
		_, ch := realSubscribe(t, "opc.eth://"+macB, b, prefix)
		toA := realOpen(t, "opc.eth://"+FormatMAC(macOf(t, a)), b, nil)
		toB := realOpen(t, "opc.eth://"+macB, a, nil)
		reject := append(bytes.Clone(prefix), "to-a"...)
		for range 5 {
			require.NoError(t, toA.Send(context.Background(), reject, transport.PublishOptions{}))
		}
		m := sendUntil(t, toB, append(bytes.Clone(prefix), "to-b"...), ch, reject)
		require.Equal(t, "to-b", string(m.Payload[len(prefix):]))
	})
}
