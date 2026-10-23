// SPDX-License-Identifier: MIT

package udp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// candidateInterfaces lists the interfaces to try multicast on: the system
// default first, then the loopback interface, then the others.
func candidateInterfaces(v6 bool) []string {
	out := []string{""}
	ifs, _ := net.Interfaces()
	var rest []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		has := false
		for _, a := range interfaceAddrs(&ifi) {
			if a.Is6() == v6 {
				has = true
			}
		}
		if !has {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			out = append(out, ifi.Name)
		} else if ifi.Flags&net.FlagMulticast != 0 {
			rest = append(rest, ifi.Name)
		}
	}
	if len(rest) > 2 {
		rest = rest[:2]
	}
	return append(out, rest...)
}

// multicastSetup finds an interface on which a datagram sent to the group
// comes back to a subscriber on this host, and returns two subscribers and a
// publisher on it. It skips the test if there is none.
func multicastSetup(t *testing.T, group string, v6 bool) (url, ifName string, subs [2]*collector) {
	t.Helper()
	for _, ifName := range candidateInterfaces(v6) {
		port := freePort(t)
		url := fmt.Sprintf("opc.udp://%s:%d", group, port)
		cfg := transport.Config{URL: url, Interface: ifName}
		var cols [2]*collector
		ok := true
		for i := range cols {
			c, err := Open(context.Background(), cfg)
			if err != nil {
				ok = false
				break
			}
			t.Cleanup(func() { _ = c.Close() })
			cols[i] = newCollector()
			if _, err := c.Subscribe(context.Background(), "", 0, cols[i].handle); err != nil {
				t.Logf("interface %q: %v", ifName, err)
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		pub, err := Open(context.Background(), cfg)
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = pub.Close() })
		if err := pub.Send(context.Background(), []byte("probe"), transport.PublishOptions{}); err != nil {
			t.Logf("interface %q: %v", ifName, err)
			continue
		}
		if cols[0].wait(t, 1, 500*time.Millisecond) && cols[1].wait(t, 1, 500*time.Millisecond) {
			return url, ifName, cols
		}
		t.Logf("interface %q: no multicast loopback", ifName)
	}
	t.Skipf("no usable multicast route for %s on this host", group)
	return "", "", subs
}

func testMulticast(t *testing.T, group string, v6 bool) {
	url, ifName, cols := multicastSetup(t, group, v6)
	t.Logf("multicast %s on interface %q", url, ifName)

	// A second publisher with TTL and explicit loopback.
	on := true
	pub := open(t, transport.Config{URL: url, Interface: ifName, MulticastTTL: 2, MulticastLoopback: &on})
	for i := 0; i < 5; i++ {
		require.NoError(t, pub.Send(context.Background(), []byte(fmt.Sprintf("m%d", i)), transport.PublishOptions{}))
	}
	for _, col := range cols {
		require.True(t, col.wait(t, 5, 5*time.Second))
		require.Equal(t, "m4", string(col.get(5).Payload))
	}

	// Without loopback this host does not see the datagrams.
	off := false
	quiet := open(t, transport.Config{URL: url, Interface: ifName, MulticastLoopback: &off})
	require.NoError(t, quiet.Send(context.Background(), []byte("silent"), transport.PublishOptions{}))
	require.False(t, cols[0].wait(t, 1, 300*time.Millisecond))

	// A third subscriber shares the port with the others.
	other := open(t, transport.Config{URL: url, Interface: ifName})
	_, err := other.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.NoError(t, err)
}

func TestMulticastIPv4(t *testing.T) {
	testMulticast(t, "239.255.42.99", false)
}

func TestMulticastIPv6(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skipf("no IPv6: %v", err)
	} else {
		_ = c.Close()
	}
	testMulticast(t, "[ff15::4299]", true)
}

func TestMulticastZoneSelectsInterface(t *testing.T) {
	ifs := candidateInterfaces(true)
	if len(ifs) < 2 {
		t.Skip("no IPv6 interface")
	}
	c := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://[ff02::4299%%%s]:4840", ifs[1])})
	require.NotNil(t, c.ifi)
	require.Equal(t, ifs[1], c.ifi.Name)
	require.True(t, c.group)
}
