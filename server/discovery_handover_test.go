// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// onNetworkRecord returns the ServerOnNetwork row of an instance, or nil.
func onNetworkRecord(s *Server, name string) *ua.ServerOnNetwork {
	for _, r := range s.ServersOnNetwork() {
		if r.ServerName == name {
			return r
		}
	}
	return nil
}

// TestMulticast_LateBrowseEventAfterLapse pins down a registered server that
// lost its row in the ServerOnNetwork table for good. A discovery server
// skips a registered instance that another responder announces, and that is
// how it took a browse event that arrived after the registration had lapsed
// (on a real link a node hears its own multicast, so the late event can be
// an echo of its own announcement, in flight while the instance was
// withdrawn). The server registered again while that row was there, was not
// announced, and when the row went away with the goodbye that followed,
// nothing put the server back until a renewal changed something: a renewal
// that changes nothing is not announced again. The interleaving is driven
// here directly.
func TestMulticast_LateBrowseEventAfterLapse(t *testing.T) {
	link := mdns.NewMemNetwork()
	seen := browseLink(t, link)
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host")))
	rs := regServer("urn:test:press")
	const name = "Press-press7"
	echo := mdns.Instance{Name: name, Type: opcuaServiceType, Host: "press7.local.", Port: 4841, Text: []string{"path=/ua", "caps=NA"}}

	status, _ := s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	require.NotNil(t, onNetworkRecord(s, name))

	// The registration lapses; the late browse event comes in after the
	// withdrawal.
	status, _ = s.disc.register(nil, &ua.RegisteredServer{ServerURI: rs.ServerURI}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Nil(t, onNetworkRecord(s, name))
	s.disc.onNetworkEvent(mdns.Event{Instance: echo})
	require.NotNil(t, onNetworkRecord(s, name), "a discovered server")

	// The server registers again, and the instance goes away on the link.
	status, _ = s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	s.disc.onNetworkEvent(mdns.Event{Removed: true, Instance: echo})

	rec := onNetworkRecord(s, name)
	require.NotNil(t, rec, "the registered server lost its ServerOnNetwork record")
	require.Equal(t, "opc.tcp://press7:4841/ua", rec.DiscoveryURL, "the record of the registration")
	require.Eventually(t, func() bool { _, ok := seen()[name]; return ok }, wait, 5*time.Millisecond,
		"the discovery server does not announce the registered server")

	// A renewal changes nothing, and the server stays.
	status, _ = s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, rec.RecordID, onNetworkRecord(s, name).RecordID)

	// A Removed event for a name the discovery server owns leaves it alone.
	s.disc.onNetworkEvent(mdns.Event{Removed: true, Instance: echo})
	require.Equal(t, rec.RecordID, onNetworkRecord(s, name).RecordID)
}

// TestMulticast_TakesOverFromAResponderThatLeaves has a registered server
// whose instance name is announced by another responder on the link (the
// server announcing itself). The discovery server leaves the name to it; when
// the responder leaves while the server stays registered, the discovery
// server announces the server itself.
func TestMulticast_TakesOverFromAResponderThatLeaves(t *testing.T) {
	link := mdns.NewMemNetwork()
	seen := browseLink(t, link)
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host")))
	const name = "Press-press7"

	peer, err := mdns.New(mdns.Config{Conns: []mdns.PacketConn{link.Conn()}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	require.NoError(t, peer.Register(mdns.Service{Instance: name, Type: opcuaServiceType, Host: "press7.local.", Port: 4841, Text: []string{"path=/self", "caps=NA"}}))
	require.Eventually(t, func() bool { return onNetworkRecord(s, name) != nil }, wait, 5*time.Millisecond)

	status, _ := s.disc.register(nil, regServer("urn:test:press"), nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, "opc.tcp://press7.local:4841/self", onNetworkRecord(s, name).DiscoveryURL, "left to the responder")

	require.True(t, peer.Unregister(name, opcuaServiceType))
	require.Eventually(t, func() bool {
		rec := onNetworkRecord(s, name)
		inst, ok := seen()[name]
		return rec != nil && rec.DiscoveryURL == "opc.tcp://press7:4841/ua" && ok && inst.Text[0] == "path=/ua"
	}, wait, 5*time.Millisecond, "the discovery server did not take over the name of the registered server")
}

// TestMulticast_TakesOverFromARegistrationThatEnds has two registered
// servers that want the same instance name. The second is not announced while
// the first has the name, and is once the first unregisters or expires.
func TestMulticast_TakesOverFromARegistrationThatEnds(t *testing.T) {
	link := mdns.NewMemNetwork()
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host")))
	clock := useFakeClock(s)
	const name = "Oven-oven1"
	reg := func(uri, url string) *ua.RegisteredServer {
		rs := regServer(uri)
		rs.ServerNames = []*ua.LocalizedText{ua.NewLocalizedText("Oven")}
		rs.DiscoveryURLs = []string{url}
		status, _ := s.disc.register(nil, rs, nil)
		require.Equal(t, ua.StatusOK, status)
		return rs
	}

	reg("urn:test:oven", "opc.tcp://oven1:4840")
	reg("urn:test:other-oven", "opc.tcp://oven1:9999")
	require.Equal(t, "opc.tcp://oven1:4840", onNetworkRecord(s, name).DiscoveryURL)

	status, _ := s.disc.register(nil, &ua.RegisteredServer{ServerURI: "urn:test:oven"}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, "opc.tcp://oven1:9999", onNetworkRecord(s, name).DiscoveryURL, "taken over on unregistration")

	// And back on expiry: the first server registers again (left out while
	// the name is taken), the second is not renewed.
	clock.Advance(time.Hour)
	reg("urn:test:oven", "opc.tcp://oven1:4840")
	require.Equal(t, "opc.tcp://oven1:9999", onNetworkRecord(s, name).DiscoveryURL)
	s.disc.cleanup(clock.Now().Add(DefaultRegistrationTimeout - time.Minute))
	require.Equal(t, []string{"urn:test:oven"}, registeredURIs(s))
	require.Equal(t, "opc.tcp://oven1:4840", onNetworkRecord(s, name).DiscoveryURL, "taken over on expiry")
}
