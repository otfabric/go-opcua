// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// TestConnectionManagerRestart (design docs/design/uafx-persistent-connections.md
// §8, C3.3): the projection of a Manager restarted on its Store exposes the
// sets as the store committed them (Version, state, §6.8.2), and they are
// processed through ProcessConnectionConfigurationSets (§6.7.5) like the
// sets of the Manager that wrote them.
func TestConnectionManagerRestart(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	key := fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"}
	open := func() (*fxcm.Manager, *cmFX) {
		admin := func(tok ua.IdentityToken) []*ua.NodeID {
			return append(server.DefaultRoleMapper(tok), fxserver.ConfigureAdmin())
		}
		srv := newServer(t, server.WithRoleMapper(admin))
		ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
		require.NoError(t, err)
		m, err := fxcm.New(fxcm.Options{Dialer: offlineDialer{}, ApplicationURI: "urn:test:cm", Store: mem, Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{Manager: m, Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		f := &cmFX{srv: srv, ns: ns, m: m, cm: cm}
		f.c = start(t, srv)
		f.set, _ = cm.SetNode(key)
		t.Cleanup(func() {
			_ = cm.Close()
			_ = m.Close()
		})
		return m, f
	}

	m, f := open()
	require.Nil(t, f.set)
	_, err := m.Add(cmConf("Line1"))
	require.NoError(t, err)
	e, err := m.StartEdit(key, "e")
	require.NoError(t, err)
	e.Conf().CommunicationFlows[0].(*uafx.PubSubCommunicationFlowConfigurationConf).PublishingInterval = ptrOf(20.0)
	_, _, err = m.CommitEdit(key, "e")
	require.NoError(t, err)
	require.NoError(t, f.cm.Close())
	require.NoError(t, m.Close())

	m, f = open()
	require.NotNil(t, f.set, "the set is projected after the restart")
	assert.Equal(t, uint32(2), f.value(t, ".Version"), "the committed Version")
	assert.Equal(t, "Ready", f.value(t, ".CurrentState").(*ua.LocalizedText).Text)
	assert.Equal(t, 20.0, f.value(t, ".Flow[Flow1].PublishingInterval"))
	st, ok := m.Status(key)
	require.True(t, ok)
	assert.True(t, st.Recovery == nil || st.Recovery.Done, "%+v", st.Recovery)

	sc, rs, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, uafx.ActionEstablishConnections, []*ua.NodeID{f.set})
	require.NoError(t, err)
	assert.Equal(t, ua.StatusGood, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
	require.Eventually(t, func() bool {
		return f.read(t, f.c, f.node(".CurrentState")).Value.Value().(*ua.LocalizedText).Text == "Error"
	}, 10*time.Second, 10*time.Millisecond, "the run of the restarted Manager (offline: Error)")
}
