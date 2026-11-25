// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// gatedDialer holds every Dial until open is closed, then fails it: a run
// stays in Processing as long as the test wants.
type gatedDialer struct {
	mu   sync.Mutex
	open chan struct{}
}

func (d *gatedDialer) gate() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.open
}

func (d *gatedDialer) Dial(ctx context.Context, _ fxcm.ServerAddress) (fxcm.Session, error) {
	select {
	case <-d.gate():
	case <-ctx.Done():
	}
	return nil, errors.New("offline")
}

// reset closes the gate of the last run and gives the next one a new one.
func (d *gatedDialer) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	close(d.open)
	d.open = make(chan struct{})
}

// TestConnectionManagerStateOnReturn: when ProcessConnectionConfigurationSets
// returns Good for a set, a read of its state right after it is
// Processing (§6.7.5, §6.9.2), not the state before the run; after
// StartEditing the Lock belongs to the caller. Before any run the set has
// no LastTransition.
func TestConnectionManagerStateOnReturn(t *testing.T) {
	t.Parallel()
	d := &gatedDialer{open: make(chan struct{})}
	t.Cleanup(d.reset)
	srv := newServer(t, server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
		return append(server.DefaultRoleMapper(tok), fxserver.ConfigureAdmin())
	}))
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	m, err := fxcm.New(fxcm.Options{Dialer: d, ApplicationURI: "urn:test:cm", Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	_, err = m.Add(cmConf("Line1"))
	require.NoError(t, err)
	cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{Manager: m, Editable: true, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })
	f := &cmFX{srv: srv, ns: ns, m: m, cm: cm}
	f.c = start(t, srv)
	f.set, _ = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	require.NotNil(t, f.set)

	assert.Equal(t, "", f.value(t, ".LastTransition").(*ua.LocalizedText).Text, "no transition yet")
	assert.True(t, f.value(t, ".LastTransition.Id").(*ua.NodeID).Equal(ua.NewTwoByteNodeID(0)))

	state := func() uint32 { return f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID() }
	for i := range 20 {
		sc, rs, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, uafx.ActionEstablishConnections, []*ua.NodeID{f.set})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, sc, "run %d", i)
		require.Equal(t, ua.StatusOK, rs[0], "run %d", i)
		require.Equal(t, uint32(fxcmid.ConnectionConfigurationSetStateMachineTypeProcessing), state(), "run %d: the state right after the Method", i)
		d.reset()
		require.Eventually(t, func() bool { return state() == fxcmid.ConnectionConfigurationSetStateMachineTypeError }, 10*time.Second, time.Millisecond)
	}
	assert.Equal(t, "ProcessingToError", f.value(t, ".LastTransition").(*ua.LocalizedText).Text)

	for i := range 20 {
		sc, _ := f.edit(t, f.c, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc)
		require.NotEqual(t, "CM", f.value(t, ".Lock.LockingUser"), "edit %d: the Lock right after StartEditing", i)
		sc, _ = f.edit(t, f.c, uafx.DiscardUpdates, f.set)
		require.Equal(t, ua.StatusOK, sc)
		require.Equal(t, "CM", f.value(t, ".Lock.LockingUser"), "edit %d: the Lock right after DiscardUpdates", i)
	}
}
