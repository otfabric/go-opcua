// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// TestMonitorDropsObservationAcrossRun: a Status the monitor read while a
// run started and ended on the set may predate what the run did: it is
// dropped, not recorded, and the record is neither marked nor deleted as
// gone (no Reestablish either), although the record and the set look
// unchanged when the read returns.
func TestMonitorDropsObservationAcrossRun(t *testing.T) {
	t.Parallel()
	events := make(chan Event, 16)
	m, err := New(Options{Dialer: offline{}, ApplicationURI: cmURI, Retry: &RetryPolicy{},
		Monitor: &MonitorOptions{Reestablish: true}, Observer: ObserverFunc(func(e Event) { events <- e })})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })

	addr := ServerAddress{Address: "opc.tcp://peer:4840"}
	fe := ua.NewStringNodeID(1, "fe")
	r := &record{EndpointRecord: EndpointRecord{FunctionalEntity: fe, Name: "E", NodeID: ua.NewStringNodeID(1, "e"), Class: KnownOwned}, addr: addr}
	k := recordKey(addr, fe, "E")
	s := &set{records: map[string]*record{k: r}, lastEstablish: new(uafx.FxProcess)}

	// The read races a run: one starts and ends while it is out.
	m.statusOf = func(context.Context, *record) (uafx.ConnectionEndpointStatus, bool, error) {
		s.mu.Lock()
		s.current = NewPendingRun()
		s.runs++
		s.current = nil
		s.mu.Unlock()
		return 0, false, nil // gone, as read before the run
	}
	m.monitorSet(context.Background(), s)
	s.mu.Lock()
	require.Same(t, r, s.records[k], "the record is not deleted")
	require.False(t, r.monitored, "nor marked")
	s.mu.Unlock()
	select {
	case e := <-events:
		t.Fatalf("an event of a dropped observation: %+v", e)
	default:
	}

	// Without a run: the observation stands.
	m.statusOf = func(context.Context, *record) (uafx.ConnectionEndpointStatus, bool, error) {
		return uafx.ConnectionEndpointOperational, true, nil
	}
	m.monitorSet(context.Background(), s)
	s.mu.Lock()
	require.True(t, r.monitored)
	require.Equal(t, uafx.ConnectionEndpointOperational, r.state)
	s.mu.Unlock()
	require.Equal(t, EventMonitor, (<-events).Kind)
}
