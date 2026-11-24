// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// hookDialer is a ClientDialer whose sessions call hook before each Call;
// a hook that returns an error replaces the result of the call, which is
// made when send is set (a lost response) and not made otherwise.
type hookDialer struct {
	fxcm.ClientDialer
	hook  func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) (send bool, err error)
	block chan struct{} // when not nil, Dial waits for it
	dials atomic.Int32
	// fault fails a service of a session before it is sent; "Dial" fails
	// the dial.
	fault func(method string, addr fxcm.ServerAddress) error
}

func newHookDialer() *hookDialer {
	return &hookDialer{ClientDialer: fxcm.ClientDialer{Options: []opcua.Option{opcua.ApplicationURI(cmURI), opcua.AutoReconnect(false), opcua.InsecureNoSecurity()}}}
}

func (d *hookDialer) Dial(ctx context.Context, addr fxcm.ServerAddress) (fxcm.Session, error) {
	d.dials.Add(1)
	if d.fault != nil {
		if err := d.fault("Dial", addr); err != nil {
			return nil, err
		}
	}
	if d.block != nil {
		select {
		case <-d.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s, err := d.ClientDialer.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &hookSession{Session: s, d: d, addr: addr}, nil
}

type hookSession struct {
	fxcm.Session
	d    *hookDialer
	addr fxcm.ServerAddress
}

// failed returns the error the dialer's fault hook gives for method.
func (s *hookSession) failed(method string) error {
	if s.d.fault == nil {
		return nil
	}
	return s.d.fault(method, s.addr)
}

func (s *hookSession) NamespaceArray(ctx context.Context) ([]string, error) {
	if err := s.failed("NamespaceArray"); err != nil {
		return nil, err
	}
	return s.Session.NamespaceArray(ctx)
}

func (s *hookSession) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	if err := s.failed("Read"); err != nil {
		return nil, err
	}
	return s.Session.Read(ctx, req)
}

func (s *hookSession) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	if err := s.failed("Browse"); err != nil {
		return nil, err
	}
	return s.Session.Browse(ctx, req)
}

func (s *hookSession) TranslateBrowsePaths(ctx context.Context, req *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error) {
	if err := s.failed("TranslateBrowsePaths"); err != nil {
		return nil, err
	}
	return s.Session.TranslateBrowsePaths(ctx, req)
}

func (s *hookSession) Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	if err := s.failed("Call"); err != nil {
		return nil, err
	}
	if s.d.hook != nil {
		if send, err := s.d.hook(s.addr, req); err != nil {
			if send {
				_, _ = s.Session.Call(ctx, req)
			}
			return nil, err
		}
	}
	return s.Session.Call(ctx, req)
}

// commandMask returns the CommandMask of an EstablishConnections call.
func commandMask(req *ua.CallMethodRequest) uafx.FxCommandMask {
	if len(req.InputArguments) == 0 {
		return 0
	}
	if v, ok := req.InputArguments[0].Value().(uint32); ok {
		return uafx.FxCommandMask(v)
	}
	return 0
}

// TestRollback: a failure on one AutomationComponent stops the run and,
// with RollbackOnError, closes what the run created on the other
// (§6.8.2, EC-10, EC-11).
func TestRollback(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := e2eConf(t, "Rollback", a, b)
	// Fixed is read-only: SetConfigurationData fails on B, which aborts
	// the call (Uncertain); fxserver reports the write as
	// Bad_UserAccessDenied.
	conf.Connections[0].Endpoint2.ConfigurationData[0].Key = n(fxtest.ConnFixed)
	m := newManager(t, fxcm.Options{})
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.Equal(t, fxcm.ProcessingToError, res.Transition)
	assert.True(t, res.RolledBack)
	assert.True(t, res.RollbackComplete)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
	require.NotEmpty(t, res.Failures)
	assert.Contains(t, res.Failures, fxcm.Failure{FxError: uafx.FxErrorSetConfigurationDataError, Status: ua.StatusBadUserAccessDenied})
	st, ok := m.Status(cfg.Key())
	require.True(t, ok)
	assert.Equal(t, fxcm.StateError, st.State)
	assert.Equal(t, uafx.FxErrorSetConfigurationDataError, st.Diagnostics[0].ErrorEndpoint2, "%+v", st.Diagnostics[0])
	assert.Empty(t, st.Endpoints)

	// Without RollbackOnError the survivors stay, and Reconcile of a set
	// in Error closes them.
	conf.BrowseName = "NoRollback"
	conf.RollbackOnError = false
	cfg2, err := m.Add(conf)
	require.NoError(t, err)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg2.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.False(t, res.RolledBack)
	st, _ = m.Status(cfg2.Key())
	assert.NotEmpty(t, st.Endpoints)
	rec := m.Reconcile(cfg2.Key())
	require.NoError(t, rec.Err)
	r, err := rec.Run.Wait(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fxcm.StateReady, r.State, "%+v", r.Failures)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
}

// TestEstablishTwice: establishing a set in Ready again closes its own
// endpoints first (step 0, ScanCloseFirst) and creates them again.
func TestEstablishTwice(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	m := newManager(t, fxcm.Options{})
	cfg, err := m.Add(e2eConf(t, "Twice", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	first := res.Created
	res = process(t, m, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Closed, 2)
	assert.Len(t, res.Created, 2)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	assert.NotEqual(t, first[0].NodeID.String()+first[1].NodeID.String(), res.Created[0].NodeID.String()+res.Created[1].NodeID.String())
	require.NoError(t, m.Remove(context.Background(), cfg.Key()))
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
	_, ok := m.Status(cfg.Key())
	assert.False(t, ok)

	// The PublishedDataSet "PDS" of the set stays on a after the remove
	// (§6.2.5.2), and the set above reused it. A set whose PublishedDataSet
	// has that Name but publishes another Variable does not reuse it: the
	// run fails before anything is created.
	other := e2eConf(t, "Other", a, b)
	model := other.AutomationComponentConfigurations[0].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	model.PubSubConfiguration.PublishedDataSets[0] = pubsub.PublishedDataItems("PDS", pubsub.Var("x", ua.NewNumericNodeID(e2eTest, fxtest.ConnGain), ua.TypeIDDouble))
	cfg, err = m.Add(other)
	require.NoError(t, err)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.Contains(t, res.Failures, fxcm.Failure{FxError: uafx.FxErrorSetCommunicationConfigurationError, Status: ua.StatusBadBrowseNameDuplicated})
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())

	// A PubSub configuration with SecurityGroups needs an SKS configured,
	// which the ConnectionManager does not do (design EC-9, D3): the set
	// is refused, not established without its security.
	sks := e2eConf(t, "SKS", a, b)
	sksModel := sks.AutomationComponentConfigurations[1].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	sksModel.PubSubConfiguration.SecurityGroups = []*ua.SecurityGroupDataType{{Name: "G"}}
	cfg, err = m.Add(sks)
	require.NoError(t, err)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.Contains(t, res.Failures, fxcm.Failure{FxError: uafx.FxErrorConnectionConfigurationSetInvalid, Status: ua.StatusBadNotSupported})
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
}

// TestTwoManagersSameApplicationURI is the Q2 safeguard: a second Manager
// with the same ApplicationUri finds the endpoints of the first under the
// Names of its set. It has no record of them, so they are Unresolved: it
// does not create, take or close them, and its rollback leaves them alone,
// with or without ExclusiveApplicationURI (design §5.4).
func TestTwoManagersSameApplicationURI(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := e2eConf(t, "Shared", a, b)
	m1 := newManager(t, fxcm.Options{})
	cfg, err := m1.Add(conf)
	require.NoError(t, err)
	res := process(t, m1, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)

	for _, exclusive := range []bool{false, true} {
		m2 := newManager(t, fxcm.Options{ExclusiveApplicationURI: exclusive})
		cfg2, err := m2.Add(conf)
		require.NoError(t, err)
		res := process(t, m2, uafx.ActionEstablishConnectionsEnabled, cfg2.Key())
		require.Equal(t, fxcm.StateError, res.State)
		assert.Contains(t, res.Failures, fxcm.Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadBrowseNameDuplicated})
		assert.Len(t, res.Unresolved, 2, "exclusive %v", exclusive)
		assert.Empty(t, res.Closed)
		assert.Equal(t, uint32(0), m2.Counters().CloseCallCount)
		assert.Equal(t, []string{"ToB"}, a.endpoints())
		assert.Equal(t, []string{"ToA"}, b.endpoints())

		// Remove of a set with Unresolved endpoints fails: they may be its
		// Connections. Settle decides; SettleForeign forgets them.
		err = m2.Remove(context.Background(), cfg2.Key())
		require.Error(t, err)
		assert.ErrorIs(t, err, ua.StatusBadInvalidState)
		for _, ep := range []fxcm.EndpointRef{{"Motion", 1}, {"Motion", 2}} {
			require.NoError(t, m2.Settle(cfg2.Key(), ep, fxcm.SettleForeign))
		}
		require.NoError(t, m2.Remove(context.Background(), cfg2.Key()))
		assert.Equal(t, []string{"ToB"}, a.endpoints())
		assert.Equal(t, []string{"ToA"}, b.endpoints())
	}
	// The Connection of the first Manager still works.
	st, _ := m1.Status(cfg.Key())
	assert.Len(t, st.Endpoints, 2)
	require.NoError(t, m1.Remove(context.Background(), cfg.Key()))
	assert.Empty(t, a.endpoints())
}

// TestLostResponse: a configure call whose response is lost is not sent
// again; the endpoint it made is found on a new session. Without
// ExclusiveApplicationURI it is Unresolved and never closed; Settle makes
// it KnownOwned, and Reconcile closes it. With ExclusiveApplicationURI it
// is KnownOwned at once and the rollback closes it (design §5.4).
func TestLostResponse(t *testing.T) {
	t.Parallel()
	for _, exclusive := range []bool{false, true} {
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		d := newHookDialer()
		var lost atomic.Bool
		d.hook = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
			if addr.Address == b.url && commandMask(req)&uafx.CreateConnectionEndpointCmd != 0 && lost.CompareAndSwap(false, true) {
				return true, ua.StatusBadCommunicationError
			}
			return false, nil
		}
		m := newManager(t, fxcm.Options{Dialer: d, ExclusiveApplicationURI: exclusive})
		cfg, err := m.Add(e2eConf(t, "Lost", a, b))
		require.NoError(t, err)
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State)
		assert.Contains(t, res.Failures, fxcm.Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadCommunicationError})
		assert.Empty(t, a.endpoints(), "the rollback closes A")
		if exclusive {
			assert.Empty(t, res.Unresolved)
			assert.Empty(t, b.endpoints(), "a KnownOwned endpoint is rolled back")
			assert.True(t, res.RollbackComplete)
			continue
		}
		require.Len(t, res.Unresolved, 1)
		assert.Equal(t, fxcm.Unresolved, res.Unresolved[0].Class)
		assert.Equal(t, []string{"ToA"}, b.endpoints(), "an Unresolved endpoint is never closed")
		require.NoError(t, m.Settle(cfg.Key(), fxcm.EndpointRef{"Motion", 2}, fxcm.SettleOwned))
		assert.ErrorIs(t, m.Settle(cfg.Key(), fxcm.EndpointRef{"Motion", 2}, fxcm.SettleOwned), ua.StatusBadInvalidState)
		st := m.Reconcile(cfg.Key())
		require.NoError(t, st.Err)
		r, err := st.Run.Wait(context.Background())
		require.NoError(t, err)
		assert.Equal(t, fxcm.StateReady, r.State, "%+v", r.Failures)
		assert.Empty(t, b.endpoints())
	}
}

// TestProcessBusy: a set being processed cannot be processed, replaced or
// removed (Table 86: Bad_InvalidState); each run has its own increasing
// RunID.
func TestProcessBusy(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	d := newHookDialer()
	d.block = make(chan struct{})
	m := newManager(t, fxcm.Options{Dialer: d})
	cfg, err := m.Add(e2eConf(t, "Busy", a, b))
	require.NoError(t, err)
	st := m.Process(uafx.ActionEstablishConnectionsDisabled, cfg.Key(), fxcm.SetKey{Name: "none"})
	require.NoError(t, st[0].Err)
	assert.ErrorIs(t, st[1].Err, ua.StatusBadNodeIDUnknown)
	again := m.Process(uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	assert.ErrorIs(t, again[0].Err, ua.StatusBadInvalidState)
	assert.ErrorIs(t, m.Remove(context.Background(), cfg.Key()), ua.StatusBadInvalidState)
	status, _ := m.Status(cfg.Key())
	assert.Equal(t, fxcm.StateProcessing, status.State)
	require.NotNil(t, status.Current)
	assert.Equal(t, st[0].Run.ID(), status.Current.ID())
	close(d.block)
	res, err := st[0].Run.Wait(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Equal(t, cfg.Version(), st[0].Run.Version())
	assert.Equal(t, uafx.ActionEstablishConnectionsDisabled, st[0].Run.Action())
	next := m.Process(uafx.ActionRemoveConnections, cfg.Key())
	require.NoError(t, next[0].Err)
	assert.Greater(t, next[0].Run.ID(), st[0].Run.ID())
	<-next[0].Run.Done()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fxcm.NewPendingRun().Wait(ctx)
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, m.Process(-7, cfg.Key())[0].Err, ua.StatusBadNotSupported)
}

// TestMonitorReestablish: the monitor finds an endpoint gone and, with
// Reestablish, processes the set again with its last establish action.
func TestMonitorReestablish(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	events := &eventLog{}
	m := newManager(t, fxcm.Options{Observer: events, Monitor: &fxcm.MonitorOptions{Interval: 20 * time.Millisecond, Reestablish: true}})
	cfg, err := m.Add(e2eConf(t, "Monitor", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	old := a.conns.Endpoints()

	// Another client removes the endpoint of A.
	c := testutil.NewTestClient(t, a.url)
	var toB *ua.NodeID
	for _, e := range old {
		if !e.Equal(a.id(fxtest.ConnPreset)) {
			toB = e
		}
	}
	_, results, err := uafx.CloseConnections(context.Background(), c, a.id(fxtest.ConnCtl), []*ua.NodeID{toB}, true)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)

	require.Eventually(t, func() bool { return len(events.transitions()) >= 2 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		st, _ := m.Status(cfg.Key())
		return st.State == fxcm.StateReady && len(a.endpoints()) == 1 && len(b.endpoints()) == 1
	}, 10*time.Second, 10*time.Millisecond)
	assert.NotEmpty(t, events.of(fxcm.EventMonitor))
	gone := false
	for _, e := range events.of(fxcm.EventMonitor) {
		if errors.Is(e.Err, ua.StatusBadNodeIDUnknown) {
			gone = true
		}
	}
	assert.True(t, gone)
}

// TestRetry: a run that fails transiently is retried by the RetryPolicy
// (§6.9.1).
func TestRetry(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	d := newHookDialer()
	var fails atomic.Int32
	d.hook = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
		// The first reservation call times out: a transient failure,
		// nothing created.
		if commandMask(req)&uafx.ReserveCommunicationIDsCmd != 0 && fails.Add(1) == 1 {
			return false, ua.StatusBadTimeout
		}
		return false, nil
	}
	events := &eventLog{}
	m := newManager(t, fxcm.Options{Dialer: d, Observer: events, Retry: &fxcm.RetryPolicy{Initial: 10 * time.Millisecond, Max: 50 * time.Millisecond, Attempts: 3}})
	cfg, err := m.Add(e2eConf(t, "Retry", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	require.Eventually(t, func() bool {
		st, _ := m.Status(cfg.Key())
		return st.State == fxcm.StateReady
	}, 10*time.Second, 10*time.Millisecond)
	assert.Len(t, events.of(fxcm.EventRetry), 1)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
}

// TestAdaptPublisherID is CS-18 (§6.16.3): a PubSubConnection of the set
// that matches one the AC has takes that one's PublisherId, and the
// ConnectionManager adapts the subscribers to it. The first set adds the
// publisher's PubSubConnection with an explicit PublisherId; it stays on
// the AC after the remove (§6.2.5.2). The same set with another
// PublisherId then matches it (ElementMatch compares the transport, not the
// PublisherId, OPC 10000-14 §9.1.3.7.2): b's DataSetReader, configured with
// the set's PublisherId, is modified in one more call, and the data flows.
// Where CommandBundleRequired forbids that call (§6.2.6) the subscriber is
// configured after its publisher, with the PublisherId the publisher's call
// returned. When the adaptation call fails the Connection fails and is
// rolled back. The remove
// after each leaves no reader behind, so the set can be established again.
func TestAdaptPublisherID(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	events := &eventLog{}
	m := newManager(t, fxcm.Options{Observer: events})
	conf := e2eConf(t, "Adapt", a, b)
	pubConn := conf.AutomationComponentConfigurations[0].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration).PubSubConfiguration.Connections[0]
	establish := func(bundle bool) *fxcm.RunResult {
		t.Helper()
		conf.AutomationComponentConfigurations[1].CommandBundleRequired = bundle
		cfg, err := m.Add(conf)
		require.NoError(t, err)
		return process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	}
	remove := func() {
		t.Helper()
		require.NoError(t, m.Remove(context.Background(), fxcm.KeyOf(conf)))
		assert.Empty(t, a.endpoints())
		assert.Empty(t, b.endpoints())
	}
	callsTo := func(url string) int {
		n := 0
		for _, e := range events.of(fxcm.EventCall) {
			if e.Address == url {
				n++
			}
		}
		return n
	}

	pubConn.PublisherID = ua.MustVariant(uint16(4242))
	res := establish(false)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	remove()

	// The set says 5151; the connection it matches has 4242.
	pubConn.PublisherID = ua.MustVariant(uint16(5151))
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnActual), 7.0))
	before := callsTo(b.url)
	res = establish(false)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Equal(t, 3, callsTo(b.url)-before, "reserve, configure and the adaptation")
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 7.0 }, 10*time.Second, 10*time.Millisecond)
	remove()

	// A reader that names the set's PublisherId itself is adapted as well.
	subConf := conf.AutomationComponentConfigurations[1].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration).PubSubConfiguration
	reader := subConf.Connections[1].ReaderGroups[0].DataSetReaders[0]
	reader.PublisherID = ua.MustVariant(uint16(5151))
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnActual), 8.0))
	before = callsTo(b.url)
	res = establish(false)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Equal(t, 3, callsTo(b.url)-before, "reserve, configure and the adaptation")
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 8.0 }, 10*time.Second, 10*time.Millisecond)
	remove()
	reader.PublisherID = nil

	// With CommandBundleRequired b cannot take the adaptation (§6.2.6): it
	// is configured after a, with the PublisherId a's call returned.
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnActual), 9.0))
	before = callsTo(b.url)
	res = establish(true)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Equal(t, 2, callsTo(b.url)-before, "reserve and configure, no adaptation")
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 9.0 }, 10*time.Second, 10*time.Millisecond)
	remove()

	// The adaptation call fails: the Connection fails and is rolled back.
	d := newHookDialer()
	d.hook = func(_ fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
		if m := commandMask(req); m&uafx.SetCommunicationConfigurationCmd != 0 && m&uafx.CreateConnectionEndpointCmd == 0 {
			return false, ua.StatusBadCommunicationError
		}
		return false, nil
	}
	m2 := newManager(t, fxcm.Options{Dialer: d})
	conf.AutomationComponentConfigurations[1].CommandBundleRequired = false
	cfg2, err := m2.Add(conf)
	require.NoError(t, err)
	res = process(t, m2, uafx.ActionEstablishConnectionsEnabled, cfg2.Key())
	require.Equal(t, fxcm.StateError, res.State)
	require.NotEmpty(t, res.Failures)
	assert.Equal(t, uafx.FxErrorSetCommunicationConfigurationError, res.Failures[0].FxError, "%+v", res.Failures)
	assert.True(t, res.RolledBack)
	require.NoError(t, m2.Remove(context.Background(), cfg2.Key()))
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())

	res = establish(false)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	remove()
}
