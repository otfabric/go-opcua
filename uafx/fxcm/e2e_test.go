// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// cmURI is the ApplicationUri of the ConnectionManagers of the tests.
const cmURI = "urn:go-opcua:fxcm:test"

// ac is an fxserver AutomationComponent of the tests: the Ctl of
// fxtest.ConnectionsNodeSet.
type ac struct {
	srv   *server.Server
	conns *fxserver.Connections
	ns    fxserver.Namespaces
	test  uint16
	uri   string
	url   string
}

func (a *ac) id(n uint32) *ua.NodeID { return ua.NewNumericNodeID(a.test, n) }

func (a *ac) value(t *testing.T, n uint32) any {
	t.Helper()
	dv := a.srv.Node(a.id(n)).Value()
	require.NotNil(t, dv)
	return dv.Value.Value()
}

// endpoints returns the Names of the ConnectionEndpoints of Motion.
func (a *ac) endpoints() []string {
	var out []string
	for _, e := range a.conns.Endpoints() {
		if nd := a.srv.Node(e); nd != nil && !e.Equal(a.id(fxtest.ConnPreset)) {
			out = append(out, nd.BrowseName().Name)
		}
	}
	return out
}

func newAC(t *testing.T, name string, opts fxserver.ConnectionOptions) *ac {
	t.Helper()
	return newACWith(t, name, opts, "")
}

// newACWith is newAC with the NodeSet extra imported after the fixture.
func newACWith(t *testing.T, name string, opts fxserver.ConnectionOptions, extra string) *ac {
	t.Helper()
	uri := "urn:go-opcua:fxcm:" + name
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(uri),
		server.WithPubSub(nil),
	)
	require.NoError(t, err)
	ns, test, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	if extra != "" {
		require.NoError(t, fxserver.ImportNodeSet(srv, []byte(extra)))
	}
	opts.Logger = slog.New(slog.DiscardHandler)
	if opts.Interval == 0 {
		opts.Interval = 10 * time.Millisecond
	}
	conns, err := fxserver.EnableConnections(srv, ns, opts)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() {
		_ = conns.Close()
		_ = srv.Close()
	})
	return &ac{srv: srv, conns: conns, ns: ns, test: test, uri: uri, url: fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())}
}

// The namespace indexes of the Namespaces of the ServerAddresses of e2eConf.
const (
	e2eTest = 1
	e2eAC   = 2
	e2eData = 3
)

func n(id uint32) *uafx.NodeIdentifier {
	return &uafx.NodeIdentifier{Node: ua.NewNumericNodeID(e2eTest, id)}
}

// e2eModel is the PubSubConfiguration of an AutomationComponent of
// e2eConf: Motion publishes Actual on out and writes what it reads on in
// to Setpoint. The ids and the PublisherIds are left to the
// ConnectionManager (E.2.2).
func e2eModel(out, in string) *uafx.PubSubCommunicationModelConfiguration {
	pds := pubsub.PublishedDataItems("PDS", pubsub.Var("x", ua.NewNumericNodeID(e2eTest, fxtest.ConnActual), ua.TypeIDDouble))
	w := pubsub.DataSetWriter("W", 0, "PDS")
	// A WriterGroup that sends the GroupHeader cannot be matched (OPC
	// 10000-14 §9.1.3.7.2): it is added with a null Name, which the AC
	// assigns (§6.16.3).
	wg := pubsub.WriterGroup("", 0, 10*time.Millisecond, w)
	md := pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})
	r := pubsub.SetTargetVariables(pubsub.DataSetReader("R", nil, 0, 0, md), pubsub.Target(ua.NewNumericNodeID(e2eTest, fxtest.ConnSetpoint)))
	// The PubSubConnections and the ReaderGroup are shared with the other
	// Connections of the AC and outlive a close (§6.2.5.2):
	// ElementAdd|ElementMatch adds or matches them (§6.16.3).
	add := ua.PubSubConfigurationRefMaskElementAdd
	match := ua.PubSubConfigurationRefMaskElementMatch
	ref := func(m ua.PubSubConfigurationRefMask, c, g, e uint16) *ua.PubSubConfigurationRefDataType {
		if m&(ua.PubSubConfigurationRefMaskReferenceConnection|ua.PubSubConfigurationRefMaskReferenceReaderGroup) != 0 {
			m |= match
		}
		return &ua.PubSubConfigurationRefDataType{ConfigurationMask: add | m, ConnectionIndex: c, GroupIndex: g, ElementIndex: e}
	}
	return &uafx.PubSubCommunicationModelConfiguration{
		PubSubConfiguration: &ua.PubSubConfiguration2DataType{
			PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
			Connections: []*ua.PubSubConnectionDataType{
				pubsub.AttachWriterGroups(pubsub.UDPConnection("Pub", out, nil), wg),
				pubsub.AttachReaderGroups(pubsub.UDPConnection("Sub", in, nil), pubsub.ReaderGroup("RG", r)),
			},
			Enabled: true,
		},
		ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{
			ref(ua.PubSubConfigurationRefMaskReferencePubDataset, 0, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceConnection, 0, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceConnection, 1, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceWriterGroup, 0, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceReaderGroup, 1, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceWriter, 0, 0, 0),
			ref(ua.PubSubConfigurationRefMaskReferenceReader, 1, 0, 0),
		},
	}
}

// e2eLinks are the CommunicationLinks of the endpoints of e2eConf, in the
// binary encoding with the namespace indexes of its ServerAddresses.
func e2eLinks(t *testing.T) *ua.ExtensionObject {
	t.Helper()
	eo, err := uafx.EncodeStructure(&uafx.PubSubCommunicationLinkConfiguration{
		DataSetWriterRef: &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceWriter},
		DataSetReaderRef: &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceReader, ConnectionIndex: 1},
	}, uafx.NamespaceIndexes{Data: e2eData, AC: e2eAC})
	require.NoError(t, err)
	return eo
}

// e2eConf is a set with the bidirectional Connection Motion between Motion
// of a and Motion of b: a publishes on ab, b on ba.
func e2eConf(t *testing.T, name string, a, b *ac) *uafx.ConnectionConfigurationSetConf {
	t.Helper()
	ab := fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
	ba := fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
	server := func(x *ac) *uafx.ServerAddressConf {
		return &uafx.ServerAddressConf{
			BrowseName:   x.uri,
			Address:      x.url,
			SecurityMode: ua.MessageSecurityModeNone,
			ServerURI:    x.uri,
			Namespaces:   []string{uaNamespace, fxtest.ConnNS, fxacid.NamespaceURI, fxdataid.NamespaceURI},
		}
	}
	endpoint := func(acIdx, out, in int32, name string) *uafx.ConnectionEndpointConfigurationConf {
		return &uafx.ConnectionEndpointConfigurationConf{
			FunctionalEntityNode:     n(fxtest.ConnMotion),
			Name:                     name,
			ConnectionEndpointTypeID: ua.NewNumericNodeID(e2eAC, fxacid.PubSubConnectionEndpointType),
			InputVariableIDs:         []*uafx.NodeIdentifier{n(fxtest.ConnSetpoint)},
			OutputVariableIDs:        []*uafx.NodeIdentifier{n(fxtest.ConnActual)},
			CleanupTimeout:           -1,
			CommunicationLinks:       e2eLinks(t),
			ConfigurationData:        []*uafx.NodeIdentifierValuePair{{Key: n(fxtest.ConnGain), Value: ua.MustVariant(2.5)}},
			AutomationComponentIndex: acIdx,
			OutboundFlowIndex:        &out,
			InboundFlowIndex:         []int32{in, 0},
		}
	}
	return &uafx.ConnectionConfigurationSetConf{
		BrowseName:      name,
		RollbackOnError: true,
		ServerAddresses: []*uafx.ServerAddressConf{server(a), server(b)},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{BrowseName: "A", AutomationComponentNode: n(fxtest.ConnCtl), ServerAddressIndex: 0, CommunicationModelConfig: e2eModel(ab, ba)},
			{BrowseName: "B", AutomationComponentNode: n(fxtest.ConnCtl), ServerAddressIndex: 1, CommunicationModelConfig: e2eModel(ba, ab)},
		},
		CommunicationFlows: []uafx.CommunicationFlowConfigurationConf{
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName: "AB", Address: &uafx.AddressSelection{Address: urlAddress(ab)},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "S", MessageReceiveTimeout: 1000}},
			},
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName: "BA", Address: &uafx.AddressSelection{Address: urlAddress(ba)},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "S", MessageReceiveTimeout: 1000}},
			},
		},
		Connections: []*uafx.ConnectionConfigurationConf{{
			BrowseName: "Motion",
			Endpoint1:  endpoint(0, 0, 1, "ToB"),
			Endpoint2:  endpoint(1, 1, 0, "ToA"),
		}},
	}
}

// eventLog is an Observer that keeps the Events.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) Observe(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) of(k EventKind) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// transitions are the transitions that ended runs (2 and 3, §6.9.2).
func (l *eventLog) transitions() []Transition {
	var out []Transition
	for _, e := range l.of(EventTransition) {
		if e.Transition == ProcessingToReady || e.Transition == ProcessingToError {
			out = append(out, e.Transition)
		}
	}
	return out
}

func newManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	if opts.Dialer == nil {
		opts.Dialer = &ClientDialer{Options: []opcua.Option{opcua.ApplicationURI(cmURI), opcua.AutoReconnect(false), opcua.InsecureNoSecurity()}}
	}
	if opts.ApplicationURI == "" {
		opts.ApplicationURI = cmURI
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.CallTimeout == 0 {
		opts.CallTimeout = 10 * time.Second
	}
	m, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func process(t *testing.T, m *Manager, action uafx.FxProcess, k SetKey) *RunResult {
	t.Helper()
	st := m.Process(action, k)
	require.Len(t, st, 1)
	require.NoError(t, st[0].Err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := st[0].Run.Wait(ctx)
	require.NoError(t, err)
	return res
}

// TestEstablishE2E is the acceptance test of C2.2: a Manager establishes a
// bidirectional Connection between two AutomationComponents with the id
// flow of E.2.2, data flows both ways, and disable, enable and remove
// follow (§6.7.5.3).
func TestEstablishE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	events := &eventLog{}
	m := newManager(t, Options{Observer: events, Monitor: &MonitorOptions{Interval: 20 * time.Millisecond}})
	cfg, err := m.Add(e2eConf(t, "E2E", a, b))
	require.NoError(t, err)
	k := cfg.Key()

	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Created, 2)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	assert.Equal(t, []string{"ToA"}, b.endpoints())
	assert.Equal(t, 2.5, a.value(t, fxtest.ConnGain))
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		return st.Diagnostics[0].ConnectionState == uafx.ConnectionOperational
	}, 10*time.Second, 10*time.Millisecond)

	// A set in Ready cannot be established twice: the Names are ours.
	res = process(t, m, uafx.ActionDisableConnections, k)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Closed, 2)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	res = process(t, m, uafx.ActionEnableConnections, k)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	res = process(t, m, uafx.ActionRemoveConnections, k)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
	c := m.Counters()
	assert.Equal(t, uint32(0), c.EstablishCallFailedCount)
	assert.Positive(t, c.EstablishCallCount)
	assert.Positive(t, c.CloseCallCount)
	assert.Equal(t, []Transition{ProcessingToReady, ProcessingToReady, ProcessingToReady, ProcessingToReady}, events.transitions())
}

// TestClientDialer: the default Dialer connects to the endpoint of the
// SecurityMode and SecurityPolicyUri and checks the ServerUri (§9.2).
func TestClientDialer(t *testing.T) {
	t.Parallel()
	a := newAC(t, "dialer", fxserver.ConnectionOptions{})
	d := &ClientDialer{Options: []opcua.Option{opcua.ApplicationURI(cmURI), opcua.AutoReconnect(false), opcua.InsecureNoSecurity()}}
	ctx := context.Background()
	none := ServerAddress{Address: a.url, SecurityMode: ua.MessageSecurityModeNone, SecurityPolicyURI: ua.SecurityPolicyURINone}

	s, err := d.Dial(ctx, ServerAddress{Address: a.url, ServerURI: a.uri, SecurityMode: none.SecurityMode, SecurityPolicyURI: none.SecurityPolicyURI})
	require.NoError(t, err)
	nsa, err := s.NamespaceArray(ctx)
	require.NoError(t, err)
	assert.Contains(t, nsa, a.uri)
	require.NoError(t, s.Close(ctx))

	_, err = d.Dial(ctx, ServerAddress{Address: a.url, ServerURI: "urn:other", SecurityMode: none.SecurityMode, SecurityPolicyURI: none.SecurityPolicyURI})
	assert.ErrorIs(t, err, ua.StatusBadServerURIInvalid)
	_, err = d.Dial(ctx, ServerAddress{Address: a.url, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
	assert.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
}
