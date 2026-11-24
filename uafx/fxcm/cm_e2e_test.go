// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The user of the sessions of the ConnectionManager to the
// AutomationComponents of TestConnectionManagerLifecycle.
const (
	cmUser = "cm"
	cmPass = "cm-secret"
)

// newSecureAC is an AutomationComponent with a SignAndEncrypt
// Basic256Sha256 endpoint and its own certificate, on which the user cmUser
// has the Role ConnectionAdmin (Part 81 §5.9).
func newSecureAC(t *testing.T, name string) (*ac, *x509.Certificate) {
	t.Helper()
	uri := "urn:go-opcua:fxcm:" + name
	der, key, err := testpki.SelfSigned(name, uri)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	var admin *ua.NodeID
	roles := func(tok ua.IdentityToken) []*ua.NodeID {
		out := server.DefaultRoleMapper(tok)
		if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == cmUser && admin != nil {
			out = append(out, admin)
		}
		return out
	}
	a := newACWith(t, name, fxserver.ConnectionOptions{}, "",
		server.Certificate(der), server.PrivateKey(key),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == cmUser && pass == cmPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(roles))
	admin = a.ns.ConnectionAdmin()
	return a, cert
}

// cmServer is a server with the UAFX CM model and EnableConnectionManager
// for m, and a client with the Role ConfigureAdmin (Part 3 §4.9.2).
type cmServer struct {
	srv *server.Server
	ns  fxserver.Namespaces
	cm  *fxserver.ConnectionManager
	c   *opcua.Client
}

func newCMServer(t *testing.T, m *fxcm.Manager) *cmServer {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI("urn:go-opcua:fxcm:cmserver"),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			return append(server.DefaultRoleMapper(tok), fxserver.ConfigureAdmin())
		}),
	)
	require.NoError(t, err)
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{
		Manager: m, Editable: true, File: true, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() {
		_ = cm.Close()
		_ = srv.Close()
	})
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), opcua.InsecureNoSecurity(),
		opcua.ApplicationURI("urn:go-opcua:fxcm:operator"), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return &cmServer{srv: srv, ns: ns, cm: cm, c: c}
}

// file calls the Method name of ConnectionManagerConfiguration (F.3).
func (s *cmServer) file(t *testing.T, name string, args ...any) []*ua.Variant {
	t.Helper()
	in := make([]*ua.Variant, len(args))
	for i, a := range args {
		in[i] = ua.MustVariant(a)
	}
	res, err := s.c.Call(context.Background(), &ua.CallMethodRequest{
		ObjectID: ua.NewStringNodeID(s.ns.CM, "cm.File"), MethodID: ua.NewStringNodeID(s.ns.CM, "cm.File."+name), InputArguments: in,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode, name)
	return res.OutputArguments
}

// value reads the member suffix of the set Object set.
func (s *cmServer) value(t *testing.T, set string, suffix string) any {
	t.Helper()
	dv, err := s.c.Node(ua.NewStringNodeID(s.ns.CM, "cm.set:"+set+suffix)).Value(context.Background())
	require.NoError(t, err)
	return dv.Value()
}

func (s *cmServer) state(t *testing.T, set string) string {
	t.Helper()
	return s.value(t, set, ".CurrentState").(*ua.LocalizedText).Text
}

// processingEvents subscribes to the ConnectionConfigurationSet events of
// the ConnectionManager (§8.6 to §8.9) and returns their EventTypes.
func processingEvents(t *testing.T, c *opcua.Client, cm *ua.NodeID) <-chan *ua.NodeID {
	t.Helper()
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(ua.NewEventFilter().SelectPaths("EventType").Build(), cm).Start(context.Background())
	require.NoError(t, err)
	out := make(chan *ua.NodeID, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case msg := <-ch:
				if msg == nil {
					return
				}
				if l, ok := msg.Value.(*ua.EventNotificationList); ok {
					for _, e := range l.Events {
						if id, ok := e.EventFields[0].Value().(*ua.NodeID); ok {
							out <- id
						}
					}
				}
			case <-done:
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = sub.Cancel(context.Background())
		close(done)
		<-exited
	})
	return out
}

// TestConnectionManagerLifecycle is the headline test of design §7.1: two
// AutomationComponents and a ConnectionManager, each its own server; a
// client drives the ConnectionManager only through its Methods, the
// SelectionList Variables of the set and the F.3 file. The
// ConnectionManager's sessions to the ACs are SignAndEncrypt, with a user
// that has the Role ConnectionAdmin.
func TestConnectionManagerLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, aCert := newSecureAC(t, "life-a")
	b, bCert := newSecureAC(t, "life-b")
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	der, key, err := testpki.SelfSigned("cm", cmURI)
	require.NoError(t, err)
	m := newManager(t, fxcm.Options{
		Dialer: &fxcm.ClientDialer{
			Options: []opcua.Option{
				opcua.ApplicationURI(cmURI), opcua.AutoReconnect(false),
				opcua.Certificate(der), opcua.PrivateKey(key), opcua.TrustedCertificates(aCert, bCert),
				opcua.AuthUsername(cmUser, cmPass),
			},
			Certificate: der,
			AuthType:    ua.UserTokenTypeUserName,
		},
		Monitor: &fxcm.MonitorOptions{Interval: 20 * time.Millisecond},
	})
	s := newCMServer(t, m)
	cmNode, err := uafx.ConnectionManagerNode(ctx, s.c)
	require.NoError(t, err)
	events := processingEvents(t, s.c, cmNode)
	ev := func(n uint32) string { return ua.NewNumericNodeID(s.ns.CM, n).String() }
	expectRun := func(action uafx.FxProcess, set *ua.NodeID) {
		t.Helper()
		sc, rs, err := uafx.ProcessConnectionConfigurationSets(ctx, s.c, action, []*ua.NodeID{set})
		require.NoError(t, err)
		require.Equal(t, ua.StatusGood, sc)
		require.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
		var got []string
		for len(got) < 2 {
			select {
			case e := <-events:
				got = append(got, e.String())
			case <-time.After(30 * time.Second):
				require.FailNow(t, "no processing events", "%v: %v", action, got)
			}
		}
		st, _ := m.Status(fxcm.SetKey{Name: "Life"})
		require.Equal(t, []string{ev(fxcmid.ConnectionConfigurationSetProcessingStartedEventType), ev(fxcmid.ConnectionConfigurationSetProcessingSucceededEventType)}, got,
			"%v: %+v", action, st.Last)
	}
	diag := func(want uafx.ConnectionState) {
		t.Helper()
		require.Eventually(t, func() bool {
			st, _ := m.Status(fxcm.SetKey{Name: "Life"})
			return len(st.Diagnostics) == 1 && st.Diagnostics[0].ConnectionState == want
		}, 10*time.Second, 10*time.Millisecond, "%v", want)
	}

	conf := e2eConf(t, "Life", a, b)
	for _, sa := range conf.ServerAddresses {
		sa.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
		sa.SecurityPolicyURI = ua.SecurityPolicyURIBasic256Sha256
	}
	ab := conf.CommunicationFlows[0].(*uafx.PubSubCommunicationFlowConfigurationConf)
	ab.PublishingInterval, ab.PublishingIntervalSelection = ptr(10.0), []float64{10, 25}

	// 1. The set arrives through the file (F.3.3): Ready, Version 1, not in
	// edit, locked to the ConnectionManager.
	body, err := fxcm.EncodeFile([]*uafx.ConnectionConfigurationSetConf{conf})
	require.NoError(t, err)
	h := s.file(t, "Open", uint8(0x06))[0].Value().(uint32)
	s.file(t, "Write", h, body)
	out := s.file(t, "CloseAndUpdate", h, true, []byte{byte(uafx.ElementAdd)})
	require.Equal(t, true, out[0].Value())
	require.Equal(t, []ua.StatusCode{ua.StatusGood}, out[1].Value())
	set := out[2].Value().([]*ua.NodeID)[0]
	assert.Equal(t, ua.NewStringNodeID(s.ns.CM, "cm.set:Life").String(), set.String())
	assert.Equal(t, uint32(1), s.value(t, "Life", ".Version"))
	assert.Equal(t, false, s.value(t, "Life", ".Edit"))
	assert.Equal(t, "CM", s.value(t, "Life", ".Lock.LockingUser"))
	assert.Equal(t, fxcm.StateReady.String(), s.state(t, "Life"))

	// 2. Establish: endpoints on both ACs, data both ways over UDP,
	// ConnectionOperational with monitoring.
	expectRun(uafx.ActionEstablishConnectionsEnabled, set)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	assert.Equal(t, []string{"ToA"}, b.endpoints())
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 10*time.Second, 10*time.Millisecond)
	diag(uafx.ConnectionOperational)
	st, _ := m.Status(fxcm.SetKey{Name: "Life"})
	assert.Equal(t, uafx.LastActivityEstablishEnabled, st.Diagnostics[0].LastActivity)
	assert.Equal(t, ua.StatusGood, st.Diagnostics[0].Endpoint1Status)
	assert.Equal(t, ua.StatusGood, st.Diagnostics[0].Endpoint2Status)
	assert.Equal(t, fxcm.StateReady.String(), s.state(t, "Life"))

	// 3. Disable: the endpoints stay, the Connection is Ready.
	expectRun(uafx.ActionDisableConnections, set)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	diag(uafx.ConnectionReady)

	// 4. Enable: data flows again.
	expectRun(uafx.ActionEnableConnections, set)
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 18.0))
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 18.0 }, 10*time.Second, 10*time.Millisecond)
	diag(uafx.ConnectionOperational)

	// 5. Edit the PublishingInterval of the flow to its other Selection:
	// Version 2 and the WriterGroup of AC1 follows (CS-19); after a remove
	// and a new establish AC1 publishes with it.
	sc, rs, err := uafx.EditConnectionConfigurationSets(ctx, s.c, uafx.StartEditing, []*ua.NodeID{set})
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, sc, "%v", rs)
	pi := ua.NewStringNodeID(s.ns.CM, "cm.set:Life.Flow[AB].PublishingInterval")
	wr, err := s.c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{NodeID: pi, AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(25.0)}}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, wr.Results[0])
	sc, rs, err = uafx.EditConnectionConfigurationSets(ctx, s.c, uafx.CommitUpdates, []*ua.NodeID{set})
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, sc, "%v", rs)
	assert.Equal(t, uint32(2), s.value(t, "Life", ".Version"))
	assert.Equal(t, 25.0, s.value(t, "Life", ".Flow[AB].PublishingInterval"))
	cfg, ok := m.Config(fxcm.SetKey{Name: "Life"})
	require.True(t, ok)
	model := cfg.Conf().AutomationComponentConfigurations[0].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	assert.InDelta(t, 25.0, model.PubSubConfiguration.Connections[0].WriterGroups[0].PublishingInterval, 0)
	expectRun(uafx.ActionRemoveConnections, set)
	expectRun(uafx.ActionEstablishConnectionsEnabled, set)
	assert.InDelta(t, 25.0, writerGroupInterval(t, a), 0)
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 19.0))
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 19.0 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)

	// 6. Remove: the endpoints and the writers and readers the
	// ConnectionManager configured are gone on both ACs.
	expectRun(uafx.ActionRemoveConnections, set)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
	assert.Zero(t, countWritersReaders(a))
	assert.Zero(t, countWritersReaders(b))
	diag(uafx.ConnectionNotEstablished)
	assert.Equal(t, fxcm.StateReady.String(), s.state(t, "Life"))
	c := m.Counters()
	assert.Zero(t, c.EstablishCallFailedCount)
	assert.Zero(t, c.CloseCallFailedCount)
	dv, err := s.c.Node(ua.NewStringNodeID(s.ns.CM, "cm.Diagnostics.EstablishCallCount")).Value(ctx)
	require.NoError(t, err)
	assert.Equal(t, c.EstablishCallCount, dv.Value(), "the Diagnostics counters follow the Manager")
}

// writerGroupInterval is the PublishingInterval of the WriterGroup of the
// PubSub runtime of a that has a DataSetWriter. A close leaves the groups
// (fxserver closeEndpoint), so a new establish adds a new one.
func writerGroupInterval(t *testing.T, a *ac) float64 {
	t.Helper()
	var out []float64
	for _, c := range a.srv.PubSub().Configuration().Connections {
		for _, wg := range c.WriterGroups {
			if len(wg.DataSetWriters) > 0 {
				out = append(out, wg.PublishingInterval)
			}
		}
	}
	require.Len(t, out, 1)
	return out[0]
}

// countWritersReaders counts the DataSetWriters and DataSetReaders of the
// PubSub runtime of a.
func countWritersReaders(a *ac) int {
	n := 0
	for _, c := range a.srv.PubSub().Configuration().Connections {
		for _, wg := range c.WriterGroups {
			n += len(wg.DataSetWriters)
		}
		for _, rg := range c.ReaderGroups {
			n += len(rg.DataSetReaders)
		}
	}
	return n
}
