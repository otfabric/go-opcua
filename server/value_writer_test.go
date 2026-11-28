// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// writerVar adds a Variable holding an Int32 to a new namespace of srv and
// returns it.
func writerVar(t *testing.T, srv *server.Server, name string, access ua.AccessLevelType) (*server.Node, *server.NodeNameSpace) {
	t.Helper()
	ns := server.NewNodeNameSpace(srv, "urn:test:"+name)
	n := server.NewVariableNode(ua.NewStringNodeID(ns.ID(), name), name, int32(1))
	require.NoError(t, n.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(uint8(access))))
	require.NoError(t, n.SetAttribute(ua.AttributeIDUserAccessLevel, server.DataValueFromValue(uint8(access))))
	ns.AddNode(n)
	ns.Objects().AddRef(n, id.HasComponent, true)
	return n, ns
}

func int32Value(v int32) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
}

// TestValueWriter_TakesTheWrite: the writer gets the session, the node and the
// written value with the server's timestamp; its status is the result; the
// server does not store the value.
func TestValueWriter_TakesTheWrite(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	n, _ := writerVar(t, srv, "Speed", ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	var got atomic.Pointer[server.ValueWrite]
	n.SetValueWriter(func(_ context.Context, w *server.ValueWrite) ua.StatusCode {
		got.Store(w)
		if w.Value.Value.Value().(int32) > 100 {
			return ua.StatusBadOutOfRange
		}
		return ua.StatusOK
	})
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := c.WriteValue(ctx, n.ID(), int32Value(42))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	w := got.Load()
	require.NotNil(t, w)
	require.True(t, w.NodeID.Equal(n.ID()))
	require.Equal(t, int32(42), w.Value.Value.Value())
	require.Equal(t, byte(ua.DataValueValue), w.Value.EncodingMask, "the value as the client wrote it")
	require.True(t, w.Session.ID().Equal(c.Session().SessionID()))

	st, err = c.WriteValue(ctx, n.ID(), int32Value(101))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadOutOfRange, st)

	// A StatusCode and a SourceTimestamp the client writes reach the writer
	// (the server refuses them for a stored value).
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	st, err = c.WriteValue(ctx, n.ID(), &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
		Value: ua.MustVariant(int32(5)), Status: ua.StatusUncertain, SourceTimestamp: at})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	w = got.Load()
	require.Equal(t, ua.StatusUncertain, w.Value.Status)
	require.True(t, w.Value.SourceTimestamp.Equal(at))

	dv, err := c.ReadValue(ctx, n.ID())
	require.NoError(t, err)
	require.Equal(t, int32(1), dv.Value.Value(), "the writer, not the server, decides what the variable holds")
}

// TestValueWriter_AccessLevelFirst: a Variable that is not writable refuses
// the Write before its writer is called.
func TestValueWriter_AccessLevelFirst(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	n, _ := writerVar(t, srv, "Level", ua.AccessLevelTypeCurrentRead)
	var calls atomic.Int32
	n.SetValueWriter(func(context.Context, *server.ValueWrite) ua.StatusCode { calls.Add(1); return ua.StatusOK })
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := c.WriteValue(ctx, n.ID(), int32Value(7))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotWritable, st)
	require.Zero(t, calls.Load())
}

// TestValueWriter_SlowWriterHoldsUpOnlyItsWrite: while a writer waits, the
// server answers other requests, of the same client and of others.
func TestValueWriter_SlowWriterHoldsUpOnlyItsWrite(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	n, _ := writerVar(t, srv, "Valve", ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	entered, release := make(chan struct{}), make(chan struct{})
	n.SetValueWriter(func(ctx context.Context, _ *server.ValueWrite) ua.StatusCode {
		close(entered)
		select {
		case <-release:
			return ua.StatusOK
		case <-ctx.Done():
			return ua.StatusBadTimeout
		}
	})
	c := testutil.NewTestClient(t, url)
	other := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan ua.StatusCode, 1)
	go func() {
		st, err := c.WriteValue(ctx, n.ID(), int32Value(3))
		if err != nil {
			st = ua.StatusBadUnexpectedError
		}
		done <- st
	}()
	<-entered
	for _, cl := range []*opcua.Client{c, other} {
		dv, err := cl.ReadValue(ctx, n.ID())
		require.NoError(t, err)
		require.Equal(t, int32(1), dv.Value.Value())
	}
	select {
	case st := <-done:
		t.Fatalf("the write was answered before its writer returned: %v", st)
	default:
	}
	close(release)
	require.Equal(t, ua.StatusOK, <-done)
}

// TestValueWriter_MixedRequest: a request with stored and taken values answers
// each operation with its own status, in the order of the request.
func TestValueWriter_MixedRequest(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	taken, ns := writerVar(t, srv, "Taken", ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	stored := server.NewVariableNode(ua.NewStringNodeID(ns.ID(), "Stored"), "Stored", int32(1))
	require.NoError(t, stored.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite))))
	ns.AddNode(stored)
	ns.Objects().AddRef(stored, id.HasComponent, true)
	taken.SetValueWriter(func(context.Context, *server.ValueWrite) ua.StatusCode { return ua.StatusBadCommunicationError })
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{
		{NodeID: taken.ID(), AttributeID: ua.AttributeIDValue, Value: int32Value(5)},
		{NodeID: stored.ID(), AttributeID: ua.AttributeIDValue, Value: int32Value(6)},
		{NodeID: ua.NewStringNodeID(ns.ID(), "Missing"), AttributeID: ua.AttributeIDValue, Value: int32Value(7)},
	}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadCommunicationError, ua.StatusOK, ua.StatusBadNodeIDUnknown}, res.Results)
	dv, err := c.ReadValue(ctx, stored.ID())
	require.NoError(t, err)
	require.Equal(t, int32(6), dv.Value.Value())
}

// TestValueWriter_PanicIsInternalError: a writer that panics fails its
// operation and leaves the server serving.
func TestValueWriter_PanicIsInternalError(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	n, _ := writerVar(t, srv, "Broken", ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	n.SetValueWriter(func(context.Context, *server.ValueWrite) ua.StatusCode { panic("writer bug") })
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := c.WriteValue(ctx, n.ID(), int32Value(1))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadInternalError, st)
	_, err = c.ReadValue(ctx, n.ID())
	require.NoError(t, err)
}

// TestValueWriter_CloseEndsWriters: Close cancels the context of a waiting
// writer and returns once it did.
func TestValueWriter_CloseEndsWriters(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	n, _ := writerVar(t, srv, "Stuck", ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)
	entered := make(chan struct{})
	var cancelled atomic.Bool
	n.SetValueWriter(func(ctx context.Context, _ *server.ValueWrite) ua.StatusCode {
		close(entered)
		<-ctx.Done()
		cancelled.Store(true)
		return ua.StatusBadTimeout
	})
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(), opcua.AutoReconnect(false))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Connect(ctx))
	defer func() { _ = c.Close(ctx) }()

	go func() { _, _ = c.WriteValue(ctx, n.ID(), int32Value(1)) }()
	<-entered
	require.NoError(t, srv.Close())
	require.True(t, cancelled.Load(), "Close returned while a writer was still running")
}

// TestCloseSession_EndsTheSession: the application closes a session; its
// subscriptions go, the observer is told, and the client's next request of
// the session fails.
func TestCloseSession_EndsTheSession(t *testing.T) {
	t.Parallel()
	obs := &closeObserver{closed: make(chan server.SessionCloseReason, 4)}
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.WithSessionObserver(obs))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(), opcua.AutoReconnect(false))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Connect(ctx))
	defer func() { _ = c.Close(ctx) }()
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 100 * time.Millisecond}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	_ = sub

	require.Equal(t, ua.StatusBadSessionIDInvalid, srv.CloseSession(ua.NewNumericNodeID(1, 424242)))
	require.Equal(t, ua.StatusBadSessionIDInvalid, srv.CloseSession(nil))
	require.NoError(t, srv.CloseSession(c.Session().SessionID()))
	select {
	case r := <-obs.closed:
		require.Equal(t, server.SessionClosedByServer, r)
	case <-time.After(5 * time.Second):
		t.Fatal("the observer was not told")
	}
	require.Equal(t, ua.StatusBadSessionIDInvalid, srv.CloseSession(c.Session().SessionID()), "closed once")
	require.Zero(t, srv.ServerDiagnosticsSummary().CurrentSubscriptionCount, "the session's subscriptions are deleted")

	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.Error(t, err)
	require.True(t, errors.Is(err, ua.StatusBadSessionIDInvalid) || errors.Is(err, ua.StatusBadSessionClosed), err.Error())
}

type closeObserver struct {
	server.BaseSessionObserver
	closed chan server.SessionCloseReason
}

func (o *closeObserver) OnSessionClosed(_ server.SessionInfo, r server.SessionCloseReason) {
	select {
	case o.closed <- r:
	default:
	}
}

// TestClientCertificateValidator: the application's validator decides which
// application certificates may open a secure channel, and sees each one.
func TestClientCertificateValidator(t *testing.T) {
	t.Parallel()
	p, err := testpki.Get()
	require.NoError(t, err)
	var mu sync.Mutex
	trusted := false
	var seen [][]byte
	validate := func(der []byte) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, der)
		if !trusted {
			return ua.StatusBadCertificateUntrusted
		}
		return nil
	}
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert), server.PrivateKey(p.ServerKey),
		server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithClientCertificateValidator(validate))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })
	connect := func() error {
		c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL,
			opcua.SecurityPolicy("Basic256Sha256"), opcua.SecurityModeString("SignAndEncrypt"),
			opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509),
			opcua.AuthAnonymous(), opcua.SecurityFromEndpoint(srv.Endpoints()[0], ua.UserTokenTypeAnonymous),
			opcua.AutoReconnect(false), opcua.DialTimeout(10*time.Second))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			return err
		}
		return c.Close(ctx)
	}

	require.Error(t, connect(), "refused until the application trusts it")
	mu.Lock()
	require.NotEmpty(t, seen)
	require.Equal(t, p.ClientCert, seen[0])
	trusted = true
	mu.Unlock()
	require.NoError(t, connect())

	_, err = server.New(server.InsecureNoSecurity(), server.WithClientCertificateValidator(validate), server.WithPushManagement(server.PushManagement{}))
	require.Error(t, err, "push management validates against its own trust list")
}
