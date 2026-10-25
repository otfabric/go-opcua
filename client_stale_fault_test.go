// SPDX-License-Identifier: MIT

package opcua_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// staleFaultQuiet is how long a fault the monitor is to ignore gets to
// cause a reconnect. The check can only miss a bug, never report one that
// is not there.
const staleFaultQuiet = 500 * time.Millisecond

// A session fault of a request sent in a session the client has left (a
// publish still under way when the application activated another session)
// does not make the client reconnect; the same fault for the session it uses
// does.
func TestStaleSessionFaultIgnored(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	rec := &recorder{}
	c := connectCovClient(t, url, rec.options()...)
	subscribe(t, c)

	left := ua.NewByteStringNodeID(0, []byte("a session the client has left"))
	c.TestingInjectChannelError(&uasc.RequestFault{Err: ua.StatusBadSessionIDInvalid, AuthToken: left})
	time.Sleep(staleFaultQuiet)
	states, _ := rec.snapshot()
	require.NotContains(t, states, opcua.Disconnected, "a fault of a session the client has left caused a reconnect")
	require.Equal(t, opcua.Connected, c.State())

	before := c.Session().SessionID().String()
	c.TestingInjectChannelError(&uasc.RequestFault{Err: ua.StatusBadSessionIDInvalid, AuthToken: c.TestingSessionAuthToken()})
	rec.waitRecovered(t, c)
	require.NotEqual(t, before, c.Session().SessionID().String(), "a new session is created")
}

// A Publish request that found the session without subscriptions marks the
// subscriptions for recreation only if none was registered since the
// request was sent: a recreation that completed while the request was under
// way is not what the server answered about.
func TestStaleNoSubscriptionIgnored(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	c := connectCovClient(t, url)
	subscribe(t, c)

	sent := c.TestingSubscriptionGeneration()
	subscribe(t, c) // registered while the request was under way
	require.Zero(t, c.TestingMarkSubscriptionsBrokenSince(sent))
	require.Equal(t, 2, c.TestingMarkSubscriptionsBrokenSince(c.TestingSubscriptionGeneration()))
}
