// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// TestTransportsJSON runs the core services over the UA JSON mappings of
// HTTPS and WebSockets (https-uajson, wss-uajson): sessions, read, write,
// browse, call, subscriptions and publish, with NodeIds of a namespace other
// than 0, which the JSON messages carry by namespace URI.
func TestTransportsJSON(t *testing.T) {
	t.Parallel()
	srv, urls := testutil.NewTransportTestServer(t, server.EnableUAJSON())
	f := testutil.AddFixture(t, srv)

	for i, tc := range []struct{ url, profile string }{
		{urls.HTTPS, ua.TransportProfileHTTPSJSON},
		{urls.WSS, ua.TransportProfileWSSJSON},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			ctx := context.Background()

			// The JSON endpoint is advertised next to the binary one and
			// selected by its transport profile.
			eps, err := opcua.GetEndpoints(ctx, tc.url, opcua.TLSConfig(testutil.TLS(t).ClientConfig()), opcua.TransportProfile(tc.profile))
			require.NoError(t, err)
			ep, err := opcua.SelectEndpointForTransport(eps, tc.profile, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, nil)
			require.NoError(t, err)
			require.Equal(t, tc.url, ep.EndpointURL)

			c := testutil.NewTransportTestClient(t, tc.url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous))
			require.True(t, c.SecureChannel().IsJSON())
			require.Contains(t, c.Namespaces(), "http://otfabric.com/conformance")

			// Write and read back a node of the fixture's namespace.
			want := int32(200 + i)
			res, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
				NodeID: f.Int32, AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(want)},
			}}})
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, res.Results[0])
			got, err := c.Node(f.Int32).Value(ctx)
			require.NoError(t, err)
			require.Equal(t, want, got.Value())

			// A NodeId value of another namespace survives the round trip.
			rr, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: f.Int32, AttributeID: ua.AttributeIDNodeID}}})
			require.NoError(t, err)
			require.Equal(t, f.Int32.String(), rr.Results[0].Value.Value().(*ua.NodeID).String())

			v, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(ctx)
			require.NoError(t, err)
			require.Equal(t, int32(ua.ServerStateRunning), v.Value())

			refs, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
			require.NoError(t, err)
			require.NotEmpty(t, refs)

			call, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: f.MethodObject, MethodID: f.SquareMethod, InputArguments: []*ua.Variant{ua.MustVariant(int32(7))}})
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, call.StatusCode)
			require.Equal(t, int32(49), call.OutputArguments[0].Value())

			notifs := make(chan *opcua.PublishNotificationData, 16)
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, notifs)
			require.NoError(t, err)
			defer func() { _ = sub.Cancel(ctx) }()
			_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1))
			require.NoError(t, err)
			waitValue := func(want int32) {
				t.Helper()
				deadline := time.After(20 * time.Second)
				for {
					select {
					case n := <-notifs:
						require.NoError(t, n.Error)
						dc, ok := n.Value.(*ua.DataChangeNotification)
						if !ok {
							continue
						}
						for _, item := range dc.MonitoredItems {
							if item.Value.Value.Value() == want {
								return
							}
						}
					case <-deadline:
						t.Fatalf("no data change to %d", want)
					}
				}
			}
			waitValue(want)
			// A Read is not held up by the Publish requests in flight.
			_, err = c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
				NodeID: f.Int32, AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(want + 10)},
			}}})
			require.NoError(t, err)
			waitValue(want + 10)
		})
	}
}

func TestTransportsJSONProfileMismatch(t *testing.T) {
	t.Parallel()
	_, urls := testutil.NewTransportTestServer(t, server.EnableUAJSON())
	c, err := opcua.NewClient(urls.HTTPS, opcua.TransportProfile(ua.TransportProfileWSSJSON), opcua.SecurityMode(ua.MessageSecurityModeNone))
	require.NoError(t, err)
	require.ErrorIs(t, c.Connect(context.Background()), errors.ErrInvalidEndpoint)
}

// TestTransportsJSONNotEnabled checks that a server without EnableUAJSON
// neither advertises nor serves the JSON mappings.
func TestTransportsJSONNotEnabled(t *testing.T) {
	t.Parallel()
	_, urls := testutil.NewTransportTestServer(t)
	ctx := context.Background()
	eps, err := opcua.GetEndpoints(ctx, urls.HTTPS, opcua.TLSConfig(testutil.TLS(t).ClientConfig()))
	require.NoError(t, err)
	for _, ep := range eps {
		require.False(t, ua.IsJSONTransportProfile(ep.TransportProfileURI), ep.TransportProfileURI)
	}
	for _, tc := range []struct{ url, profile string }{
		{urls.HTTPS, ua.TransportProfileHTTPSJSON},
		{urls.WSS, ua.TransportProfileWSSJSON},
	} {
		c, err := opcua.NewClient(tc.url, opcua.TransportProfile(tc.profile), opcua.SecurityMode(ua.MessageSecurityModeNone),
			opcua.TLSConfig(testutil.TLS(t).ClientConfig()), opcua.AutoReconnect(false), opcua.RequestTimeout(5*time.Second))
		require.NoError(t, err)
		require.Error(t, c.Connect(ctx), tc.profile)
		_ = c.Close(ctx)
	}
}

// TestTransportsJSONLegacyContentType: a client that sends
// application/opcua+uajson (HTTPSJSONContentType) is served too.
func TestTransportsJSONLegacyContentType(t *testing.T) {
	t.Parallel()
	_, urls := testutil.NewTransportTestServer(t, server.EnableUAJSON())
	c := testutil.NewTransportTestClient(t, urls.HTTPS,
		opcua.TransportProfile(ua.TransportProfileHTTPSJSON),
		opcua.HTTPSJSONContentType(uasc.HTTPSJSONContentTypeLegacy),
		opcua.SecurityMode(ua.MessageSecurityModeNone))
	require.True(t, c.SecureChannel().IsJSON())
	v, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(ua.ServerStateRunning), v.Value())
}
