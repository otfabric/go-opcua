// SPDX-License-Identifier: MIT

package transport

import (
	"context"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestTransport_EndpointURLForms: a server with opc.tcp, opc.wss and
// opc.https endpoints answers GetEndpoints (Part 4 §5.4.4, endpointUrl) and
// CreateSession (§5.6.2, serverEndpoints) with the same endpoints for the
// same URL, also when the client writes the host in other letter case or
// adds a trailing slash. A client that selects its endpoint from the
// GetEndpoints answer, and so compares that answer with the CreateSession
// response, connects.
func TestTransport_EndpointURLForms(t *testing.T) {
	f, _, urls := transportServer(t)
	tcp := urls[ua.TransportProfileUATCP]
	require.Contains(t, tcp, "//localhost:")
	upper := strings.Replace(tcp, "//localhost:", "//LOCALHOST:", 1)
	ctx := context.Background()

	for _, tc := range []struct{ name, url string }{
		{"advertised", tcp},
		{"trailing slash", tcp + "/"},
		{"upper-case host", upper},
		{"upper-case host and trailing slash", upper + "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eps, err := opcua.GetEndpoints(ctx, tc.url)
			require.NoError(t, err)
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.TransportProfileURI == ua.TransportProfileUATCP {
					ep = e
				}
			}
			require.NotNil(t, ep, "%v", eps)

			c := newClient(t, tc.url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous))
			require.Equal(t, eps, c.Session().ServerEndpoints(), "GetEndpoints and CreateSession answer with the same endpoints")
			for _, e := range eps {
				require.Equal(t, tcp, e.EndpointURL, "only the endpoints of the URL")
			}
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		})
	}
}
