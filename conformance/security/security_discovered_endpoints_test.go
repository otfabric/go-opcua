// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestSecurity_DiscoveredEndpoints: the client verifies the endpoint list it
// selected from with the serverEndpoints of CreateSession (Part 4 §5.6.2).
// The go-opcua server returns the same endpoints in both services, so the
// GetEndpoints answer and the full list given with DiscoveredEndpoints
// connect; a list without one of the server's endpoints is refused with
// Bad_SecurityChecksFailed unless InsecureSkipDiscoveredEndpointsCheck turns
// the comparison off.
func TestSecurity_DiscoveredEndpoints(t *testing.T) {
	f, url := secureServer(t)
	ctx := context.Background()
	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	var withoutEncrypt []*ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && e.SecurityMode == ua.MessageSecurityModeSign {
			ep = e
		}
		if e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
			withoutEncrypt = append(withoutEncrypt, e)
		}
	}
	require.NotNil(t, ep)
	require.Less(t, len(withoutEncrypt), len(eps))
	// A copy: only the option gives the client a list.
	epCopy := *ep

	read := func(t *testing.T, c *opcua.Client) {
		t.Helper()
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	}
	t.Run("GetEndpointsAnswer", func(t *testing.T) {
		read(t, newClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...))
	})
	t.Run("FullListGiven", func(t *testing.T) {
		read(t, newClient(t, url, append(secureClientOpts(t, &epCopy, ua.UserTokenTypeAnonymous),
			opcua.DiscoveredEndpoints(eps))...))
	})
	t.Run("ListWithoutSignAndEncryptRefused", func(t *testing.T) {
		_, err := dialClient(t, url, append(secureClientOpts(t, &epCopy, ua.UserTokenTypeAnonymous),
			opcua.DiscoveredEndpoints(withoutEncrypt))...)
		require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
	})
	t.Run("ComparisonOff", func(t *testing.T) {
		read(t, newClient(t, url, append(secureClientOpts(t, &epCopy, ua.UserTokenTypeAnonymous),
			opcua.DiscoveredEndpoints(withoutEncrypt), opcua.InsecureSkipDiscoveredEndpointsCheck())...))
	})
}
