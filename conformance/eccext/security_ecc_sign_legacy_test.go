// SPDX-License-Identifier: MIT

package eccext

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestECCExt_SignLegacyKeyLength: in the SecurityMode Sign the ECC policies
// without authenticated encryption derive the signing keys alone (Part 6
// §6.8.1 Step 1). ECCSignLegacyKeyLength on both sides restores the
// derivation of open62541 v1.5.9 (L covers all three keys) and the channel
// works; with it on one side only the signing keys differ and the client
// cannot connect.
func TestECCExt_SignLegacyKeyLength(t *testing.T) {
	pol := extPolicies[0] // ECC_brainpoolP256r1
	mode := ua.MessageSecurityModeSign

	t.Run("both legacy", func(t *testing.T) {
		f, url := extServer(t, server.ECCSignLegacyKeyLength())
		ep := endpointFor(t, url, pol.uri, mode)
		c := newClient(t, url, append(extClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous), opcua.ECCSignLegacyKeyLength())...)
		require.Equal(t, mode, c.SecurityMode())
		dv, err := c.ReadValue(context.Background(), f.String)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, dv.Status)
	})

	t.Run("client legacy only", func(t *testing.T) {
		_, url := extServer(t)
		ep := endpointFor(t, url, pol.uri, mode)
		_, err := dialClient(t, url, append(extClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous), opcua.ECCSignLegacyKeyLength(), opcua.DialTimeout(5*time.Second), opcua.RequestTimeout(5*time.Second))...)
		require.Error(t, err)
	})

	t.Run("server legacy only", func(t *testing.T) {
		_, url := extServer(t, server.ECCSignLegacyKeyLength())
		ep := endpointFor(t, url, pol.uri, mode)
		_, err := dialClient(t, url, append(extClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous), opcua.DialTimeout(5*time.Second), opcua.RequestTimeout(5*time.Second))...)
		require.Error(t, err)
	})
}
