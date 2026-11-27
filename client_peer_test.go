// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestClientPeerCertificate: the PeerCertificate is that of the active
// channel as the client validated it: none before Connect and after
// Close; verified, with the ApplicationUri of the endpoint, over a channel
// with message security and a trusted certificate; not verified with
// InsecureSkipVerify; without a certificate over SecurityMode None.
func TestClientPeerCertificate(t *testing.T) {
	t.Parallel()
	p, ep, url := secureCovServer(t)
	user := opcua.AuthUsername("user", "secret")

	t.Run("verified", func(t *testing.T) {
		c := newCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeUserName, user)...)
		_, ok := c.PeerCertificate()
		assert.False(t, ok, "no channel before Connect")
		require.NoError(t, c.Connect(context.Background()))
		pc, ok := c.PeerCertificate()
		require.True(t, ok)
		assert.True(t, pc.Verified)
		assert.Equal(t, ep.Server.ApplicationURI, pc.ApplicationURI)
		assert.Equal(t, []byte(ep.ServerCertificate), pc.Certificate)
		assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, pc.SecurityMode)
		assert.Equal(t, ua.SecurityPolicyURIBasic256Sha256, pc.SecurityPolicyURI)
		pc.Certificate[0] ^= 0xff
		again, _ := c.PeerCertificate()
		assert.Equal(t, []byte(ep.ServerCertificate), again.Certificate, "a copy")
		require.NoError(t, c.Close(context.Background()))
		_, ok = c.PeerCertificate()
		assert.False(t, ok, "no channel after Close")
	})

	t.Run("skip verify", func(t *testing.T) {
		c := connectCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeUserName, user, opcua.InsecureSkipVerify())...)
		pc, ok := c.PeerCertificate()
		require.True(t, ok)
		assert.False(t, pc.Verified)
		assert.Empty(t, pc.ApplicationURI)
		assert.NotEmpty(t, pc.Certificate, "the channel still has the certificate")
	})

	t.Run("no security", func(t *testing.T) {
		_, plain := newScriptedServer(t, nil)
		c := connectCovClient(t, plain)
		pc, ok := c.PeerCertificate()
		require.True(t, ok)
		assert.False(t, pc.Verified)
		assert.Nil(t, pc.Certificate)
		assert.Equal(t, ua.MessageSecurityModeNone, pc.SecurityMode)
	})
}
