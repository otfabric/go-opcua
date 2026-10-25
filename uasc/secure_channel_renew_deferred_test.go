// SPDX-License-Identifier: MIT

package uasc

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// renewalHeldUntilExpiry returns a client certificate validator for the
// server that holds up the first renewal (the second OpenSecureChannel)
// until the server's token has run out, and then answers it with verdict.
// The validator runs while the server processes the renewal, after it has
// received it in full: it stands for a slow key exchange on a busy machine.
func renewalHeldUntilExpiry(server *atomic.Pointer[SecureChannel], verdict error) func([]byte) error {
	var opens atomic.Int32
	expired := func() bool {
		s := server.Load()
		if s == nil {
			return false
		}
		s.instancesMu.Lock()
		defer s.instancesMu.Unlock()
		return s.expiryDeferred != nil
	}
	return func([]byte) error {
		if opens.Add(1) != 2 {
			return nil
		}
		for deadline := time.Now().Add(30 * time.Second); !expired(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				return errors.New("the token did not run out while its renewal was processed")
			}
		}
		return verdict
	}
}

// A token that runs out while the server is processing its renewal was
// renewed in time: the client sent the renewal well before the end of the
// lifetime. The server used to close the channel all the same, from the
// expiry timer, in the middle of the key exchange.
func TestRenewal_TokenRunsOutWhileItsRenewalIsProcessed(t *testing.T) {
	var server atomic.Pointer[SecureChannel]
	p := newCovPair(t, covRSA, covOpts{
		tweakClient: func(c *Config) { c.Lifetime = 400 },
		tweakServer: func(c *Config) { c.ClientCertificateValidator = renewalHeldUntilExpiry(&server, nil) },
	})
	server.Store(p.server)
	_, first := token(p.server)

	// The renewal goes through, and the token it replaced is retired.
	waitUntil(t, "the renewal", func() bool {
		_, tok := token(p.server)
		return tok > first && !hasToken(p.server, first)
	})
	p.read(t, 2)
	select {
	case <-p.srvDone:
		t.Fatal("the server closed the channel")
	case err := <-p.clientErrs:
		t.Fatalf("unexpected client error: %v", err)
	default:
	}
}

// A renewal that fails after the token ran out leaves the channel without a
// token: the server closes it, as it would have at the expiry.
func TestRenewal_TokenRunsOutWhileItsRenewalFails(t *testing.T) {
	var server atomic.Pointer[SecureChannel]
	p := newCovPair(t, covRSA, covOpts{
		tweakClient: func(c *Config) { c.Lifetime = 400 },
		tweakServer: func(c *Config) {
			c.ClientCertificateValidator = renewalHeldUntilExpiry(&server, ua.StatusBadCertificateRevoked)
		},
	})
	server.Store(p.server)

	// The server closes the connection (the test times out otherwise), and
	// the client notices.
	<-p.srvDone
	<-p.client.disconnected
}
