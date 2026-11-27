// SPDX-License-Identifier: MIT

package opcua

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Testing helpers exported only to external tests (package opcua_test).

func (c *Client) TestingRecreateSubscription(ctx context.Context, id uint32) error {
	_, err := c.recreateSubscription(ctx, id)
	return err
}

func (s *Subscription) TestingRecreateDelete(ctx context.Context) error {
	return s.recreateDelete(ctx)
}

func (s *Subscription) TestingRecreateCreate(ctx context.Context) error {
	return s.recreateCreate(ctx)
}

func (c *Client) TestingRefetchEndpoints(ctx context.Context) error {
	_, err := c.refetchEndpoints(ctx)
	return err
}

// TestingConfiguredUserToken returns the user identity token of the client
// configuration, which every session of the client shares.
func (c *Client) TestingConfiguredUserToken() any {
	return c.cfg.session.UserIdentityToken
}

// TestingSessionConfig returns the session configuration of the client.
func (c *Client) TestingSessionConfig() *uasc.SessionConfig {
	return c.cfg.session
}

// TestingInjectChannelError hands err to the connection monitor as if the
// secure channel had reported it.
func (c *Client) TestingInjectChannelError(err error) {
	c.secureChannelErrors() <- err
}

// TestingSessionAuthToken returns the authentication token of the active
// session, nil without one.
func (c *Client) TestingSessionAuthToken() *ua.NodeID {
	if s := c.Session(); s != nil {
		return s.resp.AuthenticationToken
	}
	return nil
}

// TestingSubscriptionGeneration returns the count of subscriptions
// registered so far.
func (c *Client) TestingSubscriptionGeneration() uint64 {
	c.subMux.RLock()
	defer c.subMux.RUnlock()
	return c.subGen
}

// TestingMarkSubscriptionsBrokenSince is markSubscriptionsBrokenSince.
func (c *Client) TestingMarkSubscriptionsBrokenSince(gen uint64) int {
	return c.markSubscriptionsBrokenSince(gen)
}

// TestingSetItemServerID makes the monitored item the caller knows by id
// known to the server by serverID, as a recreation does.
func (s *Subscription) TestingSetItemServerID(id, serverID uint32) {
	s.itemsMu.Lock()
	defer s.itemsMu.Unlock()
	s.items[id].serverID = serverID
}

// TestingRestoreTriggering is restoreTriggering.
func (s *Subscription) TestingRestoreTriggering(ctx context.Context) error {
	return s.restoreTriggering(ctx)
}
