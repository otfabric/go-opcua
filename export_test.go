// SPDX-License-Identifier: MIT

package opcua

import (
	"context"

	"github.com/otfabric/go-opcua/uasc"
)

// Testing helpers exported only to external tests (package opcua_test).

func (c *Client) TestingRecreateSubscription(ctx context.Context, id uint32) error {
	return c.recreateSubscription(ctx, id)
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
