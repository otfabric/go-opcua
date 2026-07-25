// SPDX-License-Identifier: MIT

package opcua

import "context"

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
