// SPDX-License-Identifier: MIT

package secure

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// TestRegressionTransferSubscriptionsNeedsTheOwner asks the server for the
// subscription of another user by its id.
//
// Regression: TransferSubscriptions moved any subscription to any session
// that asked for it. Subscription ids are consecutive numbers, so a client
// could take over the subscriptions, and with them the data, of every other
// client; the owner was left with a subscription that never delivered again.
// The server now requires the user of the owning session (Part 4 §5.13.7).
func TestRegressionTransferSubscriptionsNeedsTheOwner(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	t.Cleanup(e.feed())
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	connect := func(auth ua.UserTokenType) *opcua.Client {
		t.Helper()
		opts := append(e.securityOptions(polP256, ua.MessageSecurityModeSignAndEncrypt, auth),
			opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second), opcua.AutoReconnect(false))
		c, err := e.dialWith(nil, opts)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	transfer := func(c *opcua.Client, id uint32) ua.StatusCode {
		t.Helper()
		var status ua.StatusCode
		err := c.Send(ctx, &ua.TransferSubscriptionsRequest{SubscriptionIDs: []uint32{id}}, func(v ua.Response) error {
			res, ok := v.(*ua.TransferSubscriptionsResponse)
			if !ok || len(res.Results) != 1 || res.Results[0] == nil {
				t.Fatalf("TransferSubscriptions: unexpected response %T", v)
			}
			status = res.Results[0].StatusCode
			return nil
		})
		if err != nil {
			t.Fatalf("TransferSubscriptions: %v", err)
		}
		return status
	}

	owner := connect(ua.UserTokenTypeUserName)
	st, err := openStream(ctx, e, owner, "owner", 8, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := owner.SubscriptionIDs()
	if len(ids) != 1 {
		t.Fatalf("subscriptions of the owner: %v", ids)
	}
	awaitFresh(t, e, st)

	// Another user (anonymous, even from the same application) is refused,
	// and the subscription goes on delivering to its owner.
	thief := connect(ua.UserTokenTypeAnonymous)
	if got := transfer(thief, ids[0]); got != ua.StatusBadUserAccessDenied {
		t.Errorf("transfer to another user: %v, want BadUserAccessDenied", got)
	}
	awaitFresh(t, e, st)

	// A subscription that does not exist is still reported as such.
	if got := transfer(thief, ids[0]+1000); got != ua.StatusBadSubscriptionIDInvalid {
		t.Errorf("transfer of an unknown subscription: %v, want BadSubscriptionIdInvalid", got)
	}

	// The same user in another session may take it: that is what a client
	// does after it lost its session.
	again := connect(ua.UserTokenTypeUserName)
	if got := transfer(again, ids[0]); got != ua.StatusOK {
		t.Errorf("transfer to the same user: %v, want Good", got)
	}

	for _, c := range []*opcua.Client{thief, again, owner} {
		chaoskit.CloseClient(c, nil)
	}
	st.close()
}
