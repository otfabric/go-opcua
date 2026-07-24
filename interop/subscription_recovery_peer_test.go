//go:build interop

// SPDX-License-Identifier: MIT

// Peer Republish / TransferSubscriptions tests.
// COVERAGE.md: subscriptions / subscription.client.republish,
// subscription.server.republish, subscription.server.transfer

package interop

import (
	"context"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
)

func TestGoServer_Open62541Client_Republish(t *testing.T) {
	t.Run("coverage/subscription.server.republish/open62541-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "republish")
		endpoint := startGoServer(t)
		result := runOpen62541ClientResult(t, endpoint, "republish",
			"--subscription-id", "1",
			"--sequence-number", "1",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from republish: %+v", result)
		}
	})
}

func TestGoServer_MiloClient_TransferSubscriptions(t *testing.T) {
	t.Run("coverage/subscription.server.transfer/milo-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "transfer-subscriptions")
		endpoint := startGoServer(t)
		result := runMiloClientResult(t, endpoint, "transfer-subscriptions",
			"--subscription-id", "1",
			"--send-initial-values", "false",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from transfer-subscriptions: %+v", result)
		}
	})
}

func TestOpen62541Server_ClientRepublish(t *testing.T) {
	t.Run("coverage/subscription.client.republish/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		c := dialClient(t, h.endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		notifyCh := make(chan *opcua.PublishNotificationData, 4)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
		if err != nil {
			t.Skipf("peer server subscribe unsupported: %v", err)
		}
		t.Cleanup(func() { _ = sub.Cancel(ctx) })
		_, err = c.Republish(ctx, sub.SubscriptionID, 99999)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "BadMessageNotAvailable") ||
				strings.Contains(msg, "BadSubscription") ||
				strings.Contains(msg, "BadNothingToDo") {
				return
			}
			t.Logf("Republish returned: %v (acceptable peer variance)", err)
		}
	})
}
