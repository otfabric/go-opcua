// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSubscription_recreateDelete_ContinuesOnError(t *testing.T) {
	c, err := NewClient("opc.tcp://127.0.0.1:1")
	require.NoError(t, err)
	sub := &Subscription{
		SubscriptionID: 1,
		c:              c,
		params:         &SubscriptionParameters{Interval: 100 * time.Millisecond},
		items:          map[uint32]*monitoredItem{},
	}
	// No session/channel → send fails; recreateDelete must still return nil.
	require.NoError(t, sub.recreateDelete(context.Background()))
}

func TestSubscription_recreateCreate_ErrorWithoutSession(t *testing.T) {
	c, err := NewClient("opc.tcp://127.0.0.1:1")
	require.NoError(t, err)
	sub := &Subscription{
		SubscriptionID: 1,
		c:              c,
		params:         &SubscriptionParameters{Interval: 100 * time.Millisecond},
		items:          map[uint32]*monitoredItem{},
	}
	require.Error(t, sub.recreateCreate(context.Background()))
}
