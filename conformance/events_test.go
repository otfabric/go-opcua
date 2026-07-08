// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestEvents_MonitorAndEmit(t *testing.T) {
	c, f, ctx := setup(t)

	filter := ua.NewEventFilter().
		Select("Message", "Severity").
		Where(ua.Field("Severity").GreaterThanOrEqual(uint16(0))).
		Build()

	sub, notifyCh, err := c.NewSubscription().
		Interval(50*time.Millisecond).
		MonitorEvents(filter, f.EventObject).
		Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Give the server a moment to register the monitored item before emitting.
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, f.EmitTestEvent(
		ua.MustVariant("something happened"),
		ua.MustVariant(uint16(500)),
	))

	deadline := time.After(8 * time.Second)
	for {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			require.NotEmpty(t, enl.Events)
			fields := enl.Events[0].EventFields
			require.Len(t, fields, 2)
			require.Equal(t, "something happened", fields[0].Value())
			require.Equal(t, uint16(500), fields[1].Value())
			return
		case <-deadline:
			t.Fatal("did not receive expected event notification")
		}
	}
}
