// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCallerItemID: the server's id of an item maps back to the id Monitor
// gave the caller, also after a recreation gave the item another server id;
// an id the client does not know is returned unchanged.
func TestCallerItemID(t *testing.T) {
	t.Parallel()
	sub := &Subscription{items: map[uint32]*monitoredItem{
		5: {serverID: 5},
		7: {serverID: 21}, // recreated
	}}
	sub.itemsMu.Lock()
	defer sub.itemsMu.Unlock()
	require.Equal(t, uint32(5), sub.callerItemIDNeedsLock(5))
	require.Equal(t, uint32(7), sub.callerItemIDNeedsLock(21))
	require.Equal(t, uint32(99), sub.callerItemIDNeedsLock(99), "an item of another client")
}
