// SPDX-License-Identifier: MIT

package security

import (
	"math"
	"runtime"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestAddSecurityGroupKeyCounts is the boundary table of the key counts of
// a SecurityGroup: its past, current and future keys, MaxPastKeyCount + 1 +
// MaxFutureKeyCount, are at most 65535, the most one GetSecurityKeys
// result carries. Counts above are refused with Bad_InvalidArgument before
// a key is generated.
func TestAddSecurityGroupKeyCounts(t *testing.T) {
	const limit = maxGroupKeys - 1 // past + future
	for _, tt := range []struct {
		name         string
		future, past uint32
		ok           bool
	}{
		{"none", 0, 0, true},
		{"one each", 1, 1, true},
		{"future at the limit", limit, 0, true},
		{"past at the limit", 0, limit, true},
		{"together at the limit", limit / 2, limit - limit/2, true},
		{"future one above", limit + 1, 0, false},
		{"past one above", 0, limit + 1, false},
		{"together one above", limit / 2, limit - limit/2 + 1, false},
		{"future 2^31", 1 << 31, 0, false},
		{"largest future", math.MaxUint32, 0, false},
		{"largest past", 0, math.MaxUint32, false},
		{"largest both", math.MaxUint32, math.MaxUint32, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ks := NewKeyService(WithClock(newFakeClock().Now))
			var err error
			n := allocatedBytes(func() { err = ks.AddSecurityGroup(group("g", tt.future, tt.past)) })
			if !tt.ok {
				require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
				require.Equal(t, ua.StatusBadInvalidArgument, StatusCode(err))
				require.Less(t, n, uint64(1<<20), "bytes allocated to refuse the counts")
				_, found := ks.SecurityGroup("g")
				require.False(t, found)
				return
			}
			require.NoError(t, err)
			// The current key and the future keys, generated ahead.
			r, err := ks.GetSecurityKeys("g", 0, math.MaxUint32)
			require.NoError(t, err)
			require.Len(t, r.Keys, int(tt.future)+1)
			require.Less(t, n, 512*(uint64(tt.future)+1)+1<<20, "bytes allocated for %d keys", tt.future+1)
		})
	}
}
