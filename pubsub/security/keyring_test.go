// SPDX-License-Identifier: MIT

package security

import (
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// fakeClock is a settable clock for the rotation tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testKeys returns n distinct keys of policy p; key i starts with byte i.
func testKeys(p Policy, n int) [][]byte {
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = make([]byte, p.KeyLength())
		keys[i][0] = byte(i + 1)
	}
	return keys
}

func TestNextTokenID(t *testing.T) {
	require.Equal(t, uint32(2), NextTokenID(1))
	require.Equal(t, uint32(1), NextTokenID(0xFFFFFFFF))
	require.Equal(t, uint32(1), NextTokenID(0))
	require.Equal(t, uint32(5), advanceTokenID(2, 3))
	require.Equal(t, uint32(1), advanceTokenID(0xFFFFFFFF, 1))
	require.Equal(t, uint32(2), advanceTokenID(0xFFFFFFFE, 3))
	require.Equal(t, uint32(7), advanceTokenID(7, 0xFFFFFFFF))
}

func TestKeyRingRotation(t *testing.T) {
	clk := newFakeClock()
	p := Aes128CTR()
	r := NewKeyRing("sg", p, WithClock(clk.Now), WithMaxPastKeys(1))
	require.Equal(t, "sg", r.SecurityGroupID())
	require.Same(t, p, r.Policy())

	_, err := r.CurrentKeys()
	require.ErrorIs(t, err, ErrNoKeys)
	require.Zero(t, r.CurrentTokenID())
	require.Zero(t, r.TimeToNextKey())
	require.Zero(t, r.FutureKeyCount())

	keys := testKeys(p, 3)
	updated := r.Updated()
	require.NoError(t, r.SetKeys(p.URI(), 10, keys, 400*time.Millisecond, time.Second))
	select {
	case <-updated:
	default:
		t.Fatal("Updated not closed by SetKeys")
	}
	require.Equal(t, uint32(10), r.CurrentTokenID())
	require.Equal(t, []uint32{10, 11, 12}, r.TokenIDs())
	require.Equal(t, 2, r.FutureKeyCount())
	require.Equal(t, 400*time.Millisecond, r.TimeToNextKey())
	require.Equal(t, time.Second, r.KeyLifetime())
	k, err := r.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, byte(1), k.SigningKey[0])

	clk.Advance(399 * time.Millisecond)
	require.Equal(t, uint32(10), r.CurrentTokenID())
	clk.Advance(time.Millisecond)
	require.Equal(t, uint32(11), r.CurrentTokenID())
	require.Equal(t, time.Second, r.TimeToNextKey())
	require.Equal(t, []uint32{10, 11, 12}, r.TokenIDs())

	clk.Advance(time.Second)
	require.Equal(t, uint32(12), r.CurrentTokenID())
	require.Equal(t, []uint32{11, 12}, r.TokenIDs(), "one past key kept")
	_, err = r.KeysForToken(10)
	require.ErrorIs(t, err, ErrNoKeys)
	k, err = r.KeysForToken(11)
	require.NoError(t, err)
	require.Equal(t, uint32(11), k.TokenID)
	require.False(t, r.Stale())

	// Out of future keys: the last key stays current.
	clk.Advance(5 * time.Second)
	require.Equal(t, uint32(12), r.CurrentTokenID())
	require.True(t, r.Stale())
	require.Zero(t, r.FutureKeyCount())

	// New keys continue the sequence; the previous current key is kept.
	require.NoError(t, r.SetKeys(p.URI(), 13, testKeys(p, 2), 0, time.Second))
	require.False(t, r.Stale())
	require.Equal(t, []uint32{12, 13, 14}, r.TokenIDs())
	require.Equal(t, uint32(13), r.CurrentTokenID())
	require.Equal(t, time.Second, r.TimeToNextKey(), "TimeToNextKey 0 means KeyLifetime")
}

func TestKeyRingSetKeysKnownToken(t *testing.T) {
	clk := newFakeClock()
	p := Aes256CTR()
	r := NewKeyRing("sg", p, WithClock(clk.Now))
	require.NoError(t, r.SetKeys(p.URI(), 1, testKeys(p, 4), time.Second, time.Second))
	clk.Advance(time.Second)
	require.Equal(t, uint32(2), r.CurrentTokenID())

	// The SKS rotated too and returns the current key 3 and new futures.
	fresh := testKeys(p, 3)
	fresh[0][1] = 0xAA
	require.NoError(t, r.SetKeys(p.URI(), 3, fresh, time.Second, time.Second))
	require.Equal(t, []uint32{1, 2, 3, 4, 5}, r.TokenIDs())
	k, err := r.KeysForToken(3)
	require.NoError(t, err)
	require.Equal(t, byte(0xAA), k.SigningKey[1], "the SKS keys replace the held ones")

	// An unrelated token sequence: the old current key 3 is kept as past.
	require.NoError(t, r.SetKeys(p.URI(), 100, testKeys(p, 1), 0, 0))
	require.Equal(t, []uint32{2, 3, 100}, r.TokenIDs())
	require.Zero(t, r.TimeToNextKey(), "no rotation with a zero lifetime")
	clk.Advance(time.Hour)
	require.Equal(t, uint32(100), r.CurrentTokenID())
}

func TestKeyRingWraparound(t *testing.T) {
	clk := newFakeClock()
	p := Aes128CTR()
	r := NewKeyRing("sg", p, WithClock(clk.Now), WithMaxPastKeys(0))
	require.NoError(t, r.SetKeys(p.URI(), 0xFFFFFFFE, testKeys(p, 4), time.Second, time.Second))
	require.Equal(t, []uint32{0xFFFFFFFE, 0xFFFFFFFF, 1, 2}, r.TokenIDs())
	clk.Advance(2 * time.Second)
	require.Equal(t, uint32(1), r.CurrentTokenID())
	require.Equal(t, []uint32{1, 2}, r.TokenIDs())
	_, err := r.KeysForToken(0)
	require.ErrorIs(t, err, ErrNoKeys)
}

func TestKeyRingSetKeysErrors(t *testing.T) {
	p := Aes128CTR()
	r := NewKeyRing("sg", p, WithMaxPastKeys(-3))
	err := r.SetKeys(PolicyURIAes256CTR, 1, testKeys(p, 1), 0, 0)
	require.ErrorIs(t, err, ErrPolicyMismatch)
	require.Equal(t, ua.StatusBadSecurityPolicyRejected, StatusCode(err))
	require.Equal(t, ua.StatusBadInvalidArgument, StatusCode(r.SetKeys(p.URI(), 0, testKeys(p, 1), 0, 0)))
	require.Equal(t, ua.StatusBadInvalidArgument, StatusCode(r.SetKeys(p.URI(), 1, nil, 0, 0)))
	err = r.SetKeys(p.URI(), 1, [][]byte{make([]byte, 5)}, 0, 0)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, StatusCode(err))
	require.Empty(t, r.TokenIDs())
}

func TestKeyRingConcurrent(t *testing.T) {
	clk := newFakeClock()
	p := Aes128CTR()
	r := NewKeyRing("sg", p, WithClock(clk.Now))
	require.NoError(t, r.SetKeys(p.URI(), 1, testKeys(p, 3), time.Millisecond, time.Millisecond))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				if i == 0 {
					clk.Advance(time.Millisecond)
					if j%50 == 0 {
						_ = r.SetKeys(p.URI(), r.CurrentTokenID(), testKeys(p, 3), 0, time.Millisecond)
					}
				}
				if k, err := r.CurrentKeys(); err == nil {
					_, _ = r.KeysForToken(k.TokenID)
				}
				_ = r.TimeToNextKey()
			}
		})
	}
	wg.Wait()
	require.NotZero(t, r.CurrentTokenID())
}

func TestKeyRings(t *testing.T) {
	var rs KeyRings
	_, ok := rs.Get("a")
	require.False(t, ok)
	a := NewKeyRing("a", Aes128CTR())
	rs.Add(a)
	got, ok := rs.Get("a")
	require.True(t, ok)
	require.Same(t, a, got)
	rs.Remove("a")
	_, ok = rs.Get("a")
	require.False(t, ok)
}

func TestStatusCode(t *testing.T) {
	require.Equal(t, ua.StatusOK, StatusCode(nil))
	require.Equal(t, ua.StatusBadNotFound, StatusCode(ErrNoKeys))
	require.Equal(t, ua.StatusBadSecurityChecksFailed, StatusCode(ErrSignature))
	require.Equal(t, ua.StatusBadInternalError, StatusCode(ErrInvalidNonce))
	require.Equal(t, ua.StatusBadUserAccessDenied, StatusCode(ua.StatusBadUserAccessDenied))
}
