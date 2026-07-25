// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryCPRegistry_NilAndEmpty(t *testing.T) {
	var nilReg *historyCPRegistry
	assert.Equal(t, []byte("x"), nilReg.bind("s", []byte("x")))
	inner, st := nilReg.resolve("s", []byte("outer"))
	assert.Equal(t, ua.StatusOK, st)
	assert.Equal(t, []byte("outer"), inner)
	nilReg.release([]byte("outer"))
	nilReg.releaseSession("s")

	reg := newHistoryCPRegistry(nil)
	assert.Nil(t, reg.bind("s", nil))
	assert.Len(t, reg.bind("s", []byte{}), 0)
	inner, st = reg.resolve("s", nil)
	assert.Equal(t, ua.StatusOK, st)
	assert.Nil(t, inner)
	reg.release(nil)
	reg.releaseSession("")
}

func TestHistoryCPRegistry_ResolveUnknownAndOneShot(t *testing.T) {
	reg := newHistoryCPRegistry(nil)
	_, st := reg.resolve("s", []byte("unknown"))
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, st)

	outer := reg.bind("s", []byte("provider"))
	inner, st := reg.resolve("s", outer)
	require.Equal(t, ua.StatusOK, st)
	assert.Equal(t, []byte("provider"), inner)

	_, st = reg.resolve("s", outer)
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, st)
}

func TestHistoryCPRegistry_ReleaseCallsOnRelease(t *testing.T) {
	var got []byte
	reg := newHistoryCPRegistry(func(cp []byte) { got = append([]byte(nil), cp...) })
	outer := reg.bind("s", []byte("inner-bytes"))
	reg.release(outer)
	assert.Equal(t, []byte("inner-bytes"), got)
	_, st := reg.resolve("s", outer)
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, st)
}

func TestHistoryCPRegistry_BindCopiesProvider(t *testing.T) {
	reg := newHistoryCPRegistry(nil)
	provider := []byte("abcd")
	outer := reg.bind("s", provider)
	provider[0] = 'Z'
	inner, st := reg.resolve("s", outer)
	require.Equal(t, ua.StatusOK, st)
	assert.Equal(t, []byte("abcd"), inner)
}

func TestHistoryCPRegistry_EvictTTL(t *testing.T) {
	var released int
	reg := newHistoryCPRegistry(func([]byte) { released++ })
	outer := reg.bind("s", []byte("old"))

	reg.mu.Lock()
	for _, b := range reg.items {
		b.created = time.Now().Add(-historyContinuationTTL - time.Second)
	}
	reg.mu.Unlock()

	_, st := reg.resolve("s", outer)
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, st)
	assert.Equal(t, 1, released)
}

func TestHistoryCPRegistry_EvictCapacity(t *testing.T) {
	var released int
	reg := newHistoryCPRegistry(func([]byte) { released++ })

	for i := 0; i < maxHistoryContinuationPoints; i++ {
		reg.bind("s", []byte{byte(i)})
	}
	// Distinct ages within TTL so only the capacity branch of evictLocked runs.
	reg.mu.Lock()
	i := 0
	for _, b := range reg.items {
		b.created = time.Now().Add(-time.Duration(i) * time.Millisecond)
		i++
	}
	reg.mu.Unlock()

	// bind inserts after evictLocked, so the first overflow reaches max+1;
	// the next bind (or resolve) runs capacity eviction.
	reg.bind("s", []byte{0xff})
	assert.Equal(t, 0, released)
	reg.bind("s", []byte{0xfe})
	assert.GreaterOrEqual(t, released, 1)

	_, _ = reg.resolve("s", []byte("missing")) // triggers another evictLocked
	reg.mu.Lock()
	n := len(reg.items)
	reg.mu.Unlock()
	assert.LessOrEqual(t, n, maxHistoryContinuationPoints)
}
