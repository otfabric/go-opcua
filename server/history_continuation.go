// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// historyCPRegistry binds opaque OPC UA continuation points to sessions.
// Provider tokens remain internal; clients only ever see registry-owned bytes.
type historyCPRegistry struct {
	mu        sync.Mutex
	items     map[string]*historyCPBinding
	onRelease func([]byte)
}

type historyCPBinding struct {
	sessionAuth string
	providerCP  []byte
	created     time.Time
}

func newHistoryCPRegistry(onRelease func([]byte)) *historyCPRegistry {
	return &historyCPRegistry{
		items:     make(map[string]*historyCPBinding),
		onRelease: onRelease,
	}
}

func (r *historyCPRegistry) bind(sessionAuth string, providerCP []byte) []byte {
	if r == nil || len(providerCP) == 0 {
		return providerCP
	}
	outer := make([]byte, 16)
	_, _ = rand.Read(outer)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictLocked()
	r.items[hex.EncodeToString(outer)] = &historyCPBinding{
		sessionAuth: sessionAuth,
		providerCP:  append([]byte(nil), providerCP...),
		created:     time.Now(),
	}
	return outer
}

// resolve returns the provider CP for a client-supplied outer CP.
// On session mismatch or unknown/expired CP, returns BadContinuationPointInvalid.
func (r *historyCPRegistry) resolve(sessionAuth string, outer []byte) ([]byte, ua.StatusCode) {
	if len(outer) == 0 {
		return nil, ua.StatusOK
	}
	if r == nil {
		return outer, ua.StatusOK
	}
	key := hex.EncodeToString(outer)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictLocked()
	b, ok := r.items[key]
	if !ok {
		return nil, ua.StatusBadContinuationPointInvalid
	}
	if b.sessionAuth != sessionAuth {
		return nil, ua.StatusBadContinuationPointInvalid
	}
	// One-shot: consume outer binding; provider will issue a new inner CP if needed.
	delete(r.items, key)
	return append([]byte(nil), b.providerCP...), ua.StatusOK
}

func (r *historyCPRegistry) release(outer []byte) {
	if r == nil || len(outer) == 0 {
		return
	}
	key := hex.EncodeToString(outer)
	r.mu.Lock()
	b, ok := r.items[key]
	if ok {
		delete(r.items, key)
	}
	fn := r.onRelease
	r.mu.Unlock()
	if ok && fn != nil {
		fn(b.providerCP)
	}
}

func (r *historyCPRegistry) releaseSession(sessionAuth string) {
	if r == nil || sessionAuth == "" {
		return
	}
	r.mu.Lock()
	var provider [][]byte
	for k, b := range r.items {
		if b.sessionAuth == sessionAuth {
			provider = append(provider, b.providerCP)
			delete(r.items, k)
		}
	}
	fn := r.onRelease
	r.mu.Unlock()
	if fn != nil {
		for _, cp := range provider {
			fn(cp)
		}
	}
}

func (r *historyCPRegistry) evictLocked() {
	now := time.Now()
	for k, v := range r.items {
		if now.Sub(v.created) > historyContinuationTTL {
			if r.onRelease != nil {
				r.onRelease(v.providerCP)
			}
			delete(r.items, k)
		}
	}
	for len(r.items) > maxHistoryContinuationPoints {
		var oldest string
		var oldestTime time.Time
		for k, v := range r.items {
			if oldest == "" || v.created.Before(oldestTime) {
				oldest = k
				oldestTime = v.created
			}
		}
		if oldest == "" {
			break
		}
		if r.onRelease != nil {
			r.onRelease(r.items[oldest].providerCP)
		}
		delete(r.items, oldest)
	}
}
