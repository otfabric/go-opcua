// SPDX-License-Identifier: MIT

package security

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// DefaultMaxPastKeys is the number of past keys a KeyRing keeps by default
// to decrypt messages that were in flight during a key change.
const DefaultMaxPastKeys = 2

// ErrPolicyMismatch is returned when keys are offered for a SecurityGroup
// with another security policy (Bad_SecurityPolicyRejected).
var ErrPolicyMismatch = fmt.Errorf("pubsub/security: security policy mismatch: %w", ua.StatusBadSecurityPolicyRejected)

// NextTokenID returns the security token id following id. Token ids wrap
// around from 0xFFFFFFFF to 1: 0 is not a valid token id (Part 14 §8.3.2,
// open62541 UA_PubSubKeyStorage_addSecurityKeys).
func NextTokenID(id uint32) uint32 {
	id++
	if id == 0 {
		id = 1
	}
	return id
}

// advanceTokenID returns the token id n positions after id (id != 0).
func advanceTokenID(id uint32, n uint64) uint32 {
	const ids = 1<<32 - 1 // valid ids 1 .. 0xFFFFFFFF
	return uint32((uint64(id-1)+n%ids)%ids) + 1
}

// Option configures a KeyRing or a KeyService. Options that do not apply
// to the value being built are ignored.
type Option func(*options)

type options struct {
	now         func() time.Time
	maxPastKeys int
	rand        io.Reader
	authorizer  Authorizer
}

func buildOptions(opts []Option) options {
	o := options{now: time.Now, maxPastKeys: DefaultMaxPastKeys}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// WithClock sets the clock of the key rotation (tests use a fake clock).
func WithClock(now func() time.Time) Option {
	return func(o *options) {
		if now != nil {
			o.now = now
		}
	}
}

// WithMaxPastKeys sets how many keys before the current one a KeyRing
// keeps (default DefaultMaxPastKeys). Negative values are treated as 0.
func WithMaxPastKeys(n int) Option {
	return func(o *options) { o.maxPastKeys = max(n, 0) }
}

// WithRandom sets the source of key material of a KeyService (default
// crypto/rand).
func WithRandom(r io.Reader) Option {
	return func(o *options) { o.rand = r }
}

// WithAuthorizer sets the Authorizer of a KeyService (default
// DefaultAuthorizer).
func WithAuthorizer(a Authorizer) Option {
	return func(o *options) { o.authorizer = a }
}

type ringEntry struct {
	keys *Keys
	raw  []byte
}

// KeyRing holds the keys of one SecurityGroup as a Publisher or Subscriber
// receives them from an SKS (GetSecurityKeys) or has them pushed
// (SetSecurityKeys): the current key, the future keys and a few past keys,
// by token id. It moves to the next key every KeyLifetime, measured from
// the TimeToNextKey of the last SetKeys. When it runs out of future keys
// it keeps using the last one, as open62541 does, and Stale reports it.
//
// KeyRing implements KeySource and is safe for concurrent use.
type KeyRing struct {
	groupID string
	policy  Policy
	now     func() time.Time
	maxPast int

	mu       sync.Mutex
	entries  []ringEntry
	cur      int       // index of the current key; meaningless if entries is empty
	next     time.Time // time of the next key change; zero: no rotation
	lifetime time.Duration
	stale    bool // a key change was due but there was no future key
	updated  chan struct{}
}

var _ KeySource = (*KeyRing)(nil)

// NewKeyRing returns an empty KeyRing for a SecurityGroup with the given
// policy. Options: WithClock, WithMaxPastKeys.
func NewKeyRing(securityGroupID string, policy Policy, opts ...Option) *KeyRing {
	o := buildOptions(opts)
	return &KeyRing{
		groupID: securityGroupID,
		policy:  policy,
		now:     o.now,
		maxPast: o.maxPastKeys,
		updated: make(chan struct{}),
	}
}

// SecurityGroupID is the id of the SecurityGroup of the ring.
func (r *KeyRing) SecurityGroupID() string { return r.groupID }

// Policy is the security policy of the SecurityGroup.
func (r *KeyRing) Policy() Policy { return r.policy }

// SetKeys installs keys as returned by GetSecurityKeys or pushed with
// SetSecurityKeys: keys[0] is the key of firstTokenID and becomes the
// current key, keys[i] has token id firstTokenID+i (wrapping around to 1).
// The current key changes after timeToNextKey (keyLifetime if not
// positive) and then every keyLifetime; a keyLifetime of zero disables
// rotation. The previous current key and its predecessors are kept as past
// keys, up to the configured maximum.
func (r *KeyRing) SetKeys(policyURI string, firstTokenID uint32, keys [][]byte, timeToNextKey, keyLifetime time.Duration) error {
	if policyURI != r.policy.URI() {
		return fmt.Errorf("%w: got %q, want %q", ErrPolicyMismatch, policyURI, r.policy.URI())
	}
	if firstTokenID == 0 {
		return fmt.Errorf("pubsub/security: token id 0 is invalid: %w", ua.StatusBadInvalidArgument)
	}
	if len(keys) == 0 {
		return fmt.Errorf("pubsub/security: no keys: %w", ua.StatusBadInvalidArgument)
	}
	fresh := make([]ringEntry, 0, len(keys))
	id := firstTokenID
	for i, k := range keys {
		split, err := r.policy.SplitKey(id, k)
		if err != nil {
			return fmt.Errorf("key %d: %w: %w", i, err, ua.StatusBadSecurityChecksFailed)
		}
		fresh = append(fresh, ringEntry{keys: split, raw: split.raw()})
		id = NextTokenID(id)
	}

	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)

	// Keep the keys before the new current key: the known ones if the
	// SKS returned a key the ring has, else the previous current key and
	// its past keys.
	var past []ringEntry
	if j := r.indexLocked(firstTokenID); j >= 0 {
		past = r.entries[:j]
	} else if len(r.entries) > 0 {
		past = r.entries[:r.cur+1]
	}
	newIDs := make(map[uint32]bool, len(fresh))
	for _, e := range fresh {
		newIDs[e.keys.TokenID] = true
	}
	entries := make([]ringEntry, 0, len(past)+len(fresh))
	for _, e := range past {
		if !newIDs[e.keys.TokenID] {
			entries = append(entries, e)
		}
	}
	r.cur = len(entries)
	r.entries = append(entries, fresh...)
	r.pruneLocked()

	r.lifetime = max(keyLifetime, 0)
	if timeToNextKey <= 0 {
		timeToNextKey = r.lifetime
	}
	r.next = time.Time{}
	if r.lifetime > 0 {
		r.next = now.Add(timeToNextKey)
	}
	r.stale = false
	close(r.updated)
	r.updated = make(chan struct{})
	return nil
}

// Updated returns a channel that is closed at the next SetKeys.
func (r *KeyRing) Updated() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.updated
}

// CurrentKeys returns the keys to secure outgoing messages with.
func (r *KeyRing) CurrentKeys() (*Keys, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	if len(r.entries) == 0 {
		return nil, ErrNoKeys
	}
	return r.entries[r.cur].keys, nil
}

// KeysForToken returns the keys of a token the ring holds (past, current or
// future), or ErrNoKeys.
func (r *KeyRing) KeysForToken(tokenID uint32) (*Keys, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	if i := r.indexLocked(tokenID); i >= 0 && tokenID != 0 {
		return r.entries[i].keys, nil
	}
	return nil, fmt.Errorf("%w: token %d of security group %q", ErrNoKeys, tokenID, r.groupID)
}

// CurrentTokenID is the token id of the current key, 0 if the ring is
// empty.
func (r *KeyRing) CurrentTokenID() uint32 {
	k, err := r.CurrentKeys()
	if err != nil {
		return 0
	}
	return k.TokenID
}

// TokenIDs returns the token ids the ring holds, oldest first.
func (r *KeyRing) TokenIDs() []uint32 {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	ids := make([]uint32, len(r.entries))
	for i, e := range r.entries {
		ids[i] = e.keys.TokenID
	}
	return ids
}

// FutureKeyCount is the number of keys after the current one.
func (r *KeyRing) FutureKeyCount() int {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	if len(r.entries) == 0 {
		return 0
	}
	return len(r.entries) - r.cur - 1
}

// TimeToNextKey is the time until the current key changes; 0 if rotation
// is disabled or the ring is empty.
func (r *KeyRing) TimeToNextKey() time.Duration {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	if r.next.IsZero() {
		return 0
	}
	return max(r.next.Sub(now), 0)
}

// KeyLifetime is the lifetime of a key of the last SetKeys.
func (r *KeyRing) KeyLifetime() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lifetime
}

// Stale reports whether a key change was due while the ring had no future
// key: the current key is used beyond its lifetime.
func (r *KeyRing) Stale() bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceLocked(now)
	return r.stale
}

func (r *KeyRing) indexLocked(tokenID uint32) int {
	for i, e := range r.entries {
		if e.keys.TokenID == tokenID {
			return i
		}
	}
	return -1
}

// advanceLocked moves the current key forward for every key change due at
// now.
func (r *KeyRing) advanceLocked(now time.Time) {
	if r.next.IsZero() || r.lifetime <= 0 || now.Before(r.next) || len(r.entries) == 0 {
		return
	}
	n := uint64(now.Sub(r.next)/r.lifetime) + 1
	r.next = r.next.Add(time.Duration(n) * r.lifetime)
	avail := uint64(len(r.entries) - 1 - r.cur)
	if n > avail {
		r.stale = true
		n = avail
	}
	r.cur += int(n)
	r.pruneLocked()
}

func (r *KeyRing) pruneLocked() {
	if drop := r.cur - r.maxPast; drop > 0 {
		r.entries = append([]ringEntry(nil), r.entries[drop:]...)
		r.cur -= drop
	}
}

// raw returns the SKS key the Keys were split from.
func (k *Keys) raw() []byte {
	b := make([]byte, 0, len(k.SigningKey)+len(k.EncryptingKey)+len(k.KeyNonce))
	b = append(b, k.SigningKey...)
	b = append(b, k.EncryptingKey...)
	return append(b, k.KeyNonce...)
}

// KeyRings is a registry of the KeyRings of a process by SecurityGroupId,
// for example the push targets of SetSecurityKeys. It is safe for
// concurrent use.
type KeyRings struct {
	mu    sync.RWMutex
	rings map[string]*KeyRing
}

// Add registers a ring under its SecurityGroupId, replacing a previous one.
func (k *KeyRings) Add(r *KeyRing) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.rings == nil {
		k.rings = make(map[string]*KeyRing)
	}
	k.rings[r.SecurityGroupID()] = r
}

// Get returns the ring of a SecurityGroupId.
func (k *KeyRings) Get(securityGroupID string) (*KeyRing, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	r, ok := k.rings[securityGroupID]
	return r, ok
}

// Remove unregisters the ring of a SecurityGroupId.
func (k *KeyRings) Remove(securityGroupID string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.rings, securityGroupID)
}

// StatusCode returns the OPC UA status code carried by err: the
// ua.StatusCode it wraps, StatusOK for nil, Bad_NotFound for ErrNoKeys,
// Bad_SecurityChecksFailed for ErrSignature and ErrInvalidKey and
// Bad_SecurityPolicyRejected for ErrUnknownPolicy; Bad_InternalError
// otherwise.
func StatusCode(err error) ua.StatusCode {
	if err == nil {
		return ua.StatusOK
	}
	var sc ua.StatusCode
	switch {
	case errors.As(err, &sc):
		return sc
	case errors.Is(err, ErrNoKeys):
		return ua.StatusBadNotFound
	case errors.Is(err, ErrSignature), errors.Is(err, ErrInvalidKey):
		return ua.StatusBadSecurityChecksFailed
	case errors.Is(err, ErrUnknownPolicy):
		return ua.StatusBadSecurityPolicyRejected
	}
	return ua.StatusBadInternalError
}
