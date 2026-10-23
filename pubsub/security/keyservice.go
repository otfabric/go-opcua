// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// MaxSecurityGroupIDLength is the longest SecurityGroupId a KeyService
// accepts (open62541 ua_pubsub_securitygroup.c).
const MaxSecurityGroupIDLength = 512

// SecurityGroupConfig configures a SecurityGroup of a KeyService
// (SecurityGroupType, Part 14 §9.1.5.3; AddSecurityGroup arguments).
type SecurityGroupConfig struct {
	// SecurityGroupID identifies the group; it is also its name (the
	// SecurityGroupName argument of AddSecurityGroup and the BrowseName of
	// its node), as in open62541.
	SecurityGroupID string
	// SecurityPolicyURI is the PubSub security policy of the keys.
	SecurityPolicyURI string
	// KeyLifetime is the time a key is current. It must be positive.
	KeyLifetime time.Duration
	// MaxFutureKeyCount is the number of keys after the current one the
	// SKS generates ahead and returns at most.
	MaxFutureKeyCount uint32
	// MaxPastKeyCount is the number of keys before the current one the
	// SKS keeps.
	MaxPastKeyCount uint32
	// SecurityGroupFolder is the path of SecurityGroupFolder names below
	// PublishSubscribe.SecurityGroups the group is listed in; empty for
	// the SecurityGroups folder itself.
	SecurityGroupFolder []string
}

// SecurityKeys is the result of GetSecurityKeys and the input of
// SetSecurityKeys (Part 14 §8.3.2, §8.3.4).
type SecurityKeys struct {
	SecurityPolicyURI string
	// FirstTokenID is the token id of Keys[0]; Keys[i] has token id
	// FirstTokenID+i, wrapping around to 1.
	FirstTokenID uint32
	Keys         [][]byte
	// TimeToNextKey is the time until the current key changes.
	TimeToNextKey time.Duration
	// KeyLifetime is the lifetime of a key.
	KeyLifetime time.Duration
}

// GroupEvent tells a KeyService listener that a SecurityGroup was added or
// removed.
type GroupEvent struct {
	Added  bool
	Config SecurityGroupConfig
}

// KeyService is the key management of a Security Key Service (Part 14 §8):
// it keeps SecurityGroups, generates random keys for them, rotates them
// every KeyLifetime and answers GetSecurityKeys. It does not depend on a
// server: package server publishes it in the address space
// (server.WithSecurityKeyService) and in-process publishers can use
// KeySource directly. Key changes are computed from the clock when the keys
// are read, so the KeyService needs no goroutine. It is safe for concurrent
// use.
type KeyService struct {
	now        func() time.Time
	rand       io.Reader
	authorizer Authorizer

	mu        sync.Mutex
	groups    map[string]*sksGroup
	listeners map[int]func(GroupEvent)
	nextL     int
}

type sksGroup struct {
	cfg      SecurityGroupConfig
	policy   Policy
	entries  []sksKey // past keys, current key, future keys
	cur      int
	curStart time.Time // when the current key became current
}

type sksKey struct {
	id  uint32
	key []byte
}

// NewKeyService returns an empty KeyService. Options: WithClock,
// WithRandom, WithAuthorizer.
func NewKeyService(opts ...Option) *KeyService {
	o := buildOptions(opts)
	return &KeyService{
		now:        o.now,
		rand:       orRand(o.rand),
		authorizer: o.authorizer,
		groups:     make(map[string]*sksGroup),
		listeners:  make(map[int]func(GroupEvent)),
	}
}

// Authorize checks a call of a remote caller with the KeyService's
// Authorizer, see the package function Authorize.
func (ks *KeyService) Authorize(ctx context.Context, c *Caller, op Operation, securityGroupID string) error {
	return Authorize(ctx, ks.authorizer, c, op, securityGroupID)
}

// OnChange registers a function called after a SecurityGroup was added or
// removed; the returned function unregisters it.
func (ks *KeyService) OnChange(fn func(GroupEvent)) (cancel func()) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	n := ks.nextL
	ks.nextL++
	ks.listeners[n] = fn
	return func() {
		ks.mu.Lock()
		defer ks.mu.Unlock()
		delete(ks.listeners, n)
	}
}

func (ks *KeyService) notify(ev GroupEvent) {
	ks.mu.Lock()
	keys := make([]int, 0, len(ks.listeners))
	for k := range ks.listeners {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	fns := make([]func(GroupEvent), 0, len(keys))
	for _, k := range keys {
		fns = append(fns, ks.listeners[k])
	}
	ks.mu.Unlock()
	for _, fn := range fns {
		fn(ev)
	}
}

// AddSecurityGroup creates a SecurityGroup with a current key (token id 1)
// and MaxFutureKeyCount future keys, as open62541 does. Errors carry the
// status codes of AddSecurityGroup: Bad_InvalidArgument for an empty or
// too long id or a non-positive KeyLifetime, Bad_NodeIdExists for an id in
// use, Bad_SecurityPolicyRejected for an unknown policy.
func (ks *KeyService) AddSecurityGroup(cfg SecurityGroupConfig) error {
	if cfg.SecurityGroupID == "" || len(cfg.SecurityGroupID) > MaxSecurityGroupIDLength {
		return fmt.Errorf("pubsub/security: invalid SecurityGroupId: %w", ua.StatusBadInvalidArgument)
	}
	if cfg.KeyLifetime <= 0 {
		return fmt.Errorf("pubsub/security: KeyLifetime must be positive: %w", ua.StatusBadInvalidArgument)
	}
	if slices.Contains(cfg.SecurityGroupFolder, "") {
		return fmt.Errorf("pubsub/security: empty SecurityGroupFolder name: %w", ua.StatusBadInvalidArgument)
	}
	policy, err := PolicyByURI(cfg.SecurityPolicyURI)
	if err != nil {
		return fmt.Errorf("%w: %w", err, ua.StatusBadSecurityPolicyRejected)
	}
	cfg.SecurityGroupFolder = slices.Clone(cfg.SecurityGroupFolder)
	g := &sksGroup{cfg: cfg, policy: policy, curStart: ks.now()}
	id := uint32(1)
	for range uint64(cfg.MaxFutureKeyCount) + 1 {
		k, err := GenerateKey(policy, ks.rand)
		if err != nil {
			return fmt.Errorf("%w: %w", err, ua.StatusBadInternalError)
		}
		g.entries = append(g.entries, sksKey{id: id, key: k})
		id = NextTokenID(id)
	}

	ks.mu.Lock()
	if _, ok := ks.groups[cfg.SecurityGroupID]; ok {
		ks.mu.Unlock()
		return fmt.Errorf("pubsub/security: SecurityGroup %q exists: %w", cfg.SecurityGroupID, ua.StatusBadNodeIDExists)
	}
	ks.groups[cfg.SecurityGroupID] = g
	ks.mu.Unlock()
	ks.notify(GroupEvent{Added: true, Config: cloneConfig(cfg)})
	return nil
}

// RemoveSecurityGroup deletes a SecurityGroup and its keys
// (Bad_NotFound if there is none).
func (ks *KeyService) RemoveSecurityGroup(securityGroupID string) error {
	ks.mu.Lock()
	g, ok := ks.groups[securityGroupID]
	if !ok {
		ks.mu.Unlock()
		return fmt.Errorf("pubsub/security: SecurityGroup %q: %w", securityGroupID, ua.StatusBadNotFound)
	}
	delete(ks.groups, securityGroupID)
	ks.mu.Unlock()
	ks.notify(GroupEvent{Added: false, Config: cloneConfig(g.cfg)})
	return nil
}

// SecurityGroup returns the configuration of a SecurityGroup.
func (ks *KeyService) SecurityGroup(securityGroupID string) (SecurityGroupConfig, bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	g, ok := ks.groups[securityGroupID]
	if !ok {
		return SecurityGroupConfig{}, false
	}
	return cloneConfig(g.cfg), true
}

// SecurityGroups returns the configurations of all SecurityGroups, sorted
// by id.
func (ks *KeyService) SecurityGroups() []SecurityGroupConfig {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]SecurityGroupConfig, 0, len(ks.groups))
	for _, g := range ks.groups {
		out = append(out, cloneConfig(g.cfg))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecurityGroupID < out[j].SecurityGroupID })
	return out
}

func cloneConfig(c SecurityGroupConfig) SecurityGroupConfig {
	c.SecurityGroupFolder = slices.Clone(c.SecurityGroupFolder)
	return c
}

// GetSecurityKeys returns keys of a SecurityGroup with the semantics of
// Part 14 §8.3.2 as open62541 implements them (ua_pubsub_ns0_sks.c):
//
//   - startingTokenID 0 starts at the current key; a known token id starts
//     at that key (past, current or future); an unknown one starts at the
//     oldest key the SKS keeps.
//   - requestedKeyCount is the number of keys after the first; the SKS
//     returns at most the keys it has: a count above MaxFutureKeyCount
//     returns all keys from the first one.
//   - FirstTokenID is the token id of the first key returned, TimeToNextKey
//     the time until the current key changes, KeyLifetime the group's.
//
// It does not authorize the caller, see Authorize. An unknown group is
// Bad_NotFound.
func (ks *KeyService) GetSecurityKeys(securityGroupID string, startingTokenID, requestedKeyCount uint32) (*SecurityKeys, error) {
	now := ks.now()
	ks.mu.Lock()
	defer ks.mu.Unlock()
	g, ok := ks.groups[securityGroupID]
	if !ok {
		return nil, fmt.Errorf("pubsub/security: SecurityGroup %q: %w", securityGroupID, ua.StatusBadNotFound)
	}
	if err := ks.advanceLocked(g, now); err != nil {
		return nil, err
	}

	start := g.cur
	if startingTokenID != 0 {
		start = 0 // unknown: the oldest key
		for i, e := range g.entries {
			if e.id == startingTokenID {
				start = i
				break
			}
		}
	}
	count := uint64(requestedKeyCount) + 1
	if requestedKeyCount > g.cfg.MaxFutureKeyCount {
		count = uint64(len(g.entries))
	}
	end := min(uint64(start)+count, uint64(len(g.entries)))
	keys := make([][]byte, 0, end-uint64(start))
	for _, e := range g.entries[start:end] {
		keys = append(keys, slices.Clone(e.key))
	}
	return &SecurityKeys{
		SecurityPolicyURI: g.policy.URI(),
		FirstTokenID:      g.entries[start].id,
		Keys:              keys,
		TimeToNextKey:     max(g.cfg.KeyLifetime-now.Sub(g.curStart), 0),
		KeyLifetime:       g.cfg.KeyLifetime,
	}, nil
}

// CurrentTokenID returns the token id of the current key of a group.
func (ks *KeyService) CurrentTokenID(securityGroupID string) (uint32, error) {
	r, err := ks.GetSecurityKeys(securityGroupID, 0, 0)
	if err != nil {
		return 0, err
	}
	return r.FirstTokenID, nil
}

// KeySource returns a KeySource with the keys of a SecurityGroup of the
// KeyService, for publishers and subscribers in the process of the SKS.
// It follows the rotation of the group; once the group is removed it
// returns ErrNoKeys.
func (ks *KeyService) KeySource(securityGroupID string) (KeySource, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	g, ok := ks.groups[securityGroupID]
	if !ok {
		return nil, fmt.Errorf("pubsub/security: SecurityGroup %q: %w", securityGroupID, ua.StatusBadNotFound)
	}
	return &serviceSource{ks: ks, id: securityGroupID, policy: g.policy}, nil
}

// advanceLocked rotates the keys of a group for every KeyLifetime elapsed
// since the current key became current: the next key becomes current, a
// new key is generated at the end and the past keys are cut to
// MaxPastKeyCount.
func (ks *KeyService) advanceLocked(g *sksGroup, now time.Time) error {
	life := g.cfg.KeyLifetime
	elapsed := now.Sub(g.curStart)
	if elapsed < life {
		return nil
	}
	n := uint64(elapsed / life)
	window := uint64(g.cfg.MaxPastKeyCount) + uint64(g.cfg.MaxFutureKeyCount) + 1
	// Generate the keys first so that a failure leaves the group as it
	// was. If every key the group had is past its use, start afresh at the
	// token id the rotation has reached.
	fresh, next := n, NextTokenID(g.entries[len(g.entries)-1].id)
	if n >= window {
		fresh, next = uint64(g.cfg.MaxFutureKeyCount)+1, advanceTokenID(g.entries[g.cur].id, n)
	}
	keys := make([]sksKey, 0, fresh)
	for range fresh {
		k, err := GenerateKey(g.policy, ks.rand)
		if err != nil {
			return fmt.Errorf("%w: %w", err, ua.StatusBadInternalError)
		}
		keys = append(keys, sksKey{id: next, key: k})
		next = NextTokenID(next)
	}
	// time.Duration(n)*life cannot overflow: it is at most elapsed.
	g.curStart = g.curStart.Add(time.Duration(n) * life)
	if n >= window {
		g.entries, g.cur = keys, 0
		return nil
	}
	g.entries = append(g.entries, keys...)
	g.cur += int(n)
	if drop := g.cur - int(min(uint64(g.cfg.MaxPastKeyCount), math.MaxInt32)); drop > 0 {
		g.entries = append([]sksKey(nil), g.entries[drop:]...)
		g.cur -= drop
	}
	return nil
}

// serviceSource is the KeySource of a group of a KeyService.
type serviceSource struct {
	ks     *KeyService
	id     string
	policy Policy
}

func (s *serviceSource) Policy() Policy { return s.policy }

func (s *serviceSource) CurrentKeys() (*Keys, error) {
	r, err := s.ks.GetSecurityKeys(s.id, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoKeys, err)
	}
	return s.policy.SplitKey(r.FirstTokenID, r.Keys[0])
}

func (s *serviceSource) KeysForToken(tokenID uint32) (*Keys, error) {
	now := s.ks.now()
	s.ks.mu.Lock()
	defer s.ks.mu.Unlock()
	g, ok := s.ks.groups[s.id]
	if !ok || g.policy != s.policy {
		return nil, fmt.Errorf("%w: security group %q removed", ErrNoKeys, s.id)
	}
	if err := s.ks.advanceLocked(g, now); err != nil {
		return nil, err
	}
	for _, e := range g.entries {
		if e.id == tokenID && tokenID != 0 {
			return s.policy.SplitKey(e.id, e.key)
		}
	}
	return nil, fmt.Errorf("%w: token %d of security group %q", ErrNoKeys, tokenID, s.id)
}
