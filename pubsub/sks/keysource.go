// SPDX-License-Identifier: MIT

package sks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/pubsub/security"
)

// Defaults of Config.
const (
	DefaultMinRetry = time.Second
	DefaultMaxRetry = 30 * time.Second
	DefaultTimeout  = 30 * time.Second
)

// Config configures a KeySource.
type Config struct {
	// SecurityGroupID is the SecurityGroup whose keys are pulled.
	SecurityGroupID string

	// Client is a session with the SKS, managed by the caller. It must use
	// SignAndEncrypt. Either Client or Dial must be set.
	Client *opcua.Client
	// Dial opens a session with the SKS for one GetSecurityKeys call; the
	// KeySource closes it afterwards, as open62541 does.
	Dial func(ctx context.Context) (*opcua.Client, error)

	// RequestedKeyCount is the number of future keys asked for; 0 asks for
	// as many as the SKS gives (open62541 asks for 0xFFFFFFFF). Use
	// NoFutureKeys to ask for the current key only.
	RequestedKeyCount uint32
	// NoFutureKeys asks for the current key only.
	NoFutureKeys bool

	// MinRetry and MaxRetry bound the exponential backoff after a failed
	// fetch (defaults DefaultMinRetry, DefaultMaxRetry).
	MinRetry, MaxRetry time.Duration
	// Timeout bounds one fetch (default DefaultTimeout).
	Timeout time.Duration
	// MaxPastKeys is the number of past keys kept for in-flight messages
	// (default security.DefaultMaxPastKeys; negative: none).
	MaxPastKeys int
	// OnError, if set, is called with the error of every failed fetch of
	// the background refresh.
	OnError func(error)
	// OnUpdate, if set, is called after every successful fetch.
	OnUpdate func(*Result)
}

// KeySource is a security.KeySource for one SecurityGroup that pulls the
// keys from an SKS with GetSecurityKeys. It fetches the keys once in
// NewKeySource and then in the background: right after the key change that
// leaves the source with at most one future key, so that whenever the SKS
// hands out future keys a fetch has two key lifetimes to complete before
// the source runs out of keys. A received message with a token just ahead
// of the current one that the source does not hold (the peer fetched
// first) triggers a fetch too, at most once per MinRetry. Failed fetches
// are retried with exponential backoff. Close stops it.
//
// A fetch returns the current key and the future keys, not the past ones:
// a subscriber whose first fetch comes just after a key change does not
// hold the previous key, and rejects the messages that a publisher which
// has not changed keys yet still secures with it (at most the publisher's
// response delay). Where a publisher and a subscriber start together,
// create the subscriber's KeySource first.
type KeySource struct {
	cfg  Config
	ring *security.KeyRing

	refresh chan struct{}
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once

	mu          sync.Mutex
	lastErr     error
	lastMissRef time.Time // last Refresh triggered by an unknown token
}

// missWindow is how far ahead of the current token an unknown token may be
// to trigger a fetch: a peer that fetched first is a few keys ahead at
// most, anything further is not worth asking the SKS about.
const missWindow = 8

var _ security.KeySource = (*KeySource)(nil)

// NewKeySource fetches the keys of cfg.SecurityGroupID from the SKS and
// starts refreshing them in the background. It fails if the first fetch
// fails.
func NewKeySource(ctx context.Context, cfg Config) (*KeySource, error) {
	if cfg.Client == nil && cfg.Dial == nil {
		return nil, errors.New("pubsub/sks: KeySource needs a Client or Dial")
	}
	if cfg.MinRetry <= 0 {
		cfg.MinRetry = DefaultMinRetry
	}
	if cfg.MaxRetry < cfg.MinRetry {
		cfg.MaxRetry = max(DefaultMaxRetry, cfg.MinRetry)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxPastKeys == 0 {
		cfg.MaxPastKeys = security.DefaultMaxPastKeys
	}
	s := &KeySource{
		cfg:     cfg,
		refresh: make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	r, received, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := security.PolicyByURI(r.SecurityPolicyURI)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: %w", err)
	}
	s.ring = security.NewKeyRing(cfg.SecurityGroupID, policy, security.WithMaxPastKeys(cfg.MaxPastKeys))
	if err := s.install(r, received); err != nil {
		return nil, err
	}
	go s.run()
	return s, nil
}

// Policy is the security policy of the SecurityGroup.
func (s *KeySource) Policy() security.Policy { return s.ring.Policy() }

// CurrentKeys returns the keys to secure outgoing messages with.
func (s *KeySource) CurrentKeys() (*security.Keys, error) { return s.ring.CurrentKeys() }

// KeysForToken returns the keys of a received message's token.
func (s *KeySource) KeysForToken(tokenID uint32) (*security.Keys, error) {
	k, err := s.ring.KeysForToken(tokenID)
	if errors.Is(err, security.ErrNoKeys) && s.ahead(tokenID) {
		s.mu.Lock()
		now := time.Now()
		due := now.Sub(s.lastMissRef) >= s.cfg.MinRetry
		if due {
			s.lastMissRef = now
		}
		s.mu.Unlock()
		if due {
			s.Refresh()
		}
	}
	return k, err
}

// ahead reports whether tokenID is one of the missWindow tokens after the
// current one (token ids wrap around from 0xFFFFFFFF to 1).
func (s *KeySource) ahead(tokenID uint32) bool {
	cur := s.ring.CurrentTokenID()
	if cur == 0 || tokenID == 0 {
		return false
	}
	for range missWindow {
		cur = security.NextTokenID(cur)
		if cur == tokenID {
			return true
		}
	}
	return false
}

// Ring is the KeyRing the keys are kept in.
func (s *KeySource) Ring() *security.KeyRing { return s.ring }

// Err is the error of the last fetch, nil if it succeeded.
func (s *KeySource) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Refresh asks the background loop to fetch the keys now.
func (s *KeySource) Refresh() {
	select {
	case s.refresh <- struct{}{}:
	default:
	}
}

// Close stops the background refresh and waits for it to end. The keys
// held stay usable.
func (s *KeySource) Close() error {
	s.once.Do(func() { close(s.stop) })
	<-s.done
	return nil
}

// fetch gets the keys and returns when the response arrived: closing a
// session dialed for the fetch comes after that and must not delay the
// key changes.
func (s *KeySource) fetch(ctx context.Context) (*Result, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	c := s.cfg.Client
	if c == nil {
		var err error
		c, err = s.cfg.Dial(ctx)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("pubsub/sks: dial SKS: %w", err)
		}
		defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	}
	count := s.cfg.RequestedKeyCount
	switch {
	case s.cfg.NoFutureKeys:
		count = 0
	case count == 0:
		count = math.MaxUint32
	}
	r, err := GetSecurityKeys(ctx, c, s.cfg.SecurityGroupID, 0, count)
	return r, time.Now(), err
}

// install sets the keys of r, received at received. TimeToNextKey counts
// from the SKS's response, so the time since then is taken off: a ring
// that changed keys later than the SKS would have a publisher secure
// messages with a key its subscribers may already have given up.
func (s *KeySource) install(r *Result, received time.Time) error {
	ttnk := r.TimeToNextKey
	if ttnk > 0 {
		// At least 1 ns: SetKeys reads 0 as a whole key lifetime.
		ttnk = max(ttnk-time.Since(received), time.Nanosecond)
	}
	if err := s.ring.SetKeys(r.SecurityPolicyURI, r.FirstTokenID, r.Keys, ttnk, r.KeyLifetime); err != nil {
		return fmt.Errorf("pubsub/sks: %w", err)
	}
	if s.cfg.OnUpdate != nil {
		s.cfg.OnUpdate(r)
	}
	return nil
}

// nextFetch is the delay until the next fetch: just after the first key
// change that leaves the ring with at most one future key (with F future
// keys now that is change max(F-1, 1)), so that the fetch has a key
// lifetime to spare before the ring has none left. Zero means no rotation:
// no scheduled fetch.
func (s *KeySource) nextFetch() time.Duration {
	life := s.ring.KeyLifetime()
	if life <= 0 {
		return 0
	}
	// TimeToNextKey before FutureKeyCount: a key change between the two
	// reads makes the fetch early, never late.
	ttnk := s.ring.TimeToNextKey()
	future := s.ring.FutureKeyCount()
	k := max(future-2, 0) // key changes after the next one
	guard := min(max(life/20, time.Millisecond), 2*time.Second)
	return ttnk + time.Duration(k)*life + guard
}

func (s *KeySource) run() {
	defer close(s.done)
	retry := time.Duration(0)
	for {
		var (
			wait  <-chan time.Time
			timer *time.Timer
		)
		delay := s.nextFetch()
		if retry > 0 {
			delay = retry
		}
		if delay > 0 {
			timer = time.NewTimer(delay)
			wait = timer.C
		}
		select {
		case <-s.stop:
		case <-s.refresh:
		case <-wait:
		}
		if timer != nil {
			timer.Stop()
		}
		select {
		case <-s.stop:
			return
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-s.stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		r, received, err := s.fetch(ctx)
		if err == nil {
			err = s.install(r, received)
		}
		cancel()
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		if err != nil {
			if s.cfg.OnError != nil {
				s.cfg.OnError(err)
			}
			retry = min(max(retry*2, s.cfg.MinRetry), s.cfg.MaxRetry)
			continue
		}
		retry = 0
	}
}
