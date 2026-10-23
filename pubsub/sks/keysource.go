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
// NewKeySource and then in the background: right after the SKS changed its
// current key and the source holds at most one future key, so that a key
// is fetched before it is needed whenever the SKS hands out future keys.
// Failed fetches are retried with exponential backoff. Close stops it.
type KeySource struct {
	cfg  Config
	ring *security.KeyRing

	refresh chan struct{}
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once

	mu      sync.Mutex
	lastErr error
}

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
	r, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := security.PolicyByURI(r.SecurityPolicyURI)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: %w", err)
	}
	s.ring = security.NewKeyRing(cfg.SecurityGroupID, policy, security.WithMaxPastKeys(cfg.MaxPastKeys))
	if err := s.install(r); err != nil {
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
	return s.ring.KeysForToken(tokenID)
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

func (s *KeySource) fetch(ctx context.Context) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	c := s.cfg.Client
	if c == nil {
		var err error
		c, err = s.cfg.Dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("pubsub/sks: dial SKS: %w", err)
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
	return GetSecurityKeys(ctx, c, s.cfg.SecurityGroupID, 0, count)
}

func (s *KeySource) install(r *Result) error {
	if err := s.ring.SetKeys(r.SecurityPolicyURI, r.FirstTokenID, r.Keys, r.TimeToNextKey, r.KeyLifetime); err != nil {
		return fmt.Errorf("pubsub/sks: %w", err)
	}
	if s.cfg.OnUpdate != nil {
		s.cfg.OnUpdate(r)
	}
	return nil
}

// nextFetch is the delay until the next fetch: just after the key change
// at which the ring is left with at most one future key, or after the next
// key change if it has none. Zero means no rotation: no scheduled fetch.
func (s *KeySource) nextFetch() time.Duration {
	life := s.ring.KeyLifetime()
	if life <= 0 {
		return 0
	}
	ttnk := s.ring.TimeToNextKey()
	future := s.ring.FutureKeyCount()
	k := max(future-1, 0)
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
		r, err := s.fetch(ctx)
		if err == nil {
			err = s.install(r)
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
