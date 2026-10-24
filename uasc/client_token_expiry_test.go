// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"
	"time"
)

// newExpiryTestChannel returns a client channel on which tokens can be
// installed without a connection.
func newExpiryTestChannel() *SecureChannel {
	return &SecureChannel{
		cfg:       &Config{Logger: testLogger},
		kind:      client,
		instances: make(map[uint32][]*channelInstance),
	}
}

func (s *SecureChannel) testInstall(tokenID uint32, lifetime time.Duration, createdAt time.Time) *channelInstance {
	instance := newChannelInstance(s)
	instance.state = channelActive
	instance.secureChannelID = 77
	instance.securityTokenID = tokenID
	instance.revisedLifetime = lifetime
	instance.createdAt = createdAt

	s.instancesMu.Lock()
	s.installClientToken(instance)
	s.instancesMu.Unlock()
	return instance
}

func (s *SecureChannel) testTokens() []uint32 {
	var ids []uint32
	for _, instance := range s.getInstancesBySecureChannelID(77) {
		ids = append(ids, instance.securityTokenID)
	}
	return ids
}

func (s *SecureChannel) testHas(tokenID uint32) bool {
	for _, id := range s.testTokens() {
		if id == tokenID {
			return true
		}
	}
	return false
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Superseded tokens used to be kept forever: the expiry looked the channel's
// tokens up by token id instead of channel id and so never found any.
func TestClientToken_SupersededTokenIsRetiredAfterItsGracePeriod(t *testing.T) {
	s := newExpiryTestChannel()
	defer s.ReleaseTokens()

	s.testInstall(1, time.Second, time.Now())
	second := s.testInstall(2, time.Hour, time.Now())

	// During the grace period messages secured with the old token are still
	// accepted (it was installed a moment ago; 1.25 s have not passed).
	if !s.testHas(1) || !s.testHas(2) {
		t.Fatalf("tokens right after the renewal: %v, want both", s.testTokens())
	}

	waitUntil(t, "the superseded token to be retired", func() bool { return !s.testHas(1) })
	if got := s.testTokens(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("tokens after the grace period: %v, want only the new one", got)
	}
	if active, err := s.getActiveChannelInstance(); err != nil || active != second {
		t.Fatalf("active token changed: %v %v", active, err)
	}
}

// The active token must never be removed, however old it gets: without it
// nothing the server sends can be read. Once a renewal finally succeeds, the
// overdue token goes immediately.
func TestClientToken_ActiveTokenSurvivesItsLifetime(t *testing.T) {
	s := newExpiryTestChannel()
	defer s.ReleaseTokens()

	first := s.testInstall(1, 40*time.Millisecond, time.Now())

	// well beyond lifetime + 25% (waiting longer can only make this stricter)
	waitUntil(t, "the token to outlive its grace period", func() bool {
		s.instancesMu.Lock()
		defer s.instancesMu.Unlock()
		return first.expired
	})
	if !s.testHas(1) {
		t.Fatal("the active token was removed when its lifetime ran out")
	}
	if active, err := s.getActiveChannelInstance(); err != nil || active != first {
		t.Fatalf("active token: %v %v", active, err)
	}

	s.testInstall(2, time.Hour, time.Now())
	if s.testHas(1) {
		t.Fatal("an overdue token was kept after it was superseded")
	}
	if !s.testHas(2) {
		t.Fatal("the new token is missing")
	}
}

// The lifetime is measured locally from the moment a token is received. The
// server's CreatedAt must not matter: with a clock that is years off, a
// token would otherwise be retired at once or never.
func TestClientToken_ServerCreatedAtIsIgnored(t *testing.T) {
	for name, skew := range map[string]time.Duration{
		"server clock far behind": -10 * 365 * 24 * time.Hour,
		"server clock far ahead":  10 * 365 * 24 * time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			s := newExpiryTestChannel()
			defer s.ReleaseTokens()

			serverNow := time.Now().Add(skew)
			s.testInstall(1, time.Second, serverNow)
			second := s.testInstall(2, time.Hour, serverNow)

			// Not retired early: both tokens are there right after the
			// renewal although, by the server's clock, the first one
			// "expired" ten years ago.
			if !s.testHas(1) || !s.testHas(2) {
				t.Fatalf("tokens right after the renewal: %v, want both", s.testTokens())
			}
			// Not kept forever either: retired after its local grace period
			// although, by the server's clock, it is "valid" for ten years.
			waitUntil(t, "the superseded token to be retired", func() bool { return !s.testHas(1) })

			if active, err := s.getActiveChannelInstance(); err != nil || active != second {
				t.Fatalf("active token: %v %v", active, err)
			}
			if !s.testHas(2) {
				t.Fatal("the active token was removed")
			}
		})
	}
}

// Closing the channel stops the pending expiry timers.
func TestClientToken_ReleaseTokensStopsTimers(t *testing.T) {
	s := newExpiryTestChannel()

	first := s.testInstall(1, time.Hour, time.Now())
	second := s.testInstall(2, time.Hour, time.Now())

	s.ReleaseTokens()

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	for _, instance := range []*channelInstance{first, second} {
		// Stop reports false when the timer is no longer pending.
		if instance.expiry == nil || instance.expiry.Stop() {
			t.Fatalf("the expiry timer of token %d was still pending after ReleaseTokens", instance.securityTokenID)
		}
	}
}
