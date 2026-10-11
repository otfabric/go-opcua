// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Server-side SecurityToken renewal (Part 4 §5.5.2, Part 6 §6.7.4).
//
// A renewal issues a new SecurityToken with its own TokenId and its own
// symmetric keys while the SecureChannelId stays the same. The outgoing token
// is kept for verification until it expires, because the client may still send
// messages secured with it while the OpenSecureChannel round-trip is in
// flight.

// activeInstanceOrNil returns the instance currently used to secure outgoing
// messages, or nil if the channel has not been opened yet.
func (s *SecureChannel) activeInstanceOrNil() *channelInstance {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	return s.activeInstance
}

// isActiveInstance reports whether instance is still the one securing outgoing
// messages.
func (s *SecureChannel) isActiveInstance(instance *channelInstance) bool {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	return s.activeInstance == instance
}

// beginServerRenewal prepares the instance that decodes and answers an
// OpenSecureChannel request arriving on an already open server channel. The
// active instance is left untouched so responses sent concurrently keep using
// its symmetric keys until the renewal completes.
//
// It returns nil when the channel is not open yet (initial Issue request).
func (s *SecureChannel) beginServerRenewal(m *MessageChunk) (*channelInstance, error) {
	active := s.activeInstanceOrNil()
	if active == nil {
		return nil, nil
	}

	// A renewal must stay on the channel, policy and application instance
	// certificate it was opened with.
	if m.SecureChannelID != active.secureChannelID {
		return nil, ua.StatusBadSecureChannelIDInvalid
	}
	if m.SecurityPolicyURI != s.cfg.SecurityPolicyURI {
		return nil, ua.StatusBadSecurityPolicyRejected
	}
	if m.SecurityPolicyURI != ua.SecurityPolicyURINone && !bytes.Equal(m.SenderCertificate, s.cfg.RemoteCertificate) {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	renewing := newChannelInstance(s)
	renewing.secureChannelID = active.secureChannelID
	return renewing, nil
}

// reviseLifetime applies the server's limits to a requested token lifetime
// (milliseconds). The configured lifetime is the maximum the server grants and
// the value used when the client leaves the choice to the server.
func (s *SecureChannel) reviseLifetime(requested uint32) uint32 {
	if s.maxLifetime == 0 {
		s.maxLifetime = s.cfg.Lifetime
	}
	if s.maxLifetime != 0 && (requested == 0 || requested > s.maxLifetime) {
		return s.maxLifetime
	}
	return requested
}

// tokenGrace returns how long after it was issued a SecurityToken is still
// accepted: its lifetime plus the 25% Part 4 §5.5.2.1 allows for messages
// that were secured with it shortly before it was replaced.
func tokenGrace(lifetime time.Duration) time.Duration {
	return lifetime + lifetime/4
}

// removeInstanceNeedsLock drops a retired token from the list of tokens that
// incoming messages are verified against. instancesMu must be held.
func (s *SecureChannel) removeInstanceNeedsLock(instance *channelInstance) {
	instances := s.instances[instance.secureChannelID]
	kept := make([]*channelInstance, 0, len(instances))
	for _, other := range instances {
		if other != instance {
			kept = append(kept, other)
		}
	}
	s.instances[instance.secureChannelID] = kept
}

// scheduleServerTokenExpiry retires a server-issued SecurityToken once its
// lifetime plus the 25% grace period clients are allowed has elapsed. If the
// token is still the active one by then the client never renewed it, so the
// channel is closed.
//
// instancesMu must be held.
func (s *SecureChannel) scheduleServerTokenExpiry(instance *channelInstance) {
	lifetime := instance.revisedLifetime
	if lifetime <= 0 {
		return
	}
	instance.expiry = time.AfterFunc(tokenGrace(lifetime), func() {
		s.instancesMu.Lock()
		s.removeInstanceNeedsLock(instance)
		stillActive := s.activeInstance == instance
		s.instancesMu.Unlock()

		if stillActive {
			s.cfg.Logger.Warn("security token expired without renewal, closing secure channel",
				"channel_id", s.c.ID(), "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID)
			_ = s.c.Close()
		}
	})
}

// installClientToken makes a SecurityToken received from the server the
// active one and arranges for it to be retired.
//
// A token stays in the list of tokens that incoming messages are verified
// against until it has been superseded by a renewal and its lifetime plus
// the grace period has elapsed, whichever comes last:
//
//   - The time is measured on the local monotonic clock from the moment the
//     token was received. The CreatedAt timestamp in the token is the
//     server's wall clock; using it would retire a live token at once (or
//     keep a dead one for years) when the two clocks disagree.
//   - The active token is never removed, however old it is: without it
//     nothing the server sends could be read. A token that outlives its
//     grace period because a renewal failed is retired as soon as a later
//     renewal succeeds.
//
// instancesMu must be held.
func (s *SecureChannel) installClientToken(instance *channelInstance) {
	previous := s.activeInstance

	s.instances[instance.secureChannelID] = append(s.instances[instance.secureChannelID], instance)
	s.activeInstance = instance

	// The token that was just superseded has already outlived its grace
	// period: nothing is waiting to retire it, so do it now.
	if previous != nil && previous != instance && previous.expired {
		s.removeInstanceNeedsLock(previous)
	}

	lifetime := instance.revisedLifetime
	if lifetime <= 0 {
		return
	}
	instance.expiry = time.AfterFunc(tokenGrace(lifetime), func() {
		s.instancesMu.Lock()
		defer s.instancesMu.Unlock()
		instance.expired = true
		if s.activeInstance != instance {
			s.removeInstanceNeedsLock(instance)
		}
	})
}

// ReleaseTokens stops the expiry timers of all SecurityTokens of the channel.
// A client channel does this when it is closed; for a server channel the
// channel broker calls it once the connection is gone. Either way a closed
// channel is not retained until its tokens would have expired.
func (s *SecureChannel) ReleaseTokens() {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	for _, instances := range s.instances {
		for _, instance := range instances {
			if instance.expiry != nil {
				instance.expiry.Stop()
			}
		}
	}
}
