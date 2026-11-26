// SPDX-License-Identifier: MIT

package pubsub

import (
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/security"
)

// gateSource is a KeySource whose current and next key a test sets, as a
// Security Key Service (pull or push), a cache or pre-distributed keys
// deliver them.
type gateSource struct {
	mu        sync.Mutex
	cur, next *security.Keys
	past      []*security.Keys
	err       error
}

func gkey(id uint32, material byte) *security.Keys {
	return &security.Keys{TokenID: id, SigningKey: []byte{material, 1}, EncryptingKey: []byte{material, 2}, KeyNonce: []byte{material, 3}}
}

func (s *gateSource) set(cur, next *security.Keys) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.past = append(s.past, s.cur)
	}
	s.cur, s.next, s.err = cur, next, nil
}

func (s *gateSource) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *gateSource) Policy() security.Policy { return nil }

func (s *gateSource) CurrentKeys() (*security.Keys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.cur == nil {
		return nil, security.ErrNoKeys
	}
	return s.cur, nil
}

func (s *gateSource) KeysForToken(id uint32) (*security.Keys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	for _, k := range append([]*security.Keys{s.cur, s.next}, s.past...) {
		if k != nil && k.TokenID == id {
			return k, nil
		}
	}
	return nil, security.ErrNoKeys
}

// usable tells whether the runtime p gives the current key of group and,
// for each id, the key of that token.
func current(p *PubSub, group string) (*security.Keys, error) {
	ks := p.KeySource(group)
	if ks == nil {
		return nil, errors.New("no key source")
	}
	return ks.CurrentKeys()
}

func gated(t *testing.T) (*PubSub, *gateSource) {
	t.Helper()
	p, err := New(nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	src := &gateSource{}
	p.SetKeySource("g", src)
	p.GateSecurityGroup("g")
	return p, src
}

// TestKeyGateRotation: a gated SecurityGroup uses no key it saw current
// when the gate was set, and opens when a key it saw as the next one
// becomes current (design §4.10).
func TestKeyGateRotation(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(1, 0xa1), gkey(2, 0xa2))
	_, err := current(p, "g")
	require.ErrorIs(t, err, security.ErrNoKeys, "the key current at the restore may predate it")
	g, open := p.SecurityGroupGate("g")
	require.True(t, g)
	require.False(t, open)
	_, err = p.KeySource("g").KeysForToken(1)
	require.ErrorIs(t, err, security.ErrNoKeys, "nothing is accepted under it")

	src.set(gkey(2, 0xa2), gkey(3, 0xa3))
	k, err := current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(2), k.TokenID)
	_, open = p.SecurityGroupGate("g")
	require.True(t, open)
	_, err = p.KeySource("g").KeysForToken(1)
	require.ErrorIs(t, err, security.ErrNoKeys, "the tainted key stays refused")
	k, err = p.KeySource("g").KeysForToken(3)
	require.NoError(t, err)
	require.Equal(t, uint32(3), k.TokenID)
	// Later keys are fresh as they become current.
	src.set(gkey(3, 0xa3), gkey(4, 0xa4))
	src.set(gkey(4, 0xa4), nil)
	k, err = current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(4), k.TokenID)
	// A gate set again is the same gate.
	p.GateSecurityGroup("g")
	_, open = p.SecurityGroupGate("g")
	require.True(t, open)
}

// TestKeyGateWraparound: SecurityTokenIds are not compared: the id after
// MaxUint32 opens the gate as any other.
func TestKeyGateWraparound(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(math.MaxUint32, 1), gkey(security.NextTokenID(math.MaxUint32), 2))
	_, err := current(p, "g")
	require.Error(t, err)
	src.set(gkey(1, 2), gkey(2, 3))
	k, err := current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(1), k.TokenID)
}

// TestKeyGateReissued: an SKS that restarts and issues the same ids again,
// or the same material under a new id, does not open the gate: keys are
// told apart by their material, and only a key seen as the next one is
// fresh.
func TestKeyGateReissued(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(5, 0x05), nil)
	_, err := current(p, "g")
	require.Error(t, err)
	// The SKS restarts: id 5 again with other material, current at once.
	src.set(gkey(5, 0x55), gkey(6, 0x66))
	_, err = current(p, "g")
	require.Error(t, err, "a key seen current first is not fresh, whatever its id")
	// The tainted material under a new id.
	src.set(gkey(7, 0x05), nil)
	_, err = current(p, "g")
	require.Error(t, err)
	// The key seen as the next one becomes current: fresh.
	src.set(gkey(6, 0x66), nil)
	k, err := current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(6), k.TokenID)
	src.set(gkey(5, 0x05), nil)
	_, err = current(p, "g")
	require.Error(t, err, "a tainted key stays refused after the gate opened")
}

// TestKeyGateStaticAndUnavailable: a static key source (no next key) never
// opens the gate; an unavailable one neither, until it delivers a
// rotation.
func TestKeyGateStaticAndUnavailable(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(1, 1), nil)
	for range 3 {
		_, err := current(p, "g")
		require.Error(t, err)
	}
	_, open := p.SecurityGroupGate("g")
	require.False(t, open)

	p, src = gated(t)
	src.fail(errors.New("SKS unavailable"))
	_, err := current(p, "g")
	require.Error(t, err)
	_, err = p.KeySource("g").KeysForToken(1)
	require.Error(t, err)
	src.set(gkey(1, 1), gkey(2, 2))
	_, err = current(p, "g")
	require.Error(t, err)
	src.set(gkey(2, 2), gkey(3, 3))
	_, err = current(p, "g")
	require.NoError(t, err)
}

// TestKeyGateSurvivesKeySource: the gate is the runtime's, by
// SecurityGroupId: a new KeySource (keys pushed again, a group recreated by
// another mechanism) does not lift it; a SecurityGroup without a gate and
// one without keys are reported as such.
func TestKeyGateSurvivesKeySource(t *testing.T) {
	t.Parallel()
	p, _ := gated(t)
	src := &gateSource{}
	src.set(gkey(9, 9), gkey(10, 10))
	p.SetKeySource("g", src)
	_, err := current(p, "g")
	require.Error(t, err, "still gated after SetKeySource")
	src.set(gkey(10, 10), nil)
	_, err = current(p, "g")
	require.NoError(t, err)

	gatedG, open := p.SecurityGroupGate("other")
	require.False(t, gatedG)
	require.False(t, open)
	p.GateSecurityGroup("nokeys")
	gatedG, open = p.SecurityGroupGate("nokeys")
	require.True(t, gatedG)
	require.False(t, open)
	require.Nil(t, p.KeySource("nokeys"))
	// Not gated: the source as it is.
	p.SetKeySource("free", src)
	k, err := p.KeySource("free").CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, uint32(10), k.TokenID)
}
