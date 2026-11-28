// SPDX-License-Identifier: MIT

package pubsub

import (
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
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
	cleanup.Register(t, func() { _ = p.Close() })
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
	// Later keys are fresh as they become current, when seen coming.
	src.set(gkey(3, 0xa3), gkey(4, 0xa4))
	_, err = current(p, "g")
	require.NoError(t, err)
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

// TestKeyGateUnseenKeyAfterOpen: once the gate opened, a current key it
// never saw coming is not trusted either: a key that predates the restart
// and was never seen by this process (an SKS restored from a backup) is
// tainted and closes the gate, which opens again only on a key seen as a
// future key after that.
func TestKeyGateUnseenKeyAfterOpen(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(2, 0xb), gkey(3, 0xc)) // B current at the restart: tainted
	_, err := current(p, "g")
	require.Error(t, err)
	src.set(gkey(3, 0xc), gkey(4, 0xd)) // C seen coming: fresh, open
	_, err = current(p, "g")
	require.NoError(t, err)
	// The SKS comes back from a backup: A, used before the restart, never
	// seen here, with its own next key.
	src.set(gkey(1, 0xa), gkey(2, 0xe))
	_, err = current(p, "g")
	require.ErrorIs(t, err, security.ErrNoKeys, "an unseen key is not trusted because the gate was open")
	_, open := p.SecurityGroupGate("g")
	require.False(t, open)
	_, err = p.KeySource("g").KeysForToken(3)
	require.Error(t, err, "a closed gate accepts nothing, not even a fresh key")
	// The continuity is lost: D, a future key of before, is not fresh.
	src.set(gkey(4, 0xd), gkey(5, 0xf))
	_, err = current(p, "g")
	require.Error(t, err, "a future key seen before the continuity was lost proves nothing")
	// F, seen coming after that, is.
	src.set(gkey(5, 0xf), nil)
	k, err := current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(5), k.TokenID)
	// A key proven fresh in this process stays usable when current again.
	src.set(gkey(3, 0xc), nil)
	_, err = current(p, "g")
	require.NoError(t, err)
}

// TestKeyGateMissedRotation: a rotation the gate does not see coming closes
// it until the next one; future keys are looked at maxFutureKeys ahead.
func TestKeyGateMissedRotation(t *testing.T) {
	t.Parallel()
	p, src := gated(t)
	src.set(gkey(1, 1), gkey(2, 2))
	_, _ = current(p, "g")
	src.set(gkey(2, 2), nil)
	_, err := current(p, "g")
	require.NoError(t, err)
	src.set(gkey(3, 3), gkey(4, 4)) // not seen coming
	_, err = current(p, "g")
	require.Error(t, err)
	src.set(gkey(4, 4), nil)
	_, err = current(p, "g")
	require.NoError(t, err)

	// Several future keys: the second one ahead is seen too.
	p, ring := gated(t)
	ring.set(gkey(1, 1), gkey(2, 2))
	ring.mu.Lock()
	ring.past = append(ring.past, gkey(3, 3))
	ring.mu.Unlock()
	_, _ = current(p, "g")
	ring.set(gkey(3, 3), nil)
	_, err = current(p, "g")
	require.NoError(t, err)
}

// TestKeyGateKeySourceReplaced: replacing the KeySource forgets the future
// keys of the old source: a key announced only by the old source and
// current under the new one is not fresh; keys proven fresh stay usable.
func TestKeyGateKeySourceReplaced(t *testing.T) {
	t.Parallel()
	p, old := gated(t)
	old.set(gkey(1, 1), gkey(2, 2))
	_, _ = current(p, "g")
	old.set(gkey(2, 2), gkey(3, 3)) // 2 fresh, 3 announced by old
	_, err := current(p, "g")
	require.NoError(t, err)
	next := &gateSource{}
	next.set(gkey(3, 3), gkey(4, 4))
	p.SetKeySource("g", next)
	_, err = current(p, "g")
	require.Error(t, err, "a future key of the replaced source proves nothing")
	next.set(gkey(4, 4), nil)
	_, err = current(p, "g")
	require.NoError(t, err)
	// A key proven fresh under the old source stays usable under the new.
	other := &gateSource{}
	other.set(gkey(2, 2), nil)
	p.SetKeySource("g", other)
	_, err = current(p, "g")
	require.NoError(t, err)
}

// blockingSource is a KeySource whose KeysForToken blocks, once armed,
// until the test releases it, so that a test can act while the gate
// observes it.
type blockingSource struct {
	*gateSource
	mu       sync.Mutex
	armed    bool
	entered  chan struct{}
	released chan struct{}
}

func newBlockingSource() *blockingSource {
	return &blockingSource{gateSource: &gateSource{}, entered: make(chan struct{}), released: make(chan struct{})}
}

func (s *blockingSource) KeysForToken(id uint32) (*security.Keys, error) {
	s.mu.Lock()
	armed := s.armed
	s.armed = false
	s.mu.Unlock()
	if armed {
		close(s.entered)
		<-s.released
	}
	return s.gateSource.KeysForToken(id)
}

// TestKeyGateReplacedDuringObservation: SetKeySource while the gate is
// observing the old source starts a new generation: the observation
// records nothing (the old source's future key is not trusted under the
// new one), and the KeySource handed out for the old source gives no key
// any more (design §4.10).
func TestKeyGateReplacedDuringObservation(t *testing.T) {
	t.Parallel()
	p, err := New(nil)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = p.Close() })
	old := newBlockingSource()
	p.SetKeySource("g", old)
	p.GateSecurityGroup("g")
	old.set(gkey(1, 1), gkey(2, 2))
	stale := p.KeySource("g")
	old.mu.Lock()
	old.armed = true
	old.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := stale.CurrentKeys()
		done <- err
	}()
	<-old.entered // the observation of old has read its current key
	next := &gateSource{}
	next.set(gkey(2, 2), gkey(3, 3))
	p.SetKeySource("g", next)
	close(old.released)
	require.ErrorIs(t, <-done, security.ErrNoKeys)

	// Key 2 was announced only by the replaced source, and the observation
	// that saw it ran across the replacement: it is not fresh.
	_, err = current(p, "g")
	require.ErrorIs(t, err, security.ErrNoKeys, "a future key recorded across a replacement")
	_, open := p.SecurityGroupGate("g")
	require.False(t, open)
	next.set(gkey(3, 3), nil)
	k, err := current(p, "g")
	require.NoError(t, err, "a key the new source announced opens it")
	require.Equal(t, uint32(3), k.TokenID)

	// A KeySource handed out before the replacement gives no key, also
	// one that is usable under the new source.
	_, err = stale.CurrentKeys()
	require.ErrorIs(t, err, security.ErrNoKeys)
	_, err = stale.KeysForToken(3)
	require.ErrorIs(t, err, security.ErrNoKeys)
}

// rotatingSource, once armed, rotates to a key it never announced right
// after a read of the current key, as a source does that rotates between
// two calls.
type rotatingSource struct {
	*gateSource
	rotate bool
	reads  int
}

func (s *rotatingSource) CurrentKeys() (*security.Keys, error) {
	k, err := s.gateSource.CurrentKeys()
	s.mu.Lock()
	s.reads++
	rotate := s.rotate
	s.rotate = false
	s.mu.Unlock()
	if err == nil && rotate {
		s.set(gkey(k.TokenID+10, byte(k.TokenID+10)), nil)
	}
	return k, err
}

// TestKeyGateRotationBetweenReads: the key CurrentKeys gives is the one
// the gate observed and decided on: a rotation after the observation does
// not make it give a key the gate never looked at (design §4.10).
func TestKeyGateRotationBetweenReads(t *testing.T) {
	t.Parallel()
	p, err := New(nil)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = p.Close() })
	src := &rotatingSource{gateSource: &gateSource{}}
	p.SetKeySource("g", src)
	p.GateSecurityGroup("g")
	// Announce key 2, then make it current: fresh.
	src.set(gkey(1, 1), gkey(2, 2))
	_, _ = current(p, "g") // tainted 1, saw 2
	src.set(gkey(2, 2), gkey(3, 3))
	src.rotate, src.reads = true, 0
	k, err := current(p, "g")
	require.NoError(t, err)
	require.Equal(t, uint32(2), k.TokenID, "the key the gate observed, not the one after the rotation")
	require.Equal(t, 1, src.reads, "one read of the current key")
}
