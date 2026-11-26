// SPDX-License-Identifier: MIT

package pubsub

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua/pubsub/security"
)

// The restart gate of a SecurityGroup (OPC 10000-81 persistent
// connections, docs/design/uafx-persistent-connections.md §4.10). A
// process that restores secured writer and reader groups after a restart
// has lost the MessageNonce sequence numbers it sent and the last sequence
// numbers it received (Part 14 §7.2.3, §7.2.4.4.3): publishing again under
// a key that was in use before the restart may repeat a MessageNonce under
// that key, and receiving under it accepts again what was received before.
// A gated SecurityGroup neither publishes nor accepts messages under such a
// key.
//
// Freshness is not a SecurityTokenId comparison (ids wrap around and an SKS
// that restarts may issue them again) and not new key material alone (a
// key the process has not seen may still be one it used before the
// restart). A key is fresh only when the gate saw it as a future key of its
// source (after the current one, Part 14 §8.3.2 GetSecurityKeys) and then
// saw it become current: it was not yet current at a moment after the gate
// was set. This holds for every key, also after the gate opened: a current
// key the gate never saw coming (keys rolled back from a backup, an SKS
// that lost its state, a rotation the gate missed) is tainted and closes
// the gate, and the future keys seen before it are no longer trusted,
// since the source's continuity is lost. The gate opens again when a
// future key seen after that becomes current. Replacing the KeySource
// (SetKeySource) also ends that continuity: the future keys of the old
// source are forgotten, keys already proven fresh stay usable. Each
// replacement starts a new generation of the gate: an observation of the
// old source that is still running when it is replaced records nothing,
// and a KeySource handed out for the old source gives no keys any more.
// A decision is about the key it read: the current key the gate observed
// is the one CurrentKeys returns, never a second read of the source. Keys
// are told apart by a fingerprint of their material, never by their id.
//
// Library interpretation (labelled in docs/uafx.md#persistence): the gate
// relies on the key source never offering as a future key a key that was
// current before. A source that does (an SKS restored from a backup whose
// future keys were used before the restart, and never seen current by this
// process) cannot be told apart from a genuine one without durable
// evidence of key use, which the gate does not keep: it is not protection
// against an arbitrary SKS rollback.
//
// The gate lives in the runtime, keyed by SecurityGroupId, for the life of
// the runtime: a group recreated under the same SecurityGroup by any
// configuration change is gated as well, and replacing the KeySource does
// not lift it. A key source that is unavailable, or static (no future
// key), never yields a fresh key: the group stays gated. A rotation the
// gate does not see coming (no call of the group between the moment the
// key became known as a future key and the moment it became current; the
// gate looks maxFutureKeys keys ahead) closes it until the next one.

// maxFutureKeys is how many future keys the gate looks at each time.
const maxFutureKeys = 8

// keyFingerprint identifies the material of a key.
type keyFingerprint [sha256.Size]byte

func fingerprint(k *security.Keys) keyFingerprint {
	h := sha256.New()
	for _, b := range [][]byte{k.SigningKey, k.EncryptingKey, k.KeyNonce} {
		_, _ = fmt.Fprintf(h, "%d:", len(b)) // a hash.Hash never fails a write
		_, _ = h.Write(b)
	}
	var f keyFingerprint
	copy(f[:], h.Sum(nil))
	return f
}

// keyGate is the restart gate of one SecurityGroup.
type keyGate struct {
	mu sync.Mutex
	// open: the current key, when last seen, was fresh.
	open bool
	// tainted are keys seen current before they were seen as future keys.
	tainted map[keyFingerprint]bool
	// fresh are keys seen as future keys and then current.
	fresh map[keyFingerprint]bool
	// future are keys seen as future keys since the source's continuity
	// was last lost, not yet current.
	future map[keyFingerprint]bool
	// gen counts the replacements of the KeySource (rebase).
	gen uint64
}

func newKeyGate() *keyGate {
	return &keyGate{tainted: map[keyFingerprint]bool{}, fresh: map[keyFingerprint]bool{}, future: map[keyFingerprint]bool{}}
}

// observe looks at the current and the future keys of ks, the source of
// the generation gen, and returns the current key it looked at. An
// observation of a generation that ended records nothing.
func (g *keyGate) observe(ks security.KeySource, gen uint64) (*security.Keys, error) {
	cur, err := ks.CurrentKeys()
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, security.ErrNoKeys
	}
	var ahead []keyFingerprint
	id := cur.TokenID
	for range maxFutureKeys {
		id = security.NextTokenID(id)
		k, err := ks.KeysForToken(id)
		if err != nil || k == nil {
			break
		}
		ahead = append(ahead, fingerprint(k))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen != g.gen {
		return cur, nil
	}
	fp := fingerprint(cur)
	switch {
	case g.tainted[fp]:
		g.open = false
	case g.fresh[fp]:
		g.open = true
	case g.future[fp]:
		delete(g.future, fp)
		g.fresh[fp], g.open = true, true
	default:
		// Not seen coming: tainted, and the source's continuity is lost.
		g.tainted[fp], g.open = true, false
		clear(g.future)
	}
	for _, f := range ahead {
		if f != fp && !g.tainted[f] && !g.fresh[f] {
			g.future[f] = true
		}
	}
	return cur, nil
}

// rebase forgets the future keys and starts a new generation: the
// KeySource was replaced.
func (g *keyGate) rebase() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gen++
	clear(g.future)
}

// generation returns the generation of the gate.
func (g *keyGate) generation() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen
}

// usable reports whether messages may be secured or accepted with k, a
// key of the source of the generation gen: the generation is current, the
// gate is open and k is fresh or a future key seen since the source's
// continuity was last lost.
func (g *keyGate) usable(k *security.Keys, gen uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	fp := fingerprint(k)
	return gen == g.gen && g.open && !g.tainted[fp] && (g.fresh[fp] || g.future[fp])
}

func (g *keyGate) isOpen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

// gatedSource is the KeySource of a gated SecurityGroup: the source of the
// generation gen of its gate.
type gatedSource struct {
	security.KeySource
	g     *keyGate
	gen   uint64
	group string
}

func (s *gatedSource) CurrentKeys() (*security.Keys, error) {
	k, err := s.g.observe(s.KeySource, s.gen)
	if err != nil {
		return nil, err
	}
	if !s.g.usable(k, s.gen) {
		return nil, fmt.Errorf("pubsub: SecurityGroup %q waits for a key newer than its restart: %w", s.group, security.ErrNoKeys)
	}
	return k, nil
}

func (s *gatedSource) KeysForToken(tokenID uint32) (*security.Keys, error) {
	_, _ = s.g.observe(s.KeySource, s.gen) // a failure leaves the gate as it was
	k, err := s.KeySource.KeysForToken(tokenID)
	if err != nil {
		return nil, err
	}
	if k == nil || !s.g.usable(k, s.gen) {
		return nil, fmt.Errorf("pubsub: SecurityGroup %q: key %d may predate the restart: %w", s.group, tokenID, security.ErrNoKeys)
	}
	return k, nil
}

// GateSecurityGroup sets the restart gate of a SecurityGroup: from now on
// its writer groups secure messages, and its reader groups accept them,
// only with a key it saw coming before it became current (see the
// package documentation of the gate in keygate.go). An application that
// restores secured groups after a restart, as the persistent
// ConnectionEndpoints of OPC UA FX do, sets it before it enables them. The
// gate stays for the life of the runtime; setting it again does nothing.
func (p *PubSub) GateSecurityGroup(securityGroupID string) {
	p.ksMu.Lock()
	defer p.ksMu.Unlock()
	if p.gates == nil {
		p.gates = map[string]*keyGate{}
	}
	if p.gates[securityGroupID] == nil {
		p.gates[securityGroupID] = newKeyGate()
	}
}

// SecurityGroupGate reports whether the SecurityGroup has a restart gate
// and whether it is open (a fresh key became current).
func (p *PubSub) SecurityGroupGate(securityGroupID string) (gated, open bool) {
	ks, g, gen := p.sourceOf(securityGroupID)
	if g == nil {
		return false, false
	}
	if ks != nil {
		_, _ = g.observe(ks, gen) // a failure leaves the gate as it was
	}
	return true, g.isOpen()
}
