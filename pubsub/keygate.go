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
// restart). A key is fresh when the gate saw it as the next key of its
// source (the key after the current one) and then saw it become current:
// it was not yet current at a moment after the gate was set, so no earlier
// incarnation can have used it, as far as the key source's own view of
// time goes. Every key the gate saw current before the first fresh one is
// tainted and stays refused. Keys are told apart by a fingerprint of their
// material, never by their id.
//
// The gate lives in the runtime, keyed by SecurityGroupId, for the life of
// the runtime: a group recreated under the same SecurityGroup by any
// configuration change is gated as well, and replacing the KeySource
// (SetKeySource) does not lift it. A key source that is unavailable, or
// static (no next key), never yields a fresh key: the group stays gated.

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
	mu   sync.Mutex
	open bool
	// tainted are the keys seen current before the gate opened.
	tainted map[keyFingerprint]bool
	// allowed are the keys seen as the next key, or current after the gate
	// opened, that are not tainted.
	allowed map[keyFingerprint]bool
}

// observe looks at the current and the next key of ks.
func (g *keyGate) observe(ks security.KeySource) {
	cur, err := ks.CurrentKeys()
	if err != nil || cur == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fp := fingerprint(cur)
	switch {
	case g.tainted[fp]:
	case g.open:
		g.allowed[fp] = true
	case g.allowed[fp]:
		g.open = true
	default:
		g.tainted[fp] = true
	}
	if next, err := ks.KeysForToken(security.NextTokenID(cur.TokenID)); err == nil && next != nil {
		if nfp := fingerprint(next); !g.tainted[nfp] && nfp != fp {
			g.allowed[nfp] = true
		}
	}
}

// usable reports whether messages may be secured or accepted with k.
func (g *keyGate) usable(k *security.Keys) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	fp := fingerprint(k)
	return g.open && !g.tainted[fp] && g.allowed[fp]
}

func (g *keyGate) isOpen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

// gatedSource is the KeySource of a gated SecurityGroup.
type gatedSource struct {
	security.KeySource
	g     *keyGate
	group string
}

func (s *gatedSource) CurrentKeys() (*security.Keys, error) {
	s.g.observe(s.KeySource)
	k, err := s.KeySource.CurrentKeys()
	if err != nil {
		return nil, err
	}
	if !s.g.usable(k) {
		return nil, fmt.Errorf("pubsub: SecurityGroup %q waits for a key newer than its restart: %w", s.group, security.ErrNoKeys)
	}
	return k, nil
}

func (s *gatedSource) KeysForToken(tokenID uint32) (*security.Keys, error) {
	s.g.observe(s.KeySource)
	k, err := s.KeySource.KeysForToken(tokenID)
	if err != nil {
		return nil, err
	}
	if !s.g.usable(k) {
		return nil, fmt.Errorf("pubsub: SecurityGroup %q: key %d may predate the restart: %w", s.group, tokenID, security.ErrNoKeys)
	}
	return k, nil
}

// GateSecurityGroup sets the restart gate of a SecurityGroup: from now on
// its writer groups secure messages, and its reader groups accept them,
// only with a key that became current after the gate was set (see the
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
		p.gates[securityGroupID] = &keyGate{tainted: map[keyFingerprint]bool{}, allowed: map[keyFingerprint]bool{}}
	}
}

// SecurityGroupGate reports whether the SecurityGroup has a restart gate
// and whether it is open (a fresh key became current).
func (p *PubSub) SecurityGroupGate(securityGroupID string) (gated, open bool) {
	p.ksMu.RLock()
	g := p.gates[securityGroupID]
	p.ksMu.RUnlock()
	if g == nil {
		return false, false
	}
	if ks := p.rawKeySource(securityGroupID); ks != nil {
		g.observe(ks)
	}
	return true, g.isOpen()
}
