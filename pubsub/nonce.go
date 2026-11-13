// SPDX-License-Identifier: MIT

package pubsub

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// The MessageNonce of the PubSub-Aes128-CTR and PubSub-Aes256-CTR policies
// is four random bytes followed by a UInt32 SequenceNumber "as defined in
// 7.2.3", which the Publisher resets to 1 when the key and SecurityTokenId
// are updated (Part 14 v1.05 §7.2.4.4.3.2 Table 156). A sender keeps one
// counter per token (nonceCounter); a receiver keeps the last sequence
// number it processed per sender and token and ignores a message that is
// not newer (§7.2.3), before the message is delivered or executed
// (nonceTracker).

// nonceCounter is the MessageNonce sequence of a sender: 1, 2, ... under
// one SecurityTokenId, from 1 again under the next.
type nonceCounter struct {
	mu      sync.Mutex
	started bool
	token   uint32
	seq     uint32
}

// next returns the sequence number of the next message secured with the
// keys of tokenID.
func (n *nonceCounter) next(tokenID uint32) uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.started || n.token != tokenID {
		n.started, n.token, n.seq = true, tokenID, 0
	}
	n.seq++
	return n.seq
}

// nonceKind separates the sequences of a sender that come from different
// sources: each is a subsequence of the sender's counter and so increases
// on its own, whatever the order in which the sources send.
type nonceKind uint8

const (
	nonceDataSet nonceKind = iota + 1
	nonceActionRequest
	nonceActionResponse
)

// nonceKey identifies a sequence of MessageNonces at the receiver.
type nonceKey struct {
	kind nonceKind
	// sender is the PublisherId of the NetworkMessage or, for an
	// ActionRequest, the RequestorId of its ActionHeader.
	sender  string
	senderT message.PublisherIDType
	hasWG   bool
	wg      uint16
	// writers are the DataSetWriterIds of a message without
	// WriterGroupId; corr the CorrelationData of an ActionRequest without
	// RequestorId.
	writers string
	corr    string
	token   uint32
	group   string
}

type nonceRecord struct {
	ks   security.KeySource
	last uint32
	// accepted is when the record last took a message, expiry how long
	// it is kept without one (0: as long as the token is held).
	accepted time.Time
	expiry   time.Duration
	// unchecked is set for a sender whose numbers are not a sequence (see
	// accept).
	unchecked bool
}

const (
	// maxNonceRecords bounds the records of a connection; the record that
	// took a message least recently makes room for a new one.
	maxNonceRecords = 4096
	// nonceSweepInterval is how often the records of tokens that left
	// their KeyRing, and expired ones, are dropped. Whether the token of a
	// record is still held is asked once the record had no message for
	// nonceTokenCheck: a token in use is held.
	nonceSweepInterval = time.Second
	nonceTokenCheck    = time.Minute
	// nonceWindow is the §7.2.3 window of a 32 bit sequence number: a
	// number less than 2^30 ahead is newer.
	nonceWindow = 1 << 30
)

// nonceTracker keeps the last MessageNonce sequence number processed per
// sender, group and SecurityTokenId of a connection. It is safe for
// concurrent use; a nil tracker accepts everything.
type nonceTracker struct {
	mu        sync.Mutex
	records   map[nonceKey]*nonceRecord
	lastSweep time.Time
}

func newNonceTracker() *nonceTracker {
	return &nonceTracker{records: map[nonceKey]*nonceRecord{}}
}

// nonceSequence returns the SequenceNumber of the MessageNonce of a
// received message secured with a policy whose nonce has the layout of
// Table 156.
func nonceSequence(h *message.SecurityHeader, ks security.KeySource) (uint32, bool) {
	if h == nil || !h.Signed || ks == nil || len(h.MessageNonce) != security.MessageNonceLength {
		return 0, false
	}
	p := ks.Policy()
	if p == nil || (p.URI() != security.PolicyURIAes128CTR && p.URI() != security.PolicyURIAes256CTR) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(h.MessageNonce[4:]), true
}

// accept checks the sequence number seq of a message verified with the
// keys of ks under key, received at now, and records it if it is newer
// than the last one (Part 14 §7.2.3: newer if less than 2^30 ahead; the
// same and older numbers, less than 2^30 behind, are ignored). A record is
// discarded after expiry without a message it took (expiry 0: never) and
// when its token is no longer in the KeySource.
//
// A number 2^30 or more away from the last one is invalid by §7.2.3. A
// sender that counts its messages under one token does not produce one
// before its 2^30th message, and a copy of an earlier message is older or
// the same: such a number means that the sender's MessageNonces are not a
// sequence (random, as a sender that does not implement Table 156 makes
// them). Its messages are taken and no longer checked under this record,
// instead of ignoring three quarters of them.
func (t *nonceTracker) accept(key nonceKey, ks security.KeySource, seq uint32, expiry time.Duration, now time.Time) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastSweep) >= nonceSweepInterval || now.Before(t.lastSweep) {
		t.sweepLocked(now)
	}
	r := t.records[key]
	if r != nil && r.expiry > 0 && now.Sub(r.accepted) >= r.expiry {
		delete(t.records, key)
		r = nil
	}
	if r != nil {
		switch d := seq - r.last; {
		case r.unchecked:
		case d == 0 || d > 1<<32-nonceWindow:
			return false
		case d >= nonceWindow:
			r.unchecked = true
		}
		r.last, r.accepted, r.expiry, r.ks = seq, now, expiry, ks
		return true
	}
	if len(t.records) >= maxNonceRecords {
		var oldest nonceKey
		var at time.Time
		for k, x := range t.records {
			if at.IsZero() || x.accepted.Before(at) {
				oldest, at = k, x.accepted
			}
		}
		delete(t.records, oldest)
	}
	t.records[key] = &nonceRecord{ks: ks, last: seq, accepted: now, expiry: expiry}
	return true
}

// sweepLocked drops the records whose token left its KeySource (a token
// the keys of which are gone verifies no message any more, and a new
// token starts its sequence at 1) and the expired ones.
func (t *nonceTracker) sweepLocked(now time.Time) {
	t.lastSweep = now
	for k, r := range t.records {
		if r.expiry > 0 && now.Sub(r.accepted) >= r.expiry {
			delete(t.records, k)
			continue
		}
		if now.Sub(r.accepted) < nonceTokenCheck {
			continue
		}
		if keys, err := r.ks.KeysForToken(k.token); err != nil || keys == nil {
			delete(t.records, k)
		}
	}
}

// len returns the number of records.
func (t *nonceTracker) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.records)
}

func publisherKey(id message.PublisherID) (string, message.PublisherIDType) {
	return id.String(), id.Type
}

// freshNonce applies the MessageNonce sequence check to a received secured
// UADP NetworkMessage (a chunk too) verified with the keys of keyGroup. It
// returns false, and counts the message, if the message is to be ignored.
// expiry is how long the record of the sender stays without a message it
// took: two MessageReceiveTimeouts of the readers for DataSetMessages, the
// time after which §7.2.3 discards the sequence records.
func (p *PubSub) freshNonce(c *connection, gen uint64, nm *message.NetworkMessage, keyGroup string, expiry time.Duration, now time.Time) bool {
	if nm == nil || nm.Security == nil || !nm.Security.Signed || keyGroup == "" {
		return true
	}
	ks := p.KeySource(keyGroup)
	seq, ok := nonceSequence(nm.Security, ks)
	if !ok {
		return true
	}
	key := nonceKey{kind: nonceDataSet, token: nm.Security.SecurityTokenID, group: keyGroup}
	if nm.UADPMask&ua.UADPNetworkMessageContentMaskPublisherID != 0 {
		key.sender, key.senderT = publisherKey(nm.PublisherID)
	}
	if nm.UADPMask&ua.UADPNetworkMessageContentMaskGroupHeader != 0 && nm.UADPMask&ua.UADPNetworkMessageContentMaskWriterGroupID != 0 {
		key.hasWG, key.wg = true, nm.GroupHeader.WriterGroupID
	} else {
		var b []byte
		for _, m := range nm.Messages {
			if m != nil {
				b = binary.LittleEndian.AppendUint16(b, m.DataSetWriterID)
			}
		}
		key.writers = string(b)
	}
	request := false
	if a := nm.Action; a != nil {
		expiry = 0
		if a.Type == message.ActionRequest {
			request = true
			key.kind = nonceActionRequest
			key.sender, key.senderT = "", 0
			if r := a.RequestorID; r != nil {
				key.sender, key.senderT = publisherKey(*r)
			} else {
				// Without a RequestorId the requests of several
				// Requestors cannot be told apart by sender.
				key.corr = string(a.CorrelationData)
			}
		} else {
			key.kind = nonceActionResponse
		}
	}
	if c.nonces.accept(key, ks, seq, expiry, now) {
		return true
	}
	p.lock()
	if c.gen == gen {
		c.ctr.NonceSequenceDiscards++
		if request {
			c.ctr.ActionRequestsRejected++
		}
	}
	p.unlock()
	p.log.Debug("pubsub: secured message with an old MessageNonce sequence number ignored", "connection", c.name, "sequence", seq, "token", key.token)
	return false
}
