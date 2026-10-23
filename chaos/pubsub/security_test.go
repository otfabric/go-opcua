// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// forged returns a UADP message that claims to come from writer 1 of writer
// group 1 of publisher 7 with sequence number seq and a counter far ahead of
// the real one. Delivered, it would break the checker's invariants; taken
// into the reader's sequence state, it would block the real messages.
func forged(t *testing.T, seq uint16, opts *uadp.EncodeOptions) []byte {
	t.Helper()
	n := int64(1) << 40
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    pubsub.DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: seq},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 1,
			Type:            message.DataSetMessageKeyFrame,
			Valid:           true,
			UADPMask:        pubsub.DefaultUADPDataSetMessageContentMask,
			SequenceNumber:  uint32(seq),
			Status:          ua.StatusGood,
			Fields: []*message.Field{
				{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(n)}},
				{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("forged")}},
				{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(float64(n) / 4)}},
			},
		}},
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lastSeq returns the last sequence number the checker saw for reader ds0.
func (c *checker) lastSeq() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, st := range c.streams {
		if dsOfReader(k) == "ds0" {
			return st.seq
		}
	}
	return 0
}

// TestChaosSecurityAttacks attacks a secured publisher/subscriber pair:
// tampered messages, replayed messages, messages signed with keys of
// another SKS, with a token id the subscriber does not know, unsecured and
// downgraded messages, all with sequence numbers ahead of the real ones.
// None of them may be delivered or disturb the sequence state of the
// reader; the real messages keep being delivered, and the counters show the
// rejected and discarded messages.
func TestChaosSecurityAttacks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mode   ua.MessageSecurityMode
		policy string
	}{
		{"Sign-Aes256", ua.MessageSecurityModeSign, security.PolicyURIAes256CTR},
		{"SignAndEncrypt-Aes128", ua.MessageSecurityModeSignAndEncrypt, security.PolicyURIAes128CTR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			ks := keyService(t, "sg", tc.policy, time.Hour, 2, 2)
			src := keySource(t, ks, "sg")
			p := newUDPPair(t, seed, pairOpts{writers: 2, mode: tc.mode, pubKeys: src, subKeys: keySource(t, ks, "sg")})
			p.chk.waitGrowth(t, 5, p.readers...)

			// An SKS of the attacker: same group name, same token ids,
			// other keys.
			evil := keySource(t, keyService(t, "sg", tc.policy, time.Hour, 2, 2), "sg")
			// The real key under a token id the subscriber does not know.
			cur, err := ks.GetSecurityKeys("sg", 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			policy, _ := security.PolicyByURI(tc.policy)
			unknown := security.NewKeyRing("sg", policy)
			if err := unknown.SetKeys(tc.policy, 4711, cur.Keys, 0, 0); err != nil {
				t.Fatal(err)
			}

			sub := compID(t, p.sub, pubsub.KindConnection, "sub")
			before := status(t, p.sub, sub).Counters
			rejected, replayed, tampered := 0, 0, 0
			nonce := uint32(1 << 30)
			end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
			for time.Now().Before(end) {
				seq := p.chk.lastSeq() + uint16(10+rng.Intn(1000))
				nonce++
				var b []byte
				switch k := rng.Intn(7); k {
				case 0: // tampered: a real message with a byte changed
					caps := p.relay.captured()
					b = caps[rng.Intn(len(caps))]
					b[rng.Intn(len(b))] ^= byte(1 + rng.Intn(255))
					// A change of the header may make the message
					// one for no reader: filtered, not rejected.
					tampered++
					p.relay.inject(b)
					time.Sleep(time.Millisecond)
					continue
				case 1: // replayed
					caps := p.relay.captured()
					p.relay.inject(caps[rng.Intn(len(caps))])
					replayed++
					time.Sleep(time.Millisecond)
					continue
				case 2: // keys of another SKS
					b = forged(t, seq, &uadp.EncodeOptions{SecurityMode: tc.mode, Keys: evil, NonceSequence: nonce})
				case 3: // unknown token id
					b = forged(t, seq, &uadp.EncodeOptions{SecurityMode: tc.mode, Keys: unknown, NonceSequence: nonce})
				case 4: // unsecured
					b = forged(t, seq, nil)
				case 5: // downgraded (or the right mode for Sign readers: then forged with evil keys)
					mode := ua.MessageSecurityModeSign
					keys := src
					if tc.mode == ua.MessageSecurityModeSign {
						keys = evil
					}
					b = forged(t, seq, &uadp.EncodeOptions{SecurityMode: mode, Keys: keys, NonceSequence: nonce})
				default: // the real keys, but the signature cut off
					b = forged(t, seq, &uadp.EncodeOptions{SecurityMode: tc.mode, Keys: evil, NonceSequence: nonce})
					b = b[:len(b)-1-rng.Intn(31)]
				}
				p.relay.inject(b)
				rejected++
				time.Sleep(time.Millisecond)
			}
			p.chk.waitGrowth(t, 10, p.readers...)
			after := status(t, p.sub, sub).Counters
			t.Logf("rejected %d, tampered %d, replayed %d: decode errors %d, sequence discards %d", rejected, tampered, replayed,
				after.DecodeErrors-before.DecodeErrors, after.SequenceDiscards-before.SequenceDiscards)
			if got := after.DecodeErrors - before.DecodeErrors; got < uint64(rejected) || got > uint64(rejected+tampered) {
				t.Errorf("%d forged and %d tampered messages, %d decode errors", rejected, tampered, got)
			}
			if replayed > 0 && after.SequenceDiscards == before.SequenceDiscards {
				t.Errorf("%d messages replayed, none discarded", replayed)
			}
			p.stopChecking()
			p.chk.sink.Report(t)
		})
	}
}

// TestChaosKeyRotationStorm rotates the keys of the SecurityGroup every 80
// ms while the publisher sends every 10 ms: no message may be lost to the
// rotation. Messages recorded earlier and injected after their key left
// the subscriber's past keys are rejected for their key.
func TestChaosKeyRotationStorm(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	const life = 80 * time.Millisecond
	ks := keyService(t, "sg", security.PolicyURIAes256CTR, life, 2, 3)
	p := newUDPPair(t, seed, pairOpts{writers: 2, mode: ua.MessageSecurityModeSignAndEncrypt, pubKeys: keySource(t, ks, "sg"), subKeys: keySource(t, ks, "sg")})
	p.chk.waitGrowth(t, 5, p.readers...)
	stalls := chaoskit.WatchStalls(t)

	sub := compID(t, p.sub, pubsub.KindConnection, "sub")
	old := p.relay.captured()
	first, err := ks.CurrentTokenID("sg")
	if err != nil {
		t.Fatal(err)
	}
	var injected int
	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for time.Now().Before(end) {
		time.Sleep(time.Duration(20+rng.Intn(80)) * time.Millisecond)
		// Recorded at least 5 key lifetimes ago: past MaxPastKeyCount.
		if cur, _ := ks.CurrentTokenID("sg"); cur-first > 5 && len(old) > 0 {
			p.relay.inject(old[rng.Intn(len(old))])
			injected++
		}
	}
	last, _ := ks.CurrentTokenID("sg")
	p.chk.waitGrowth(t, 10, p.readers...)
	ctr := status(t, p.sub, sub).Counters
	t.Logf("tokens %d..%d, injected %d old messages, subscriber %+v", first, last, injected, ctr)
	if last-first < 10 {
		t.Errorf("only %d key changes", last-first)
	}
	if s := stalls.Max(); s > 2*life {
		t.Logf("the process stalled for %v: messages may outlive their keys, not checking for losses", s)
	} else if ctr.DecodeErrors != uint64(injected) {
		t.Errorf("%d old messages injected, %d decode errors: the rotation lost messages", injected, ctr.DecodeErrors)
	}
	if injected > 0 && ctr.DecodeErrors < uint64(injected) {
		t.Errorf("%d messages with a key past MaxPastKeyCount injected, only %d rejected", injected, ctr.DecodeErrors)
	}
	p.stopChecking()
	p.chk.sink.Report(t)
}

// ---------------------------------------------------------------------------
// Security Key Service over OPC UA
// ---------------------------------------------------------------------------

const (
	sksPolicy = ua.SecurityPolicyURIBasic256Sha256
	sksMode   = ua.MessageSecurityModeSignAndEncrypt
)

// sksServer is an OPC UA server that is the SKS of a KeyService on a fixed
// port, so that it can be stopped and started again.
type sksServer struct {
	t    *testing.T
	ks   *security.KeyService
	port int

	mu  sync.Mutex
	srv *server.Server
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func startSKS(t *testing.T, ks *security.KeyService) *sksServer {
	t.Helper()
	s := &sksServer{t: t, ks: ks, port: freeTCPPort(t)}
	s.start()
	t.Cleanup(s.stop)
	return s
}

func (s *sksServer) url() string { return fmt.Sprintf("opc.tcp://localhost:%d", s.port) }

func (s *sksServer) start() {
	s.t.Helper()
	p, err := testpki.Get()
	if err != nil {
		s.t.Fatal(err)
	}
	var srv *server.Server
	// The port of the previous instance may still be in TIME_WAIT for a
	// moment.
	ok := chaoskit.Eventually(settle, func() bool {
		srv, err = server.New(
			server.EndPoint("localhost", s.port),
			server.Certificate(p.ServerCert),
			server.PrivateKey(p.ServerKey),
			server.EnableSecurity(sksPolicy, sksMode),
			server.EnableAuthMode(ua.UserTokenTypeUserName),
			server.WithUsernameValidator(func(user, pass string) error {
				if user == "pub" && pass == "pw" {
					return nil
				}
				return errors.New("denied")
			}),
		)
		if err != nil {
			return false
		}
		if _, err = srv.EnableSecurityKeyService(s.ks); err != nil {
			return false
		}
		if err = srv.Start(context.Background()); err != nil {
			_ = srv.Close()
			return false
		}
		return true
	})
	if !ok {
		s.t.Fatalf("SKS does not start: %v", err)
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
}

func (s *sksServer) stop() {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// dialSKS connects to the SKS over Basic256Sha256 SignAndEncrypt.
func dialSKS(ctx context.Context, url string) (*opcua.Client, error) {
	p, err := testpki.Get()
	if err != nil {
		return nil, err
	}
	eps, err := opcua.GetEndpoints(ctx, url)
	if err != nil {
		return nil, err
	}
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == sksPolicy && e.SecurityMode == sksMode {
			ep = e
		}
	}
	if ep == nil {
		return nil, errors.New("no SignAndEncrypt endpoint")
	}
	c, err := opcua.NewClient(url, opcua.AutoReconnect(false), opcua.AuthUsername("pub", "pw"), opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
		opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509))
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// pullKeys returns a KeySource that pulls the keys of sg from the SKS, and
// the number of its failed background fetches.
func pullKeys(t *testing.T, s *sksServer, sg string) (*sks.KeySource, *atomic.Int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), settle)
	defer cancel()
	fails := new(atomic.Int64)
	src, err := sks.NewKeySource(ctx, sks.Config{
		SecurityGroupID: sg,
		Dial:            func(ctx context.Context) (*opcua.Client, error) { return dialSKS(ctx, s.url()) },
		MinRetry:        50 * time.Millisecond,
		MaxRetry:        200 * time.Millisecond,
		Timeout:         5 * time.Second,
		OnError:         func(error) { fails.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src, fails
}

// TestChaosSKSOutage pulls the keys of publisher and subscriber from an SKS
// over OPC UA while the keys rotate, and stops the SKS: for less than the
// future keys last (traffic must go on without a decode error), and for
// longer (the key sources go stale; the subscriber must recover once the
// SKS is back). The pulling key sources must report the outage and recover
// on their own.
func TestChaosSKSOutage(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	const life = 500 * time.Millisecond
	ks := keyService(t, "sg", security.PolicyURIAes128CTR, life, 4, 2)
	s := startSKS(t, ks)
	pubSrc, pubFails := pullKeys(t, s, "sg")
	subSrc, subFails := pullKeys(t, s, "sg")
	p := newUDPPair(t, seed, pairOpts{writers: 2, mode: ua.MessageSecurityModeSignAndEncrypt, pubKeys: pubSrc, subKeys: subSrc})
	p.chk.waitGrowth(t, 5, p.readers...)
	sub := compID(t, p.sub, pubsub.KindConnection, "sub")

	inSync := func() bool {
		cur, err := ks.CurrentTokenID("sg")
		return err == nil && pubSrc.Err() == nil && subSrc.Err() == nil &&
			pubSrc.Ring().CurrentTokenID() == cur && subSrc.Ring().CurrentTokenID() == cur
	}
	for round := range 2 {
		// Short outage: the keys the sources hold carry the traffic.
		short := time.Duration(150+rng.Intn(350)) * time.Millisecond
		t.Logf("round %d: SKS down for %v", round, short)
		before := status(t, p.sub, sub).Counters.DecodeErrors
		fails := pubFails.Load() + subFails.Load()
		s.stop()
		time.Sleep(short)
		s.start()
		if !chaoskit.Eventually(settle, inSync) {
			t.Fatalf("key sources did not recover: pub %v sub %v", pubSrc.Err(), subSrc.Err())
		}
		p.chk.waitGrowth(t, 10, p.readers...)
		d := status(t, p.sub, sub).Counters.DecodeErrors - before
		// When neither source had to fetch during the outage, the keys
		// they held carried the traffic: nothing may have been lost.
		if pubFails.Load()+subFails.Load() == fails && d > 0 {
			t.Errorf("round %d: %d decode errors during a short SKS outage", round, d)
		}
		t.Logf("round %d: %d failed fetches, %d decode errors", round, pubFails.Load()+subFails.Load()-fails, d)
	}

	// Long outage: past the future keys. Both sides stay on their last
	// key; once the SKS is back they get the current keys again.
	t.Log("SKS down for 6 key lifetimes")
	s.stop()
	time.Sleep(6 * life)
	if pubSrc.Err() == nil && subSrc.Err() == nil {
		t.Error("the key sources report no error while the SKS is down")
	}
	s.start()
	if !chaoskit.Eventually(settle, inSync) {
		t.Fatalf("key sources did not recover: pub %v sub %v", pubSrc.Err(), subSrc.Err())
	}
	p.chk.waitGrowth(t, 10, p.readers...)
	for _, r := range p.readers {
		waitState(t, p.sub, compID(t, p.sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
	}
	p.stopChecking()
	p.chk.sink.Report(t)
}
