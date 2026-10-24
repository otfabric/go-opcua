// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// psKeyService returns a KeyService with the given SecurityGroups, all with
// policy and key lifetime.
func psKeyService(t *testing.T, policy string, lifetime time.Duration, groups ...string) *security.KeyService {
	t.Helper()
	ks := security.NewKeyService()
	for _, g := range groups {
		require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{
			SecurityGroupID: g, SecurityPolicyURI: policy, KeyLifetime: lifetime, MaxFutureKeyCount: 2, MaxPastKeyCount: 2,
		}))
	}
	return ks
}

func psKeySource(t *testing.T, ks *security.KeyService, g string) security.KeySource {
	t.Helper()
	src, err := ks.KeySource(g)
	require.NoError(t, err)
	return src
}

// psCounterSource publishes a counter that grows with every sample.
type psCounterSource struct{ n atomic.Int32 }

func (s *psCounterSource) ReadPublishedData(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
	n := s.n.Add(1)
	out := make([]*ua.DataValue, len(vars))
	for i := range vars {
		out[i] = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(n)}
	}
	return out
}

// TestPubSub_MessageSecurity sends Sign and SignAndEncrypt messages with
// the Aes128-CTR and Aes256-CTR policies, with keys from an in-process
// KeyService, and rotates the keys of one SecurityGroup every 100 ms during
// the traffic: every message must be verified (no decode error, no gap
// caused by a key change). A reader that requires SignAndEncrypt does not
// take Sign messages, and one with other keys takes nothing.
func TestPubSub_MessageSecurity(t *testing.T) {
	parallel(t)
	url := psUDPURL(t)
	type combo struct {
		group  string
		mode   ua.MessageSecurityMode
		policy string
	}
	combos := []combo{
		{"sign128", ua.MessageSecurityModeSign, security.PolicyURIAes128CTR},
		{"enc128", ua.MessageSecurityModeSignAndEncrypt, security.PolicyURIAes128CTR},
		{"sign256", ua.MessageSecurityModeSign, security.PolicyURIAes256CTR},
		{"enc256", ua.MessageSecurityModeSignAndEncrypt, security.PolicyURIAes256CTR},
	}
	const rotate = 100 * time.Millisecond
	rotating := psKeyService(t, security.PolicyURIAes256CTR, rotate, "rotating")
	var pubOpts, subOpts []pubsub.Option
	pubConn := pubsub.UDPConnection("pub", url, uint16(9))
	subConn := pubsub.UDPConnection("sub", url, nil)
	var pdss []*ua.PublishedDataSetDataType
	for i, c := range append(combos, combo{"rotating", ua.MessageSecurityModeSignAndEncrypt, security.PolicyURIAes256CTR}) {
		ks := rotating
		if c.group != "rotating" {
			ks = psKeyService(t, c.policy, time.Hour, c.group)
		}
		pubOpts = append(pubOpts, pubsub.WithKeySource(c.group, psKeySource(t, ks, c.group)))
		subOpts = append(subOpts, pubsub.WithKeySource(c.group, psKeySource(t, ks, c.group)))
		pds := pubsub.PublishedDataItems(c.group, pubsub.Var("n", ua.NewStringNodeID(1, c.group), ua.TypeIDInt32))
		pdss = append(pdss, pds)
		gid := uint16(i + 1)
		pubsub.AttachWriterGroups(pubConn, pubsub.Secure(pubsub.WriterGroup(c.group, gid, psInterval, pubsub.DataSetWriter("w", 1, c.group)), c.mode, c.group))
		pubsub.AttachReaderGroups(subConn, pubsub.Secure(pubsub.ReaderGroup(c.group, pubsub.DataSetReader(c.group, uint16(9), gid, 1, pubsub.DataSetMetaDataOf(pds))), c.mode, c.group))
	}
	// A SignAndEncrypt reader of the Sign group, and a reader with keys of
	// another KeyService.
	pubsub.AttachReaderGroups(subConn,
		pubsub.Secure(pubsub.ReaderGroup("downgrade", pubsub.DataSetReader("downgrade", uint16(9), 1, 1, nil)), ua.MessageSecurityModeSignAndEncrypt, "sign128"),
		pubsub.Secure(pubsub.ReaderGroup("otherkeys", pubsub.DataSetReader("otherkeys", uint16(9), 4, 1, nil)), ua.MessageSecurityModeSignAndEncrypt, "other"))
	subOpts = append(subOpts, pubsub.WithKeySource("other", psKeySource(t, psKeyService(t, security.PolicyURIAes256CTR, time.Hour, "enc256"), "enc256")))

	rec := newPSRecorder()
	sub := psRuntime(t, pubsub.NewConfiguration(nil, subConn), append(subOpts, pubsub.WithDataSetHandler(rec.handle))...)
	pub := psRuntime(t, pubsub.NewConfiguration(pdss, pubConn), append(pubOpts, pubsub.WithDataSource(&psCounterSource{}))...)

	first, err := rotating.CurrentTokenID("rotating")
	require.NoError(t, err)
	for _, c := range combos {
		d := rec.waitFor(t, c.group, func(d *pubsub.ReceivedDataSet) bool { return d.Complete })
		v := d.Field("n").Value.Value()
		require.IsType(t, int32(0), v, c.group)
		psWaitState(t, sub, psComponent(t, sub, pubsub.KindDataSetReader, c.group), ua.PubSubStateOperational)
	}
	// Five key changes of the rotating group.
	eventually(t, func() bool {
		cur, err := rotating.CurrentTokenID("rotating")
		return err == nil && cur >= first+5
	}, "the keys rotate")
	n := len(rec.of("rotating"))
	eventually(t, func() bool { return len(rec.of("rotating")) > n+5 }, "the rotating group delivers after the rotations")
	// A message lost to a key change is an encode error of the publisher
	// (the sequence number is taken before the message is secured) or a
	// decode error of the subscriber (checked below). UDP itself may drop a
	// datagram on a loaded host: allow one lone gap of one message, while a
	// key change problem leaves a gap at each of the rotations.
	wg, err := pub.Status(psComponent(t, pub, pubsub.KindWriterGroup, "rotating"))
	require.NoError(t, err)
	require.Zero(t, wg.Counters.EncodeErrors, "the publisher lacked keys at a key change")
	require.Zero(t, wg.Counters.SendErrors)
	sets := rec.of("rotating")
	gaps := 0
	for i := 1; i < len(sets); i++ {
		if d := uint16(sets[i].SequenceNumber) - uint16(sets[i-1].SequenceNumber); d != 1 {
			require.Equal(t, uint16(2), d, "messages were lost at a key change")
			gaps++
		}
	}
	require.LessOrEqual(t, gaps, 1, "messages were lost at a key change")
	require.Empty(t, rec.of("downgrade"), "a SignAndEncrypt reader took Sign messages")
	require.Empty(t, rec.of("otherkeys"), "a reader took messages signed with keys it does not have")
	st, err := sub.Status(psComponent(t, sub, pubsub.KindConnection, "sub"))
	require.NoError(t, err)
	// Every message was verified (with the keys of the reader of its
	// writer); the downgrade and otherkeys readers just do not take them.
	require.Zero(t, st.Counters.DecodeErrors)
	for _, r := range []string{"downgrade", "otherkeys"} {
		s, err := sub.State(psComponent(t, sub, pubsub.KindDataSetReader, r))
		require.NoError(t, err)
		require.Equal(t, ua.PubSubStatePreOperational, s, r)
	}
}

// psSKS starts a server that is the Security Key Service of ks and the
// target of SetSecurityKeys for rings, over a Basic256Sha256
// SignAndEncrypt endpoint with the user "pub" (password "pw"), and runs a
// PubSub runtime with opts.
func psSKS(t *testing.T, ks *security.KeyService, rings *security.KeyRings, opts ...pubsub.Option) (*server.Server, string) {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "pub" && pass == "pw" {
				return nil
			}
			return errors.New("denied")
		}),
		server.WithPubSub(nil, opts...),
	)
	require.NoError(t, err)
	_, err = srv.EnableSecurityKeyService(ks)
	require.NoError(t, err)
	require.NoError(t, srv.EnableSecurityKeyPush(rings))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

func psDialSKS(ctx context.Context, url string) (*opcua.Client, error) {
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
		if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
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

// TestPubSub_SecurityKeyService gets the keys of PubSub groups from a
// Security Key Service over OPC UA: a publisher and a subscriber pull them
// with GetSecurityKeys (pubsub/sks) while they rotate, and an SKS pushes
// them with SetSecurityKeys to the subscriber of a server, which takes no
// message before and every message after the push.
func TestPubSub_SecurityKeyService(t *testing.T) {
	parallel(t)
	// The key sources fetch right after a key change that leaves them one
	// future key, so a fetch has about two key lifetimes before the
	// publisher uses a key the subscriber does not hold. Every fetch dials
	// a new Basic256Sha256 SignAndEncrypt session: with 300 ms keys a fetch
	// slowed down past 600 ms by the race detector on a loaded machine got
	// messages rejected at a key change.
	ks := psKeyService(t, security.PolicyURIAes128CTR, time.Second, "pull")
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{
		SecurityGroupID: "push", SecurityPolicyURI: security.PolicyURIAes256CTR, KeyLifetime: time.Hour, MaxFutureKeyCount: 1,
	}))
	rings := &security.KeyRings{}
	pushRing := security.NewKeyRing("push", security.Aes256CTR())
	rings.Add(pushRing)
	rec := newPSRecorder()
	pushURL := psUDPURL(t)
	pushPDS := pubsub.PublishedDataItems("push", pubsub.Var("n", ua.NewStringNodeID(1, "push"), ua.TypeIDInt32))
	srv, url := psSKS(t, ks, rings, pubsub.WithDataSetHandler(rec.handle), pubsub.WithKeySourceLookup(func(g string) security.KeySource {
		if r, ok := rings.Get(g); ok {
			return r
		}
		return nil
	}))
	_, err := srv.PubSub().AddConnection(pubsub.AttachReaderGroups(pubsub.UDPConnection("push-sub", pushURL, nil),
		pubsub.Secure(pubsub.ReaderGroup("push", pubsub.DataSetReader("push", uint16(5), 1, 1, pubsub.DataSetMetaDataOf(pushPDS))), ua.MessageSecurityModeSignAndEncrypt, "push")))
	require.NoError(t, err)
	psRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pushPDS}, pubsub.AttachWriterGroups(pubsub.UDPConnection("push-pub", pushURL, uint16(5)),
		pubsub.Secure(pubsub.WriterGroup("push", 1, psInterval, pubsub.DataSetWriter("w", 1, "push")), ua.MessageSecurityModeSignAndEncrypt, "push"))),
		pubsub.WithKeySource("push", psKeySource(t, ks, "push")), pubsub.WithDataSource(&psCounterSource{}))

	// Pull: both sides fetch the keys of "pull" from the SKS.
	pull := func() *sks.KeySource {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()
		src, err := sks.NewKeySource(ctx, sks.Config{
			SecurityGroupID: "pull",
			Dial:            func(ctx context.Context) (*opcua.Client, error) { return psDialSKS(ctx, url) },
			MinRetry:        50 * time.Millisecond,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = src.Close() })
		return src
	}
	// The subscriber fetches first: a fetch returns no past keys, so a
	// subscriber that fetched just after a key change would not hold the
	// key the publisher still uses until its own change (sks.KeySource).
	subKeys := pull()
	pubKeys := pull()
	pullURL := psUDPURL(t)
	pullPDS := pubsub.PublishedDataItems("pull", pubsub.Var("n", ua.NewStringNodeID(1, "pull"), ua.TypeIDInt32))
	pullRec := newPSRecorder()
	pullSub := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", pullURL, nil),
		pubsub.Secure(pubsub.ReaderGroup("rg", pubsub.DataSetReader("pull", uint16(6), 1, 1, pubsub.DataSetMetaDataOf(pullPDS))), ua.MessageSecurityModeSignAndEncrypt, "pull"))),
		pubsub.WithKeySource("pull", subKeys), pubsub.WithDataSetHandler(pullRec.handle))
	psRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pullPDS}, pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", pullURL, uint16(6)),
		pubsub.Secure(pubsub.WriterGroup("wg", 1, psInterval, pubsub.DataSetWriter("w", 1, "pull")), ua.MessageSecurityModeSignAndEncrypt, "pull"))),
		pubsub.WithKeySource("pull", pubKeys), pubsub.WithDataSource(&psCounterSource{}))
	first := pubKeys.Ring().CurrentTokenID()
	pullRec.waitFor(t, "pull", func(d *pubsub.ReceivedDataSet) bool { return d.Complete })
	eventually(t, func() bool {
		cur, err := ks.CurrentTokenID("pull")
		return err == nil && cur >= first+3 && pubKeys.Ring().CurrentTokenID() == cur && subKeys.Ring().CurrentTokenID() == cur
	}, "the pulled keys follow three rotations")
	n := len(pullRec.of("pull"))
	eventually(t, func() bool { return len(pullRec.of("pull")) > n+5 }, "data flows with the pulled keys")
	st, err := pullSub.Status(psComponent(t, pullSub, pubsub.KindConnection, "sub"))
	require.NoError(t, err)
	require.Zero(t, st.Counters.DecodeErrors, "a message was rejected at a key change: %v (publisher tokens %v, subscriber tokens %v)",
		st.LastError, pubKeys.Ring().TokenIDs(), subKeys.Ring().TokenIDs())
	require.NoError(t, pubKeys.Err())

	// Push: the server's subscriber has no keys and takes nothing...
	pushSub := srv.PubSub()
	conn := psComponent(t, pushSub, pubsub.KindConnection, "push-sub")
	eventually(t, func() bool {
		st, err := pushSub.Status(conn)
		return err == nil && st.Counters.DecodeErrors > 3
	}, "messages without keys are rejected")
	require.Empty(t, rec.of("push"))
	// ... until the SKS pushes them.
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	c, err := psDialSKS(ctx, url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	require.NoError(t, sks.Push(ctx, ks, c, "push"))
	cur, err := ks.CurrentTokenID("push")
	require.NoError(t, err)
	require.Equal(t, cur, pushRing.CurrentTokenID())
	d := rec.waitFor(t, "push", func(d *pubsub.ReceivedDataSet) bool { return d.Complete })
	require.IsType(t, int32(0), d.Field("n").Value.Value())
	psWaitState(t, pushSub, psComponent(t, pushSub, pubsub.KindDataSetReader, "push"), ua.PubSubStateOperational)
	// Unknown groups are refused.
	err = sks.SetSecurityKeys(ctx, c, "nosuch", &sks.Result{SecurityPolicyURI: security.PolicyURIAes256CTR, FirstTokenID: 1, Keys: [][]byte{make([]byte, 64)}})
	require.ErrorIs(t, err, ua.StatusBadNotFound)
}
