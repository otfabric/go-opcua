// SPDX-License-Identifier: MIT

package sks

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// pullEndpoint is an element of SecurityKeyServices for the SKS at url,
// as Part 14 §6.2.5.4 Table 40 has it.
func pullEndpoint(url string) *ua.EndpointDescription {
	return &ua.EndpointDescription{
		Server: &ua.ApplicationDescription{
			ApplicationURI: testpki.ServerAppURI, ApplicationType: ua.ApplicationTypeServer, DiscoveryURLs: []string{url},
		},
		SecurityMode:      encrypt,
		SecurityPolicyURI: policy256,
	}
}

// testDialer is the EndpointDialer of the user "pub".
func testDialer(t *testing.T) *EndpointDialer {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return &EndpointDialer{
		Options: []opcua.Option{
			opcua.AutoReconnect(false), opcua.AuthUsername("pub", "pw"),
			opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509),
		},
		Certificate: p.ClientCert,
		AuthType:    ua.UserTokenTypeUserName,
	}
}

func TestEndpointDialer(t *testing.T) {
	ks := newKeyService(t, time.Hour, 1)
	s := startSKS(t, ks)
	d := testDialer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := d.Dial(ctx, pullEndpoint(s.url))
	require.NoError(t, err)
	_, err = GetSecurityKeys(ctx, c, "sg", 0, 0)
	require.NoError(t, err)
	require.NoError(t, c.Close(ctx))

	// An EndpointUrl without DiscoveryUrls (a tolerance), and a first URL
	// that fails before one that answers.
	ep := pullEndpoint(s.url)
	ep.Server.DiscoveryURLs, ep.EndpointURL = nil, s.url
	c, err = d.Dial(ctx, ep)
	require.NoError(t, err)
	require.NoError(t, c.Close(ctx))
	ep = pullEndpoint(s.url)
	ep.Server.DiscoveryURLs = []string{"opc.tcp://127.0.0.1:1", s.url}
	c, err = d.Dial(ctx, ep)
	require.NoError(t, err)
	require.NoError(t, c.Close(ctx))

	for name, ep := range map[string]*ua.EndpointDescription{
		"nil":       nil,
		"no Server": {SecurityMode: encrypt},
		"push":      {Server: &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, DiscoveryURLs: []string{s.url}}},
		"no URL":    {Server: &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeServer}},
	} {
		_, err := d.Dial(ctx, ep)
		assert.ErrorIs(t, err, ErrEndpoint, name)
	}
	ep = pullEndpoint(s.url)
	ep.Server.ApplicationURI = "urn:other"
	_, err = d.Dial(ctx, ep)
	assert.ErrorIs(t, err, ua.StatusBadServerURIInvalid)
	ep = pullEndpoint(s.url)
	ep.SecurityPolicyURI = ua.SecurityPolicyURIAes256Sha256RsaPss
	_, err = d.Dial(ctx, ep)
	assert.Error(t, err, "no endpoint of the policy")
	_, err = d.Dial(ctx, pullEndpoint("opc.tcp://127.0.0.1:1"))
	assert.Error(t, err)
	_, err = (&EndpointDialer{Options: []opcua.Option{opcua.SecurityPolicy("nope")}}).Dial(ctx, pullEndpoint(s.url))
	assert.Error(t, err, "a client that cannot be made")
	// An option the discovery takes that the session client does not.
	applied := 0
	second := opcua.Option(func(*opcua.Config) error {
		if applied++; applied > 1 {
			return errors.New("refused")
		}
		return nil
	})
	d2 := testDialer(t)
	d2.Options = append(d2.Options, second)
	_, err = d2.Dial(ctx, pullEndpoint(s.url))
	assert.ErrorContains(t, err, "refused")
	bad := &EndpointDialer{Options: []opcua.Option{opcua.AutoReconnect(false), opcua.AuthUsername("pub", "wrong")}, AuthType: ua.UserTokenTypeUserName}
	_, err = bad.Dial(ctx, pullEndpoint(s.url))
	assert.Error(t, err, "a session the SKS refuses")
}

// securedConfig is a runtime configuration with a WriterGroup and a
// ReaderGroup of the SecurityGroup "sg" that pull from eps, and a
// DataSetReader of "rd" that takes the SecurityKeyServices of its group.
func securedConfig(eps ...*ua.EndpointDescription) *ua.PubSubConfigurationDataType {
	wg := pubsub.WriterGroup("WG", 1, time.Hour)
	wg.SecurityMode, wg.SecurityGroupID, wg.SecurityKeyServices = encrypt, "sg", eps
	r := pubsub.DataSetReader("R", nil, 0, 0, pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble}))
	r.SecurityMode, r.SecurityGroupID = ua.MessageSecurityModeSign, "rd"
	rg := pubsub.ReaderGroup("RG", r)
	rg.SecurityMode, rg.SecurityGroupID, rg.SecurityKeyServices = encrypt, "sg", eps
	plain := pubsub.WriterGroup("Plain", 2, time.Hour)
	plain.SecurityGroupID, plain.SecurityKeyServices = "none", eps
	return pubsub.NewConfiguration(nil,
		pubsub.AttachReaderGroups(pubsub.AttachWriterGroups(pubsub.UDPConnection("C", "opc.udp://127.0.0.1:4840", uint16(1)), wg, plain), rg))
}

func TestPullGroups(t *testing.T) {
	ep := pullEndpoint("opc.tcp://a")
	push := &ua.EndpointDescription{Server: &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient}}
	got := pullGroups(securedConfig(ep, push, nil, &ua.EndpointDescription{}, pullEndpoint("opc.tcp://a")))
	assert.Equal(t, map[string][]*ua.EndpointDescription{"sg": {ep}, "rd": {ep}}, got, "pull endpoints only, once, of secured components")
	assert.Empty(t, pullGroups(nil))
	cfg := securedConfig(ep)
	cfg.Connections = append(cfg.Connections, nil, &ua.PubSubConnectionDataType{
		WriterGroups: []*ua.WriterGroupDataType{nil}, ReaderGroups: []*ua.ReaderGroupDataType{nil, {DataSetReaders: []*ua.DataSetReaderDataType{nil}}},
	})
	assert.Len(t, pullGroups(cfg), 2)
}

// TestPuller: a Puller supplies the keys of the secured groups from the SKS
// their SecurityKeyServices name, leaves a group with keys of another
// source alone, retries a first fetch that fails and drops the keys of a
// group that is gone.
func TestPuller(t *testing.T) {
	ks := newKeyService(t, time.Hour, 1)
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: "rd", SecurityPolicyURI: security.PolicyURIAes128CTR, KeyLifetime: time.Hour}))
	s := startSKS(t, ks)
	static := security.NewKeyRing("static", security.Aes128CTR())
	cfg := securedConfig(pullEndpoint("opc.tcp://127.0.0.1:1"), pullEndpoint(s.url))
	wg := pubsub.WriterGroup("Static", 3, time.Hour)
	wg.SecurityMode, wg.SecurityGroupID, wg.SecurityKeyServices = encrypt, "static", []*ua.EndpointDescription{pullEndpoint(s.url)}
	cfg.Connections[0].WriterGroups = append(cfg.Connections[0].WriterGroups, wg)
	rt, err := pubsub.New(cfg, pubsub.WithKeySource("static", static))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = rt.Close() })

	_, err = NewPuller(nil, PullerOptions{Dial: testDialer(t).Dial})
	require.Error(t, err)
	_, err = NewPuller(rt, PullerOptions{})
	require.Error(t, err)

	var mu sync.Mutex
	failures := map[string]int{}
	p, err := NewPuller(rt, PullerOptions{
		Dial: testDialer(t).Dial, Interval: 10 * time.Millisecond,
		Source: Config{MinRetry: 10 * time.Millisecond, MaxRetry: 20 * time.Millisecond},
		OnError: func(g string, _ error) {
			mu.Lock()
			failures[g]++
			mu.Unlock()
		},
	})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = p.Close() })
	require.Eventually(t, func() bool { return len(p.SecurityGroups()) == 2 }, 20*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"rd", "sg"}, p.SecurityGroups(), "the static group is not the Puller's")
	want, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	got, err := rt.KeySource("sg").CurrentKeys()
	require.NoError(t, err)
	assert.Equal(t, want.Keys[0], append(append(append([]byte{}, got.SigningKey...), got.EncryptingKey...), got.KeyNonce...), "the keys of the SKS")
	assert.Same(t, static, rt.KeySource("static"))

	// A group whose SKS refuses: retried with backoff, reported.
	bad := pubsub.WriterGroup("Unknown", 4, time.Hour)
	bad.SecurityMode, bad.SecurityGroupID, bad.SecurityKeyServices = encrypt, "unknown", []*ua.EndpointDescription{pullEndpoint(s.url)}
	conn := rt.Components()
	var connID pubsub.ComponentID
	for _, c := range conn {
		if c.Kind == pubsub.KindConnection {
			connID = c.ID
		}
	}
	gid, err := rt.AddWriterGroup(connID, bad)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return failures["unknown"] >= 2
	}, 20*time.Second, 10*time.Millisecond)
	// Gone while it is retried, and the group "sg" gone: dropped.
	require.NoError(t, rt.RemoveWriterGroup(gid))
	for _, c := range rt.Components() {
		if c.Kind == pubsub.KindWriterGroup || c.Kind == pubsub.KindReaderGroup {
			if c.Name == "WG" || c.Name == "RG" {
				require.NoError(t, rt.RemoveGroup(c.ID))
			}
		}
	}
	p.Sync()
	assert.Empty(t, p.SecurityGroups())
	assert.Nil(t, rt.KeySource("sg"))
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
	p.Sync() // after Close: nothing
}

// TestPullerClose: Close cancels a fetch in progress and removes the keys
// it set; a fetch that completes after its group went is not installed.
func TestPullerClose(t *testing.T) {
	ks := newKeyService(t, time.Hour, 1)
	s := startSKS(t, ks)
	rt, err := pubsub.New(securedConfig(pullEndpoint(s.url)))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = rt.Close() })
	release := make(chan struct{})
	dialed := make(chan struct{}, 4)
	d := testDialer(t)
	p, err := NewPuller(rt, PullerOptions{Dial: func(ctx context.Context, ep *ua.EndpointDescription) (*opcua.Client, error) {
		dialed <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return d.Dial(ctx, ep)
	}, Interval: time.Hour, Source: Config{MinRetry: time.Hour}})
	require.NoError(t, err)
	<-dialed
	require.NoError(t, p.Close())
	assert.Nil(t, rt.KeySource("sg"))

	// install after the fetch was cancelled.
	p2 := &Puller{rt: rt, sources: map[string]*KeySource{}, pending: map[string]context.CancelFunc{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src, err := NewKeySource(context.Background(), Config{SecurityGroupID: "sg", Dial: func(ctx context.Context) (*opcua.Client, error) { return d.Dial(ctx, pullEndpoint(s.url)) }})
	require.NoError(t, err)
	p2.install(ctx, "sg", src)
	assert.Nil(t, rt.KeySource("sg"))
	assert.Empty(t, p2.SecurityGroups())
	close(release)
}

// TestPullerRetryCancelled: a fetch waiting for its retry ends when its
// group goes.
func TestPullerRetryCancelled(t *testing.T) {
	rt, err := pubsub.New(securedConfig(pullEndpoint("opc.tcp://127.0.0.1:1")))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = rt.Close() })
	errs := make(chan error, 8)
	p, err := NewPuller(rt, PullerOptions{
		Dial:    func(context.Context, *ua.EndpointDescription) (*opcua.Client, error) { return nil, errors.New("down") },
		OnError: func(_ string, err error) { errs <- err },
		Source:  Config{MinRetry: time.Hour},
	})
	require.NoError(t, err)
	assert.Error(t, <-errs)
	for _, c := range rt.Components() {
		if c.Kind == pubsub.KindConnection {
			require.NoError(t, rt.RemoveConnection(c.ID))
		}
	}
	p.Sync()
	require.NoError(t, p.Close())
}

// TestPullerDefaults: the Interval and the retry bounds of a Puller
// without them.
func TestPullerDefaults(t *testing.T) {
	rt, err := pubsub.New(nil)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = rt.Close() })
	p, err := NewPuller(rt, PullerOptions{Dial: func(context.Context, *ua.EndpointDescription) (*opcua.Client, error) {
		return nil, errors.New("unused")
	}})
	require.NoError(t, err)
	assert.Equal(t, DefaultPullInterval, p.opts.Interval)
	assert.Equal(t, DefaultMinRetry, p.opts.Source.MinRetry)
	assert.Equal(t, DefaultMaxRetry, p.opts.Source.MaxRetry)
	assert.Empty(t, p.SecurityGroups())
	require.NoError(t, p.Close())
	require.NoError(t, p.Close(), "twice")
}
