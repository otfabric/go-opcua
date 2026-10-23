// SPDX-License-Identifier: MIT

package sks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

const (
	policy256 = ua.SecurityPolicyURIBasic256Sha256
	encrypt   = ua.MessageSecurityModeSignAndEncrypt
)

type sksServer struct {
	url   string
	ks    *security.KeyService
	rings *security.KeyRings
}

// startSKS starts a go-opcua server that is an SKS for ks and a
// SetSecurityKeys target, with a Basic256Sha256 SignAndEncrypt endpoint and
// the user "pub" (password "pw").
func startSKS(t *testing.T, ks *security.KeyService) *sksServer {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity(policy256, encrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "pub" && pass == "pw" {
				return nil
			}
			return errors.New("denied")
		}),
	)
	require.NoError(t, err)
	_, err = srv.EnableSecurityKeyService(ks)
	require.NoError(t, err)
	rings := &security.KeyRings{}
	require.NoError(t, srv.EnableSecurityKeyPush(rings))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return &sksServer{url: fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), ks: ks, rings: rings}
}

// dial connects to url over Basic256Sha256 SignAndEncrypt as "pub", or
// anonymously.
func dial(ctx context.Context, url string, anonymous bool) (*opcua.Client, error) {
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
		if e.SecurityPolicyURI == policy256 && e.SecurityMode == encrypt {
			ep = e
		}
	}
	if ep == nil {
		return nil, errors.New("no endpoint")
	}
	auth, login := ua.UserTokenTypeUserName, opcua.AuthUsername("pub", "pw")
	if anonymous {
		auth, login = ua.UserTokenTypeAnonymous, opcua.AuthAnonymous()
	}
	c, err := opcua.NewClient(url, opcua.AutoReconnect(false), login, opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509))
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func connect(t *testing.T, url string, anonymous bool) *opcua.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := dial(ctx, url, anonymous)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func newKeyService(t *testing.T, lifetime time.Duration, future uint32) *security.KeyService {
	t.Helper()
	ks := security.NewKeyService()
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{
		SecurityGroupID:   "sg",
		SecurityPolicyURI: security.PolicyURIAes128CTR,
		KeyLifetime:       lifetime,
		MaxFutureKeyCount: future,
		MaxPastKeyCount:   2,
	}))
	return ks
}

func TestGetSecurityKeys(t *testing.T) {
	ks := newKeyService(t, time.Hour, 3)
	s := startSKS(t, ks)
	c := connect(t, s.url, false)
	ctx := context.Background()

	r, err := GetSecurityKeys(ctx, c, "sg", 0, 2)
	require.NoError(t, err)
	want, err := ks.GetSecurityKeys("sg", 0, 2)
	require.NoError(t, err)
	require.Equal(t, want.SecurityPolicyURI, r.SecurityPolicyURI)
	require.Equal(t, want.FirstTokenID, r.FirstTokenID)
	require.Equal(t, want.Keys, r.Keys)
	require.Equal(t, time.Hour, r.KeyLifetime)
	require.InDelta(t, float64(time.Hour), float64(r.TimeToNextKey), float64(time.Minute))

	_, err = GetSecurityKeys(ctx, c, "nope", 0, 0)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	anon := connect(t, s.url, true)
	_, err = GetSecurityKeys(ctx, anon, "sg", 0, 0)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = GetSecurityKeys(cctx, c, "sg", 0, 0)
	require.Error(t, err)
}

func TestPushAndSetSecurityKeys(t *testing.T) {
	ks := newKeyService(t, time.Hour, 2)
	s := startSKS(t, ks)
	ring := security.NewKeyRing("sg", security.Aes128CTR())
	s.rings.Add(ring)
	c := connect(t, s.url, false)
	ctx := context.Background()

	require.NoError(t, Push(ctx, ks, c, "sg"))
	require.Equal(t, []uint32{1, 2, 3}, ring.TokenIDs())
	src, err := ks.KeySource("sg")
	require.NoError(t, err)
	want, err := src.CurrentKeys()
	require.NoError(t, err)
	got, err := ring.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, want, got)

	// Only a current key.
	r, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	require.NoError(t, SetSecurityKeys(ctx, c, "sg", r))

	require.ErrorIs(t, Push(ctx, ks, c, "nope"), ua.StatusBadNotFound)
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: "other", SecurityPolicyURI: security.PolicyURIAes128CTR, KeyLifetime: time.Hour}))
	require.ErrorIs(t, Push(ctx, ks, c, "other"), ua.StatusBadNotFound, "no ring on the target")
	require.Error(t, SetSecurityKeys(ctx, c, "sg", nil))
	anon := connect(t, s.url, true)
	require.ErrorIs(t, SetSecurityKeys(ctx, anon, "sg", r), ua.StatusBadUserAccessDenied)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, SetSecurityKeys(cctx, c, "sg", r))
}

// TestKeySourceRefresh pulls keys with a short KeyLifetime and checks that
// the KeySource follows the rotation of the SKS without running out of
// keys.
func TestKeySourceRefresh(t *testing.T) {
	for _, tc := range []struct {
		name   string
		future uint32
		dial   bool
	}{
		{"client one future key", 1, false},
		{"dial three future keys", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const life = 400 * time.Millisecond
			ks := newKeyService(t, life, tc.future)
			s := startSKS(t, ks)
			cfg := Config{SecurityGroupID: "sg", MinRetry: 50 * time.Millisecond}
			if tc.dial {
				cfg.Dial = func(ctx context.Context) (*opcua.Client, error) { return dial(ctx, s.url, false) }
			} else {
				cfg.Client = connect(t, s.url, false)
			}
			var updates atomic.Int32
			cfg.OnUpdate = func(*Result) { updates.Add(1) }
			src, err := NewKeySource(context.Background(), cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = src.Close() })
			require.Same(t, security.Aes128CTR(), src.Policy())
			require.Equal(t, uint32(1), src.Ring().CurrentTokenID())
			require.Equal(t, int(tc.future), src.Ring().FutureKeyCount())

			svc, err := ks.KeySource("sg")
			require.NoError(t, err)
			require.Eventually(t, func() bool { return src.Ring().CurrentTokenID() >= 5 }, 10*time.Second, 10*time.Millisecond)
			// Whatever token the SKS uses, the source has its key.
			for range 5 {
				want, err := svc.CurrentKeys()
				require.NoError(t, err)
				got, err := src.KeysForToken(want.TokenID)
				require.NoError(t, err, "token %d", want.TokenID)
				require.Equal(t, want, got)
				time.Sleep(life / 3)
			}
			cur, err := src.CurrentKeys()
			require.NoError(t, err)
			require.NotZero(t, cur.TokenID)
			require.NoError(t, src.Err())
			require.GreaterOrEqual(t, updates.Load(), int32(2))
			require.NoError(t, src.Close())
			require.NoError(t, src.Close())
		})
	}
}

func TestKeySourceRetry(t *testing.T) {
	ks := newKeyService(t, time.Hour, 1)
	s := startSKS(t, ks)
	var fail atomic.Bool
	var errs atomic.Int32
	src, err := NewKeySource(context.Background(), Config{
		SecurityGroupID: "sg",
		NoFutureKeys:    true,
		MinRetry:        20 * time.Millisecond,
		MaxRetry:        40 * time.Millisecond,
		Dial: func(ctx context.Context) (*opcua.Client, error) {
			if fail.Load() {
				return nil, errors.New("SKS down")
			}
			return dial(ctx, s.url, false)
		},
		OnError: func(error) { errs.Add(1) },
	})
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	require.Zero(t, src.Ring().FutureKeyCount(), "NoFutureKeys")

	fail.Store(true)
	src.Refresh()
	require.Eventually(t, func() bool { return errs.Load() >= 3 }, 10*time.Second, 5*time.Millisecond)
	require.ErrorContains(t, src.Err(), "SKS down")
	fail.Store(false)
	require.Eventually(t, func() bool { return src.Err() == nil }, 10*time.Second, 5*time.Millisecond)
}

func TestNewKeySourceErrors(t *testing.T) {
	ctx := context.Background()
	_, err := NewKeySource(ctx, Config{SecurityGroupID: "sg"})
	require.Error(t, err)
	_, err = NewKeySource(ctx, Config{SecurityGroupID: "sg", Dial: func(context.Context) (*opcua.Client, error) {
		return nil, errors.New("down")
	}})
	require.ErrorContains(t, err, "down")

	ks := newKeyService(t, time.Hour, 1)
	s := startSKS(t, ks)
	c := connect(t, s.url, false)
	_, err = NewKeySource(ctx, Config{SecurityGroupID: "nope", Client: c, MaxRetry: time.Millisecond, MaxPastKeys: -1})
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// A source on a group without rotation never refetches by itself.
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: "slow", SecurityPolicyURI: security.PolicyURIAes256CTR, KeyLifetime: 1000 * time.Hour}))
	src, err := NewKeySource(ctx, Config{SecurityGroupID: "slow", Client: c, RequestedKeyCount: 1, Timeout: time.Minute})
	require.NoError(t, err)
	require.Same(t, security.Aes256CTR(), src.Policy())
	require.NoError(t, src.Close())
}

func TestParseResult(t *testing.T) {
	v := func(x any) *ua.Variant { return ua.MustVariant(x) }
	_, err := parseResult(nil)
	require.ErrorIs(t, err, ErrBadResponse)
	_, err = parseResult([]*ua.Variant{v("u"), v(int32(1)), v([][]byte{{1}}), v(1.0), v(1.0)})
	require.ErrorIs(t, err, ErrBadResponse)
	_, err = parseResult([]*ua.Variant{v("u"), v(uint32(1)), v([][]byte{}), v(1.0), v(1.0)})
	require.ErrorIs(t, err, ErrBadResponse)
	r, err := parseResult([]*ua.Variant{v("u"), v(uint32(1)), v([][]byte{{1}}), v(math.NaN()), v(1e300)})
	require.NoError(t, err)
	require.Zero(t, r.TimeToNextKey)
	require.Equal(t, time.Duration(math.MaxInt64), r.KeyLifetime)
	require.Equal(t, 1.5, durationMS(1500*time.Microsecond))
}

func TestNextFetch(t *testing.T) {
	ring := security.NewKeyRing("sg", security.Aes128CTR())
	s := &KeySource{ring: ring}
	require.Zero(t, s.nextFetch(), "no keys, no rotation")
	keys := make([][]byte, 4)
	for i := range keys {
		keys[i] = make([]byte, 52)
	}
	require.NoError(t, ring.SetKeys(security.PolicyURIAes128CTR, 1, keys, time.Second, 10*time.Second))
	d := s.nextFetch()
	// 3 future keys: fetch after the second key change from now.
	require.InDelta(t, float64(time.Second+20*time.Second+500*time.Millisecond), float64(d), float64(50*time.Millisecond))
	require.NoError(t, ring.SetKeys(security.PolicyURIAes128CTR, 1, keys[:1], time.Second, 10*time.Second))
	require.InDelta(t, float64(time.Second+500*time.Millisecond), float64(s.nextFetch()), float64(50*time.Millisecond))
}
