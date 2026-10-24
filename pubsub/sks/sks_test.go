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
			// Under load the first rotation may already have happened by now
			// (the key lifetime is short), so only bound the start state.
			require.NotZero(t, src.Ring().CurrentTokenID())
			require.LessOrEqual(t, src.Ring().FutureKeyCount(), int(tc.future))

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
	// 3 future keys: fetch after the second key change from now, which
	// leaves one future key.
	require.InDelta(t, float64(time.Second+10*time.Second+500*time.Millisecond), float64(d), float64(50*time.Millisecond))
	require.NoError(t, ring.SetKeys(security.PolicyURIAes128CTR, 1, keys[:1], time.Second, 10*time.Second))
	require.InDelta(t, float64(time.Second+500*time.Millisecond), float64(s.nextFetch()), float64(50*time.Millisecond))
}

// TestNextFetchLeavesAFutureKey checks the refresh schedule on a fake clock:
// when the SKS hands out two or more future keys, the scheduled fetch
// happens while the ring still holds one, so that a fetch may take up to a
// key lifetime without the ring ever running out of keys. With fewer future
// keys the fetch is right after the next key change, when the SKS has the
// next key.
func TestNextFetchLeavesAFutureKey(t *testing.T) {
	const life = 10 * time.Second
	for future := 0; future <= 5; future++ {
		for _, ttnk := range []time.Duration{time.Millisecond, 3 * time.Second, life} {
			now := time.Unix(1_000_000, 0)
			ring := security.NewKeyRing("sg", security.Aes128CTR(), security.WithClock(func() time.Time { return now }))
			s := &KeySource{ring: ring}
			keys := make([][]byte, future+1)
			for i := range keys {
				keys[i] = make([]byte, 52)
			}
			require.NoError(t, ring.SetKeys(security.PolicyURIAes128CTR, 7, keys, ttnk, life))
			d := s.nextFetch()
			require.Greater(t, d, ttnk, "future=%d ttnk=%v: fetch after the next key change", future, ttnk)
			now = now.Add(d)
			want := min(future-1, 1)
			if future == 0 {
				want = 0 // the ring keeps using its only key until the fetch
			}
			require.Equal(t, max(want, 0), ring.FutureKeyCount(), "future=%d ttnk=%v: future keys left at the fetch", future, ttnk)
			require.False(t, ring.Stale() && future > 0, "future=%d ttnk=%v: ring stale at the fetch", future, ttnk)
			// The fetch has (almost) a whole key lifetime before the ring
			// would need a key it does not hold.
			if future >= 2 {
				require.Greater(t, ring.TimeToNextKey()+life, life+life/2, "future=%d ttnk=%v", future, ttnk)
			}
		}
	}
}

// TestKeySourceSlowSKS pulls the keys of a group with a short key lifetime
// from an SKS that takes a whole key lifetime to answer: the source must
// hold the key of every token the SKS uses and never run out of keys.
func TestKeySourceSlowSKS(t *testing.T) {
	t.Parallel()
	const life = 600 * time.Millisecond
	ks := newKeyService(t, life, 2)
	s := startSKS(t, ks)
	src, err := NewKeySource(context.Background(), Config{
		SecurityGroupID: "sg",
		MinRetry:        50 * time.Millisecond,
		Dial: func(ctx context.Context) (*opcua.Client, error) {
			select {
			case <-time.After(life):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return dial(ctx, s.url, false)
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })
	svc, err := ks.KeySource("sg")
	require.NoError(t, err)
	first := src.Ring().CurrentTokenID()
	deadline := time.Now().Add(8 * life)
	for time.Now().Before(deadline) {
		want, err := svc.CurrentKeys()
		require.NoError(t, err)
		_, err = src.Ring().KeysForToken(want.TokenID)
		require.NoError(t, err, "the SKS uses token %d, the source holds %v", want.TokenID, src.Ring().TokenIDs())
		require.False(t, src.Ring().Stale(), "the source ran out of future keys")
		time.Sleep(life / 12)
	}
	require.GreaterOrEqual(t, src.Ring().CurrentTokenID(), first+5)
	require.NoError(t, src.Err())
}

// TestKeySourceRefreshOnUnknownToken: a message with a token just ahead of
// the source's keys makes it fetch now; tokens far ahead (or behind) do
// not, and neither does a burst of them within MinRetry.
func TestKeySourceRefreshOnUnknownToken(t *testing.T) {
	ks := newKeyService(t, time.Hour, 0)
	s := startSKS(t, ks)
	var fetches atomic.Int32
	src, err := NewKeySource(context.Background(), Config{
		SecurityGroupID: "sg",
		MinRetry:        time.Hour,
		Dial: func(ctx context.Context) (*opcua.Client, error) {
			fetches.Add(1)
			return dial(ctx, s.url, false)
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })
	require.Equal(t, int32(1), fetches.Load())
	cur := src.Ring().CurrentTokenID()

	_, err = src.KeysForToken(cur + missWindow + 1)
	require.ErrorIs(t, err, security.ErrNoKeys)
	_, err = src.KeysForToken(cur - 1)
	require.ErrorIs(t, err, security.ErrNoKeys)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(1), fetches.Load(), "tokens outside the window do not fetch")

	for range 10 {
		_, err = src.KeysForToken(cur + 1)
		require.ErrorIs(t, err, security.ErrNoKeys)
	}
	require.Eventually(t, func() bool { return fetches.Load() == 2 }, 10*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(2), fetches.Load(), "one fetch per MinRetry")
	require.True(t, src.ahead(cur+1))
	require.False(t, src.ahead(0))
	require.False(t, (&KeySource{ring: security.NewKeyRing("x", security.Aes128CTR())}).ahead(1), "empty ring")
}
