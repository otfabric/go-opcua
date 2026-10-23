// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func newService(t *testing.T, clk *fakeClock, cfgs ...SecurityGroupConfig) *KeyService {
	t.Helper()
	ks := NewKeyService(WithClock(clk.Now))
	for _, c := range cfgs {
		require.NoError(t, ks.AddSecurityGroup(c))
	}
	return ks
}

func group(id string, future, past uint32) SecurityGroupConfig {
	return SecurityGroupConfig{
		SecurityGroupID:   id,
		SecurityPolicyURI: PolicyURIAes128CTR,
		KeyLifetime:       time.Second,
		MaxFutureKeyCount: future,
		MaxPastKeyCount:   past,
	}
}

func TestKeyServiceAddRemove(t *testing.T) {
	clk := newFakeClock()
	ks := newService(t, clk)
	var events []GroupEvent
	cancel := ks.OnChange(func(ev GroupEvent) { events = append(events, ev) })

	cfg := group("b", 2, 1)
	cfg.SecurityGroupFolder = []string{"plant", "line1"}
	require.NoError(t, ks.AddSecurityGroup(cfg))
	require.NoError(t, ks.AddSecurityGroup(group("a", 0, 0)))
	got, ok := ks.SecurityGroup("b")
	require.True(t, ok)
	require.Equal(t, cfg, got)
	got.SecurityGroupFolder[0] = "x"
	again, _ := ks.SecurityGroup("b")
	require.Equal(t, "plant", again.SecurityGroupFolder[0], "configs are copies")
	all := ks.SecurityGroups()
	require.Len(t, all, 2)
	require.Equal(t, "a", all[0].SecurityGroupID)

	cases := []struct {
		name string
		cfg  SecurityGroupConfig
		want ua.StatusCode
	}{
		{"exists", group("a", 0, 0), ua.StatusBadNodeIDExists},
		{"empty id", group("", 0, 0), ua.StatusBadInvalidArgument},
		{"long id", group(string(make([]byte, 513)), 0, 0), ua.StatusBadInvalidArgument},
		{"lifetime", SecurityGroupConfig{SecurityGroupID: "z", SecurityPolicyURI: PolicyURIAes128CTR}, ua.StatusBadInvalidArgument},
		{"policy", SecurityGroupConfig{SecurityGroupID: "z", SecurityPolicyURI: "urn:x", KeyLifetime: time.Second}, ua.StatusBadSecurityPolicyRejected},
		{"folder", SecurityGroupConfig{SecurityGroupID: "z", SecurityPolicyURI: PolicyURIAes128CTR, KeyLifetime: time.Second, SecurityGroupFolder: []string{""}}, ua.StatusBadInvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, StatusCode(ks.AddSecurityGroup(c.cfg)))
		})
	}

	require.NoError(t, ks.RemoveSecurityGroup("a"))
	require.Equal(t, ua.StatusBadNotFound, StatusCode(ks.RemoveSecurityGroup("a")))
	_, ok = ks.SecurityGroup("a")
	require.False(t, ok)
	require.Len(t, events, 3)
	require.True(t, events[0].Added)
	require.Equal(t, "a", events[2].Config.SecurityGroupID)
	require.False(t, events[2].Added)
	cancel()
	require.NoError(t, ks.RemoveSecurityGroup("b"))
	require.Len(t, events, 3)
}

// TestGetSecurityKeysSemantics follows open62541 ua_pubsub_ns0_sks.c
// getSecurityKeysAction. The group has MaxFutureKeyCount 3 and
// MaxPastKeyCount 2; after two rotations the SKS holds tokens 1..6 with
// current token 3.
func TestGetSecurityKeysSemantics(t *testing.T) {
	clk := newFakeClock()
	ks := newService(t, clk, group("sg", 3, 2))

	r, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(1), r.FirstTokenID)
	require.Len(t, r.Keys, 1)
	require.Len(t, r.Keys[0], 52)
	require.Equal(t, PolicyURIAes128CTR, r.SecurityPolicyURI)
	require.Equal(t, time.Second, r.TimeToNextKey)
	require.Equal(t, time.Second, r.KeyLifetime)

	clk.Advance(2*time.Second + 250*time.Millisecond)
	cases := []struct {
		name         string
		start, count uint32
		first        uint32
		n            int
		wantErr      ua.StatusCode
		group        string
	}{
		{name: "current only", start: 0, count: 0, first: 3, n: 1},
		{name: "current and futures", start: 0, count: 3, first: 3, n: 4},
		{name: "count above max: all from start", start: 0, count: 4, first: 3, n: 4},
		{name: "count max uint32", start: 0, count: 0xFFFFFFFF, first: 3, n: 4},
		{name: "past start", start: 1, count: 1, first: 1, n: 2},
		{name: "past start all", start: 2, count: 100, first: 2, n: 5},
		{name: "future start", start: 5, count: 3, first: 5, n: 2},
		{name: "unknown token: oldest", start: 99, count: 0, first: 1, n: 1},
		{name: "unknown group", group: "nope", wantErr: ua.StatusBadNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := c.group
			if g == "" {
				g = "sg"
			}
			r, err := ks.GetSecurityKeys(g, c.start, c.count)
			if c.wantErr != 0 {
				require.Equal(t, c.wantErr, StatusCode(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.first, r.FirstTokenID)
			require.Len(t, r.Keys, c.n)
			require.Equal(t, 750*time.Millisecond, r.TimeToNextKey)
		})
	}

	// The keys are stable across calls and distinct.
	a, err := ks.GetSecurityKeys("sg", 0, 3)
	require.NoError(t, err)
	b, err := ks.GetSecurityKeys("sg", 3, 3)
	require.NoError(t, err)
	require.Equal(t, a.Keys, b.Keys)
	require.NotEqual(t, a.Keys[0], a.Keys[1])
	a.Keys[0][0] ^= 0xFF
	c, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	require.Equal(t, b.Keys[0], c.Keys[0], "results are copies")

	// A key handed out as future key is the key when it becomes current.
	clk.Advance(750 * time.Millisecond)
	d, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(4), d.FirstTokenID)
	require.Equal(t, b.Keys[1], d.Keys[0])
	id, err := ks.CurrentTokenID("sg")
	require.NoError(t, err)
	require.Equal(t, uint32(4), id)
	_, err = ks.CurrentTokenID("nope")
	require.Error(t, err)
}

func TestKeyServiceLongGap(t *testing.T) {
	clk := newFakeClock()
	ks := newService(t, clk, group("sg", 1, 1))
	clk.Advance(1000*time.Second + 100*time.Millisecond)
	r, err := ks.GetSecurityKeys("sg", 0, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1001), r.FirstTokenID)
	require.Len(t, r.Keys, 2)
	require.Equal(t, 900*time.Millisecond, r.TimeToNextKey)
	clk.Advance(time.Second)
	r2, err := ks.GetSecurityKeys("sg", 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(1002), r2.FirstTokenID)
	require.Equal(t, r.Keys[1], r2.Keys[0])
}

func TestKeyServiceWraparound(t *testing.T) {
	clk := newFakeClock()
	ks := newService(t, clk, group("sg", 2, 0))
	// Rotate the token ids close to the end of the range.
	clk.Advance(time.Duration(0xFFFFFFFD) * time.Second)
	r, err := ks.GetSecurityKeys("sg", 0, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(0xFFFFFFFE), r.FirstTokenID)
	clk.Advance(2 * time.Second)
	r, err = ks.GetSecurityKeys("sg", 0, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(1), r.FirstTokenID, "token 0 is skipped")
	require.Len(t, r.Keys, 3)
}

func TestKeyServiceKeySource(t *testing.T) {
	clk := newFakeClock()
	ks := newService(t, clk, group("sg", 1, 1))
	_, err := ks.KeySource("nope")
	require.Equal(t, ua.StatusBadNotFound, StatusCode(err))
	src, err := ks.KeySource("sg")
	require.NoError(t, err)
	require.Same(t, Aes128CTR(), src.Policy())

	k, err := src.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, uint32(1), k.TokenID)
	next, err := src.KeysForToken(2)
	require.NoError(t, err)

	// A ring fed from GetSecurityKeys agrees with the service.
	r, err := ks.GetSecurityKeys("sg", 0, 1)
	require.NoError(t, err)
	ring := NewKeyRing("sg", Aes128CTR(), WithClock(clk.Now))
	require.NoError(t, ring.SetKeys(r.SecurityPolicyURI, r.FirstTokenID, r.Keys, r.TimeToNextKey, r.KeyLifetime))

	clk.Advance(time.Second)
	k, err = src.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, next, k)
	rk, err := ring.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, k, rk)
	_, err = src.KeysForToken(1)
	require.NoError(t, err, "one past key")
	_, err = src.KeysForToken(0)
	require.ErrorIs(t, err, ErrNoKeys)

	require.NoError(t, ks.RemoveSecurityGroup("sg"))
	_, err = src.CurrentKeys()
	require.ErrorIs(t, err, ErrNoKeys)
	_, err = src.KeysForToken(2)
	require.ErrorIs(t, err, ErrNoKeys)
}

func TestKeyServiceRandomFailure(t *testing.T) {
	clk := newFakeClock()
	ks := NewKeyService(WithClock(clk.Now), WithRandom(errReader{}))
	require.Equal(t, ua.StatusBadInternalError, StatusCode(ks.AddSecurityGroup(group("sg", 0, 0))))

	// Rotation failures surface from GetSecurityKeys and the KeySource.
	fr := &flakyReader{}
	ks = NewKeyService(WithClock(clk.Now), WithRandom(fr))
	require.NoError(t, ks.AddSecurityGroup(group("sg", 0, 0)))
	src, err := ks.KeySource("sg")
	require.NoError(t, err)
	fr.fail = true
	clk.Advance(time.Second)
	_, err = ks.GetSecurityKeys("sg", 0, 0)
	require.Equal(t, ua.StatusBadInternalError, StatusCode(err))
	_, err = src.KeysForToken(1)
	require.Error(t, err)
	clk.Advance(100 * time.Second)
	_, err = ks.GetSecurityKeys("sg", 0, 0)
	require.Error(t, err)
}

type flakyReader struct{ fail bool }

func (f *flakyReader) Read(b []byte) (int, error) {
	if f.fail {
		return 0, errors.New("no entropy")
	}
	for i := range b {
		b[i] = byte(i)
	}
	return len(b), nil
}

func TestAuthorize(t *testing.T) {
	ctx := context.Background()
	enc := ua.MessageSecurityModeSignAndEncrypt
	user := &Caller{SecurityMode: enc, Identity: &ua.UserNameIdentityToken{UserName: "alice"}, Roles: []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}}
	anon := &Caller{SecurityMode: enc, Identity: &ua.AnonymousIdentityToken{}}
	signOnly := &Caller{SecurityMode: ua.MessageSecurityModeSign, Identity: user.Identity}

	require.Equal(t, "alice", user.UserName())
	require.Empty(t, anon.UserName())
	require.Empty(t, (*Caller)(nil).UserName())
	require.True(t, (*Caller)(nil).Anonymous())
	require.True(t, (&Caller{}).Anonymous())
	require.False(t, (*Caller)(nil).HasRole(ua.RoleSecurityAdmin.NodeID()))
	require.False(t, user.HasRole(nil))

	cases := []struct {
		name string
		a    Authorizer
		c    *Caller
		want error
	}{
		{"default user", nil, user, nil},
		{"default anonymous", nil, anon, ua.StatusBadUserAccessDenied},
		{"sign only", AllowAll, signOnly, ua.StatusBadSecurityModeInsufficient},
		{"no caller", AllowAll, nil, ua.StatusBadSecurityModeInsufficient},
		{"allow all anonymous", AllowAll, anon, nil},
		{"role ok", RequireRoles(ua.RoleObserver.NodeID(), ua.RoleSecurityAdmin.NodeID()), user, nil},
		{"role missing", RequireRoles(ua.RoleObserver.NodeID()), user, ua.StatusBadUserAccessDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Authorize(ctx, c.a, c.c, OpGetSecurityKeys, "sg")
			if c.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, c.want)
			}
		})
	}

	var seen []string
	ks := NewKeyService(WithAuthorizer(func(_ context.Context, _ *Caller, op Operation, id string) error {
		seen = append(seen, op.String()+":"+id)
		return nil
	}))
	for _, op := range []Operation{OpGetSecurityKeys, OpSetSecurityKeys, OpAddSecurityGroup, OpRemoveSecurityGroup, OpGetSecurityGroup} {
		require.NoError(t, ks.Authorize(ctx, anon, op, "g"))
	}
	require.Equal(t, []string{"GetSecurityKeys:g", "SetSecurityKeys:g", "AddSecurityGroup:g", "RemoveSecurityGroup:g", "GetSecurityGroup:g"}, seen)
	require.Equal(t, "Operation(?)", Operation(0).String())
}
