// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// TestSameServer: the identity of a server is compared like for like
// (design §6.5): a reported identity is never taken for an authenticated
// one, and an authenticated record needs the same certificate.
func TestSameServer(t *testing.T) {
	t.Parallel()
	rep := serverEvidence{ApplicationURI: "urn:a", Source: identityReported}
	auth := serverEvidence{ApplicationURI: "urn:a", Source: identityAuthenticated, Thumbprint: []byte{1}}
	for _, tc := range []struct {
		name      string
		rec, cur  serverEvidence
		ok, retry bool
	}{
		{"no identity in the record", serverEvidence{}, rep, false, false},
		{"no identity in the session", rep, serverEvidence{}, false, true},
		{"another server", rep, serverEvidence{ApplicationURI: "urn:b", Source: identityReported}, false, false},
		{"reported, reported", rep, rep, true, false},
		{"reported, authenticated", rep, auth, true, false},
		{"authenticated, reported", auth, rep, false, true},
		{"authenticated, another certificate", auth, serverEvidence{ApplicationURI: "urn:a", Source: identityAuthenticated, Thumbprint: []byte{2}}, false, false},
		{"authenticated, authenticated", auth, auth, true, false},
	} {
		ok, retry, why := sameServer(tc.rec, tc.cur)
		assert.Equal(t, tc.ok, ok, tc.name)
		assert.Equal(t, tc.retry, retry, tc.name)
		assert.Equal(t, tc.ok, why == "", tc.name)
	}
}

// TestSameParam: the parameters of an endpoint by their namespace-qualified
// Variables, every negative CleanupTimeout alike (§6.6.2), a null
// RelatedEndpoint like none.
func TestSameParam(t *testing.T) {
	t.Parallel()
	nsa := []string{"http://opcfoundation.org/UA/", "urn:test"}
	related, err := ua.Encode(&uafx.RelatedEndpoint{Address: "opc.tcp://b", ConnectionEndpointName: "ToB"})
	require.NoError(t, err)
	base := storedParam{Set: true, Mode: 3, Inputs: []*qualifiedID{qualify(ua.NewNumericNodeID(1, 7), nsa)}, CleanupTimeout: -1}
	with := func(f func(p *storedParam)) storedParam {
		p := base
		f(&p)
		return p
	}
	assert.True(t, sameParam(base, base))
	assert.True(t, sameParam(base, with(func(p *storedParam) { p.CleanupTimeout = -5 })))
	assert.True(t, sameParam(base, with(func(p *storedParam) { p.Related = nil })))
	assert.False(t, sameParam(base, storedParam{}), "not set")
	assert.False(t, sameParam(base, with(func(p *storedParam) { p.Mode = 1 })))
	assert.False(t, sameParam(base, with(func(p *storedParam) { p.IsPersistent = true })))
	assert.False(t, sameParam(base, with(func(p *storedParam) { p.CleanupTimeout = 3 })))
	assert.False(t, sameParam(base, with(func(p *storedParam) { p.Outputs = base.Inputs })))
	assert.False(t, sameParam(base, with(func(p *storedParam) {
		p.Inputs = []*qualifiedID{{NamespaceURI: "urn:other", ID: base.Inputs[0].ID}}
	})), "another namespace")
	assert.False(t, sameParam(base, with(func(p *storedParam) { p.Related = []byte{1} })), "does not decode")
	r := with(func(p *storedParam) { p.Related = related })
	assert.True(t, sameParam(r, r))
	assert.False(t, sameParam(r, base), "a RelatedEndpoint and none")
	assert.False(t, sameParam(base, r))
}

func TestSameDuration(t *testing.T) {
	t.Parallel()
	assert.True(t, sameDuration(-1, -2))
	assert.True(t, sameDuration(5, 5))
	assert.True(t, sameDuration(math.Inf(1), math.Inf(1)))
	assert.False(t, sameDuration(-1, 0))
	assert.False(t, sameDuration(5, 6))
}

func TestSameNodes(t *testing.T) {
	t.Parallel()
	a, b := ua.NewNumericNodeID(1, 1), ua.NewNumericNodeID(1, 2)
	assert.True(t, sameNodes(nil, nil))
	assert.True(t, sameNodes([]*ua.NodeID{a, b}, []*ua.NodeID{b, a}))
	assert.False(t, sameNodes([]*ua.NodeID{a}, []*ua.NodeID{a, b}))
	assert.False(t, sameNodes([]*ua.NodeID{a, a}, []*ua.NodeID{a, b}))
}

func TestProofString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "KnownOwned", proof{class: KnownOwned}.String())
	assert.Equal(t, "Unresolved: why", proof{class: Unresolved, why: "why"}.String())
	assert.Equal(t, "dropped: gone", proof{drop: true, why: "gone"}.String())
	assert.Equal(t, "Unverified: boom", proof{class: Unverified, err: errors.New("boom")}.String())
	assert.Equal(t, -1, compareStrings("a", "b"))
	assert.Equal(t, 1, compareStrings("b", "a"))
	assert.Equal(t, 0, compareStrings("a", "a"))
}

// TestVerifyOptionsDefaults: New fills the VerifyOptions it is not given.
func TestVerifyOptionsDefaults(t *testing.T) {
	t.Parallel()
	m, err := New(Options{Dialer: offline{}, ApplicationURI: cmURI, Verify: VerifyOptions{RetryInitial: 2 * DefaultVerifyRetryMax}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	v := m.opts.Verify
	assert.Equal(t, DefaultVerifyTimeout, v.Timeout)
	assert.Positive(t, v.Parallelism)
	assert.GreaterOrEqual(t, v.RetryMax, v.RetryInitial, "RetryMax is at least RetryInitial")
}
