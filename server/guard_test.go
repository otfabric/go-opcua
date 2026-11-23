// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGuard rejects the writes and calls of the nodes in deny and records
// what it was asked and the sessions that ended.
type testGuard struct {
	deny   map[string]ua.StatusCode
	asked  []string
	ended  []*Session
	panics bool
}

func (g *testGuard) check(nid *ua.NodeID) ua.StatusCode {
	g.asked = append(g.asked, nid.String())
	if st, ok := g.deny[nid.String()]; ok {
		return st
	}
	return ua.StatusOK
}

func (g *testGuard) CheckWrite(_ context.Context, _ *Session, nid *ua.NodeID) ua.StatusCode {
	return g.check(nid)
}

func (g *testGuard) CheckCall(_ context.Context, _ *Session, _, mid *ua.NodeID) ua.StatusCode {
	return g.check(mid)
}

func (g *testGuard) SessionEnded(s *Session) {
	if g.panics {
		panic("guard")
	}
	g.ended = append(g.ended, s)
}

// plainGuard is a Guard that is not a SessionEndGuard.
type plainGuard struct{ g testGuard }

func (p *plainGuard) CheckWrite(ctx context.Context, s *Session, nid *ua.NodeID) ua.StatusCode {
	return p.g.CheckWrite(ctx, s, nid)
}

func (p *plainGuard) CheckCall(ctx context.Context, s *Session, oid, mid *ua.NodeID) ua.StatusCode {
	return p.g.CheckCall(ctx, s, oid, mid)
}

func TestGuards(t *testing.T) {
	var logs bytes.Buffer
	srv, err := New(InsecureNoSecurity(), EndPoint("localhost", 4840), SetLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	require.NoError(t, err)
	ctx := context.Background()
	a, b := ua.NewNumericNodeID(1, 1), ua.NewNumericNodeID(1, 2)

	// Without Guards everything is allowed.
	assert.Equal(t, ua.StatusOK, srv.guardWrite(ctx, nil, a))
	assert.Equal(t, ua.StatusOK, srv.guardCall(ctx, nil, a, b))
	srv.guardSessionEnded(&session{})

	srv.AddGuard(nil)
	assert.Empty(t, srv.guardList())
	first := &testGuard{deny: map[string]ua.StatusCode{a.String(): ua.StatusBadLocked}}
	second := &testGuard{deny: map[string]ua.StatusCode{b.String(): ua.StatusBadUserAccessDenied}}
	srv.AddGuard(first)
	srv.AddGuard(second)
	plain := &plainGuard{}
	srv.AddGuard(plain)
	require.Len(t, srv.guardList(), 3)

	// The first rejection wins; later Guards are not asked.
	assert.Equal(t, ua.StatusBadLocked, srv.guardWrite(ctx, nil, a))
	assert.Equal(t, []string{a.String()}, first.asked)
	assert.Empty(t, second.asked)
	assert.Equal(t, ua.StatusBadUserAccessDenied, srv.guardCall(ctx, nil, a, b))
	assert.Equal(t, []string{b.String()}, second.asked)
	assert.Equal(t, ua.StatusOK, srv.guardWrite(ctx, nil, ua.NewNumericNodeID(1, 3)))
	assert.Equal(t, []string{"ns=1;i=3"}, plain.g.asked)

	// SessionEndGuards learn the end; a panic is logged and the others
	// are still told.
	sess := &session{ID: ua.NewNumericNodeID(1, 99)}
	first.panics = true
	srv.guardSessionEnded(sess)
	assert.Empty(t, first.ended)
	require.Len(t, second.ended, 1)
	assert.Same(t, sess, second.ended[0].s)
	assert.Empty(t, plain.g.ended)
	assert.Contains(t, logs.String(), "SessionEndGuard")
}

func TestSessionClientApplicationURI(t *testing.T) {
	assert.Empty(t, (*Session)(nil).ClientApplicationURI())
	s := &session{}
	assert.Empty(t, s.handle().ClientApplicationURI())
	s.diag.client = &ua.ApplicationDescription{ApplicationURI: "urn:client"}
	assert.Equal(t, "urn:client", s.handle().ClientApplicationURI())
}
