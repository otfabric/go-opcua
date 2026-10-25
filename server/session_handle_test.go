// SPDX-License-Identifier: MIT

package server

import (
	"log/slog"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSessionHandle(t *testing.T) {
	var none *Session
	require.Nil(t, none.ID())
	require.Nil(t, none.Identity())
	require.Nil(t, none.Roles())
	require.Nil(t, none.ClientCertificate())
	require.Nil(t, (*session)(nil).handle())

	sb := &sessionBroker{s: map[string]*session{}}
	s := sb.NewSession()
	s.identityToken = &ua.UserNameIdentityToken{UserName: "olivia"}
	s.roles = []*ua.NodeID{ua.RoleOperator.NodeID()}
	s.remoteCertificate = []byte{1, 2}
	h := s.handle()
	require.Same(t, h, s.handle(), "a broker session has one handle")
	require.Same(t, s.ID, h.ID())
	require.Equal(t, "olivia", h.Identity().(*ua.UserNameIdentityToken).UserName)

	roles := h.Roles()
	roles[0] = nil
	require.NotNil(t, s.roles[0], "Roles returns a copy")
	cert := h.ClientCertificate()
	cert[0] = 9
	require.Equal(t, byte(1), s.remoteCertificate[0], "ClientCertificate returns a copy")

	bare := &session{ID: ua.NewNumericNodeID(1, 7)}
	require.Same(t, bare.ID, bare.handle().ID(), "a session made without the broker still has a handle")
}

func TestServerSession(t *testing.T) {
	srv := &Server{sb: newSessionBroker(slog.New(slog.DiscardHandler))}
	s := srv.sb.NewSession()

	require.Nil(t, srv.Session(nil))
	require.Nil(t, srv.Session(&ua.RequestHeader{}), "no token")
	require.Nil(t, srv.Session(&ua.RequestHeader{AuthenticationToken: ua.NewNumericNodeID(0, 1)}), "unknown token")
	h := srv.Session(&ua.RequestHeader{AuthenticationToken: s.AuthTokenID})
	require.Same(t, s.handle(), h)
	require.Same(t, s.ID, h.ID())
}
