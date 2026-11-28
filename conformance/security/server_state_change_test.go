// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// TestSecurity_RequestServerStateChange: RequestServerStateChange of the
// Server Object (OPC 10000-5 §9.4) "shall provide credentials with
// administrative rights": a ConfigureAdmin is accepted, an anonymous user
// is Bad_UserAccessDenied, and the AccessRestrictions of the Method in the
// NodeSet (SigningRequired) refuse a channel without security. An accepted
// change is in the ServerStatus and the EstimatedReturnTime Property.
func TestSecurity_RequestServerStateChange(t *testing.T) {
	var (
		mu  sync.Mutex
		got []server.ServerStateChange
	)
	roles := func(tok ua.IdentityToken) []*ua.NodeID {
		if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == "alice" {
			return []*ua.NodeID{ua.RoleConfigureAdmin.NodeID()}
		}
		return []*ua.NodeID{ua.RoleAnonymous.NodeID()}
	}
	_, url := secureServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator),
		server.WithRoleMapper(roles),
		server.WithServerStateChange(func(_ context.Context, c server.ServerStateChange) ua.StatusCode {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, c)
			if c.State == ua.ServerStateFailed {
				return ua.StatusBadInvalidState
			}
			return ua.StatusOK
		}),
	)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign)
	admin := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), opcua.AuthUsername("alice", "wonderland"))...)
	anon := newClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...)
	plain := newClient(t, url)

	shutdown := &uamethod.ServerTypeRequestServerStateChangeInput{
		State:               int32(ua.ServerStateShutdown),
		EstimatedReturnTime: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		SecondsTillShutdown: 120,
		Reason:              ua.NewLocalizedTextWithLocale("firmware update", "en"),
	}
	require.ErrorIs(t, anon.RequestServerStateChange(ctx, shutdown), ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, plain.RequestServerStateChange(ctx, shutdown), ua.StatusBadSecurityModeInsufficient)
	mu.Lock()
	require.Empty(t, got, "refused before the application sees it")
	mu.Unlock()

	require.NoError(t, admin.RequestServerStateChange(ctx, shutdown))
	st, err := admin.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateShutdown, st.State)
	require.InDelta(t, 120, st.SecondsTillShutdown, 3)
	require.Equal(t, "firmware update", st.ShutdownReason.Text)
	dv, err := admin.Node(ua.NewNumericNodeID(0, id.ServerEstimatedReturnTime)).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, shutdown.EstimatedReturnTime, dv.Value())
	dv, err = admin.Node(ua.NewNumericNodeID(0, id.ServerServerStatusSecondsTillShutdown)).Value(ctx)
	require.NoError(t, err)
	require.IsType(t, uint32(0), dv.Value(), "a UInt32 (Part 5 §12.10)")

	// The declaration of ServerType, called on the Server Object, is the
	// same Method (Part 4 §5.12.2.2 in 1.05.06).
	back := &uamethod.ServerTypeRequestServerStateChangeInput{State: int32(ua.ServerStateRunning), EstimatedReturnTime: time.Now()}
	require.NoError(t, uamethod.CallServerTypeRequestServerStateChange(ctx, admin, ua.NewNumericNodeID(0, id.Server), nil, back))
	st, err = admin.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateRunning, st.State)
	require.Zero(t, st.SecondsTillShutdown)
	dv, err = admin.Node(ua.NewNumericNodeID(0, id.ServerEstimatedReturnTime)).Value(ctx)
	require.NoError(t, err)
	require.True(t, dv.Value().(time.Time).IsZero(), "null in RUNNING_0")

	// A state the application refuses, and one that is no ServerState.
	require.ErrorIs(t, admin.RequestServerStateChange(ctx, &uamethod.ServerTypeRequestServerStateChangeInput{State: int32(ua.ServerStateFailed)}), ua.StatusBadInvalidState)
	require.ErrorIs(t, admin.RequestServerStateChange(ctx, &uamethod.ServerTypeRequestServerStateChangeInput{State: 42}), ua.StatusBadInvalidState)
	mu.Lock()
	require.Len(t, got, 3)
	require.Equal(t, uint32(120), got[0].SecondsTillShutdown)
	require.Equal(t, ua.ServerStateRunning, got[1].State)
	mu.Unlock()
}
