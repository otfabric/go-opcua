// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestReturnDiagnostics_Option(t *testing.T) {
	cfg := &Config{}
	require.NoError(t, ReturnDiagnostics(0xFFFFFFFF)(cfg))
	require.Equal(t, uint32(ua.ReturnDiagnosticsAll), cfg.returnDiagnostics)
}

func TestPrepareDiagnostics(t *testing.T) {
	c := &Client{cfg: &Config{returnDiagnostics: ua.ServiceLevelSymbolicID}}

	// A request without header gets one.
	req := &ua.ReadRequest{}
	require.True(t, c.wantsDiagnostics(req))
	h, rh := c.prepareDiagnostics(req, nil)
	require.Equal(t, uint32(ua.ServiceLevelSymbolicID), req.RequestHeader.ReturnDiagnostics)
	require.NoError(t, h(&ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{RequestHandle: 7}}))
	require.Equal(t, uint32(7), rh.RequestHandle)
	require.NoError(t, h(nil))

	// The header of the caller is copied, not changed.
	own := &ua.RequestHeader{RequestHandle: 3}
	req = &ua.ReadRequest{RequestHeader: own}
	called := false
	h, _ = c.prepareDiagnostics(req, func(ua.Response) error { called = true; return nil })
	require.Zero(t, own.ReturnDiagnostics)
	require.Equal(t, uint32(ua.ServiceLevelSymbolicID), req.RequestHeader.ReturnDiagnostics)
	require.Equal(t, uint32(3), req.RequestHeader.RequestHandle)
	require.NoError(t, h(&ua.ReadResponse{}))
	require.True(t, called)

	// A request with a mask of its own keeps it.
	req = &ua.ReadRequest{RequestHeader: &ua.RequestHeader{ReturnDiagnostics: ua.OperationLevelAll}}
	_, _ = c.prepareDiagnostics(req, nil)
	require.Equal(t, uint32(ua.OperationLevelAll), req.RequestHeader.ReturnDiagnostics)

	plain := &Client{cfg: &Config{}}
	require.False(t, plain.wantsDiagnostics(nil))
	require.False(t, plain.wantsDiagnostics(&ua.ReadRequest{}))
	require.True(t, plain.wantsDiagnostics(req))
	_, _ = plain.prepareDiagnostics(nil, nil)
}

func TestServiceError(t *testing.T) {
	rh := &ua.ResponseHeader{
		ServiceResult:      ua.StatusBadTimeout,
		StringTable:        []string{"BadTimeout"},
		ServiceDiagnostics: &ua.DiagnosticInfo{EncodingMask: ua.DiagnosticInfoSymbolicID},
	}
	err := serviceError(ua.StatusBadTimeout, rh)
	var se *ServiceError
	require.True(t, errors.As(err, &se))
	require.Equal(t, ua.StatusBadTimeout, se.StatusCode)
	require.ErrorIs(t, err, ua.StatusBadTimeout)
	require.Contains(t, err.Error(), "(BadTimeout)")
	require.Equal(t, ua.StatusBadTimeout.Error(), (&ServiceError{StatusCode: ua.StatusBadTimeout}).Error())

	// Left as they are: no error, another status, a wrapped status, no
	// diagnostics.
	require.NoError(t, serviceError(nil, rh))
	require.Equal(t, ua.StatusBadInternalError, serviceError(ua.StatusBadInternalError, rh))
	wrapped := fmt.Errorf("x: %w", ua.StatusBadTimeout)
	require.Equal(t, wrapped, serviceError(wrapped, rh))
	require.Equal(t, ua.StatusBadTimeout, serviceError(ua.StatusBadTimeout, &ua.ResponseHeader{ServiceResult: ua.StatusBadTimeout}))
	require.Equal(t, ua.StatusBadTimeout, serviceError(ua.StatusBadTimeout, nil))
}

func TestDiagnosticsHelpers_NotConnected(t *testing.T) {
	c, err := NewClient("opc.tcp://localhost:1")
	require.NoError(t, err)
	ctx := context.Background()
	_, err = c.ServerDiagnosticsSummary(ctx)
	require.Error(t, err)
	_, err = c.ServerDiagnosticsEnabled(ctx)
	require.Error(t, err)
	require.Error(t, c.SetServerDiagnosticsEnabled(ctx, true))
	_, err = c.SessionDiagnostics(ctx)
	require.Error(t, err)
	_, err = c.SessionDiagnosticsOf(ctx, nil)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)
	_, err = c.SessionSecurityDiagnosticsOf(ctx, ua.NewNumericNodeID(1, 1))
	require.Error(t, err)
}
