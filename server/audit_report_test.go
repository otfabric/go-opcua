// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestReportAuditEvent(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	ev := &BaseEvent{EventType: ua.NewNumericNodeID(0, id.AuditUpdateMethodEventType), Fields: map[string]*ua.Variant{"Status": ua.MustVariant(true)}}
	require.False(t, s.ReportAuditEvent(callerCtx(&ua.UserNameIdentityToken{UserName: "u"}), ev), "auditing is off")
	require.False(t, s.ReportAuditEvent(callerCtx(nil), nil))

	s.SetAuditing(true)
	n := ua.NewNumericNodeID(1, 7)
	require.True(t, s.ReportAuditEvent(callerCtx(&ua.UserNameIdentityToken{UserName: "u"}), ev,
		n, nil, n, ua.NewNumericNodeID(0, id.Server)))
	require.Nil(t, ev.EventID, "the event of the caller is not changed")
	require.Len(t, ev.Fields, 1)
}
