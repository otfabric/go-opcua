// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestEmitEvent_NoMonitoredItems(t *testing.T) {
	srv := newTestServer()
	require.NoError(t, srv.EmitEvent(ua.NewStringNodeID(0, "event"), &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("msg")},
	}))
}
