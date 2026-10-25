//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (Part 9) against UA-.NETStandard, both directions
// (shared assertions: alarms_peer_test.go).
// COVERAGE: testdata/ledger-dotnet.json alarms.condition-refresh,
// alarms.acknowledgeable

package interop

import "testing"

func TestDotnetServer_Alarms(t *testing.T) {
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "alarms")
	s := newPeerAlarmSession(t, startDotnetServer(t).endpoint)
	t.Run("coverage/alarms.condition-refresh/go-client-to-dotnet-server", s.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/go-client-to-dotnet-server", s.assertActions)
}

func TestGoServer_DotnetClient_Alarms(t *testing.T) {
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "alarms")
	r := runPeerAlarms(t, runDotnetClientResult)
	t.Run("coverage/alarms.condition-refresh/dotnet-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/dotnet-client-to-go-server", r.assertActions)
}
