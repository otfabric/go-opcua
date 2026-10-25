//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (Part 9): the async-opcua client against the go-opcua
// server (shared assertions: alarms_peer_test.go; no async-opcua alarm
// server fixture).
// COVERAGE: testdata/ledger-async-opcua.json alarms.condition-refresh,
// alarms.acknowledgeable

package interop

import "testing"

func TestGoServer_AsyncOpcuaClient_Alarms(t *testing.T) {
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "alarms")
	r := runPeerAlarms(t, runAsyncOpcuaClientResult)
	t.Run("coverage/alarms.condition-refresh/async-opcua-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/async-opcua-client-to-go-server", r.assertActions)
}

func TestGoServer_AsyncOpcuaClient_Alarms105(t *testing.T) {
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "call")
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
	p := startAlarms105(t, runAsyncOpcuaClientResult)
	t.Run("coverage/alarms.alarm-state-methods/async-opcua-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/async-opcua-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/async-opcua-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/async-opcua-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/async-opcua-client-to-go-server", p.assertAudit)
}

func TestGoServer_AsyncOpcuaClient_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "read")
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "call")
	p := startAlarmTiming(t, runAsyncOpcuaClientResult)
	t.Run("coverage/alarms.alarm-timing/async-opcua-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/async-opcua-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/async-opcua-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/async-opcua-client-to-go-server", p.assertMetrics)
}
