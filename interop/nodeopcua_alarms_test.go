//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (Part 9) against node-opcua, both directions (shared
// assertions: alarms_peer_test.go).
// COVERAGE: testdata/ledger-node-opcua.json alarms.condition-refresh,
// alarms.acknowledgeable

package interop

import "testing"

func TestNodeOpcuaServer_Alarms(t *testing.T) {
	requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	s := newPeerAlarmSession(t, startNodeOpcuaServer(t).endpoint)
	t.Run("coverage/alarms.condition-refresh/go-client-to-node-opcua-server", s.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/go-client-to-node-opcua-server", s.assertActions)
}

func TestGoServer_NodeOpcuaClient_Alarms(t *testing.T) {
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	r := runPeerAlarms(t, runNodeOpcuaClientResult)
	t.Run("coverage/alarms.condition-refresh/node-opcua-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/node-opcua-client-to-go-server", r.assertActions)
}

func TestGoServer_NodeOpcuaClient_Alarms105(t *testing.T) {
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "call")
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
	p := startAlarms105(t, runNodeOpcuaClientResult)
	t.Run("coverage/alarms.alarm-state-methods/node-opcua-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/node-opcua-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/node-opcua-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/node-opcua-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/node-opcua-client-to-go-server", p.assertAudit)
}
