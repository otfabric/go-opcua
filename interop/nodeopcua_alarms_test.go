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
