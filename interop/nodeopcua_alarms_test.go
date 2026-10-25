//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (Part 9) against node-opcua, both directions (shared
// assertions: alarms_peer_test.go).
// COVERAGE: testdata/ledger-node-opcua.json alarms.condition-refresh,
// alarms.acknowledgeable, alarms.audit-events

package interop

import "testing"

func TestNodeOpcuaServer_Alarms(t *testing.T) {
	requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	s := newPeerAlarmSession(t, startNodeOpcuaServer(t).endpoint)
	t.Run("coverage/alarms.condition-refresh/go-client-to-node-opcua-server", s.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/go-client-to-node-opcua-server", s.assertActions)
}

// TestNodeOpcuaServer_AlarmAudit: node-opcua 2.187.12 raises the condition
// audit events of Acknowledge, Confirm and AddComment without an auditing
// switch (node-opcua-address-space ua_condition_impl,
// ua_acknowledgeable_condition_impl) and delivers them to SecurityAdmin
// sessions only (node-opcua-server audit_event_permissions). Its events
// leave MethodId / InputArguments null, carry the Status of Acknowledge and
// Confirm as a StatusCode, the EventId after the call as the ConditionEventId
// of Acknowledge, and raise the AddComment audit event on the Server object.
func TestNodeOpcuaServer_AlarmAudit(t *testing.T) {
	requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	s := newPeerAuditAlarmSession(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "node-opcua-server")
	t.Run("coverage/alarms.audit-events/go-client-to-node-opcua-server", func(t *testing.T) {
		s.assertAudit(t, auditPeer{noMethodID: true, ackEventIDAfter: true, commentOnServer: true, ackStatusCode: true})
	})
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

func TestGoServer_NodeOpcuaClient_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "read")
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "call")
	p := startAlarmTiming(t, runNodeOpcuaClientResult)
	t.Run("coverage/alarms.alarm-timing/node-opcua-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/node-opcua-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/node-opcua-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/node-opcua-client-to-go-server", p.assertMetrics)
}
