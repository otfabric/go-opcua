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
