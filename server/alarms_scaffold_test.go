// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func TestAlarmsConditionsSupported(t *testing.T) {
	if AlarmsConditionsSupported() {
		t.Fatal("A&C is deferred; helper must report false")
	}
	if AcknowledgeableConditionTypeNodeID.IntID() != id.AcknowledgeableConditionType {
		t.Fatalf("unexpected NodeId %v", AcknowledgeableConditionTypeNodeID)
	}
}
