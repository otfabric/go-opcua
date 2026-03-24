// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func TestWellKnownRoleString(t *testing.T) {
	tests := []struct {
		role WellKnownRole
		want string
	}{
		{RoleAnonymous, "Anonymous"},
		{RoleAuthenticatedUser, "AuthenticatedUser"},
		{RoleObserver, "Observer"},
		{RoleOperator, "Operator"},
		{RoleSupervisor, "Supervisor"},
		{RoleSecurityAdmin, "SecurityAdmin"},
		{RoleConfigureAdmin, "ConfigureAdmin"},
		{RoleEngineer, "Engineer"},
		{RoleTrustedApplication, "TrustedApplication"},
		{RoleSecurityKeyServerAdmin, "SecurityKeyServerAdmin"},
		{RoleSecurityKeyServerPush, "SecurityKeyServerPush"},
		{RoleSecurityKeyServerAccess, "SecurityKeyServerAccess"},
		{WellKnownRole(0), "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWellKnownRoleNodeID(t *testing.T) {
	n := RoleAnonymous.NodeID()
	if got, want := n.IntID(), uint32(id.WellKnownRoleAnonymous); got != want {
		t.Errorf("NodeID().IntID() = %d, want %d", got, want)
	}
}

func TestRoleByName(t *testing.T) {
	for name, role := range RoleByName {
		if got := role.String(); got != name {
			t.Errorf("RoleByName[%q].String() = %q, want %q", name, got, name)
		}
	}
	if _, ok := RoleByName["NonExistent"]; ok {
		t.Error("RoleByName should not contain NonExistent")
	}
}
