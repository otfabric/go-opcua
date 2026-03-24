// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"github.com/otfabric/go-opcua/id"
)

// WellKnownRole identifies a standard OPC UA role.
// Values are the numeric NodeID of the role object in namespace 0.
type WellKnownRole uint32

const (
	RoleAnonymous               WellKnownRole = id.WellKnownRole_Anonymous
	RoleAuthenticatedUser       WellKnownRole = id.WellKnownRole_AuthenticatedUser
	RoleObserver                WellKnownRole = id.WellKnownRole_Observer
	RoleOperator                WellKnownRole = id.WellKnownRole_Operator
	RoleSupervisor              WellKnownRole = id.WellKnownRole_Supervisor
	RoleSecurityAdmin           WellKnownRole = id.WellKnownRole_SecurityAdmin
	RoleConfigureAdmin          WellKnownRole = id.WellKnownRole_ConfigureAdmin
	RoleEngineer                WellKnownRole = id.WellKnownRole_Engineer
	RoleTrustedApplication      WellKnownRole = id.WellKnownRole_TrustedApplication
	RoleSecurityKeyServerAdmin  WellKnownRole = id.WellKnownRole_SecurityKeyServerAdmin
	RoleSecurityKeyServerPush   WellKnownRole = id.WellKnownRole_SecurityKeyServerPush
	RoleSecurityKeyServerAccess WellKnownRole = id.WellKnownRole_SecurityKeyServerAccess
)

// String returns the short name of the role (e.g. "Anonymous").
func (r WellKnownRole) String() string {
	if s, ok := roleToName[r]; ok {
		return s
	}
	return "Unknown"
}

// NodeID returns the OPC UA NodeID for this role.
func (r WellKnownRole) NodeID() *NodeID {
	return NewNumericNodeID(0, uint32(r))
}

// RoleByName maps short role names (as used in the permissions CSV)
// to well-known role constants.
var RoleByName = map[string]WellKnownRole{
	"Anonymous":               RoleAnonymous,
	"AuthenticatedUser":       RoleAuthenticatedUser,
	"Observer":                RoleObserver,
	"Operator":                RoleOperator,
	"Supervisor":              RoleSupervisor,
	"SecurityAdmin":           RoleSecurityAdmin,
	"ConfigureAdmin":          RoleConfigureAdmin,
	"Engineer":                RoleEngineer,
	"TrustedApplication":      RoleTrustedApplication,
	"SecurityKeyServerAdmin":  RoleSecurityKeyServerAdmin,
	"SecurityKeyServerPush":   RoleSecurityKeyServerPush,
	"SecurityKeyServerAccess": RoleSecurityKeyServerAccess,
}

var roleToName = map[WellKnownRole]string{
	RoleAnonymous:               "Anonymous",
	RoleAuthenticatedUser:       "AuthenticatedUser",
	RoleObserver:                "Observer",
	RoleOperator:                "Operator",
	RoleSupervisor:              "Supervisor",
	RoleSecurityAdmin:           "SecurityAdmin",
	RoleConfigureAdmin:          "ConfigureAdmin",
	RoleEngineer:                "Engineer",
	RoleTrustedApplication:      "TrustedApplication",
	RoleSecurityKeyServerAdmin:  "SecurityKeyServerAdmin",
	RoleSecurityKeyServerPush:   "SecurityKeyServerPush",
	RoleSecurityKeyServerAccess: "SecurityKeyServerAccess",
}
