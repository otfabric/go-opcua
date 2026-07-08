// SPDX-License-Identifier: MIT

package ua

import (
	"github.com/otfabric/go-opcua/id"
)

// WellKnownRole identifies a standard OPC UA role.
// Values are the numeric NodeID of the role object in namespace 0.
type WellKnownRole uint32

const (
	RoleAnonymous               WellKnownRole = id.WellKnownRoleAnonymous
	RoleAuthenticatedUser       WellKnownRole = id.WellKnownRoleAuthenticatedUser
	RoleObserver                WellKnownRole = id.WellKnownRoleObserver
	RoleOperator                WellKnownRole = id.WellKnownRoleOperator
	RoleSupervisor              WellKnownRole = id.WellKnownRoleSupervisor
	RoleSecurityAdmin           WellKnownRole = id.WellKnownRoleSecurityAdmin
	RoleConfigureAdmin          WellKnownRole = id.WellKnownRoleConfigureAdmin
	RoleEngineer                WellKnownRole = id.WellKnownRoleEngineer
	RoleTrustedApplication      WellKnownRole = id.WellKnownRoleTrustedApplication
	RoleSecurityKeyServerAdmin  WellKnownRole = id.WellKnownRoleSecurityKeyServerAdmin
	RoleSecurityKeyServerPush   WellKnownRole = id.WellKnownRoleSecurityKeyServerPush
	RoleSecurityKeyServerAccess WellKnownRole = id.WellKnownRoleSecurityKeyServerAccess
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
