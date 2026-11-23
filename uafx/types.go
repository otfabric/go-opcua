// SPDX-License-Identifier: MIT

package uafx

import (
	"strconv"
	"strings"
)

// ConnectionEndpointStatus is the ConnectionEndpointStatusEnum of Part 81
// §10.17, the Status of a ConnectionEndpoint.
type ConnectionEndpointStatus int32

// The values of ConnectionEndpointStatusEnum (Part 81 §10.17).
const (
	ConnectionEndpointInitial        ConnectionEndpointStatus = 0
	ConnectionEndpointReady          ConnectionEndpointStatus = 1
	ConnectionEndpointPreOperational ConnectionEndpointStatus = 2
	ConnectionEndpointOperational    ConnectionEndpointStatus = 3
	ConnectionEndpointError          ConnectionEndpointStatus = 4
)

var endpointStatusNames = [...]string{"Initial", "Ready", "PreOperational", "Operational", "Error"}

// String returns the name of the status, or its number if it has none.
func (s ConnectionEndpointStatus) String() string {
	if s >= 0 && int(s) < len(endpointStatusNames) {
		return endpointStatusNames[s]
	}
	return "ConnectionEndpointStatus(" + strconv.FormatInt(int64(s), 10) + ")"
}

// DeviceHealth is the DeviceHealthOptionSet of Part 81 §10.21: the
// aggregated health of the Assets of an AutomationComponent.
type DeviceHealth uint16

// The bits of DeviceHealthOptionSet.
const (
	DeviceFailure             DeviceHealth = 1 << 0
	DeviceCheckFunction       DeviceHealth = 1 << 1
	DeviceMaintenanceRequired DeviceHealth = 1 << 2
	DeviceOffSpec             DeviceHealth = 1 << 3
)

var deviceHealthNames = []bitName{
	{0, "DeviceFailure"}, {1, "DeviceCheckFunction"}, {2, "DeviceMaintenanceRequired"}, {3, "DeviceOffSpec"},
}

// String returns the names of the bits that are set, separated by "|", or
// "OK" when none is.
func (h DeviceHealth) String() string { return bitString(uint64(h), deviceHealthNames) }

// OperationalHealth is the OperationalHealthOptionSet of Part 81 §10.34: the
// operational health of a FunctionalEntity, and aggregated, of the
// FunctionalEntities of an AutomationComponent.
type OperationalHealth uint32

// The bits of OperationalHealthOptionSet, a subtype of UInt32 whose
// definition names bits 16 to 19. String shows other bits as a number.
const (
	OperationalWarning    OperationalHealth = 1 << 16
	OperationalError      OperationalHealth = 1 << 17
	SubOperationalWarning OperationalHealth = 1 << 18
	SubOperationalError   OperationalHealth = 1 << 19
)

var operationalHealthNames = []bitName{
	{16, "OperationalWarning"}, {17, "OperationalError"}, {18, "SubOperationalWarning"}, {19, "SubOperationalError"},
}

// String returns the names of the bits that are set, separated by "|", or
// "OK" when none is.
func (h OperationalHealth) String() string {
	return bitString(uint64(h), operationalHealthNames)
}

// AggregatedHealth is the AggregatedHealthDataType of Part 81 §10.1.
type AggregatedHealth struct {
	// AggregatedDeviceHealth aggregates the DeviceHealth of the top-level
	// Assets.
	AggregatedDeviceHealth DeviceHealth
	// AggregatedOperationalHealth aggregates the OperationalHealth of the
	// top-level FunctionalEntities.
	AggregatedOperationalHealth OperationalHealth
}

// FxVersion is the FxVersion structure of Part 81 §10.28, the version of a
// FunctionalEntity.
type FxVersion struct {
	Major    uint16
	Minor    uint16
	Build    uint16
	SubBuild uint16
}

// String returns the version as Major.Minor.Build.SubBuild.
func (v FxVersion) String() string {
	return strconv.Itoa(int(v.Major)) + "." + strconv.Itoa(int(v.Minor)) + "." +
		strconv.Itoa(int(v.Build)) + "." + strconv.Itoa(int(v.SubBuild))
}

type bitName struct {
	bit  uint
	name string
}

func bitString(v uint64, names []bitName) string {
	if v == 0 {
		return "OK"
	}
	var parts []string
	for _, n := range names {
		if v&(1<<n.bit) != 0 {
			parts = append(parts, n.name)
			v &^= 1 << n.bit
		}
	}
	if v != 0 {
		parts = append(parts, "0x"+strconv.FormatUint(v, 16))
	}
	return strings.Join(parts, "|")
}
