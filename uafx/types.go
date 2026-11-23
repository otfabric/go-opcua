// SPDX-License-Identifier: MIT

package uafx

import (
	"strconv"
	"strings"
)

var endpointStatusNames = [...]string{"Initial", "Ready", "PreOperational", "Operational", "Error"}

// String returns the name of the status, or its number if it has none.
func (s ConnectionEndpointStatus) String() string {
	if s >= 0 && int(s) < len(endpointStatusNames) {
		return endpointStatusNames[s]
	}
	return "ConnectionEndpointStatus(" + strconv.FormatInt(int64(s), 10) + ")"
}

var deviceHealthNames = []bitName{
	{0, "DeviceFailure"}, {1, "DeviceCheckFunction"}, {2, "DeviceMaintenanceRequired"}, {3, "DeviceOffSpec"},
}

// String returns the names of the bits that are set, separated by "|", or
// "OK" when none is.
func (h DeviceHealth) String() string { return bitString(uint64(h), deviceHealthNames) }

var operationalHealthNames = []bitName{
	{16, "OperationalWarning"}, {17, "OperationalError"}, {18, "SubOperationalWarning"}, {19, "SubOperationalError"},
}

// String returns the names of the bits that are set, separated by "|", or
// "OK" when none is.
func (h OperationalHealth) String() string {
	return bitString(uint64(h), operationalHealthNames)
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
