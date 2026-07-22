// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"strings"
)

// StatusCode info-bit masks (IEC 62541-4 StatusCode / DataValue InfoBits).
// Overflow is only meaningful when InfoType is DataValue and QueueSize > 1.
const (
	StatusCodeInfoTypeDataValue StatusCode = 0x00000400
	StatusCodeOverflowBit       StatusCode = 0x00000080
	// StatusCodeGoodOverflow is Good with InfoType=DataValue and Overflow set (0x480).
	StatusCodeGoodOverflow StatusCode = StatusCodeInfoTypeDataValue | StatusCodeOverflowBit
)

// WithOverflow returns s with the DataValue Overflow InfoBit set.
func (s StatusCode) WithOverflow() StatusCode {
	return s | StatusCodeGoodOverflow
}

// HasOverflow reports whether the DataValue Overflow InfoBit is set.
func (s StatusCode) HasOverflow() bool {
	return s&StatusCodeOverflowBit != 0 && s&StatusCodeInfoTypeDataValue != 0
}

// Uint32 returns the raw 32-bit status code value for serialization (e.g. CSV/JSON).
// Use Symbol() or Error() for human-readable strings.
func (s StatusCode) Uint32() uint32 {
	return uint32(s)
}

// Symbol returns the short symbolic name for the status code (e.g. "Good",
// "BadServiceUnsupported", "BadUserAccessDenied"). It strips the "Status"
// prefix from the known name when present. For unknown codes, returns the hex
// string. Use for compact status rendering instead of Error().
func (s StatusCode) Symbol() string {
	if d, ok := StatusCodes[s]; ok && d.Name != "" {
		name := d.Name
		if strings.HasPrefix(name, "Status") {
			return name[6:] // "Status" is 6 bytes
		}
		return name
	}
	return fmt.Sprintf("0x%X", uint32(s))
}
