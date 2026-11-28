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

// HistorianBits of the DataValue InfoBits (Part 4 §7.38.1, Table 177): set
// only on values read from history, the processed values of an Aggregate
// above all (Part 13 §5.3.3). Bits 0:1 give the data location (Raw is 00,
// so a raw value has neither Calculated nor Interpolated), bit 2 Partial,
// bit 3 Extra Data and bit 4 Multi Value. A StatusCode with any of them set
// also has InfoType DataValue ([StatusCodeInfoTypeDataValue]).
const (
	// StatusCodeHistorianCalculated is Calculated: "A data value which was
	// calculated" (Table 177).
	StatusCodeHistorianCalculated StatusCode = 0x00000001
	// StatusCodeHistorianInterpolated is Interpolated: "A data value which
	// was interpolated" (Table 177).
	StatusCodeHistorianInterpolated StatusCode = 0x00000002
	// StatusCodeHistorianDataLocation masks the data location bits (Raw,
	// Calculated, Interpolated).
	StatusCodeHistorianDataLocation StatusCode = 0x00000003
	// StatusCodeHistorianPartial is Partial: "A data value which was
	// calculated with an incomplete interval" (Table 177).
	StatusCodeHistorianPartial StatusCode = 0x00000004
	// StatusCodeHistorianExtraData is Extra Data: "A raw data value that
	// hides other data at the same timestamp" (Table 177).
	StatusCodeHistorianExtraData StatusCode = 0x00000008
	// StatusCodeHistorianMultiValue is Multi Value: "Multiple values match
	// the Aggregate criteria (i.e. multiple minimum values at different
	// timestamps within the same interval)" (Table 177).
	StatusCodeHistorianMultiValue StatusCode = 0x00000010
	// StatusCodeHistorianBits masks all HistorianBits.
	StatusCodeHistorianBits StatusCode = 0x0000001F
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
