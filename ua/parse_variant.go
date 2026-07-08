// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseVariant parses a string value into a Variant of the given type.
// This is the inverse of Variant.String().
//
// The target type must be known (e.g. from reading the node's DataType).
// Supported types: Boolean, SByte through UInt64, Float, Double, String,
// DateTime (RFC 3339), GUID, ByteString (hex), NodeID, StatusCode, and
// XMLElement.
func ParseVariant(s string, typeID TypeID) (*Variant, error) {
	v, err := parseScalar(s, typeID)
	if err != nil {
		return nil, fmt.Errorf("opcua: parse variant %s %q: %w", typeID, s, err)
	}
	return NewVariant(v)
}

func parseScalar(s string, typeID TypeID) (interface{}, error) {
	switch typeID {
	case TypeIDBoolean:
		switch strings.ToLower(s) {
		case "true", "1":
			return true, nil
		case "false", "0":
			return false, nil
		default:
			return nil, fmt.Errorf("opcua: invalid boolean: %q", s)
		}

	case TypeIDSByte:
		v, err := strconv.ParseInt(s, 10, 8)
		return int8(v), err

	case TypeIDByte:
		v, err := strconv.ParseUint(s, 10, 8)
		return uint8(v), err

	case TypeIDInt16:
		v, err := strconv.ParseInt(s, 10, 16)
		return int16(v), err

	case TypeIDUint16:
		v, err := strconv.ParseUint(s, 10, 16)
		return uint16(v), err

	case TypeIDInt32:
		v, err := strconv.ParseInt(s, 10, 32)
		return int32(v), err

	case TypeIDUint32:
		v, err := strconv.ParseUint(s, 10, 32)
		return uint32(v), err

	case TypeIDInt64:
		v, err := strconv.ParseInt(s, 10, 64)
		return v, err

	case TypeIDUint64:
		v, err := strconv.ParseUint(s, 10, 64)
		return v, err

	case TypeIDFloat:
		v, err := strconv.ParseFloat(s, 32)
		return float32(v), err

	case TypeIDDouble:
		v, err := strconv.ParseFloat(s, 64)
		return v, err

	case TypeIDString:
		return s, nil

	case TypeIDDateTime:
		return time.Parse(time.RFC3339Nano, s)

	case TypeIDGUID:
		g := NewGUID(s)
		if g == nil {
			return nil, fmt.Errorf("opcua: invalid GUID: %q", s)
		}
		return g, nil

	case TypeIDByteString:
		return hex.DecodeString(s)

	case TypeIDXMLElement:
		return XMLElement(s), nil

	case TypeIDNodeID:
		nid, err := ParseNodeID(s)
		if err != nil {
			return nil, err
		}
		return nid, nil

	case TypeIDStatusCode:
		// Try to parse as hex status code
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			v, err := strconv.ParseUint(s[2:], 16, 32)
			if err != nil {
				return nil, err
			}
			return StatusCode(v), nil
		}
		// Try to find by name
		for code, desc := range StatusCodes {
			if strings.EqualFold(desc.Name, s) {
				return code, nil
			}
		}
		return nil, fmt.Errorf("opcua: unknown status code: %q", s)

	default:
		return nil, fmt.Errorf("opcua: unsupported type for parsing: %d", typeID)
	}
}
