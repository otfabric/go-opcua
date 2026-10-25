// SPDX-License-Identifier: MIT

package server

import (
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The ValueRank values of Part 3 §5.6.2 used for new Variables.
const (
	valueRankAny    = int32(-2)
	valueRankScalar = int32(-1)
)

// browseNameIn returns the BrowseName name in the namespace of nodeID.
func browseNameIn(nodeID *ua.NodeID, name string) *ua.QualifiedName {
	qn := &ua.QualifiedName{Name: name}
	if nodeID != nil {
		qn.NamespaceIndex = nodeID.Namespace()
	}
	return qn
}

// variantOf returns the Variant value is encoded as, as DataValueFromValue
// encodes it, or nil for nil or a type a Variant cannot hold.
func variantOf(value any) *ua.Variant {
	switch v := value.(type) {
	case nil:
		return nil
	case *ua.DataValue:
		if v == nil {
			return nil
		}
		return v.Value
	case ua.DataValue:
		return v.Value
	case *ua.Variant:
		return v
	case ua.Variant:
		return &v
	case int:
		value = int32(v)
	}
	v, err := ua.NewVariant(value)
	if err != nil {
		return nil
	}
	return v
}

// variantDataType returns the DataType NodeId of the value of v (Part 3
// §5.6.2, Part 6 §5.1.2): the DataType of the built-in type, the DataType of
// a structure of namespace 0 found from its encoding, Structure for other
// structures and BaseDataType for nil, a Variant and unknown types.
func variantDataType(v *ua.Variant) *ua.NodeID {
	if v == nil || v.Value() == nil {
		return ua.NewNumericNodeID(0, id.BaseDataType)
	}
	switch t := v.Type(); t {
	case ua.TypeIDNull, ua.TypeIDVariant:
		return ua.NewNumericNodeID(0, id.BaseDataType)
	case ua.TypeIDExtensionObject:
		return extensionObjectDataType(v.Value())
	default:
		if t > ua.TypeIDDiagnosticInfo {
			return ua.NewNumericNodeID(0, id.BaseDataType)
		}
		// The built-in types 1..25 are the DataTypes with the same
		// numeric NodeId in namespace 0.
		return ua.NewNumericNodeID(0, uint32(t))
	}
}

// extensionObjectDataType returns the DataType of the structure in an
// ExtensionObject value (or the first of an array of them).
func extensionObjectDataType(val any) *ua.NodeID {
	var eo *ua.ExtensionObject
	switch x := val.(type) {
	case *ua.ExtensionObject:
		eo = x
	case []*ua.ExtensionObject:
		if len(x) > 0 {
			eo = x[0]
		}
	}
	structure := ua.NewNumericNodeID(0, id.Structure)
	if eo == nil || eo.TypeID == nil || eo.TypeID.NodeID == nil {
		return structure
	}
	enc := eo.TypeID.NodeID
	if enc.Namespace() != 0 || enc.Type() == ua.NodeIDTypeString || enc.Type() == ua.NodeIDTypeGUID || enc.Type() == ua.NodeIDTypeByteString {
		return structure
	}
	name, ok := strings.CutSuffix(id.Name(enc.IntID()), "_Encoding_DefaultBinary")
	if !ok {
		return structure
	}
	if dt, ok := id.NodeIDByName(name); ok && id.DataTypeName(dt) != "" {
		return ua.NewNumericNodeID(0, dt)
	}
	return structure
}

// variantValueRank returns the ValueRank of the value of v and, for an
// array, its ArrayDimensions with every length 0 (any length).
func variantValueRank(v *ua.Variant) (int32, []uint32) {
	if v == nil || v.Value() == nil {
		return valueRankAny, nil
	}
	if !v.IsArray() {
		return valueRankScalar, nil
	}
	n := len(v.ArrayDimensions())
	if n == 0 {
		n = 1
	}
	return int32(n), make([]uint32, n)
}
