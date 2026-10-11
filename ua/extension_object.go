// SPDX-License-Identifier: MIT

package ua

import (
	"log/slog"
	"reflect"

	"github.com/otfabric/go-opcua/id"
)

// eotypes contains all known extension objects.
var eotypes = NewTypeRegistry()

// RegisterExtensionObject registers a new extension object type.
// It panics if the type or the id is already registered.
func RegisterExtensionObject(typeID *NodeID, v interface{}) {
	if err := eotypes.Register(typeID, v); err != nil {
		panic("Extension object " + err.Error())
	}
	codecTypes.extensionObjectRegistered(reflect.TypeOf(v))
}

// These flags define the value type of an ExtensionObject.
// They cannot be combined.
const (
	ExtensionObjectEmpty  = 0
	ExtensionObjectBinary = 1
	ExtensionObjectXML    = 2
)

// ExtensionObject is encoded as sequence of bytes prefixed by the NodeId of its DataTypeEncoding
// and the number of bytes encoded.
//
// Specification: Part 6, 5.2.2.15.
type ExtensionObject struct {
	EncodingMask uint8
	TypeID       *ExpandedNodeID
	Value        interface{}
}

func NewExtensionObject(value interface{}) *ExtensionObject {
	e := &ExtensionObject{
		TypeID: ExtensionObjectTypeID(value),
		Value:  value,
	}
	e.UpdateMask()
	return e
}

func (e *ExtensionObject) Decode(b []byte) (int, error) {
	buf := NewBuffer(b)
	e.TypeID = new(ExpandedNodeID)
	buf.ReadStruct(e.TypeID)

	e.EncodingMask = buf.ReadUint8()
	if e.EncodingMask == ExtensionObjectEmpty {
		return buf.Pos(), buf.Error()
	}

	length := buf.ReadUint32()
	if length == 0 || length == 0xffffffff || buf.Error() != nil {
		return buf.Pos(), buf.Error()
	}

	body := NewBuffer(buf.ReadN(int(length)))
	if buf.Error() != nil {
		return buf.Pos(), buf.Error()
	}

	if e.EncodingMask == ExtensionObjectXML {
		v := new(XMLElement)
		e.Value = v
		body.ReadStruct(v)
		return buf.Pos(), body.Error()
	}

	typeID := e.TypeID.NodeID
	e.Value = eotypes.New(typeID)
	if e.Value == nil {
		slog.Default().Debug("unknown extension object", "type_id", typeID)
		return buf.Pos(), buf.Error()
	}

	body.ReadStruct(e.Value)
	return buf.Pos(), body.Error()
}

func (e *ExtensionObject) Encode() ([]byte, error) {
	buf := NewBuffer(nil)
	if e == nil {
		e = &ExtensionObject{TypeID: NewTwoByteExpandedNodeID(0), EncodingMask: ExtensionObjectEmpty}
	}
	buf.WriteStruct(e.TypeID)
	if e.EncodingMask == ExtensionObjectEmpty || e.Value == nil {
		// No body. This includes an object of an unknown type as left by
		// Decode, which keeps the type id but not the body.
		_ = buf.WriteByte(ExtensionObjectEmpty)
		return buf.Bytes(), buf.Error()
	}
	_ = buf.WriteByte(e.EncodingMask)

	body := NewBuffer(nil)
	if raw, ok := e.Value.([]byte); ok {
		// An opaque, already encoded body, as the JSON and XML decoders
		// keep it for types that are not registered.
		body.Write(raw)
	} else {
		body.WriteStruct(e.Value)
	}
	if body.Error() != nil {
		return nil, body.Error()
	}
	buf.WriteUint32(uint32(body.Len()))
	buf.Write(body.Bytes())
	return buf.Bytes(), buf.Error()
}

func (e *ExtensionObject) UpdateMask() {
	if e.Value == nil {
		e.EncodingMask = ExtensionObjectEmpty
	} else if _, ok := e.Value.(*XMLElement); ok {
		e.EncodingMask = ExtensionObjectXML
	} else {
		e.EncodingMask = ExtensionObjectBinary
	}
}

func ExtensionObjectTypeID(v interface{}) *ExpandedNodeID {
	switch v.(type) {
	case *AnonymousIdentityToken:
		return NewFourByteExpandedNodeID(0, id.AnonymousIdentityTokenEncodingDefaultBinary)
	case *UserNameIdentityToken:
		return NewFourByteExpandedNodeID(0, id.UserNameIdentityTokenEncodingDefaultBinary)
	case *X509IdentityToken:
		return NewFourByteExpandedNodeID(0, id.X509IdentityTokenEncodingDefaultBinary)
	case *IssuedIdentityToken:
		return NewFourByteExpandedNodeID(0, id.IssuedIdentityTokenEncodingDefaultBinary)
	case *ServerStatusDataType:
		return NewFourByteExpandedNodeID(0, id.ServerStatusDataTypeEncodingDefaultBinary)
	default:
		if id := eotypes.Lookup(v); id != nil {
			return &ExpandedNodeID{NodeID: id}
		}
		return NewTwoByteExpandedNodeID(0)
	}
}
