// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"log/slog"
)

// svcreg contains all known service request/response objects.
var svcreg = NewTypeRegistry()

// RegisterService registers a new service object type.
// It panics if the type or the id is already registered.
func RegisterService(typeID uint16, v interface{}) {
	if err := svcreg.Register(NewFourByteNodeID(0, typeID), v); err != nil {
		panic("Service " + err.Error())
	}
}

// ServiceTypeID returns the id of the service object type as
// registered with RegisterService. If the service object is not
// known the function returns 0.
func ServiceTypeID(v interface{}) uint16 {
	id := svcreg.Lookup(v)
	if id == nil {
		return 0
	}
	return uint16(id.IntID())
}

func DecodeService(b []byte) (*ExpandedNodeID, interface{}, error) {
	typeID := new(ExpandedNodeID)
	n, err := typeID.Decode(b)
	if err != nil {
		return nil, nil, err
	}
	b = b[n:]

	v := svcreg.New(typeID.NodeID)
	if v == nil {
		return nil, nil, StatusBadServiceUnsupported
	}

	slog.Debug("decoding service", "type", fmt.Sprintf("%T", v), "bytes", len(b))

	_, err = Decode(b, v)
	return typeID, v, err
}
