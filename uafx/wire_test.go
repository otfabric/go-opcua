// SPDX-License-Identifier: MIT

package uafx

import (
	"fmt"

	"github.com/otfabric/go-opcua/ua"
)

// The tests build wire bytes with the reflection encoder of package ua and
// these structures, independently of the generated codec.

// eo returns v, encoded by package ua, in an ExtensionObject with the
// encoding NodeId ns=Data;i=enc.
func (c codec) eo(enc uint32, v any) (*ua.ExtensionObject, error) {
	body, err := ua.Encode(v)
	if err != nil {
		return nil, err
	}
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(c.ns.Data, enc),
		Value:        body,
	}, nil
}

// endpointConfigurationWire is the ConnectionEndpointConfigurationDataType
// on the wire: its union and its abstract CommunicationLinks field as they
// are encoded.
type endpointConfigurationWire struct {
	FunctionalEntityNode          *ua.NodeID
	ConnectionEndpoint            *definitionWire
	ExpectedVerificationVariables []*NodeIDValuePair
	ControlGroups                 []*ua.NodeID
	ConfigurationData             []*NodeIDValuePair
	CommunicationLinks            *ua.ExtensionObject
}

// definitionWire is the ConnectionEndpointDefinitionDataType union on the
// wire: SwitchField 0 (null), 1 (Parameter, an ExtensionObject since its
// DataType is abstract) or 2 (Node).
type definitionWire struct {
	Switch    uint32
	Parameter *ua.ExtensionObject
	Node      *ua.NodeID
}

// Encode implements ua.BinaryEncoder.
func (d *definitionWire) Encode() ([]byte, error) {
	b := ua.NewBuffer(nil)
	b.WriteUint32(d.Switch)
	switch d.Switch {
	case 0:
	case 1:
		b.WriteStruct(d.Parameter)
	case 2:
		b.WriteStruct(d.Node)
	default:
		return nil, fmt.Errorf("%w: ConnectionEndpointDefinitionDataType switch %d", ErrCodec, d.Switch)
	}
	return b.Bytes(), b.Error()
}

// reserveV1 is PubSubReserveCommunicationIdsDataType (Part 81 §10.44.1).
type reserveV1 struct {
	TransportProfileURI    string
	NumReqWriterGroupIDs   uint16
	NumReqDataSetWriterIDs uint16
}

// reserveResultV1 is PubSubReserveCommunicationIdsResultDataType (Part 81
// §10.43.3).
type reserveResultV1 struct {
	Result             ua.StatusCode
	DefaultPublisherID *ua.Variant
	WriterGroupIDs     []uint16
	DataSetWriterIDs   []uint16
}
