// SPDX-License-Identifier: MIT

package uafx

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// ErrCodec reports a UAFX structure that cannot be encoded or decoded.
var ErrCodec = errors.New("uafx: codec")

// The arguments of EstablishConnections and CloseConnections are
// structures of the UAFX Data namespace (Part 81 §10). Their encoding
// NodeIds have the index the server gives that namespace, so package ua
// cannot register them: the functions here take that index, data, and
// encode each structure in an ExtensionObject (Part 6 §5.2.2.15) whose body
// is the binary encoding of Part 6 §5.2.6: the fields in the order of the
// definition, those of a subtype (PubSubConnectionEndpointParameterDataType,
// PubSubReserveCommunicationIds2DataType, ...) after those of its supertype,
// which the UAFX NodeSet does not repeat in the definition of the subtype.
// A field whose DataType is abstract (AllowSubTypes) is an ExtensionObject
// of its own, the union ConnectionEndpointDefinitionDataType a UInt32
// switch field and the selected field (Part 6 §5.2.8).

// EncodeEstablishConnectionsRequest returns the input arguments of
// EstablishConnections for the UAFX Data namespace index data.
func EncodeEstablishConnectionsRequest(r *EstablishConnectionsRequest, data uint16) ([]*ua.Variant, error) {
	c := codec{data}
	av, err := encodeAll(c, r.AssetVerifications, func(v *AssetVerification) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.AssetVerificationDataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	cfgs, err := encodeAll(c, r.ConnectionEndpointConfigurations, c.endpointConfiguration)
	if err != nil {
		return nil, err
	}
	res, err := encodeAll(c, r.ReserveCommunicationIDs, func(v *PubSubReserveCommunicationIDs) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.PubSubReserveCommunicationIDs2DataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	comm, err := encodeAll(c, r.CommunicationConfigurations, func(v *PubSubCommunicationConfiguration) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.PubSubCommunicationConfigurationDataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	return []*ua.Variant{ua.MustVariant(uint32(r.CommandMask)), ua.MustVariant(av), ua.MustVariant(cfgs), ua.MustVariant(res), ua.MustVariant(comm)}, nil
}

// DecodeEstablishConnectionsRequest decodes the input arguments of
// EstablishConnections for the UAFX Data namespace index data.
func DecodeEstablishConnectionsRequest(args []*ua.Variant, data uint16) (*EstablishConnectionsRequest, error) {
	if len(args) != 5 {
		return nil, fmt.Errorf("%w: EstablishConnections has 5 input arguments, not %d", ErrCodec, len(args))
	}
	mask, ok := val(args[0]).(uint32)
	if !ok {
		return nil, fmt.Errorf("%w: CommandMask is a %T, not a UInt32", ErrCodec, val(args[0]))
	}
	c := codec{data}
	r := &EstablishConnectionsRequest{CommandMask: FxCommandMask(mask)}
	var err error
	if r.AssetVerifications, err = decodeAll(c, args[1], "AssetVerifications", func(eo *ua.ExtensionObject) (*AssetVerification, error) {
		v := new(AssetVerification)
		return v, c.decode(eo, v, fxdataid.AssetVerificationDataTypeEncodingDefaultBinary)
	}); err != nil {
		return nil, err
	}
	if r.ConnectionEndpointConfigurations, err = decodeAll(c, args[2], "ConnectionEndpointConfigurations", c.decodeEndpointConfiguration); err != nil {
		return nil, err
	}
	if r.ReserveCommunicationIDs, err = decodeAll(c, args[3], "ReserveCommunicationIds", c.decodeReserve); err != nil {
		return nil, err
	}
	if r.CommunicationConfigurations, err = decodeAll(c, args[4], "CommunicationConfigurations", func(eo *ua.ExtensionObject) (*PubSubCommunicationConfiguration, error) {
		v := new(PubSubCommunicationConfiguration)
		return v, c.decode(eo, v, fxdataid.PubSubCommunicationConfigurationDataTypeEncodingDefaultBinary)
	}); err != nil {
		return nil, err
	}
	return r, nil
}

// EncodeEstablishConnectionsResult returns the output arguments of
// EstablishConnections for the UAFX Data namespace index data. The Status
// of r is the status of the call, not an argument.
func EncodeEstablishConnectionsResult(r *EstablishConnectionsResult, data uint16) ([]*ua.Variant, error) {
	c := codec{data}
	av, err := encodeAll(c, r.AssetVerificationResults, func(v *AssetVerificationResultData) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.AssetVerificationResultDataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	cfgs, err := encodeAll(c, r.ConnectionEndpointConfigurationResults, func(v *ConnectionEndpointConfigurationResult) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.ConnectionEndpointConfigurationResultDataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	res, err := encodeAll(c, r.ReserveCommunicationIDsResults, func(v *PubSubReserveCommunicationIDsResult) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.PubSubReserveCommunicationIDsResult2DataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	comm, err := encodeAll(c, r.CommunicationConfigurationResults, func(v *PubSubCommunicationConfigurationResult) (*ua.ExtensionObject, error) {
		return c.eo(fxdataid.PubSubCommunicationConfigurationResultDataTypeEncodingDefaultBinary, v)
	})
	if err != nil {
		return nil, err
	}
	return []*ua.Variant{ua.MustVariant(av), ua.MustVariant(cfgs), ua.MustVariant(res), ua.MustVariant(comm)}, nil
}

// DecodeEstablishConnectionsResult decodes the output arguments of
// EstablishConnections for the UAFX Data namespace index data. It leaves
// Status, the status of the call, to the caller.
func DecodeEstablishConnectionsResult(out []*ua.Variant, data uint16) (*EstablishConnectionsResult, error) {
	if len(out) != 4 {
		return nil, fmt.Errorf("%w: EstablishConnections has 4 output arguments, not %d", ErrCodec, len(out))
	}
	c := codec{data}
	r := new(EstablishConnectionsResult)
	var err error
	if r.AssetVerificationResults, err = decodeAll(c, out[0], "AssetVerificationResults", func(eo *ua.ExtensionObject) (*AssetVerificationResultData, error) {
		v := new(AssetVerificationResultData)
		return v, c.decode(eo, v, fxdataid.AssetVerificationResultDataTypeEncodingDefaultBinary)
	}); err != nil {
		return nil, err
	}
	if r.ConnectionEndpointConfigurationResults, err = decodeAll(c, out[1], "ConnectionEndpointConfigurationResults", func(eo *ua.ExtensionObject) (*ConnectionEndpointConfigurationResult, error) {
		v := new(ConnectionEndpointConfigurationResult)
		return v, c.decode(eo, v, fxdataid.ConnectionEndpointConfigurationResultDataTypeEncodingDefaultBinary)
	}); err != nil {
		return nil, err
	}
	if r.ReserveCommunicationIDsResults, err = decodeAll(c, out[2], "ReserveCommunicationIdsResults", c.decodeReserveResult); err != nil {
		return nil, err
	}
	if r.CommunicationConfigurationResults, err = decodeAll(c, out[3], "CommunicationConfigurationResults", func(eo *ua.ExtensionObject) (*PubSubCommunicationConfigurationResult, error) {
		v := new(PubSubCommunicationConfigurationResult)
		return v, c.decode(eo, v, fxdataid.PubSubCommunicationConfigurationResultDataTypeEncodingDefaultBinary)
	}); err != nil {
		return nil, err
	}
	return r, nil
}

// codec encodes and decodes the structures of the UAFX Data namespace,
// whose index on the server is data.
type codec struct{ data uint16 }

// eo returns v in an ExtensionObject with the encoding NodeId ns=data;i=enc.
func (c codec) eo(enc uint32, v any) (*ua.ExtensionObject, error) {
	body, err := ua.Encode(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %T: %w", ErrCodec, v, err)
	}
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(c.data, enc),
		Value:        body,
	}, nil
}

// nullEO is the null ExtensionObject of an abstract field that is not set.
func nullEO() *ua.ExtensionObject {
	return &ua.ExtensionObject{TypeID: ua.NewTwoByteExpandedNodeID(0), EncodingMask: ua.ExtensionObjectEmpty}
}

// isNull reports whether eo is a null ExtensionObject.
func isNull(eo *ua.ExtensionObject) bool {
	return eo == nil || eo.EncodingMask == ua.ExtensionObjectEmpty && (eo.TypeID == nil || eo.TypeID.NodeID == nil || eo.TypeID.NodeID.Equal(ua.NewTwoByteNodeID(0)))
}

// body returns the encoding id and the binary body of eo, a structure of
// the Data namespace.
func (c codec) body(eo *ua.ExtensionObject) (uint32, []byte, error) {
	if eo == nil || eo.TypeID == nil || eo.TypeID.NodeID == nil {
		return 0, nil, fmt.Errorf("%w: an ExtensionObject without a type", ErrCodec)
	}
	id := eo.TypeID.NodeID
	if eo.TypeID.NamespaceURI != "" || id.Namespace() != c.data || id.Type() != ua.NodeIDTypeNumeric && id.Type() != ua.NodeIDTypeFourByte && id.Type() != ua.NodeIDTypeTwoByte {
		return 0, nil, fmt.Errorf("%w: the encoding %v is not in the UAFX Data namespace (ns=%d)", ErrCodec, eo.TypeID, c.data)
	}
	if eo.EncodingMask != ua.ExtensionObjectBinary {
		return 0, nil, fmt.Errorf("%w: %v is not in the binary encoding", ErrCodec, id)
	}
	switch b := eo.Value.(type) {
	case nil:
		return id.IntID(), eo.RawBody, nil
	case []byte:
		return id.IntID(), b, nil
	}
	return 0, nil, fmt.Errorf("%w: %v decoded as a %T", ErrCodec, id, eo.Value)
}

// decode decodes eo, which must have the encoding enc, into v.
func (c codec) decode(eo *ua.ExtensionObject, v any, enc uint32) error {
	got, b, err := c.body(eo)
	if err != nil {
		return err
	}
	if got != enc {
		return fmt.Errorf("%w: %T: the encoding is i=%d, not i=%d", ErrCodec, v, got, enc)
	}
	if err := decodeExact(b, v); err != nil {
		return fmt.Errorf("%w: %T: %w", ErrCodec, v, err)
	}
	return nil
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

// Decode implements ua.BinaryDecoder.
func (d *definitionWire) Decode(data []byte) (int, error) {
	b := ua.NewBuffer(data)
	d.Switch = b.ReadUint32()
	switch d.Switch {
	case 0:
	case 1:
		d.Parameter = new(ua.ExtensionObject)
		b.ReadStruct(d.Parameter)
	case 2:
		d.Node = new(ua.NodeID)
		b.ReadStruct(d.Node)
	default:
		if b.Error() == nil {
			return b.Pos(), fmt.Errorf("%w: ConnectionEndpointDefinitionDataType switch %d", ErrCodec, d.Switch)
		}
	}
	return b.Pos(), b.Error()
}

func (c codec) endpointConfiguration(v *ConnectionEndpointConfiguration) (*ua.ExtensionObject, error) {
	w := &endpointConfigurationWire{
		FunctionalEntityNode:          v.FunctionalEntityNode,
		ConnectionEndpoint:            &definitionWire{},
		ExpectedVerificationVariables: v.ExpectedVerificationVariables,
		ControlGroups:                 v.ControlGroups,
		ConfigurationData:             v.ConfigurationData,
		CommunicationLinks:            nullEO(),
	}
	if d := v.ConnectionEndpoint; d != nil {
		switch {
		case d.Parameter != nil && d.Node != nil:
			return nil, fmt.Errorf("%w: a ConnectionEndpointDefinition has both Parameter and Node", ErrCodec)
		case d.Parameter != nil:
			eo, err := c.eo(fxdataid.PubSubConnectionEndpointParameterDataTypeEncodingDefaultBinary, d.Parameter)
			if err != nil {
				return nil, err
			}
			w.ConnectionEndpoint = &definitionWire{Switch: 1, Parameter: eo}
		case d.Node != nil:
			w.ConnectionEndpoint = &definitionWire{Switch: 2, Node: d.Node}
		}
	}
	if v.CommunicationLinks != nil {
		eo, err := c.eo(fxdataid.PubSubCommunicationLinkConfigurationDataTypeEncodingDefaultBinary, v.CommunicationLinks)
		if err != nil {
			return nil, err
		}
		w.CommunicationLinks = eo
	}
	return c.eo(fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary, w)
}

func (c codec) decodeEndpointConfiguration(eo *ua.ExtensionObject) (*ConnectionEndpointConfiguration, error) {
	var w endpointConfigurationWire
	if err := c.decode(eo, &w, fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary); err != nil {
		return nil, err
	}
	v := &ConnectionEndpointConfiguration{
		FunctionalEntityNode:          w.FunctionalEntityNode,
		ExpectedVerificationVariables: w.ExpectedVerificationVariables,
		ControlGroups:                 w.ControlGroups,
		ConfigurationData:             w.ConfigurationData,
	}
	if d := w.ConnectionEndpoint; d != nil {
		switch d.Switch {
		case 1:
			if isNull(d.Parameter) {
				return nil, fmt.Errorf("%w: ConnectionEndpointDefinitionDataType: a null Parameter", ErrCodec)
			}
			p := new(PubSubConnectionEndpointParameter)
			if err := c.decode(d.Parameter, p, fxdataid.PubSubConnectionEndpointParameterDataTypeEncodingDefaultBinary); err != nil {
				return nil, err
			}
			v.ConnectionEndpoint = &ConnectionEndpointDefinition{Parameter: p}
		case 2:
			v.ConnectionEndpoint = &ConnectionEndpointDefinition{Node: d.Node}
		}
	}
	if !isNull(w.CommunicationLinks) {
		l := new(PubSubCommunicationLinkConfiguration)
		if err := c.decode(w.CommunicationLinks, l, fxdataid.PubSubCommunicationLinkConfigurationDataTypeEncodingDefaultBinary); err != nil {
			return nil, err
		}
		v.CommunicationLinks = l
	}
	return v, nil
}

// reserveV1 is PubSubReserveCommunicationIdsDataType (Part 81 §10.44.1).
type reserveV1 struct {
	TransportProfileURI    string
	NumReqWriterGroupIDs   uint16
	NumReqDataSetWriterIDs uint16
}

func (c codec) decodeReserve(eo *ua.ExtensionObject) (*PubSubReserveCommunicationIDs, error) {
	enc, _, err := c.body(eo)
	if err != nil {
		return nil, err
	}
	v := new(PubSubReserveCommunicationIDs)
	if enc == fxdataid.PubSubReserveCommunicationIDsDataTypeEncodingDefaultBinary {
		var w reserveV1
		if err := c.decode(eo, &w, enc); err != nil {
			return nil, err
		}
		*v = PubSubReserveCommunicationIDs{TransportProfileURI: w.TransportProfileURI, NumReqWriterGroupIDs: w.NumReqWriterGroupIDs, NumReqDataSetWriterIDs: w.NumReqDataSetWriterIDs}
		return v, nil
	}
	return v, c.decode(eo, v, fxdataid.PubSubReserveCommunicationIDs2DataTypeEncodingDefaultBinary)
}

// reserveResultV1 is PubSubReserveCommunicationIdsResultDataType (Part 81
// §10.43.3).
type reserveResultV1 struct {
	Result             ua.StatusCode
	DefaultPublisherID *ua.Variant
	WriterGroupIDs     []uint16
	DataSetWriterIDs   []uint16
}

func (c codec) decodeReserveResult(eo *ua.ExtensionObject) (*PubSubReserveCommunicationIDsResult, error) {
	enc, _, err := c.body(eo)
	if err != nil {
		return nil, err
	}
	v := new(PubSubReserveCommunicationIDsResult)
	if enc == fxdataid.PubSubReserveCommunicationIDsResultDataTypeEncodingDefaultBinary {
		var w reserveResultV1
		if err := c.decode(eo, &w, enc); err != nil {
			return nil, err
		}
		*v = PubSubReserveCommunicationIDsResult{Result: w.Result, DefaultPublisherID: w.DefaultPublisherID, WriterGroupIDs: w.WriterGroupIDs, DataSetWriterIDs: w.DataSetWriterIDs}
		return v, nil
	}
	return v, c.decode(eo, v, fxdataid.PubSubReserveCommunicationIDsResult2DataTypeEncodingDefaultBinary)
}

// encodeAll encodes the elements of vs, which must not be nil.
func encodeAll[T any](_ codec, vs []*T, f func(*T) (*ua.ExtensionObject, error)) ([]*ua.ExtensionObject, error) {
	out := make([]*ua.ExtensionObject, len(vs))
	for i, v := range vs {
		if v == nil {
			return nil, fmt.Errorf("%w: element %d of a %T array is nil", ErrCodec, i, v)
		}
		eo, err := f(v)
		if err != nil {
			return nil, err
		}
		out[i] = eo
	}
	return out, nil
}

// decodeAll decodes the ExtensionObject array of v, which may be null.
func decodeAll[T any](_ codec, v *ua.Variant, name string, f func(*ua.ExtensionObject) (*T, error)) ([]*T, error) {
	var eos []*ua.ExtensionObject
	switch x := val(v).(type) {
	case nil:
		return nil, nil
	case []*ua.ExtensionObject:
		eos = x
	default:
		return nil, fmt.Errorf("%w: %s is a %T, not an array of structures", ErrCodec, name, x)
	}
	out := make([]*T, len(eos))
	for i, eo := range eos {
		x, err := f(eo)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		out[i] = x
	}
	return out, nil
}
