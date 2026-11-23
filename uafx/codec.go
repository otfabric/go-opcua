// SPDX-License-Identifier: MIT

package uafx

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/ua"
)

// ErrCodec reports a UAFX structure that cannot be encoded or decoded.
var ErrCodec = errors.New("uafx: codec")

// The arguments of EstablishConnections are structures of the UAFX Data
// namespace (Part 81 §10), which the functions here encode with the index
// data the server has for that namespace (see Structure).

// EncodeEstablishConnectionsRequest returns the input arguments of
// EstablishConnections for the UAFX Data namespace index data.
func EncodeEstablishConnectionsRequest(r *EstablishConnectionsRequest, data uint16) ([]*ua.Variant, error) {
	c := dataCodec(data)
	av, err := encodeAll(c, r.AssetVerifications)
	if err != nil {
		return nil, err
	}
	cfgs, err := encodeAll(c, r.ConnectionEndpointConfigurations)
	if err != nil {
		return nil, err
	}
	res, err := encodeAll(c, r.ReserveCommunicationIDs)
	if err != nil {
		return nil, err
	}
	comm, err := encodeAll(c, r.CommunicationConfigurations)
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
	c := dataCodec(data)
	r := &EstablishConnectionsRequest{CommandMask: FxCommandMask(mask)}
	var err error
	if r.AssetVerifications, err = decodeAll[*AssetVerification](c, args[1], "AssetVerifications"); err != nil {
		return nil, err
	}
	if r.ConnectionEndpointConfigurations, err = decodeAll[*ConnectionEndpointConfiguration](c, args[2], "ConnectionEndpointConfigurations"); err != nil {
		return nil, err
	}
	if r.ReserveCommunicationIDs, err = decodeAllWith(c, args[3], "ReserveCommunicationIds", c.decodeReserve); err != nil {
		return nil, err
	}
	if r.CommunicationConfigurations, err = decodeAll[*PubSubCommunicationConfiguration](c, args[4], "CommunicationConfigurations"); err != nil {
		return nil, err
	}
	return r, nil
}

// EncodeEstablishConnectionsResult returns the output arguments of
// EstablishConnections for the UAFX Data namespace index data. The Status
// of r is the status of the call, not an argument.
func EncodeEstablishConnectionsResult(r *EstablishConnectionsResult, data uint16) ([]*ua.Variant, error) {
	c := dataCodec(data)
	av, err := encodeAll(c, r.AssetVerificationResults)
	if err != nil {
		return nil, err
	}
	cfgs, err := encodeAll(c, r.ConnectionEndpointConfigurationResults)
	if err != nil {
		return nil, err
	}
	res, err := encodeAll(c, r.ReserveCommunicationIDsResults)
	if err != nil {
		return nil, err
	}
	comm, err := encodeAll(c, r.CommunicationConfigurationResults)
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
	c := dataCodec(data)
	r := new(EstablishConnectionsResult)
	var err error
	if r.AssetVerificationResults, err = decodeAll[*AssetVerificationResultData](c, out[0], "AssetVerificationResults"); err != nil {
		return nil, err
	}
	if r.ConnectionEndpointConfigurationResults, err = decodeAll[*ConnectionEndpointConfigurationResult](c, out[1], "ConnectionEndpointConfigurationResults"); err != nil {
		return nil, err
	}
	if r.ReserveCommunicationIDsResults, err = decodeAllWith(c, out[2], "ReserveCommunicationIdsResults", c.decodeReserveResult); err != nil {
		return nil, err
	}
	if r.CommunicationConfigurationResults, err = decodeAll[*PubSubCommunicationConfigurationResult](c, out[3], "CommunicationConfigurationResults"); err != nil {
		return nil, err
	}
	return r, nil
}

// dataCodec is the codec of a server whose Data namespace has the index
// data; the arguments of EstablishConnections have no structures of the
// other UAFX namespaces.
func dataCodec(data uint16) codec { return codec{NamespaceIndexes{Data: data}} }

// decodeReserve decodes a PubSubReserveCommunicationIds2DataType or the
// older PubSubReserveCommunicationIdsDataType (Part 81 §10.44.1), which
// has no RequestTransportSpecificInfo.
func (c codec) decodeReserve(eo *ua.ExtensionObject) (*PubSubReserveCommunicationIDs, error) {
	v, err := decodeAs[ReserveCommunicationIDs](c, eo)
	if err != nil {
		return nil, err
	}
	if v1, ok := v.(*PubSubReserveCommunicationIDs1); ok {
		return &PubSubReserveCommunicationIDs{TransportProfileURI: v1.TransportProfileURI, NumReqWriterGroupIDs: v1.NumReqWriterGroupIDs, NumReqDataSetWriterIDs: v1.NumReqDataSetWriterIDs}, nil
	}
	return v.(*PubSubReserveCommunicationIDs), nil
}

// decodeReserveResult decodes a PubSubReserveCommunicationIdsResult2DataType
// or the older PubSubReserveCommunicationIdsResultDataType (Part 81
// §10.43.3), which has no TransportSpecificInfo.
func (c codec) decodeReserveResult(eo *ua.ExtensionObject) (*PubSubReserveCommunicationIDsResult, error) {
	v, err := decodeAs[ReserveCommunicationIDsResult](c, eo)
	if err != nil {
		return nil, err
	}
	if v1, ok := v.(*PubSubReserveCommunicationIDsResult1); ok {
		return &PubSubReserveCommunicationIDsResult{Result: v1.Result, DefaultPublisherID: v1.DefaultPublisherID, WriterGroupIDs: v1.WriterGroupIDs, DataSetWriterIDs: v1.DataSetWriterIDs}, nil
	}
	return v.(*PubSubReserveCommunicationIDsResult), nil
}

// encodeAll encodes the elements of vs, which must not be nil.
func encodeAll[T Structure](c codec, vs []T) ([]*ua.ExtensionObject, error) {
	out := make([]*ua.ExtensionObject, len(vs))
	for i, v := range vs {
		if isNil(v) {
			return nil, fmt.Errorf("%w: element %d of a %T array is nil", ErrCodec, i, v)
		}
		eo, err := c.encode(v)
		if err != nil {
			return nil, err
		}
		out[i] = eo
	}
	return out, nil
}

// decodeAll decodes the ExtensionObject array of v, which may be null, as
// structures of type T.
func decodeAll[T Structure](c codec, v *ua.Variant, name string) ([]T, error) {
	return decodeAllWith(c, v, name, func(eo *ua.ExtensionObject) (T, error) { return decodeAs[T](c, eo) })
}

func decodeAllWith[T any](_ codec, v *ua.Variant, name string, f func(*ua.ExtensionObject) (T, error)) ([]T, error) {
	var eos []*ua.ExtensionObject
	switch x := val(v).(type) {
	case nil:
		return nil, nil
	case []*ua.ExtensionObject:
		eos = x
	default:
		return nil, fmt.Errorf("%w: %s is a %T, not an array of structures", ErrCodec, name, x)
	}
	out := make([]T, len(eos))
	for i, eo := range eos {
		x, err := f(eo)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		out[i] = x
	}
	return out, nil
}
