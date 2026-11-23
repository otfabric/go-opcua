// SPDX-License-Identifier: MIT

package uafx

import (
	"fmt"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

// The structures of the AC namespace are not registered with package ua:
// their encoding NodeIds have the namespace index of the server, which
// differs from server to server. The client keeps their body undecoded
// (ExtensionObject.RawBody), and Inspect decodes the few it reports with
// the namespace index the server has for AC.

// decodeAggregatedHealth decodes an AggregatedHealthDataType value (Part 81
// §10.1) in the binary encoding: a UInt16 DeviceHealthOptionSet followed by
// a UInt32 OperationalHealthOptionSet.
func decodeAggregatedHealth(v *ua.Variant, ac uint16) (*AggregatedHealth, error) {
	body, err := structBody(v, ac, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, "AggregatedHealthDataType")
	if err != nil {
		return nil, err
	}
	var w struct {
		Device      uint16
		Operational uint32
	}
	if err := decodeExact(body, &w); err != nil {
		return nil, fmt.Errorf("AggregatedHealthDataType: %w", err)
	}
	return &AggregatedHealth{AggregatedDeviceHealth: DeviceHealth(w.Device), AggregatedOperationalHealth: OperationalHealth(w.Operational)}, nil
}

// decodeFxVersion decodes an FxVersion value (Part 81 §10.28) in the binary
// encoding: four UInt16.
func decodeFxVersion(v *ua.Variant, ac uint16) (*FxVersion, error) {
	body, err := structBody(v, ac, fxacid.FxVersionEncodingDefaultBinary, "FxVersion")
	if err != nil {
		return nil, err
	}
	var ver FxVersion
	if err := decodeExact(body, &ver); err != nil {
		return nil, fmt.Errorf("FxVersion: %w", err)
	}
	return &ver, nil
}

// structBody returns the binary body of the ExtensionObject v holds, which
// must have the encoding NodeId ns=ac;i=encoding.
func structBody(v *ua.Variant, ac uint16, encoding uint32, name string) ([]byte, error) {
	eo, ok := val(v).(*ua.ExtensionObject)
	if !ok || eo == nil {
		return nil, fmt.Errorf("%s: the value is a %T, not an ExtensionObject", name, val(v))
	}
	if eo.EncodingMask != ua.ExtensionObjectBinary {
		return nil, fmt.Errorf("%s: the value is not in the binary encoding", name)
	}
	if eo.TypeID == nil || eo.TypeID.NodeID == nil || !eo.TypeID.NodeID.Equal(ua.NewNumericNodeID(ac, encoding)) {
		return nil, fmt.Errorf("%s: the value has the encoding %v, not ns=%d;i=%d", name, eo.TypeID, ac, encoding)
	}
	switch body := eo.Value.(type) {
	case []byte:
		return body, nil
	case nil:
		return eo.RawBody, nil
	}
	return nil, fmt.Errorf("%s: the value decoded as a %T", name, eo.Value)
}

// decodeExact decodes b into v, which must take all of b.
func decodeExact(b []byte, v any) error {
	n, err := ua.Decode(b, v)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("%d bytes after the structure", len(b)-n)
	}
	return nil
}
