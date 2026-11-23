// SPDX-License-Identifier: MIT

package uafx

import (
	"fmt"

	"github.com/otfabric/go-opcua/ua"
)

// The structures of the AC namespace are not registered with package ua:
// their encoding NodeIds have the namespace index of the server, which
// differs from server to server. The client keeps their body undecoded
// (ExtensionObject.RawBody), and Inspect decodes the few it reports with
// the namespace index the server has for AC.

// decodeAggregatedHealth decodes an AggregatedHealthDataType value (Part 81
// §10.1).
func decodeAggregatedHealth(v *ua.Variant, ac uint16) (*AggregatedHealth, error) {
	return decodeValue[*AggregatedHealth](v, ac, "AggregatedHealthDataType")
}

// decodeFxVersion decodes an FxVersion value (Part 81 §10.28).
func decodeFxVersion(v *ua.Variant, ac uint16) (*FxVersion, error) {
	return decodeValue[*FxVersion](v, ac, "FxVersion")
}

// decodeValue decodes the structure of the AC namespace (index ac) that the
// value v holds.
func decodeValue[T Structure](v *ua.Variant, ac uint16, name string) (T, error) {
	var zero T
	eo, ok := val(v).(*ua.ExtensionObject)
	if !ok || eo == nil {
		return zero, fmt.Errorf("%s: the value is a %T, not an ExtensionObject", name, val(v))
	}
	x, err := decodeAs[T](codec{NamespaceIndexes{AC: ac}}, eo)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", name, err)
	}
	return x, nil
}
