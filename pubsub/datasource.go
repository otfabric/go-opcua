// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// MemoryDataSource is a [DataSource] that publishes values the application
// sets, for publishers that run without an OPC UA server. It honours the
// IndexRange of the published variables; only the Value attribute exists.
type MemoryDataSource struct {
	mu     sync.RWMutex
	values map[string]*ua.DataValue
	meta   map[string]*ua.FieldMetaData
}

// NewMemoryDataSource returns an empty MemoryDataSource.
func NewMemoryDataSource() *MemoryDataSource {
	return &MemoryDataSource{values: map[string]*ua.DataValue{}, meta: map[string]*ua.FieldMetaData{}}
}

// Set sets the value of a variable. v is a *ua.DataValue, a *ua.Variant or
// a value ua.NewVariant accepts; the source timestamp is set to now if v
// has none.
func (m *MemoryDataSource) Set(nodeID *ua.NodeID, v any) error {
	var dv *ua.DataValue
	switch x := v.(type) {
	case *ua.DataValue:
		cp := *x
		dv = &cp
	case *ua.Variant:
		dv = &ua.DataValue{Value: x}
	default:
		vv, err := ua.NewVariant(v)
		if err != nil {
			return err
		}
		dv = &ua.DataValue{Value: vv}
	}
	if dv.SourceTimestamp.IsZero() {
		dv.SourceTimestamp = time.Now()
	}
	dv.UpdateMask()
	m.mu.Lock()
	m.values[nodeID.String()] = dv
	if dv.Value != nil && dv.Value.Value() != nil {
		vr := int32(-1)
		if dv.Value.IsArray() {
			vr = 1
		}
		m.meta[nodeID.String()] = &ua.FieldMetaData{
			BuiltInType: uint8(dv.Value.Type()),
			DataType:    ua.NewNumericNodeID(0, uint32(dv.Value.Type())),
			ValueRank:   vr,
		}
	}
	m.mu.Unlock()
	return nil
}

// ReadPublishedData implements [DataSource].
func (m *MemoryDataSource) ReadPublishedData(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
	out := make([]*ua.DataValue, len(vars))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i, v := range vars {
		dv := m.values[v.PublishedVariable.String()]
		switch {
		case dv == nil:
			out[i] = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNodeIDUnknown}
		case v.AttributeID != ua.AttributeIDValue:
			out[i] = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadAttributeIDInvalid}
		case v.IndexRange != "":
			sliced, sc := ua.SliceVariantRead(dv.Value, v.IndexRange)
			if sc != ua.StatusOK {
				out[i] = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: sc}
				continue
			}
			cp := *dv
			cp.Value = sliced
			out[i] = &cp
		default:
			out[i] = dv
		}
	}
	return out
}

// FieldMetaData implements [FieldMetaDataResolver] from the type of the value
// that was set.
func (m *MemoryDataSource) FieldMetaData(v *ua.PublishedVariableDataType) *ua.FieldMetaData {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f := m.meta[v.PublishedVariable.String()]
	if f == nil || v.IndexRange != "" {
		return nil
	}
	cp := *f
	return &cp
}
