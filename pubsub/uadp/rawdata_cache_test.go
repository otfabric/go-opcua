// SPDX-License-Identifier: MIT

package uadp

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// cachedStructTypes is the number of entries of the structure type cache.
func cachedStructTypes() int {
	n := 0
	structTypes.Range(func(any, any) bool { n++; return true })
	return n
}

// TestRawDataUnknownStructureTypesAreNotCached: decoding RawData structures
// of DataTypes without a registered Go type, each with its own DataType and
// DefaultEncodingId NodeId, leaves the structure type cache as it was and
// keeps nothing alive; a registered type is cached once. It does not run in
// parallel: it measures the live heap.
func TestRawDataUnknownStructureTypesAreNotCached(t *testing.T) {
	const decodes = 100_000
	msg := h(t, "01 03 01")
	decode := func(k uint32) error {
		dt := ua.NewNumericNodeID(3, 2_000_000+k)
		md := &ua.DataSetMetaDataType{
			StructureDataTypes: []*ua.StructureDescription{{
				DataTypeID:          dt,
				StructureDefinition: &ua.StructureDefinition{DefaultEncodingID: ua.NewNumericNodeID(3, 3_000_000+k)},
			}},
			Fields: []*ua.FieldMetaData{{Name: "s", BuiltInType: uint8(ua.TypeIDExtensionObject), DataType: dt, ValueRank: -1}},
		}
		_, err := Decode(msg, &DecodeOptions{MetaData: metaLookup(md)})
		return err
	}
	require.ErrorIs(t, decode(0), ErrUnsupported)

	entries := cachedStructTypes()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for k := range uint32(decodes) {
		if err := decode(k); err == nil {
			t.Fatalf("decode %d: a structure of an unknown DataType decoded", k)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	require.Equal(t, entries, cachedStructTypes(), "cache entries after %d decodes of unknown DataTypes", decodes)
	require.Less(t, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(4<<20), "live heap grown by %d decodes of unknown DataTypes", decodes)

	// A registered type is found by its encoding NodeId and cached.
	enc := ua.NewNumericNodeID(0, id.RangeEncodingDefaultBinary)
	require.Equal(t, "Range", lookupStructType(enc).Name())
	cached, ok := structTypes.Load(enc.String())
	require.True(t, ok)
	require.Equal(t, lookupStructType(enc), cached)
	require.Nil(t, lookupStructType(ua.NewNumericNodeID(3, 1)))
	_, ok = structTypes.Load(ua.NewNumericNodeID(3, 1).String())
	require.False(t, ok)
}
