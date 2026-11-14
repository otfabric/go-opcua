// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// dataSetMessages is a ua-data NetworkMessage of n DataSetMessages of
// writer 1, each with the one field named field.
func dataSetMessages(n int, field string) []byte {
	var b strings.Builder
	b.WriteString(`{"MessageType":"ua-data","PublisherId":"7","Messages":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"DataSetWriterId":1,"Payload":{%q:%d}}`, field, i)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

// TestDecodeIndexesMetaDataOncePerMessage: the DataSetMessages of a
// NetworkMessage share the index of the field names of their
// DataSetMetaData, so decoding the most DataSetMessages a NetworkMessage
// may have against the largest DataSetMetaData stays within a budget.
func TestDecodeIndexesMetaDataOncePerMessage(t *testing.T) {
	md := &ua.DataSetMetaDataType{Fields: make([]*ua.FieldMetaData, DefaultMaxFields)}
	for i := range md.Fields {
		md.Fields[i] = &ua.FieldMetaData{Name: fmt.Sprintf("f%d", i), BuiltInType: byte(ua.TypeIDInt64), ValueRank: -1}
	}
	lookups := 0
	opts := &DecodeOptions{MetaData: func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType {
		lookups++
		return md
	}}
	last := fmt.Sprintf("f%d", DefaultMaxFields-1)
	for _, n := range []int{1, 64, DefaultMaxDataSetMessages} {
		in := dataSetMessages(n, last)
		lookups = 0
		var nm *message.NetworkMessage
		var err error
		alloc := allocatedBytes(func() { nm, err = Decode(in, opts) })
		require.NoError(t, err)
		require.Len(t, nm.Messages, n)
		require.Equal(t, n, lookups)
		require.Less(t, alloc, uint64(64<<20), "bytes allocated for %d DataSetMessages against %d fields", n, len(md.Fields))
		for i, dsm := range nm.Messages {
			require.Len(t, dsm.Fields, 1)
			require.EqualValues(t, DefaultMaxFields-1, dsm.Fields[0].Index)
			require.Equal(t, int64(i), dsm.Fields[0].Value.Value.Value())
		}
	}
}

// TestDecodeFieldNamesPerMetaData: within one NetworkMessage, each
// DataSetMessage is matched to the DataSetMetaData of its own writer; a
// name several fields share is the last of them.
func TestDecodeFieldNamesPerMetaData(t *testing.T) {
	t.Parallel()
	field := func(name string) *ua.FieldMetaData {
		return &ua.FieldMetaData{Name: name, BuiltInType: byte(ua.TypeIDInt64), ValueRank: -1}
	}
	mds := map[uint16]*ua.DataSetMetaDataType{
		1: {Fields: []*ua.FieldMetaData{field("a"), field("b"), field("c")}},
		2: {Fields: []*ua.FieldMetaData{field("c"), nil, field("a")}},
		3: {Fields: []*ua.FieldMetaData{field("a"), field("x"), field("a")}},
	}
	opts := &DecodeOptions{MetaData: func(_ message.PublisherID, _, w uint16) *ua.DataSetMetaDataType {
		return mds[w]
	}}
	in := `{"MessageType":"ua-data","PublisherId":"7","Messages":[
		{"DataSetWriterId":1,"Payload":{"c":1,"a":2}},
		{"DataSetWriterId":2,"Payload":{"a":3,"c":4}},
		{"DataSetWriterId":1,"Payload":{"b":5}},
		{"DataSetWriterId":3,"Payload":{"a":6,"x":7}},
		{"DataSetWriterId":2,"Payload":{"c":8}}]}`
	nm, err := Decode([]byte(in), opts)
	require.NoError(t, err)
	type got struct {
		index uint16
		value int64
	}
	var out [][]got
	for _, dsm := range nm.Messages {
		var fs []got
		for _, f := range dsm.Fields {
			fs = append(fs, got{f.Index, f.Value.Value.Value().(int64)})
		}
		out = append(out, fs)
	}
	require.Equal(t, [][]got{
		{{0, 2}, {2, 1}},
		{{0, 4}, {2, 3}},
		{{1, 5}},
		{{1, 7}, {2, 6}},
		{{0, 8}},
	}, out)

	_, err = Decode([]byte(`{"MessageType":"ua-data","PublisherId":"7","Messages":[{"DataSetWriterId":2,"Payload":{"b":1}}]}`), opts)
	require.ErrorIs(t, err, ErrDecode, "a field the metadata does not have")
}

// TestDecodeFieldNameIndexesAreBounded: the indexes of one message cover
// at most maxIndexedFields fields, also when every DataSetMessage is
// matched to a DataSetMetaData of its own, and the index of a
// DataSetMetaData is reused.
func TestDecodeFieldNameIndexesAreBounded(t *testing.T) {
	t.Parallel()
	fields := make([]*ua.FieldMetaData, DefaultMaxFields)
	for i := range fields {
		fields[i] = &ua.FieldMetaData{Name: fmt.Sprintf("f%d", i)}
	}
	d := &decoder{}
	covered := func() int {
		n := 0
		for md := range d.names {
			n += len(md.Fields)
		}
		return n
	}
	first := &ua.DataSetMetaDataType{Fields: fields}
	d.fieldNames(first)
	for k := range 3 * maxIndexedFields / DefaultMaxFields {
		md := &ua.DataSetMetaDataType{Fields: fields}
		require.Len(t, d.fieldNames(md), DefaultMaxFields)
		require.LessOrEqual(t, covered(), maxIndexedFields, "after %d DataSetMetaData", k+2)
		require.Equal(t, covered(), d.indexed)
	}

	d = &decoder{}
	index := d.fieldNames(first)
	require.Equal(t, reflect.ValueOf(index).UnsafePointer(), reflect.ValueOf(d.fieldNames(first)).UnsafePointer(), "the index is reused")
	require.Equal(t, DefaultMaxFields, d.indexed)
}
