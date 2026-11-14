// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// namedMetaData is a DataSetMetaData of n Int32 fields named f0, f1, ...
func namedMetaData(n int, major uint32) *ua.DataSetMetaDataType {
	md := MetaData("pds")
	md.Fields = make([]*ua.FieldMetaData, n)
	for i := range md.Fields {
		md.Fields[i] = Field{Name: fmt.Sprintf("f%d", i), Type: ua.TypeIDInt32}.metaData()
	}
	md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: major, MinorVersion: 1}
	return md
}

func int32Value(v int32) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
}

// TestJSONFieldNamesAreLookedUp: a reader finds the fields of a JSON
// DataSetMessage by name in an index of its DataSetMetaData, built once per
// DataSetMetaData: per field of a message one name is compared, whatever
// the number of fields of the metadata. It does not run in parallel: it
// sets the test seam nameCompared.
func TestJSONFieldNamesAreLookedUp(t *testing.T) {
	const mdFields, msgFields = 65000, 20000
	rec := &recorder{}
	p, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", memURL(t), nil),
		ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, namedMetaData(mdFields, 1))))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	rid := mustID(t, p, KindDataSetReader, mustID(t, p, KindReaderGroup, mustID(t, p, KindConnection, Root, "sub"), "rg"), "r")
	r := p.comps[rid].(*dataSetReader)

	var compared atomic.Int64
	nameCompared = func() { compared.Add(1) }
	t.Cleanup(func() { nameCompared = nil })

	// The fields of the message are the last ones of the metadata, in
	// reverse order, and one the metadata does not have.
	dsm := &message.DataSetMessage{DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true}
	for k := range msgFields {
		dsm.Fields = append(dsm.Fields, &message.Field{Name: fmt.Sprintf("f%d", mdFields-1-k), Value: int32Value(int32(k))})
	}
	dsm.Fields = append(dsm.Fields, &message.Field{Name: "unknown", Value: int32Value(-1)})
	nm := &message.NetworkMessage{Type: message.NetworkMessageDataSet, PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7), Messages: []*message.DataSetMessage{dsm}}

	process := func() {
		p.lock()
		p.processDSM(r, nm, dsm, encJSON, time.Now())
		p.unlock()
	}
	process()
	require.LessOrEqual(t, compared.Load(), int64(msgFields), "names compared for %d fields against %d", msgFields, mdFields)
	require.Len(t, rec.dataSets(), 1)
	ds := rec.dataSets()[0]
	require.Len(t, ds.Fields, mdFields)
	require.Len(t, ds.Changed, msgFields+1)
	for k := range msgFields {
		f := ds.Fields[mdFields-1-k]
		require.Equal(t, fmt.Sprintf("f%d", mdFields-1-k), f.Name)
		require.Equal(t, int32(k), f.Value.Value.Value())
	}
	// The unknown field takes the position it has in the message.
	require.Equal(t, int32(-1), ds.Fields[msgFields].Value.Value.Value())

	// The index is kept for the next message of the same metadata...
	index := reflect.ValueOf(r.names).UnsafePointer()
	compared.Store(0)
	process()
	require.LessOrEqual(t, compared.Load(), int64(msgFields))
	require.Equal(t, index, reflect.ValueOf(r.names).UnsafePointer(), "the index is not built again")

	// ...and built again for new metadata.
	p.lock()
	r.md = namedMetaData(3, 2)
	p.unlock()
	compared.Store(0)
	small := &message.DataSetMessage{DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
		Fields: []*message.Field{{Name: "f2", Value: int32Value(2)}, {Name: "f0", Value: int32Value(0)}}}
	p.lock()
	p.processDSM(r, nm, small, encJSON, time.Now())
	p.unlock()
	require.EqualValues(t, 2, compared.Load())
	require.Len(t, r.names, 3)
	ds = rec.dataSets()[len(rec.dataSets())-1]
	require.Equal(t, []int{2, 0}, ds.Changed)
	require.Equal(t, int32(2), ds.Fields[2].Value.Value.Value())
}

// TestFieldNamesFirstOfDuplicates: where fields of the metadata share a
// name, a message field of that name is the first of them, as the search
// through the metadata gave it.
func TestFieldNamesFirstOfDuplicates(t *testing.T) {
	t.Parallel()
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32}, Field{Name: "b", Type: ua.TypeIDInt32}, Field{Name: "a", Type: ua.TypeIDInt32})
	md.Fields = append(md.Fields, nil, &ua.FieldMetaData{Name: "c"})
	r := &dataSetReader{md: md}
	require.Equal(t, map[string]int{"a": 0, "b": 1, "c": 4}, r.fieldNames())
	for _, tt := range []struct {
		name string
		j    int
		t    message.DataSetMessageType
		enc  encoding
		want int
	}{
		{"a", 5, message.DataSetMessageKeyFrame, encJSON, 0},
		{"b", 5, message.DataSetMessageKeyFrame, encJSON, 1},
		{"c", 5, message.DataSetMessageKeyFrame, encJSON, 4},
		{"x", 5, message.DataSetMessageKeyFrame, encJSON, 5},   // unknown: its position
		{"x", 5, message.DataSetMessageDeltaFrame, encJSON, 9}, // unknown in a delta frame: its index
		{"", 5, message.DataSetMessageKeyFrame, encJSON, 5},
		{"a", 5, message.DataSetMessageKeyFrame, encUADP, 5}, // UADP: never by name
	} {
		f := &message.Field{Name: tt.name, Index: 9}
		require.Equal(t, tt.want, fieldIndex(r.fieldNames(), md.Fields, f, tt.j, tt.t, tt.enc), "%+v", tt)
	}
	require.Nil(t, (&dataSetReader{}).fieldNames())
}

// TestNetworkMetaDataFieldCountIsBounded: a reader takes a DataSetMetaData
// from the network with at most maxNetworkMetaDataFields fields, the most a
// DataSetMessage can carry; a larger one is a decode error and leaves the
// reader as it was.
func TestNetworkMetaDataFieldCountIsBounded(t *testing.T) {
	t.Parallel()
	p, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", memURL(t), nil),
		ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, nil)))))
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })
	cid := mustID(t, p, KindConnection, Root, "sub")
	rid := mustID(t, p, KindDataSetReader, mustID(t, p, KindReaderGroup, cid, "rg"), "r")

	metaData := func(fields int, major uint32) []byte {
		var b strings.Builder
		fmt.Fprintf(&b, `{"MessageId":"m","MessageType":"ua-metadata","PublisherId":"7","DataSetWriterId":1,"MetaData":{"Name":"ds","ConfigurationVersion":{"MajorVersion":%d,"MinorVersion":1},"Fields":[`, major)
		for i := range fields {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"Name":"f%d","BuiltInType":6,"ValueRank":-1}`, i)
		}
		b.WriteString(`]}}`)
		return []byte(b.String())
	}
	p.lock()
	c := p.conns[0]
	gen := c.gen
	p.unlock()
	state := func() (fields int, metaReceived, decodeErrors uint64) {
		p.lock()
		defer p.unlock()
		r := p.comps[rid].(*dataSetReader)
		if r.md != nil {
			fields = len(r.md.Fields)
		}
		return fields, r.ctr.MetaDataReceived, c.ctr.DecodeErrors
	}

	for _, tt := range []struct {
		fields int
		taken  bool
	}{
		{maxNetworkMetaDataFields + 1, false},
		{maxNetworkMetaDataFields + 1000, false},
		{1, true},
		{maxNetworkMetaDataFields, true},
		{maxNetworkMetaDataFields + 1, false},
	} {
		f0, m0, e0 := state()
		p.receive(c, gen, &transport.Message{Payload: metaData(tt.fields, uint32(tt.fields))})
		f1, m1, e1 := state()
		if tt.taken {
			require.Equal(t, tt.fields, f1, "fields of the reader after metadata of %d fields", tt.fields)
			require.Equal(t, m0+1, m1)
			require.Equal(t, e0, e1)
		} else {
			require.Equal(t, f0, f1, "metadata of %d fields is not taken", tt.fields)
			require.Equal(t, m0, m1)
			require.Equal(t, e0+1, e1, "metadata of %d fields is a decode error", tt.fields)
		}
	}
	require.NoError(t, checkNetworkMetaData(nil))
}
