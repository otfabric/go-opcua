// SPDX-License-Identifier: MIT

package fxserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func sampleEndpoint() (*epIdentity, *epBody) {
	id := &epIdentity{
		Namespaces:       []string{"http://opcfoundation.org/UA/", "urn:app", "urn:fx"},
		AC:               ua.NewNumericNodeID(2, 10),
		Endpoint:         ua.NewNumericNodeID(2, 11),
		FunctionalEntity: ua.NewStringNodeID(1, "FE"),
		Name:             "EP",
		Nodes:            []*ua.NodeID{ua.NewNumericNodeID(2, 11), ua.NewNumericNodeID(2, 12)},
		WriterGroupIDs:   []uint16{0x8000},
		DataSetWriterIDs: []uint16{0x8001},
		Components:       []string{componentKey("conn/C")},
		Paths:            []string{"conn/C"},
	}
	body := &epBody{
		State: stateActive, Enabled: true, Folder: ua.NewNumericNodeID(2, 5), Mode: 1,
		Inputs:       []*ua.NodeID{ua.NewStringNodeID(1, "in")},
		CreationTime: time.Unix(1700000000, 0).UTC(), ModificationTime: time.Unix(1700000001, 0).UTC(),
		Reader: componentKey("reader/C/G/R"), OwnReader: true,
	}
	return id, body
}

// TestRecordRoundTrip: records decode to what was encoded; the identity
// header decodes on its own when the body is corrupt; truncation, checksums,
// the format byte and trailing data are detected.
func TestRecordRoundTrip(t *testing.T) {
	t.Parallel()
	id, body := sampleEndpoint()
	b, err := encodeEndpoint(id, body)
	require.NoError(t, err)
	gid, gbody, err := decodeEndpoint(b)
	require.NoError(t, err)
	require.Equal(t, id.Name, gid.Name)
	require.Equal(t, id.Paths, gid.Paths)
	require.True(t, id.Endpoint.Equal(gid.Endpoint))
	require.Equal(t, body.Reader, gbody.Reader)
	require.True(t, body.CreationTime.Equal(gbody.CreationTime))

	// A corrupt body: the identity is still read.
	bad := append([]byte(nil), b...)
	bad[len(bad)-6] ^= 0xff
	gid, gbody, err = decodeEndpoint(bad)
	require.ErrorIs(t, err, errRecord)
	require.NotNil(t, gid)
	require.Nil(t, gbody)
	// Trailing data.
	_, _, err = decodeEndpoint(append(append([]byte(nil), b...), 0))
	require.ErrorIs(t, err, errRecord)
	// Format byte, truncation, a corrupt identity.
	for name, v := range map[string][]byte{
		"empty": nil, "format": append([]byte{9}, b[1:]...), "short": b[:5],
		"length":   append([]byte{recordFormat, 0xff, 0xff, 0xff, 0x7f}, b[5:]...),
		"identity": func() []byte { c := append([]byte(nil), b...); c[6] ^= 0xff; return c }(),
	} {
		gid, _, err := decodeEndpoint(v)
		require.ErrorIs(t, err, errRecord, name)
		require.Nil(t, gid, name)
	}
	// A part that checksums but does not decode exactly.
	junk := appendPart([]byte{recordFormat}, []byte{1, 2, 3})
	_, _, err = decodeEndpoint(junk)
	require.ErrorIs(t, err, errRecord)
	ib, _ := ua.Encode(id)
	_, _, err = decodeEndpoint(appendPart(appendPart([]byte{recordFormat}, ib), []byte{0xff}))
	require.ErrorIs(t, err, errRecord)
	_, _, err = decodeEndpoint(appendPart([]byte{recordFormat}, append(ib, 0)))
	require.ErrorIs(t, err, errRecord, "left-over bytes in a part")

	c := &compRecord{Namespaces: id.Namespaces, Kind: uint8(pubsub.KindConnection), Path: []string{"C"},
		Config:     ua.NewExtensionObject(pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", uint16(3))),
		Provenance: provCreated, Refs: []string{"a/b"}}
	cb, err := encodeComponent(c)
	require.NoError(t, err)
	gc, err := decodeComponent(cb)
	require.NoError(t, err)
	require.Equal(t, c.Path, gc.Path)
	require.Equal(t, "C", gc.Config.Value.(*ua.PubSubConnectionDataType).Name)
	for name, v := range map[string][]byte{
		"empty": nil, "format": append([]byte{9}, cb[1:]...), "short": cb[:3],
		"trailing": append(append([]byte(nil), cb...), 0), "junk": junk,
	} {
		_, err := decodeComponent(v)
		require.ErrorIs(t, err, errRecord, name)
	}
	_, err = relatedOf([]byte{0xff})
	require.ErrorIs(t, err, errRecord)
	rb, err := ua.Encode(&uafx.RelatedEndpoint{ConnectionEndpointName: "R"})
	require.NoError(t, err)
	r, err := relatedOf(rb)
	require.NoError(t, err)
	require.Equal(t, "R", r.ConnectionEndpointName)
}

// TestRecordKeys: keys are qualified by namespace URI, not index.
func TestRecordKeys(t *testing.T) {
	t.Parallel()
	a := []string{"http://opcfoundation.org/UA/", "urn:a", "urn:b"}
	b := []string{"http://opcfoundation.org/UA/", "urn:b", "urn:a"}
	require.Equal(t, "urn:a|i=5", qualified(ua.NewNumericNodeID(1, 5), a))
	require.Equal(t, qualified(ua.NewNumericNodeID(1, 5), a), qualified(ua.NewNumericNodeID(2, 5), b))
	require.Equal(t, "http://opcfoundation.org/UA/|i=5", qualified(ua.NewNumericNodeID(0, 5), a))
	require.Empty(t, qualified(nil, a))
	require.Empty(t, qualified(ua.NewNumericNodeID(7, 5), a))
	k := endpointKey(ua.NewNumericNodeID(1, 1), ua.NewNumericNodeID(2, 2), a)
	require.Equal(t, k, endpointKey(ua.NewNumericNodeID(2, 1), ua.NewNumericNodeID(1, 2), b))
	require.Len(t, k, 65)
	require.Equal(t, k[:32], acOfKey(k))
	require.Empty(t, acOfKey("nokey"))
	require.NotEqual(t, hashKey("ab", "c"), hashKey("a", "bc"), "parts are length-prefixed")
	require.Equal(t, "Connection/C/G", componentPath(pubsub.KindConnection, "C", "G"))
}

// TestRemap: every NodeId of a PubSub configuration, nested in
// ExtensionObjects and Variants included, follows a reordered
// NamespaceArray; a missing namespace fails; an ExpandedNodeId with a
// NamespaceUri is left alone.
func TestRemap(t *testing.T) {
	t.Parallel()
	from := []string{"http://opcfoundation.org/UA/", "urn:a", "urn:b"}
	to := []string{"http://opcfoundation.org/UA/", "urn:x", "urn:b", "urn:a"}
	r := newRemapper(from, to)
	require.False(t, r.identity())
	require.True(t, newRemapper(from, from).identity())
	require.False(t, newRemapper(from, from[:2]).identity())

	pds := &ua.PublishedDataSetDataType{
		Name: "P",
		DataSetSource: ua.NewExtensionObject(&ua.PublishedDataItemsDataType{
			PublishedData: []*ua.PublishedVariableDataType{{PublishedVariable: ua.NewNumericNodeID(1, 7), AttributeID: 13,
				SubstituteValue: ua.MustVariant(ua.NewStringNodeID(2, "sub"))}},
		}),
	}
	reader := &ua.DataSetReaderDataType{
		Name: "R",
		SubscribedDataSet: ua.NewExtensionObject(&ua.TargetVariablesDataType{
			TargetVariables: []*ua.FieldTargetDataType{{TargetNodeID: ua.NewStringNodeID(1, "t"), AttributeID: 13}},
		}),
		DataSetReaderProperties: []*ua.KeyValuePair{{Key: &ua.QualifiedName{NamespaceIndex: 1, Name: "k"},
			Value: ua.MustVariant(ua.NewExpandedNodeID(ua.NewNumericNodeID(2, 9), "", 0))}},
	}
	keep := ua.NewExpandedNodeID(ua.NewNumericNodeID(1, 3), "urn:other", 0)
	cfg := &ua.PubSubConfiguration2DataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
		Connections: []*ua.PubSubConnectionDataType{{Name: "C",
			ReaderGroups:         []*ua.ReaderGroupDataType{{Name: "G", DataSetReaders: []*ua.DataSetReaderDataType{reader}}},
			ConnectionProperties: []*ua.KeyValuePair{{Value: ua.MustVariant(keep)}},
		}},
	}
	require.NoError(t, r.remap(cfg))
	pv := pds.DataSetSource.Value.(*ua.PublishedDataItemsDataType).PublishedData[0]
	require.Equal(t, uint16(3), pv.PublishedVariable.Namespace())
	require.Equal(t, uint16(2), pv.SubstituteValue.Value().(*ua.NodeID).Namespace())
	tv := reader.SubscribedDataSet.Value.(*ua.TargetVariablesDataType).TargetVariables[0]
	require.Equal(t, uint16(3), tv.TargetNodeID.Namespace())
	require.Equal(t, uint16(2), reader.DataSetReaderProperties[0].Value.Value().(*ua.ExpandedNodeID).NodeID.Namespace())
	require.Equal(t, uint16(1), keep.NodeID.Namespace(), "an ExpandedNodeId with a NamespaceUri is not remapped")

	// A two-byte NodeId cannot hold a namespace: it is replaced.
	id := &epIdentity{AC: ua.NewTwoByteNodeID(5), Nodes: []*ua.NodeID{ua.NewFourByteNodeID(1, 6)}}
	require.NoError(t, newRemapper([]string{"urn:z", "urn:a"}, []string{"urn:q", "urn:z", "urn:a"}).remap(id))
	require.Equal(t, uint16(1), id.AC.Namespace())
	require.Equal(t, uint32(5), id.AC.IntID())
	require.Equal(t, uint16(2), id.Nodes[0].Namespace())

	// Missing namespaces.
	require.ErrorIs(t, newRemapper(from, from[:2]).remap(&epIdentity{AC: ua.NewNumericNodeID(2, 1)}), errNamespace)
	require.ErrorIs(t, r.remap(&epIdentity{AC: ua.NewNumericNodeID(9, 1)}), errNamespace)
	// Maps and interfaces are walked; a cycle stops.
	m := map[string]any{"x": ua.NewNumericNodeID(1, 1)}
	require.NoError(t, r.remap(m))
	require.Equal(t, uint16(3), m["x"].(*ua.NodeID).Namespace())
	type loop struct{ Next *loop }
	l := &loop{}
	l.Next = l
	require.NoError(t, r.remap(l))
	// Nesting deeper than the walker goes.
	var deep any = ua.NewNumericNodeID(1, 1)
	for range 70 {
		deep = []any{deep}
	}
	require.ErrorIs(t, r.remap(deep), errRecord)
}

func TestWithNamespace(t *testing.T) {
	t.Parallel()
	for _, n := range []*ua.NodeID{
		ua.NewTwoByteNodeID(1), ua.NewFourByteNodeID(1, 300), ua.NewNumericNodeID(1, 1<<20),
		ua.NewStringNodeID(1, "s"), ua.NewGUIDNodeID(1, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"),
		ua.NewByteStringNodeID(1, []byte{1, 2}),
	} {
		m := withNamespace(n, 400)
		require.NotNil(t, m, n.String())
		require.Equal(t, uint16(400), m.Namespace())
		require.Equal(t, n.Type() == ua.NodeIDTypeString, m.Type() == ua.NodeIDTypeString)
	}
}

// FuzzDecodeEndpoint: an endpoint record from the store is untrusted: it
// decodes or fails with errRecord, never panics, and what decodes encodes
// again.
func FuzzDecodeEndpoint(f *testing.F) {
	id, body := sampleEndpoint()
	b, err := encodeEndpoint(id, body)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add(b[:len(b)/2])
	f.Add([]byte{recordFormat})
	f.Fuzz(func(t *testing.T, v []byte) {
		gid, gbody, err := decodeEndpoint(v)
		if err != nil {
			require.ErrorIs(t, err, errRecord)
			return
		}
		_, err = encodeEndpoint(gid, gbody)
		require.NoError(t, err)
		_ = newRemapper(gid.Namespaces, id.Namespaces).remap(gid)
	})
}

// FuzzDecodeComponent: a component record is untrusted as well.
func FuzzDecodeComponent(f *testing.F) {
	c := &compRecord{Namespaces: []string{"http://opcfoundation.org/UA/"}, Kind: uint8(pubsub.KindWriterGroup), Path: []string{"C", "G"},
		Config: ua.NewExtensionObject(pubsub.WriterGroup("G", 0x8000, time.Second)), Provenance: provAdopted}
	b, err := encodeComponent(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add(b[:len(b)-1])
	f.Fuzz(func(t *testing.T, v []byte) {
		r, err := decodeComponent(v)
		if err != nil {
			require.ErrorIs(t, err, errRecord)
			return
		}
		_, err = encodeComponent(r)
		require.NoError(t, err)
		_ = newRemapper(r.Namespaces, c.Namespaces).remap(r)
	})
}
