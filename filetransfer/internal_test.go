// SPDX-License-Identifier: MIT

package filetransfer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func ref(nid *ua.NodeID, name *ua.QualifiedName, typeDef *ua.ExpandedNodeID) *ua.ReferenceDescription {
	r := &ua.ReferenceDescription{BrowseName: name, TypeDefinition: typeDef}
	if nid != nil {
		r.NodeID = ua.NewExpandedNodeID(nid, "", 0)
	}
	return r
}

// TestEntryOf: only FileDirectoryType and FileType Objects of namespace 0
// with all their fields are entries.
func TestEntryOf(t *testing.T) {
	n := ua.NewNumericNodeID(1, 7)
	q := &ua.QualifiedName{NamespaceIndex: 1, Name: "x"}
	dirType := ua.NewNumericExpandedNodeID(0, id.FileDirectoryType)
	e, ok := entryOf(ref(n, q, dirType))
	require.True(t, ok)
	require.Equal(t, Entry{NodeID: n, Name: "x", Dir: true}, e)
	e, ok = entryOf(ref(n, q, ua.NewNumericExpandedNodeID(0, id.FileType)))
	require.True(t, ok)
	require.Equal(t, Entry{NodeID: n, Name: "x"}, e)
	for name, r := range map[string]*ua.ReferenceDescription{
		"nil":                 nil,
		"no NodeId":           ref(nil, q, dirType),
		"no BrowseName":       ref(n, nil, dirType),
		"no TypeDefinition":   ref(n, q, nil),
		"null TypeDefinition": ref(n, q, &ua.ExpandedNodeID{}),
		"type of namespace 1": ref(n, q, ua.NewNumericExpandedNodeID(1, id.FileType)),
		"another type":        ref(n, q, ua.NewNumericExpandedNodeID(0, id.FolderType)),
	} {
		_, ok := entryOf(r)
		require.False(t, ok, name)
	}
}

// TestInfoReadsAndInfoOf: the FileType Properties of namespace 0 are read,
// missing values and values of another type leave a field zero, and a
// response with another number of results is refused.
func TestInfoReadsAndInfoOf(t *testing.T) {
	n := ua.NewNumericNodeID(1, 7)
	nodes, names := infoReads([]*ua.ReferenceDescription{
		nil,
		ref(n, nil, nil),
		ref(nil, &ua.QualifiedName{Name: "Size"}, nil),
		ref(n, &ua.QualifiedName{NamespaceIndex: 1, Name: "Size"}, nil),
		ref(n, &ua.QualifiedName{Name: "Other"}, nil),
		ref(n, &ua.QualifiedName{Name: "Size"}, nil),
		ref(n, &ua.QualifiedName{Name: "MimeType"}, nil),
		ref(n, &ua.QualifiedName{Name: "OpenCount"}, nil),
	})
	require.Equal(t, []string{"Size", "MimeType", "OpenCount"}, names)
	require.Len(t, nodes, 3)

	_, err := infoOf(names, []*ua.DataValue{{}})
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	info, err := infoOf(names, []*ua.DataValue{
		{Value: ua.MustVariant(uint64(3))},
		nil,
		{Value: ua.MustVariant("not a UInt16")},
	})
	require.NoError(t, err)
	require.Equal(t, &Info{Size: 3}, info)
	info, err = infoOf([]string{"LastModifiedTime", "Writable"}, []*ua.DataValue{{}, {Value: ua.MustVariant(true)}})
	require.NoError(t, err)
	require.Equal(t, &Info{Writable: true, LastModifiedTime: time.Time{}}, info)
}
