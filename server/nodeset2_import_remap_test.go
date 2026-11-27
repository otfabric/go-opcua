// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// remapDoc is a NodeSet2 document with the namespace table uris and two
// objects in its namespace 1, the second a component of the first, and a
// variable in its namespace 2 when it has two namespaces.
func remapDoc(uris ...string) []byte {
	table := ""
	for _, u := range uris {
		table += "<Uri>" + u + "</Uri>"
	}
	second := ""
	if len(uris) > 1 {
		second = `
  <UAVariable NodeId="ns=2;i=7001" BrowseName="2:Level" DataType="i=6" ParentNodeId="ns=1;i=7000">
    <DisplayName>Level</DisplayName>
    <References><Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=7000</Reference></References>
  </UAVariable>`
	}
	return []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>` + table + `</NamespaceUris>
  <Aliases><Alias Alias="HasComponent">i=47</Alias></Aliases>
  <UAObject NodeId="ns=1;i=7000" BrowseName="1:Tank">
    <DisplayName>Tank</DisplayName>
    <References><Reference ReferenceType="HasComponent">ns=1;i=7002</Reference></References>
  </UAObject>
  <UAObject NodeId="ns=1;i=7002" BrowseName="Valve">
    <DisplayName>Valve</DisplayName>
  </UAObject>` + second + `
</UANodeSet>`)
}

func namespaceNames(srv *Server) []string {
	var out []string
	for _, ns := range srv.Namespaces() {
		out = append(out, ns.Name())
	}
	return out
}

// TestImportNodeSetXML_RemapsNamespaces: the namespace indexes of a NodeSet
// are those of its NamespaceUris (Part 6 §F.2); a server whose table
// differs gets the nodes in its own namespaces for the same URIs.
//
// Regression: the document's indexes were used as the server's, so the
// nodes landed in whatever namespace had that index on the server, and
// each import added its URIs again as new namespaces.
func TestImportNodeSetXML_RemapsNamespaces(t *testing.T) {
	srv := newTestServer()
	other := NewNodeNameSpace(srv, "urn:test:other") // index 1
	require.Equal(t, uint16(1), other.ID())

	require.NoError(t, srv.ImportNodeSetXML(remapDoc("urn:test:tanks")))
	require.Equal(t, []string{"http://opcfoundation.org/UA/", "urn:test:other", "urn:test:tanks"}, namespaceNames(srv))

	tank, valve := ua.NewNumericNodeID(2, 7000), ua.NewNumericNodeID(2, 7002)
	require.NotNil(t, srv.Node(tank))
	require.Nil(t, other.Node(ua.NewNumericNodeID(1, 7000)), "nothing lands in the namespace with the document's index")
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: 2, Name: "Tank"}, srv.Node(tank).BrowseName())
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: 2, Name: "Valve"}, srv.Node(valve).BrowseName(),
		"a BrowseName without a prefix stays in the namespace of its node")
	require.True(t, hasRef(srv.Node(tank), valve, id.HasComponent, true))

	// The same document again reuses the namespace.
	require.NoError(t, srv.ImportNodeSetXML(remapDoc("urn:test:tanks")))
	require.Len(t, srv.Namespaces(), 3)
}

// TestImportNodeSetXML_RemapsReorderedNamespaces: a document that lists two
// namespaces of the server in the other order.
func TestImportNodeSetXML_RemapsReorderedNamespaces(t *testing.T) {
	srv := newTestServer()
	b := NewNodeNameSpace(srv, "urn:test:b") // 1
	a := NewNodeNameSpace(srv, "urn:test:a") // 2

	require.NoError(t, srv.ImportNodeSetXML(remapDoc("urn:test:a", "urn:test:b")))
	require.Len(t, srv.Namespaces(), 3)
	tank, level := ua.NewNumericNodeID(a.ID(), 7000), ua.NewNumericNodeID(b.ID(), 7001)
	require.NotNil(t, a.Node(tank))
	require.NotNil(t, b.Node(level))
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: b.ID(), Name: "Level"}, srv.Node(level).BrowseName())
	require.True(t, hasRef(srv.Node(tank), level, id.HasComponent, true), "the reference follows both ends")
}

// TestImportNodeSetXML_MatchingNamespaces: a document whose indexes are
// those of the server is imported as before, and a URI the server has is
// not added again.
func TestImportNodeSetXML_MatchingNamespaces(t *testing.T) {
	srv := newTestServer()
	NewNodeNameSpace(srv, "urn:test:a") // 1

	require.NoError(t, srv.ImportNodeSetXML(remapDoc("urn:test:a", "urn:test:new")))
	require.Equal(t, []string{"http://opcfoundation.org/UA/", "urn:test:a", "urn:test:new"}, namespaceNames(srv))
	require.NotNil(t, srv.Node(ua.NewNumericNodeID(1, 7000)))
	require.NotNil(t, srv.Node(ua.NewNumericNodeID(2, 7001)))
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: 1, Name: "Valve"}, srv.Node(ua.NewNumericNodeID(1, 7002)).BrowseName())

	// A document without NamespaceUris names the server's indexes.
	require.NoError(t, srv.ImportNodeSetXML([]byte(`<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <UAObject NodeId="ns=2;i=7100" BrowseName="2:Plain"><DisplayName>Plain</DisplayName></UAObject>
</UANodeSet>`)))
	require.NotNil(t, srv.Node(ua.NewNumericNodeID(2, 7100)))
}

// TestImportNodeSetXML_RemapErrors: an index outside the namespace table
// of a document that needs to be rewritten fails the import.
func TestImportNodeSetXML_RemapErrors(t *testing.T) {
	srv := newTestServer()
	NewNodeNameSpace(srv, "urn:test:other")
	err := srv.ImportNodeSetXML([]byte(`<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:doc</Uri></NamespaceUris>
  <UAObject NodeId="ns=3;i=1" BrowseName="3:Bad"><DisplayName>Bad</DisplayName></UAObject>
</UANodeSet>`))
	require.ErrorContains(t, err, "map the namespaces of the NodeSet")
	require.ErrorContains(t, err, "not in the namespace table")
}

// TestNamespaceIndex_Full: a server without a free namespace index cannot
// take a new namespace.
func TestNamespaceIndex_Full(t *testing.T) {
	srv := newTestServer()
	filler := NewNameSpace("urn:test:filler")
	srv.mu.Lock()
	for len(srv.namespaces) < maxNamespaces {
		srv.namespaces = append(srv.namespaces, filler)
	}
	srv.publishNamespaces()
	srv.mu.Unlock()

	idx, err := srv.namespaceIndex("urn:test:filler")
	require.NoError(t, err)
	require.Equal(t, uint16(1), idx)
	_, err = srv.namespaceIndex("urn:test:new")
	require.ErrorContains(t, err, "no namespace index left")
}
