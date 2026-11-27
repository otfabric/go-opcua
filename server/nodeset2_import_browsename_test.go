// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// companionDoc is a NodeSet2 document of a companion model in the style of
// the DI model: a Method with the 0:InputArguments and 0:OutputArguments
// Properties, written without a prefix as the official NodeSets do (DI
// ns=1;i=6167 BrowseName="InputArguments"), and a DataType with its
// "Default Binary" and "Default XML" encodings (Part 6 §F.15), next to
// names with the prefixes 1: and 2:.
const companionDoc = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:companion</Uri><Uri>urn:test:second</Uri></NamespaceUris>
  <Aliases><Alias Alias="HasProperty">i=46</Alias><Alias Alias="HasEncoding">i=38</Alias></Aliases>
  <UAMethod NodeId="ns=1;i=7100" BrowseName="1:Reset">
    <DisplayName>Reset</DisplayName>
    <References>
      <Reference ReferenceType="HasProperty">ns=1;i=7101</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=7102</Reference>
    </References>
  </UAMethod>
  <UAVariable NodeId="ns=1;i=7101" BrowseName="InputArguments" ParentNodeId="ns=1;i=7100" DataType="i=296" ValueRank="1">
    <DisplayName>InputArguments</DisplayName>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=7102" BrowseName="OutputArguments" ParentNodeId="ns=1;i=7100" DataType="i=296" ValueRank="1">
    <DisplayName>OutputArguments</DisplayName>
  </UAVariable>
  <UADataType NodeId="ns=1;i=3100" BrowseName="1:Settings">
    <DisplayName>Settings</DisplayName>
    <References>
      <Reference ReferenceType="HasEncoding">ns=1;i=5100</Reference>
      <Reference ReferenceType="HasEncoding">ns=1;i=5101</Reference>
    </References>
  </UADataType>
  <UAObject NodeId="ns=1;i=5100" BrowseName="Default Binary" SymbolicName="DefaultBinary">
    <DisplayName>Default Binary</DisplayName>
  </UAObject>
  <UAObject NodeId="ns=1;i=5101" BrowseName="Default XML" SymbolicName="DefaultXml">
    <DisplayName>Default XML</DisplayName>
  </UAObject>
  <UAObject NodeId="ns=2;i=5200" BrowseName="2:Station">
    <DisplayName>Station</DisplayName>
  </UAObject>
</UANodeSet>`

// TestImportNodeSetXML_UnprefixedBrowseNameIsNamespace0: a BrowseName
// without a prefix on a node of a companion namespace is a name in the OPC
// UA namespace, "The form without a prefix ... shall only be used for
// QualifiedNames in the OPC UA Namespace" (Part 6 §5.1.12); the prefixes
// 1: and 2: are those of the document's NamespaceUris and are rewritten to
// the indexes of the server.
//
// Regression: the importer put a name without a prefix in the namespace of
// its node, so the InputArguments of a companion Method were
// <ns>:InputArguments, which no client browsing for 0:InputArguments finds.
func TestImportNodeSetXML_UnprefixedBrowseNameIsNamespace0(t *testing.T) {
	check := func(t *testing.T, srv *Server, companion, second uint16) {
		t.Helper()
		for _, c := range []struct {
			id   uint32
			ns   uint16
			want *ua.QualifiedName
		}{
			{7100, companion, &ua.QualifiedName{NamespaceIndex: companion, Name: "Reset"}},
			{7101, companion, &ua.QualifiedName{NamespaceIndex: 0, Name: "InputArguments"}},
			{7102, companion, &ua.QualifiedName{NamespaceIndex: 0, Name: "OutputArguments"}},
			{3100, companion, &ua.QualifiedName{NamespaceIndex: companion, Name: "Settings"}},
			{5100, companion, &ua.QualifiedName{NamespaceIndex: 0, Name: "Default Binary"}},
			{5101, companion, &ua.QualifiedName{NamespaceIndex: 0, Name: "Default XML"}},
			{5200, second, &ua.QualifiedName{NamespaceIndex: second, Name: "Station"}},
		} {
			n := srv.Node(ua.NewNumericNodeID(c.ns, c.id))
			require.NotNil(t, n, "ns=%d;i=%d", c.ns, c.id)
			require.Equal(t, c.want, n.BrowseName(), "ns=%d;i=%d", c.ns, c.id)
		}
	}

	t.Run("indexes rewritten", func(t *testing.T) {
		srv := newTestServer()
		NewNodeNameSpace(srv, "urn:test:other")  // 1
		NewNodeNameSpace(srv, "urn:test:second") // 2
		require.NoError(t, srv.ImportNodeSetXML([]byte(companionDoc)))
		check(t, srv, 3, 2)
	})
	t.Run("indexes kept", func(t *testing.T) {
		srv := newTestServer()
		require.NoError(t, srv.ImportNodeSetXML([]byte(companionDoc)))
		check(t, srv, 1, 2)
	})
}

// TestImportNodeSetXML_BrowseNamePrefixErrors: a BrowseName prefix that
// names no namespace fails the import, in a document that is rewritten
// (an index outside its NamespaceUris), in one without NamespaceUris (an
// index the server does not have) and with a prefix that is not a UInt16.
func TestImportNodeSetXML_BrowseNamePrefixErrors(t *testing.T) {
	const head = `<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">`
	t.Run("outside the NamespaceUris", func(t *testing.T) {
		srv := newTestServer()
		NewNodeNameSpace(srv, "urn:test:other")
		err := srv.ImportNodeSetXML([]byte(head + `<NamespaceUris><Uri>urn:test:doc</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=1" BrowseName="2:Bad"><DisplayName>Bad</DisplayName></UAObject></UANodeSet>`))
		require.ErrorContains(t, err, "namespace index 2 is not in the namespace table")
	})

	// Every kind of node checks its BrowseName.
	for _, el := range []string{"UAReferenceType", "UADataType", "UAObjectType", "UAVariableType", "UAVariable", "UAMethod", "UAObject"} {
		t.Run(el, func(t *testing.T) {
			for _, c := range []struct{ name, want string }{
				{"5:Bad", "the server has no namespace 5"},
				{"70000:Bad", "namespace index 70000 is not a UInt16"},
			} {
				srv := newTestServer()
				NewNodeNameSpace(srv, "urn:test:one")
				err := srv.ImportNodeSetXML([]byte(fmt.Sprintf(`%s<%s NodeId="ns=1;i=1" BrowseName=%q><DisplayName>Bad</DisplayName></%s></UANodeSet>`, head, el, c.name, el)))
				require.ErrorContains(t, err, c.want)
				require.ErrorContains(t, err, "ns=1;i=1")
				require.Nil(t, srv.Node(ua.NewNumericNodeID(1, 1)), "nothing of the node is imported")
			}
		})
	}
}
