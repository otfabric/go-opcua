// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// blindNameSpace keeps the nodes added to it but finds none of them: a
// NameSpace implementation of an application that serves its nodes some
// other way.
type blindNameSpace struct{ *NodeNameSpace }

func (blindNameSpace) Node(*ua.NodeID) *Node { return nil }

// TestImportNodeSetXML_NodeNotFoundForReferences: the references of a node
// the namespace does not return after the import are skipped, for every
// kind of node, and the import goes on.
func TestImportNodeSetXML_NodeNotFoundForReferences(t *testing.T) {
	srv := newTestServer()
	ns := blindNameSpace{NewNameSpace("urn:test:blind")}
	require.Equal(t, 1, srv.AddNamespace(ns))

	var body string
	for i, el := range []string{"UAReferenceType", "UADataType", "UAObjectType", "UAVariableType", "UAVariable", "UAMethod", "UAObject"} {
		body += fmt.Sprintf(`
  <%s NodeId="ns=1;i=%d" BrowseName="1:N%d"><DisplayName>N</DisplayName>
    <References><Reference ReferenceType="i=35" IsForward="false">i=85</Reference></References>
  </%s>`, el, 100+i, i, el)
	}
	err := srv.ImportNodeSetXML([]byte(`<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">` + body + `
</UANodeSet>`))
	require.NoError(t, err)
	require.Len(t, ns.m, 7, "the nodes were added")
}
