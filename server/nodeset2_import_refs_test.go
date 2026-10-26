// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeSetKinds lists every NodeSet2 node element the importer handles together
// with the attributes that element requires.
var nodeSetKinds = []struct {
	elem  string
	attrs string
	class ua.NodeClass
}{
	{"UAReferenceType", `IsAbstract="false" Symmetric="false"`, ua.NodeClassReferenceType},
	{"UADataType", ``, ua.NodeClassDataType},
	{"UAObjectType", `IsAbstract="false"`, ua.NodeClassObjectType},
	{"UAVariableType", `DataType="i=6"`, ua.NodeClassVariableType},
	{"UAVariable", `DataType="i=6"`, ua.NodeClassVariable},
	{"UAMethod", ``, ua.NodeClassMethod},
	{"UAObject", ``, ua.NodeClassObject},
}

// nodeSetDoc wraps body in a NodeSet2 document that declares one custom
// namespace (index 1 on a fresh test server) and the HasComponent alias.
func nodeSetDoc(body string) []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:refs</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="HasComponent">i=47</Alias>
  </Aliases>
` + body + `
</UANodeSet>`)
}

func nodeSetElem(elem, attrs, nodeID, name, inner string) string {
	return fmt.Sprintf(`  <%s NodeId=%q BrowseName="1:%s" %s>
    <DisplayName>%s</DisplayName>
%s
  </%s>`, elem, nodeID, name, attrs, name, inner, elem)
}

// hasRef reports whether n holds a reference of the given type and direction
// to target.
func hasRef(n *Node, target *ua.NodeID, rt uint32, forward bool) bool {
	for _, r := range n.refsSnapshot() {
		if r.NodeID.NodeID.String() == target.String() && r.IsForward == forward &&
			r.ReferenceTypeID.IntID() == rt {
			return true
		}
	}
	return false
}

func TestImportNodeSetXML_NodeWithoutReferences(t *testing.T) {
	for _, k := range nodeSetKinds {
		t.Run(k.elem, func(t *testing.T) {
			srv := newTestServer()
			nid := ua.NewNumericNodeID(1, 5000)
			err := srv.ImportNodeSetXML(nodeSetDoc(nodeSetElem(k.elem, k.attrs, "ns=1;i=5000", "Lonely",
				`    <Description>a lonely node</Description>`)))
			require.NoError(t, err)

			n := srv.Node(nid)
			require.NotNil(t, n)
			assert.Equal(t, k.class, n.NodeClass())
			assert.Equal(t, &ua.QualifiedName{NamespaceIndex: 1, Name: "Lonely"}, n.BrowseName())
			assert.Equal(t, "Lonely", n.DisplayName().Text)
			if k.elem != "UAMethod" && k.elem != "UAVariableType" {
				// Methods and variable types do not import a Description.
				assert.Equal(t, "a lonely node", n.Description().Text)
			}
			assert.Empty(t, n.refsSnapshot())
		})
	}
}

func TestImportNodeSetXML_UnknownNamespace(t *testing.T) {
	for _, k := range nodeSetKinds {
		t.Run(k.elem, func(t *testing.T) {
			srv := newTestServer()
			err := srv.ImportNodeSetXML(nodeSetDoc(nodeSetElem(k.elem, k.attrs, "ns=99;i=1", "Orphan", "")))
			require.Error(t, err)
			assert.ErrorContains(t, err, "problem creating nodes")
			assert.ErrorContains(t, err, "namespace 99 not found")
			assert.Nil(t, srv.Node(ua.NewNumericNodeID(99, 1)))
		})
	}
}

func TestImportNodeSetXML_ReferenceErrors(t *testing.T) {
	ref := func(refType, target string) string {
		return fmt.Sprintf(`    <References><Reference ReferenceType=%q>%s</Reference></References>`, refType, target)
	}
	for _, k := range nodeSetKinds {
		t.Run(k.elem+"/unparsable target", func(t *testing.T) {
			srv := newTestServer()
			err := srv.ImportNodeSetXML(nodeSetDoc(nodeSetElem(k.elem, k.attrs, "ns=1;i=5100", "Src",
				ref("HasComponent", "i=bad_target"))))
			require.Error(t, err)
			assert.ErrorContains(t, err, "problem creating references")
			assert.ErrorContains(t, err, `parse reference target "i=bad_target"`)
		})

		t.Run(k.elem+"/unknown reference type", func(t *testing.T) {
			srv := newTestServer()
			body := nodeSetElem(k.elem, k.attrs, "ns=1;i=5100", "Src", ref("NoSuchRefType", "ns=1;i=5101")) + "\n" +
				nodeSetElem("UAObject", "", "ns=1;i=5101", "Dst", "")
			if k.elem == "UAObject" {
				// Keep the declaring node first within its own section.
				body = nodeSetElem(k.elem, k.attrs, "ns=1;i=5100", "Src", ref("NoSuchRefType", "ns=1;i=5102")) + "\n" +
					nodeSetElem("UAVariable", `DataType="i=6"`, "ns=1;i=5102", "Dst", "")
			}
			err := srv.ImportNodeSetXML(nodeSetDoc(body))
			require.Error(t, err)
			assert.ErrorContains(t, err, `unknown reference type "NoSuchRefType"`)
			assert.ErrorContains(t, err, "ns=1;i=5100")
		})

		t.Run(k.elem+"/missing target is skipped", func(t *testing.T) {
			srv := newTestServer()
			err := srv.ImportNodeSetXML(nodeSetDoc(nodeSetElem(k.elem, k.attrs, "ns=1;i=5100", "Src",
				ref("HasComponent", "ns=1;i=424242"))))
			require.NoError(t, err, "a dangling reference target must not fail the import")
			n := srv.Node(ua.NewNumericNodeID(1, 5100))
			require.NotNil(t, n)
			assert.Empty(t, n.refsSnapshot(), "no reference may be created to a node that does not exist")
		})
	}
}

func TestImportNodeSetXML_ReferenceBetweenImportedNodes(t *testing.T) {
	for _, k := range nodeSetKinds {
		t.Run(k.elem, func(t *testing.T) {
			srv := newTestServer()
			dstElem, dstAttrs := "UAObject", ""
			if k.elem == "UAObject" {
				dstElem, dstAttrs = "UAVariable", `DataType="i=6"`
			}
			body := nodeSetElem(k.elem, k.attrs, "ns=1;i=5200", "Src",
				`    <References><Reference ReferenceType="HasComponent">ns=1;i=5201</Reference></References>`) + "\n" +
				nodeSetElem(dstElem, dstAttrs, "ns=1;i=5201", "Dst", "")
			require.NoError(t, srv.ImportNodeSetXML(nodeSetDoc(body)))

			srcID, dstID := ua.NewNumericNodeID(1, 5200), ua.NewNumericNodeID(1, 5201)
			src, dst := srv.Node(srcID), srv.Node(dstID)
			require.NotNil(t, src)
			require.NotNil(t, dst)
			assert.True(t, hasRef(src, dstID, id.HasComponent, true), "forward reference on the declaring node")
			assert.True(t, hasRef(dst, srcID, id.HasComponent, false), "derived inverse reference on the target")
			assert.Len(t, src.refsSnapshot(), 1)
			assert.Len(t, dst.refsSnapshot(), 1)
		})
	}
}

func TestImportNodeSetXML_Aliases(t *testing.T) {
	doc := func(aliases, body string) []byte {
		return []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:alias</Uri></NamespaceUris>
  <Aliases>` + aliases + `</Aliases>
` + body + `
</UANodeSet>`)
	}
	pair := nodeSetElem("UAObject", "", "ns=1;i=5300", "Src",
		`    <References><Reference ReferenceType="%s">ns=1;i=5301</Reference></References>`) + "\n" +
		nodeSetElem("UAVariable", `DataType="i=6"`, "ns=1;i=5301", "Dst", "")

	t.Run("alias of unknown node is not a reference type", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(doc(`<Alias Alias="Ghost">ns=1;i=999999</Alias>`, fmt.Sprintf(pair, "Ghost")))
		require.Error(t, err)
		assert.ErrorContains(t, err, `unknown reference type "Ghost"`)
	})

	t.Run("two aliases for one reference type", func(t *testing.T) {
		srv := newTestServer()
		aliases := `<Alias Alias="HasComponent">i=47</Alias><Alias Alias="Contains">i=47</Alias>`
		require.NoError(t, srv.ImportNodeSetXML(doc(aliases, fmt.Sprintf(pair, "Contains"))))
		src := srv.Node(ua.NewNumericNodeID(1, 5300))
		require.NotNil(t, src)
		assert.True(t, hasRef(src, ua.NewNumericNodeID(1, 5301), id.HasComponent, true))
	})

	t.Run("alias shadowed by a declared reference type", func(t *testing.T) {
		srv := newTestServer()
		body := nodeSetElem("UAReferenceType", `IsAbstract="false" Symmetric="true"`, "ns=1;i=5310", "Mine", "") + "\n" +
			fmt.Sprintf(pair, "1:Mine")
		// The alias name collides with the BrowseName key of the declared
		// reference type; the declared type must win.
		require.NoError(t, srv.ImportNodeSetXML(doc(`<Alias Alias="1:Mine">i=47</Alias>`, body)))
		src, dst := srv.Node(ua.NewNumericNodeID(1, 5300)), srv.Node(ua.NewNumericNodeID(1, 5301))
		require.NotNil(t, src)
		require.NotNil(t, dst)
		assert.True(t, hasRef(src, ua.NewNumericNodeID(1, 5301), 5310, true))
		// The other end holds it too, of the declared type in namespace 1.
		refs := dst.refsSnapshot()
		require.Len(t, refs, 1)
		assert.False(t, refs[0].IsForward)
		assert.Equal(t, "ns=1;i=5310", refs[0].ReferenceTypeID.String())
		assert.Equal(t, "ns=1;i=5300", refs[0].NodeID.NodeID.String())
	})
}

// A reference is stored once per end: declared on both ends, imported
// again, or symmetric and declared forward on both ends.
func TestImportNodeSetXML_ReferencesOnce(t *testing.T) {
	doc := []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:once</Uri></NamespaceUris>
  <Aliases><Alias Alias="HasComponent">i=47</Alias></Aliases>
` + nodeSetElem("UAReferenceType", `IsAbstract="false" Symmetric="true"`, "ns=1;i=5410", "Peer", "") + "\n" +
		nodeSetElem("UAObject", "", "ns=1;i=5400", "A", `    <References>
      <Reference ReferenceType="HasComponent">ns=1;i=5401</Reference>
      <Reference ReferenceType="ns=1;i=5410">ns=1;i=5401</Reference>
    </References>`) + "\n" +
		nodeSetElem("UAVariable", `DataType="i=6"`, "ns=1;i=5401", "B", `    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5400</Reference>
      <Reference ReferenceType="ns=1;i=5410">ns=1;i=5400</Reference>
    </References>`) + `
</UANodeSet>`)
	srv := newTestServer()
	require.NoError(t, srv.ImportNodeSetXML(doc))
	require.NoError(t, srv.ImportNodeSetXML(doc))
	a, b := srv.Node(ua.NewNumericNodeID(1, 5400)), srv.Node(ua.NewNumericNodeID(1, 5401))
	require.NotNil(t, a)
	require.NotNil(t, b)
	require.Equal(t, 1, countRefs(a, b.ID(), id.HasComponent, true))
	require.Equal(t, 1, countRefs(b, a.ID(), id.HasComponent, false))
	// Peer: one reference, recorded on both ends, whichever declaration
	// the importer read first; the other one is the same reference.
	fwdA, fwdB := countRefs(a, b.ID(), 5410, true), countRefs(b, a.ID(), 5410, true)
	require.Equal(t, 1, fwdA+fwdB)
	require.Equal(t, fwdA, countRefs(b, a.ID(), 5410, false))
	require.Equal(t, fwdB, countRefs(a, b.ID(), 5410, false))
	require.Len(t, a.refsSnapshot(), 2)
	require.Len(t, b.refsSnapshot(), 2)
}
