// SPDX-License-Identifier: MIT

package nodeset

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const doc = `<UANodeSet>
  <NamespaceUris>
    <Uri>urn:a</Uri>
    <Uri>urn:b</Uri>
  </NamespaceUris>
  <Aliases><Alias Alias="T">ns=2;i=7</Alias></Aliases>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:Obj" ParentNodeId="ns=2;s=x">
    <References><Reference ReferenceType="HasTypeDefinition">ns=2;i=5</Reference></References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=2" BrowseName="InputArguments" DataType="i=12">
    <Value><QualifiedName><NamespaceIndex>2</NamespaceIndex><Name>Q</Name></QualifiedName></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=3" BrowseName="3DVector" DataType="i=12"/>
  <UADataType NodeId="ns=1;i=4" BrowseName="2:DT"><Definition Name="2:DT"><Field Name="F" DataType="ns=0;i=1"/></Definition></UADataType>
  <Description>Holds nsu=urn:x and terms like columns=4;</Description>
</UANodeSet>`

func table(m map[string]uint16) Resolver {
	return func(uri string) (uint16, error) {
		if i, ok := m[uri]; ok {
			return i, nil
		}
		return 0, errors.New("unknown")
	}
}

func TestURIs(t *testing.T) {
	uris, err := URIs([]byte(doc))
	require.NoError(t, err)
	assert.Equal(t, []string{"urn:a", "urn:b"}, uris)

	uris, err = URIs([]byte(`<UANodeSet/>`))
	require.NoError(t, err)
	assert.Nil(t, uris)

	_, err = URIs([]byte(`<NamespaceUris><Uri>x</Uri>`))
	assert.Error(t, err)
	_, err = URIs([]byte(`<NamespaceUris><Uri>x</NamespaceUris>`))
	assert.Error(t, err)

	big := "<NamespaceUris>" + strings.Repeat("<Uri>u</Uri>", maxURIs+1) + "</NamespaceUris>"
	_, err = URIs([]byte(big))
	assert.Error(t, err)
}

func TestRemap(t *testing.T) {
	out, err := Remap([]byte(doc), table(map[string]uint16{"urn:a": 7, "urn:b": 3}))
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "NamespaceUris")
	assert.Contains(t, s, `<Alias Alias="T">ns=3;i=7</Alias>`)
	assert.Contains(t, s, `NodeId="ns=7;i=1" BrowseName="7:Obj" ParentNodeId="ns=3;s=x"`)
	assert.Contains(t, s, `>ns=3;i=5</Reference>`)
	assert.Contains(t, s, `BrowseName="0:InputArguments"`)
	assert.Contains(t, s, `BrowseName="0:3DVector"`)
	assert.Contains(t, s, `<NamespaceIndex>3</NamespaceIndex>`)
	assert.Contains(t, s, `BrowseName="3:DT"><Definition Name="3:DT"><Field Name="F" DataType="ns=0;i=1"/>`)
	assert.Contains(t, s, "nsu=urn:x and terms like columns=4;")
}

func TestRemapErrors(t *testing.T) {
	_, err := Remap([]byte(doc), table(map[string]uint16{"urn:a": 7}))
	assert.ErrorContains(t, err, `namespace "urn:b"`)

	for _, bad := range []string{
		`<NamespaceUris><Uri>urn:a</Uri></NamespaceUris><UAObject NodeId="ns=2;i=1"/>`,
		`<NamespaceUris><Uri>urn:a</Uri></NamespaceUris><UAObject BrowseName="5:X"/>`,
		`<NamespaceUris><Uri>urn:a</Uri></NamespaceUris><NamespaceIndex>2</NamespaceIndex>`,
		`<UAObject NodeId="ns=99999999999;i=1"/>`,
		`<NamespaceUris><Uri>urn:a</Uri>`,
	} {
		_, err := Remap([]byte(bad), table(map[string]uint16{"urn:a": 1}))
		assert.Error(t, err, bad)
	}
}

// TestRemapStrayEnd checks that only the table is cut out of a document
// with an end tag of NamespaceUris before the table.
func TestRemapStrayEnd(t *testing.T) {
	out, err := Remap([]byte(`</NamespaceUris>A<NamespaceUris><Uri>u</Uri></NamespaceUris>B`), table(map[string]uint16{"u": 2}))
	require.NoError(t, err)
	assert.Equal(t, `</NamespaceUris>AB`, string(out))
}

func TestRemapNoTable(t *testing.T) {
	out, err := Remap([]byte(`<UAObject NodeId="ns=0;i=1" BrowseName="X"/>`), table(nil))
	require.NoError(t, err)
	assert.Equal(t, `<UAObject NodeId="ns=0;i=1" BrowseName="0:X"/>`, string(out))
}

// TestRemapLeavesText checks that NodeId-like text outside the places of
// Part 6 Annex F is copied as it is: descriptions, display names, string
// values, comments and Extensions.
func TestRemapLeavesText(t *testing.T) {
	src := `<UANodeSet>
  <NamespaceUris><Uri>urn:a</Uri></NamespaceUris>
  <!-- see ns=1;i=7 -->
  <UAVariable NodeId="ns=1;i=1" BrowseName="1:V" DataType="String">
    <DisplayName>ns=1;i=7</DisplayName>
    <Description>Example NodeId: ns=1;i=7</Description>
    <Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">ns=1;i=7</String></Value>
  </UAVariable>
  <Extensions><Extension><Vendor Ref="ns=1;i=7">ns=1;i=7</Vendor></Extension></Extensions>
</UANodeSet>`
	out, err := Remap([]byte(src), table(map[string]uint16{"urn:a": 5}))
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `NodeId="ns=5;i=1" BrowseName="5:V"`)
	assert.Equal(t, 6, strings.Count(s, "ns=1;i=7"), s)
	assert.Contains(t, s, "<!-- see ns=1;i=7 -->")
	assert.Contains(t, s, "<Description>Example NodeId: ns=1;i=7</Description>")
	assert.Contains(t, s, `<Vendor Ref="ns=1;i=7">ns=1;i=7</Vendor>`)
}

// TestRemapForms checks the forms XML allows for the places that are
// rewritten: single quotes, white space around "=", prefixed element
// names, NodeIds in values, CDATA.
func TestRemapForms(t *testing.T) {
	src := `<UANodeSet>
  <NamespaceUris><Uri>urn:a</Uri></NamespaceUris>
  <UAObject NodeId = 'ns=1;i=1' BrowseName	=	"1:O" ParentNodeId='ns=1;i=2'>
    <References><Reference ReferenceType='ns=1;i=9' IsForward="false"><![CDATA[ns=1;i=3]]></Reference></References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=4" BrowseName="1:V" DataType="NodeId">
    <Value><uax:NodeId xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd"><uax:Identifier>ns=1;i=5</uax:Identifier></uax:NodeId></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6" BrowseName="1:Q" DataType="QualifiedName">
    <Value><QualifiedName><NamespaceIndex> 1 </NamespaceIndex><Name>ns=1;i=8</Name></QualifiedName></Value>
  </UAVariable>
</UANodeSet>`
	out, err := Remap([]byte(src), table(map[string]uint16{"urn:a": 5}))
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `<UAObject NodeId = 'ns=5;i=1' BrowseName	=	"5:O" ParentNodeId='ns=5;i=2'>`)
	assert.Contains(t, s, `<Reference ReferenceType='ns=5;i=9' IsForward="false"><![CDATA[ns=5;i=3]]></Reference>`)
	assert.Contains(t, s, `<uax:Identifier>ns=5;i=5</uax:Identifier>`)
	assert.Contains(t, s, `<NamespaceIndex> 5 </NamespaceIndex><Name>ns=1;i=8</Name>`)
}

func TestRemapMalformed(t *testing.T) {
	for _, bad := range []string{
		`<UAObject NodeId="ns=1;i=1"`,
		`<NamespaceUris><Uri>a</Uri><Other/></NamespaceUris>`,
		`<A>&unknown;</A>`,
	} {
		_, err := Remap([]byte(bad), table(map[string]uint16{"a": 1}))
		assert.Error(t, err, bad)
	}
	// An empty table element is cut out as well.
	out, err := Remap([]byte(`<UANodeSet><NamespaceUris/><UAObject NodeId="i=1" BrowseName="X"/></UANodeSet>`), table(nil))
	require.NoError(t, err)
	assert.Equal(t, `<UANodeSet><UAObject NodeId="i=1" BrowseName="0:X"/></UANodeSet>`, string(out))
}

func TestNodeIDsAndNodes(t *testing.T) {
	ids, err := NodeIDs([]byte(doc))
	require.NoError(t, err)
	assert.Equal(t, []string{"ns=2;i=7", "ns=1;i=1", "ns=2;s=x", "HasTypeDefinition", "ns=2;i=5", "ns=1;i=2", "i=12", "ns=1;i=3", "ns=1;i=4", "ns=0;i=1"}, ids)
	nodes, err := Nodes([]byte(doc))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"ns=1;i=1": "UAObject", "ns=1;i=2": "UAVariable", "ns=1;i=3": "UAVariable", "ns=1;i=4": "UADataType"}, nodes)
	_, err = NodeIDs([]byte(`<A`))
	assert.Error(t, err)
	_, err = Nodes([]byte(`<A`))
	assert.Error(t, err)
}

// FuzzRemap feeds arbitrary documents, which come from the application or
// a file, to Remap: it never panics, and a document it returns has no
// namespace table of its own.
func FuzzRemap(f *testing.F) {
	f.Add([]byte(doc))
	f.Add([]byte(`<NamespaceUris><Uri>a</Uri></NamespaceUris>ns=1;ns=2; BrowseName="1:x"`))
	f.Add([]byte(`<NamespaceUris></NamespaceUris>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Remap(b, func(string) (uint16, error) { return 9, nil })
		if err != nil {
			return
		}
		// The namespace table of the document is gone, and a rewrite adds
		// at most "0:" to a BrowseName and a few digits to an index.
		if bytes.Count(out, []byte("<NamespaceUris>")) != max(0, bytes.Count(b, []byte("<NamespaceUris>"))-1) {
			t.Fatalf("the namespace table is left in %q", out)
		}
		if len(out) > 3*len(b)+16 {
			t.Fatalf("%d bytes became %d", len(b), len(out))
		}
	})
}
