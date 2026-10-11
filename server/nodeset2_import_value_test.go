// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// valueNodeSet is a NodeSet2 document in the shape modelling tools export:
// the uax prefix is declared on the root element only, values are pretty
// printed, and data types are given as aliases as well as NodeIds.
const valueNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:test:values</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="Double">i=11</Alias>
    <Alias Alias="Argument">i=296</Alias>
    <Alias Alias="HasComponent">i=47</Alias>
  </Aliases>
  <UAVariable NodeId="ns=1;i=6001" BrowseName="1:Scalar" DataType="Int32" AccessLevel="3" UserAccessLevel="1">
    <DisplayName>Scalar</DisplayName>
    <Value>
      <uax:Int32>42</uax:Int32>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6002" BrowseName="1:Array" DataType="Double" ValueRank="1" ArrayDimensions="3">
    <DisplayName>Array</DisplayName>
    <Value>
      <uax:ListOfDouble>
        <uax:Double>1.5</uax:Double>
        <uax:Double>2.5</uax:Double>
        <uax:Double>3.5</uax:Double>
      </uax:ListOfDouble>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6003" BrowseName="1:InputArguments" DataType="Argument" ValueRank="1" ArrayDimensions="1">
    <DisplayName>InputArguments</DisplayName>
    <Value>
      <uax:ListOfExtensionObject>
        <uax:ExtensionObject>
          <uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>
          <uax:Body>
            <uax:Argument>
              <uax:Name>Speed</uax:Name>
              <uax:DataType><uax:Identifier>i=11</uax:Identifier></uax:DataType>
              <uax:ValueRank>-1</uax:ValueRank>
              <uax:ArrayDimensions />
              <uax:Description><uax:Text>target speed</uax:Text></uax:Description>
            </uax:Argument>
          </uax:Body>
        </uax:ExtensionObject>
      </uax:ListOfExtensionObject>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6004" BrowseName="1:NoValue" DataType="ns=1;i=3001" ValueRank="0">
    <DisplayName>NoValue</DisplayName>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6005" BrowseName="1:Defaults">
    <DisplayName>Defaults</DisplayName>
    <Value>
      <String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">text</String>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6006" BrowseName="1:Broken" DataType="NoSuchAlias" ArrayDimensions="2,x">
    <DisplayName>Broken</DisplayName>
    <Value>
      <uax:Int32>not a number</uax:Int32>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6007" BrowseName="1:Matrix" DataType="Int32" ValueRank="2" ArrayDimensions="2, 2">
    <DisplayName>Matrix</DisplayName>
    <Value>
      <uax:Matrix>
        <uax:Dimensions><uax:Int32>2</uax:Int32><uax:Int32>2</uax:Int32></uax:Dimensions>
        <uax:Elements><uax:Int32>1</uax:Int32><uax:Int32>2</uax:Int32><uax:Int32>3</uax:Int32><uax:Int32>4</uax:Int32></uax:Elements>
      </uax:Matrix>
    </Value>
  </UAVariable>
</UANodeSet>`

func TestImportNodeSetXML_VariableValues(t *testing.T) {
	srv := newTestServer()
	require.NoError(t, srv.ImportNodeSetXML([]byte(valueNodeSet)))

	node := func(i uint32) *Node {
		t.Helper()
		n := srv.Node(ua.NewNumericNodeID(1, i))
		require.NotNil(t, n, "ns=1;i=%d", i)
		return n
	}
	attr := func(n *Node, a ua.AttributeID) interface{} {
		t.Helper()
		v, err := n.Attribute(a)
		require.NoError(t, err, "%s", a)
		return v.Value.Value.Value()
	}
	dataType := func(n *Node) string {
		return attr(n, ua.AttributeIDDataType).(*ua.ExpandedNodeID).NodeID.String()
	}

	t.Run("scalar with alias data type and access levels", func(t *testing.T) {
		n := node(6001)
		require.Equal(t, int32(42), attr(n, ua.AttributeIDValue))
		require.Equal(t, "i=6", dataType(n))
		require.Equal(t, int32(-1), attr(n, ua.AttributeIDValueRank), "ValueRank defaults to Scalar")
		require.Equal(t, byte(3), attr(n, ua.AttributeIDAccessLevel))
		require.Equal(t, byte(1), attr(n, ua.AttributeIDUserAccessLevel))
		_, err := n.Attribute(ua.AttributeIDArrayDimensions)
		require.Error(t, err)

		// UserAccessLevel="1" makes the variable read-only.
		require.Equal(t, ua.StatusBadUserAccessDenied,
			n.SetAttribute(ua.AttributeIDValue, DataValueFromValue(int32(1))))
	})

	t.Run("array", func(t *testing.T) {
		n := node(6002)
		require.Equal(t, []float64{1.5, 2.5, 3.5}, attr(n, ua.AttributeIDValue))
		require.Equal(t, "i=11", dataType(n))
		require.Equal(t, int32(1), attr(n, ua.AttributeIDValueRank))
		require.Equal(t, []uint32{3}, attr(n, ua.AttributeIDArrayDimensions))
	})

	t.Run("array of structures", func(t *testing.T) {
		n := node(6003)
		args := attr(n, ua.AttributeIDValue).([]*ua.ExtensionObject)
		require.Len(t, args, 1)
		arg, ok := args[0].Value.(*ua.Argument)
		require.True(t, ok, "decoded as %T", args[0].Value)
		require.Equal(t, "Speed", arg.Name)
		require.Equal(t, "i=11", arg.DataType.String())
		require.Equal(t, int32(-1), arg.ValueRank)
		require.Equal(t, "target speed", arg.Description.Text)
		require.Equal(t, "i=296", dataType(n))

		// The value must be servable: it has to encode in binary.
		v, err := n.Attribute(ua.AttributeIDValue)
		require.NoError(t, err)
		_, err = ua.Encode(v.Value)
		require.NoError(t, err)
	})

	t.Run("matrix", func(t *testing.T) {
		n := node(6007)
		require.Equal(t, [][]int32{{1, 2}, {3, 4}}, attr(n, ua.AttributeIDValue))
		require.Equal(t, int32(2), attr(n, ua.AttributeIDValueRank))
		require.Equal(t, []uint32{2, 2}, attr(n, ua.AttributeIDArrayDimensions))
	})

	t.Run("no value, explicit ValueRank 0 and NodeId data type", func(t *testing.T) {
		n := node(6004)
		_, err := n.Attribute(ua.AttributeIDValue)
		require.Error(t, err)
		require.Equal(t, "ns=1;i=3001", dataType(n))
		require.Equal(t, int32(0), attr(n, ua.AttributeIDValueRank), "an explicit 0 is not the default")
	})

	t.Run("defaults", func(t *testing.T) {
		n := node(6005)
		require.Equal(t, "text", attr(n, ua.AttributeIDValue))
		require.Equal(t, "i=24", dataType(n), "DataType defaults to BaseDataType")
		_, err := n.Attribute(ua.AttributeIDAccessLevel)
		require.Error(t, err, "no AccessLevel attribute, the variable stays writable")
		require.NoError(t, n.SetAttribute(ua.AttributeIDValue, DataValueFromValue("new")))
		require.Equal(t, "new", attr(n, ua.AttributeIDValue))
	})

	t.Run("undecodable parts are skipped, not fatal", func(t *testing.T) {
		n := node(6006)
		_, err := n.Attribute(ua.AttributeIDValue)
		require.Error(t, err)
		require.Equal(t, "i=24", dataType(n))
		_, err = n.Attribute(ua.AttributeIDArrayDimensions)
		require.Error(t, err)
	})
}

// TestImportNodeSet_StandardValues checks that the values of the standard
// node set, which every server imports, are served.
func TestImportNodeSet_StandardValues(t *testing.T) {
	srv := newTestServer()

	value := func(i uint32) interface{} {
		t.Helper()
		n := srv.Node(ua.NewNumericNodeID(0, i))
		require.NotNil(t, n, "i=%d", i)
		v, err := n.Attribute(ua.AttributeIDValue)
		require.NoError(t, err, "i=%d", i)
		return v.Value.Value.Value()
	}

	// EnumValues of NamingRuleType: an array of EnumValueType structures.
	vals := value(id.NamingRuleTypeEnumValues).([]*ua.ExtensionObject)
	require.Len(t, vals, 3)
	require.Equal(t, "Mandatory", vals[0].Value.(*ua.EnumValueType).DisplayName.Text)

	// EnumStrings of a standard enumeration: an array of LocalizedText.
	texts := value(id.ServerStateEnumStrings).([]*ua.LocalizedText)
	require.Equal(t, "Running", texts[0].Text)

	// InputArguments of a standard method: an array of Argument structures.
	args := value(id.ServerGetMonitoredItemsInputArguments).([]*ua.ExtensionObject)
	require.Len(t, args, 1)
	require.Equal(t, "SubscriptionId", args[0].Value.(*ua.Argument).Name)

	// Every imported value can be put on the wire.
	n := 0
	for _, v := range builtinNodeSet.UAVariable {
		if v.Value == nil {
			continue
		}
		val := builtinNodeSetValues[v.Value]
		require.NotNil(t, val, "%s: value not decoded", v.NodeIDAttr)
		_, err := ua.Encode(val)
		require.NoError(t, err, v.NodeIDAttr)
		n++
	}
	require.Greater(t, n, 1000)
}
