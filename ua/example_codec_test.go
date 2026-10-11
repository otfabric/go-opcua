// SPDX-License-Identifier: MIT

package ua_test

import (
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// A DataValue in the JSON DataEncoding. The default is the Compact form of
// OPC UA 1.05.04.
func ExampleEncodeJSON() {
	dv := &ua.DataValue{
		Value:           ua.MustVariant([]float64{1.5, 2.5}),
		Status:          ua.StatusBadNodeIDUnknown,
		SourceTimestamp: time.Date(2024, 2, 29, 12, 34, 56, 0, time.UTC),
	}
	dv.UpdateMask()

	doc, _ := ua.EncodeJSON(dv)
	fmt.Println(string(doc))

	doc, _ = ua.EncodeJSON(dv, ua.WithJSONForm(ua.JSONVerbose))
	fmt.Println(string(doc))

	doc, _ = ua.EncodeJSON(dv, ua.WithJSONForm(ua.JSONLegacyReversible))
	fmt.Println(string(doc))

	// Output:
	// {"UaType":11,"Value":[1.5,2.5],"Status":{"Code":2150891520},"SourceTimestamp":"2024-02-29T12:34:56Z"}
	// {"UaType":11,"Value":[1.5,2.5],"Status":{"Code":2150891520,"Symbol":"BadNodeIdUnknown"},"SourceTimestamp":"2024-02-29T12:34:56Z"}
	// {"Value":{"Type":11,"Body":[1.5,2.5]},"Status":2150891520,"SourceTimestamp":"2024-02-29T12:34:56Z"}
}

// DecodeJSON accepts the 1.05 forms and the 1.04 reversible form alike.
func ExampleDecodeJSON() {
	for _, doc := range []string{
		`{"UaType":6,"Value":[1,2,3,4],"Dimensions":[2,2]}`,
		`{"Type":6,"Body":[1,2,3,4],"Dimensions":[2,2]}`,
	} {
		var v ua.Variant
		if err := ua.DecodeJSON([]byte(doc), &v); err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(v.Type(), v.ArrayDimensions(), v.Value())
	}

	// Output:
	// TypeIDInt32 [2 2] [[1 2] [3 4]]
	// TypeIDInt32 [2 2] [[1 2] [3 4]]
}

// A structure in the XML DataEncoding.
func ExampleEncodeXML() {
	arg := &ua.Argument{
		Name:        "Speed",
		DataType:    ua.NewTwoByteNodeID(11),
		ValueRank:   -1,
		Description: ua.NewLocalizedText("target speed"),
	}
	doc, _ := ua.EncodeXML(arg, ua.WithIndent("  "))
	fmt.Println(string(doc))

	// Output:
	// <Argument xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
	//   <Name>Speed</Name>
	//   <DataType>
	//     <Identifier>i=11</Identifier>
	//   </DataType>
	//   <ValueRank>-1</ValueRank>
	//   <Description>
	//     <Text>target speed</Text>
	//   </Description>
	// </Argument>
}

// The <Value> element of a NodeSet2 UAVariable can be decoded as it is.
func ExampleDecodeXML() {
	doc := `<Value>
  <uax:ListOfExtensionObject xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
    <uax:ExtensionObject>
      <uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>
      <uax:Body>
        <uax:Argument>
          <uax:Name>Speed</uax:Name>
          <uax:DataType><uax:Identifier>i=11</uax:Identifier></uax:DataType>
          <uax:ValueRank>-1</uax:ValueRank>
        </uax:Argument>
      </uax:Body>
    </uax:ExtensionObject>
  </uax:ListOfExtensionObject>
</Value>`

	var v ua.Variant
	if err := ua.DecodeXML([]byte(doc), &v); err != nil {
		fmt.Println(err)
		return
	}
	for _, eo := range v.Value().([]*ua.ExtensionObject) {
		arg := eo.Value.(*ua.Argument)
		fmt.Println(arg.Name, arg.DataType, arg.ValueRank)
	}

	// Output:
	// Speed i=11 -1
}

// With the NamespaceArray of the server the documents carry namespace URIs,
// which stay valid when the namespace indexes differ on another server.
func ExampleWithNamespaceArray() {
	namespaces := []string{"http://opcfoundation.org/UA/", "urn:server", "urn:my:model"}
	opts := []ua.CodecOption{ua.WithNamespaceArray(namespaces)}

	doc, _ := ua.EncodeJSON(ua.NewNumericNodeID(2, 7), opts...)
	fmt.Println(string(doc))

	var id ua.NodeID
	_ = ua.DecodeJSON(doc, &id, opts...)
	fmt.Println(id.String())

	// Output:
	// "nsu=urn:my:model;i=7"
	// ns=2;i=7
}
