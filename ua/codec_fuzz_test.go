// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// fuzzTargets are the types hostile documents are decoded into. Together
// they reach every decoder: all built-in types through Variant, the object
// forms through DataValue / ExtensionObject / DiagnosticInfo, and structure,
// enumeration and array fields through the service messages.
func fuzzTargets() []interface{} {
	return []interface{}{
		new(Variant),
		new(DataValue),
		new(ExtensionObject),
		new(DiagnosticInfo),
		new(ExpandedNodeID),
		new(ReadResponse),
		new(EndpointDescription),
		new([]*Variant),
	}
}

// fuzzCodec decodes data into every target. Whatever is accepted must be a
// value the encoders - binary included - can write, and writing and reading
// it again must be stable.
func fuzzCodec(t *testing.T, data []byte,
	decode func([]byte, interface{}, ...CodecOption) error,
	encode func(interface{}, ...CodecOption) ([]byte, error)) {
	for _, target := range fuzzTargets() {
		if err := decode(data, target); err != nil {
			continue
		}
		if _, err := Encode(target); err != nil {
			t.Fatalf("%T: accepted a value the binary encoder rejects: %v\n%s", target, err, data)
		}
		doc, err := encode(target)
		if err != nil {
			t.Fatalf("%T: accepted a value that cannot be encoded again: %v\n%s", target, err, data)
		}
		again := reflect.New(reflect.TypeOf(target).Elem()).Interface()
		if err := decode(doc, again); err != nil {
			t.Fatalf("%T: cannot decode own output: %v\n in:  %s\n out: %s", target, err, data, doc)
		}
		doc2, err := encode(again)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(doc, doc2) {
			t.Fatalf("%T: encoding is not stable\n in:  %s\n 1st: %s\n 2nd: %s", target, data, doc, doc2)
		}
	}
}

// corpusSeeds adds the documents of the open62541 corpus as seeds.
func corpusSeeds(f *testing.F, pick func(corpusEntry) []string) {
	raw, err := os.ReadFile(corpusFile)
	if err != nil {
		f.Fatal(err)
	}
	var entries []corpusEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		for _, doc := range pick(e) {
			f.Add([]byte(doc))
		}
	}
}

func FuzzDecodeJSON(f *testing.F) {
	corpusSeeds(f, func(e corpusEntry) []string { return []string{e.JSON, e.GoJSON} })
	for _, seed := range []string{
		`{"Type":22,"Body":{"TypeId":{"Id":15375},"Body":{"Low":1,"High":2}}}`,
		`{"Value":{"Type":6,"Body":[1,2,3,4],"Dimensions":[2,2]},"Status":2150891520}`,
		`{"IdType":2,"Id":"C496578A-0DFE-4B8F-870A-745238C6AEAE","Namespace":"urn:x","ServerUri":3}`,
		`{"UaTypeId":"i=884","UaEncoding":1,"UaBody":"AAAAAAAA8D8AAAAAAAAAQA=="}`,
		`{"UaType":24,"Value":[{"UaType":24,"Value":[{"UaType":25,"Value":{"InnerDiagnosticInfo":{"InnerDiagnosticInfo":{}}}}]}]}`,
		`{"UaType":12,"Value":["🙂","\u0000"],"Dimensions":[2,1]}`,
		`[[[[[[[[[[[[[[[[[[[[[[`,
		`{"UaType":6,"Value":[],"Dimensions":[0]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCodec(t, data, DecodeJSON, EncodeJSON)
	})
}

func FuzzDecodeXML(f *testing.F) {
	corpusSeeds(f, func(e corpusEntry) []string { return []string{e.XML, e.GoXML} })
	for _, seed := range []string{
		`<Value><uax:ListOfExtensionObject xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd"><uax:ExtensionObject><uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId><uax:Body><uax:Argument><uax:Name>a</uax:Name><uax:DataType><uax:Identifier>i=6</uax:Identifier></uax:DataType><uax:ValueRank>-1</uax:ValueRank></uax:Argument></uax:Body></uax:ExtensionObject></uax:ListOfExtensionObject></Value>`,
		`<Variant><Value><Matrix><Dimensions><Int32>2</Int32><Int32>1</Int32></Dimensions><Elements><Variant><Value><Matrix><Dimensions><Int32>1</Int32></Dimensions><Elements><Guid><String>C496578A-0DFE-4B8F-870A-745238C6AEAE</String></Guid></Elements></Matrix></Value></Variant><Variant/></Elements></Matrix></Value></Variant>`,
		`<ExtensionObject><TypeId><Identifier>ns=2;i=1</Identifier></TypeId><Body><x><![CDATA[<y>]]>&amp;<z a="b"/></x></Body></ExtensionObject>`,
		`<DataValue><Value><Value><ListOfByteString xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></Value></Value><StatusCode><Code>1</Code></StatusCode></DataValue>`,
		`<a><a><a><a><a><a><a><a><a><a><a><a>`,
		`<!DOCTYPE a [<!ENTITY b "bbbb"><!ENTITY c "&b;&b;&b;">]><String>&c;</String>`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCodec(t, data, DecodeXML, EncodeXML)
	})
}
