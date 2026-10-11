// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Custom structures as an application registers them.

type codecMotor struct {
	Speed  float64
	Label  string `opcua:"DisplayLabel"`
	Limits codecLimits
	Tags   []string
	Mode   codecMotorMode
}

type codecLimits struct {
	Low  int32
	High int32
}

type codecMotorMode int32

// codecPlain is registered without any JSON/XML metadata.
type codecPlain struct {
	A int32
	B *QualifiedName
}

func init() {
	RegisterExtensionObject(NewNumericNodeID(7, 5001), new(codecMotor))
	RegisterDataTypeInfo(new(codecMotor), DataTypeInfo{
		Name:           "MotorType",
		DataTypeID:     NewNumericNodeID(7, 3001),
		XMLEncodingID:  NewNumericNodeID(7, 5002),
		JSONEncodingID: NewNumericNodeID(7, 5003),
	})
	RegisterExtensionObject(NewNumericNodeID(7, 5010), new(codecPlain))
}

func TestCustomStructureCodec(t *testing.T) {
	motor := &codecMotor{Speed: 1.5, Label: "M1", Limits: codecLimits{Low: -1, High: 9}, Tags: []string{"a"}, Mode: 2}

	t.Run("structure", func(t *testing.T) {
		j, err := EncodeJSON(motor)
		require.NoError(t, err)
		require.Equal(t, `{"Speed":1.5,"DisplayLabel":"M1","Limits":{"Low":-1,"High":9},"Tags":["a"],"Mode":2}`, string(j))
		var back codecMotor
		require.NoError(t, DecodeJSON(j, &back))
		require.Equal(t, *motor, back)

		x, err := EncodeXML(motor, WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<MotorType><Speed>1.5</Speed><DisplayLabel>M1</DisplayLabel><Limits><Low>-1</Low><High>9</High></Limits><Tags><String>a</String></Tags><Mode>2</Mode></MotorType>`, string(x))
		back = codecMotor{}
		require.NoError(t, DecodeXML(x, &back))
		require.Equal(t, *motor, back)
	})

	t.Run("extension object with metadata", func(t *testing.T) {
		v := MustVariant(NewExtensionObject(motor))
		require.NoError(t, checkIdentity(v))

		// JSON identifies the body by the DataType, XML by the DefaultXml
		// encoding node.
		j, err := EncodeJSON(v)
		require.NoError(t, err)
		require.Equal(t, `{"UaType":22,"Value":{"UaTypeId":"ns=7;i=3001","Speed":1.5,"DisplayLabel":"M1","Limits":{"Low":-1,"High":9},"Tags":["a"],"Mode":2}}`, string(j))
		x, err := EncodeXML(v, WithoutXMLNamespace())
		require.NoError(t, err)
		require.Contains(t, string(x), `<ExtensionObject><TypeId><Identifier>ns=7;i=5002</Identifier></TypeId><Body><MotorType><Speed>1.5</Speed>`)

		// Every id of the type is accepted when decoding.
		for _, id := range []string{"ns=7;i=3001", "ns=7;i=5001", "ns=7;i=5002", "ns=7;i=5003"} {
			var eo ExtensionObject
			require.NoError(t, DecodeJSON([]byte(`{"UaTypeId":"`+id+`","Speed":2}`), &eo), id)
			require.Equal(t, &codecMotor{Speed: 2}, eo.Value, id)
			require.Equal(t, "ns=7;i=5001", eo.TypeID.NodeID.String(), "the binary encoding id is restored")
		}

		// A structure may appear under its name in an XML Variant.
		var bare Variant
		require.NoError(t, DecodeXML([]byte(`<Variant><Value><MotorType><Speed>3</Speed></MotorType></Value></Variant>`), &bare))
		require.Equal(t, &codecMotor{Speed: 3}, bare.Value().(*ExtensionObject).Value)
	})

	t.Run("extension object without metadata", func(t *testing.T) {
		plain := &codecPlain{A: 4, B: &QualifiedName{NamespaceIndex: 1, Name: "b"}}
		v := MustVariant([]*ExtensionObject{NewExtensionObject(plain), NewExtensionObject(motor)})
		require.NoError(t, checkIdentity(v))

		// The id the type was registered with stands in for the missing
		// DataType id.
		j, err := EncodeJSON(NewExtensionObject(plain))
		require.NoError(t, err)
		require.Equal(t, `{"UaTypeId":"ns=7;i=5010","A":4,"B":"1:b"}`, string(j))
		x, err := EncodeXML(NewExtensionObject(plain), WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ExtensionObject><TypeId><Identifier>ns=7;i=5010</Identifier></TypeId><Body><codecPlain><A>4</A><B><NamespaceIndex>1</NamespaceIndex><Name>b</Name></B></codecPlain></Body></ExtensionObject>`, string(x))
	})

	t.Run("namespace URIs", func(t *testing.T) {
		opts := []CodecOption{WithNamespaceArray([]string{"http://opcfoundation.org/UA/", "urn:1", "urn:2", "urn:3", "urn:4", "urn:5", "urn:6", "urn:motors"})}
		v := MustVariant(NewExtensionObject(motor))
		j, err := EncodeJSON(v, opts...)
		require.NoError(t, err)
		require.Contains(t, string(j), `"UaTypeId":"nsu=urn:motors;i=3001"`)
		require.NoError(t, checkIdentity(v, opts...))
	})

	t.Run("non-structure body", func(t *testing.T) {
		// open62541 writes such bodies under UaBody (NON-STANDARD in its
		// source); the same form is used here.
		mode := codecMotorMode(3)
		eo := &ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewFourByteExpandedNodeID(7, 5020), Value: &mode}
		j, err := EncodeJSON(eo)
		require.NoError(t, err)
		require.Equal(t, `{"UaTypeId":"ns=7;i=5020","UaBody":3}`, string(j))
		x, err := EncodeXML(eo, WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ExtensionObject><TypeId><Identifier>ns=7;i=5020</Identifier></TypeId><Body><codecMotorMode>3</codecMotorMode></Body></ExtensionObject>`, string(x))

		var nilMode *codecMotorMode
		j, err = EncodeJSON(&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewFourByteExpandedNodeID(7, 5020), Value: nilMode})
		require.NoError(t, err)
		require.Equal(t, `null`, string(j))
		x, err = EncodeXML(&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewFourByteExpandedNodeID(7, 5020), Value: nilMode}, WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ExtensionObject></ExtensionObject>`, string(x))
	})
}

// TestBinaryNilSafety pins the binary codec fixes the JSON and XML codecs
// rely on: values decoded from a document that leaves fields out contain nil
// pointers, which must encode as the null value of their type.
func TestBinaryNilSafety(t *testing.T) {
	for name, tc := range map[string]struct {
		v    interface{}
		want string
	}{
		"Variant":            {(*Variant)(nil), "00"},
		"DataValue":          {(*DataValue)(nil), "00"},
		"DiagnosticInfo":     {(*DiagnosticInfo)(nil), "00"},
		"GUID":               {(*GUID)(nil), "00000000000000000000000000000000"},
		"GUID short":         {&GUID{Data1: 1}, "01000000000000000000000000000000"},
		"DataValue no value": {&DataValue{EncodingMask: DataValueValue}, "0100"},
		"struct fields":      {&KeyValuePair{}, "0000ffffffff00"},
		"unknown ext object": {&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(9)}, "000900"},
		"raw ext object":     {&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(9), Value: []byte{1, 2}}, "000901020000000102"},
		"ByteString array":   {MustVariant([][]byte{{1}, {2, 3}}), "8f020000000100000001020000000203"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, binOf(t, tc.v))
		})
	}

	t.Run("DateTime range", func(t *testing.T) {
		for _, s := range []string{"1601-01-01T00:00:00.0000001Z", "1677-01-01T00:00:00Z", "2263-01-01T00:00:00.1234567Z", "9999-12-31T23:59:59.9999999Z"} {
			in := mustTime(s)
			buf := NewBuffer(nil)
			buf.WriteTime(in)
			require.NoError(t, buf.Error())
			out := NewBuffer(buf.Bytes()).ReadTime()
			require.True(t, in.Equal(out), "%s came back as %s", s, out)
		}
		buf := NewBuffer(nil)
		buf.WriteTime(mustTime("1500-06-01T00:00:00Z"))
		require.Equal(t, make([]byte, 8), buf.Bytes(), "before the epoch is the null DateTime")
	})
}
