// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// file encodes sets in a UABinaryFileDataType with the Namespaces uris
// and the indexes ns.
func file(t testing.TB, uris []string, ns uafx.NamespaceIndexes, body *ua.Variant) []byte {
	t.Helper()
	b, err := ua.Encode(&ua.UABinaryFileDataType{Namespaces: uris, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setsBody(t testing.TB, ns uafx.NamespaceIndexes, sets ...uafx.Structure) *ua.Variant {
	t.Helper()
	eos := make([]*ua.ExtensionObject, len(sets))
	for i, s := range sets {
		eo, err := uafx.EncodeStructure(s, ns)
		if err != nil {
			t.Fatal(err)
		}
		eos[i] = eo
	}
	return ua.MustVariant(eos)
}

func TestFileRoundTrip(t *testing.T) {
	a := validConf()
	b := validConf()
	b.BrowseName = "Line2"
	b.ConnectionConfigurationSetFolder = nil
	data, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{a, b})
	if err != nil {
		t.Fatal(err)
	}
	sets, err := DecodeFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || sets[0].BrowseName != "Line1" || sets[1].BrowseName != "Line2" {
		t.Fatalf("sets %v", sets)
	}
	for _, s := range sets {
		if _, err := NewConfig(s); err != nil {
			t.Error(err)
		}
	}
	again, err := EncodeFile(sets)
	if err != nil || !bytes.Equal(again, data) {
		t.Errorf("a second encoding differs: %v", err)
	}

	// The Namespaces of the file (F.2: at least OPC UA and CM).
	var fd ua.UABinaryFileDataType
	if _, err := ua.Decode(data, &fd); err != nil {
		t.Fatal(err)
	}
	if len(fd.Namespaces) != 4 || fd.Namespaces[0] != uaNamespace || fd.Namespaces[3] != fxcmid.NamespaceURI {
		t.Errorf("Namespaces %v", fd.Namespaces)
	}

	// An empty Body: no sets (Bad_NothingToDo is CloseAndUpdate's).
	empty, err := EncodeFile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if sets, err := DecodeFile(empty); err != nil || len(sets) != 0 {
		t.Errorf("empty: %v %v", sets, err)
	}
}

// TestFileNamespaceLayouts reads files whose Namespaces follow Part 5
// §12.31 (first entry index 1) with and without the OPC UA namespace, and
// one written as a NamespaceArray (first entry index 0).
func TestFileNamespaceLayouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		uris []string
		ns   uafx.NamespaceIndexes
	}{
		{"Part 5 with OPC UA", []string{uaNamespace, fxcmid.NamespaceURI, fxacid.NamespaceURI, fxdataid.NamespaceURI}, uafx.NamespaceIndexes{CM: 2, AC: 3, Data: 4}},
		{"Part 5 without OPC UA", []string{fxacid.NamespaceURI, fxcmid.NamespaceURI}, uafx.NamespaceIndexes{AC: 1, CM: 2}},
		{"NamespaceArray", []string{uaNamespace, fxcmid.NamespaceURI, fxacid.NamespaceURI, fxdataid.NamespaceURI}, uafx.NamespaceIndexes{CM: 1, AC: 2, Data: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := DecodeFile(file(t, tc.uris, tc.ns, setsBody(t, tc.ns, validConf())))
			if err != nil || len(sets) != 1 {
				t.Fatalf("%v %v", sets, err)
			}
			if _, err := NewConfig(sets[0]); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDecodeFileErrors(t *testing.T) {
	part5 := []string{uaNamespace, fxdataid.NamespaceURI, fxacid.NamespaceURI, fxcmid.NamespaceURI}
	valid, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{validConf()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"garbage", []byte{1, 2, 3}},
		{"trailing bytes", append(bytes.Clone(valid), 0)},
		{"too large", make([]byte, MaxFileSize+1)},
		{"no Body", file(t, part5, fileNS, nil)},
		{"a scalar Body", file(t, part5, fileNS, ua.MustVariant("x"))},
		{"no CM namespace", file(t, []string{fxacid.NamespaceURI}, fileNS, setsBody(t, fileNS, validConf()))},
		{"no CM namespace, OPC UA first", file(t, []string{uaNamespace, fxacid.NamespaceURI}, fileNS, setsBody(t, fileNS, validConf()))},
		{"another structure", file(t, part5, fileNS, setsBody(t, fileNS, &uafx.ServerAddressConf{}))},
		{"a null structure", file(t, part5, fileNS, ua.MustVariant([]*ua.ExtensionObject{nil}))},
		{"wrong indexes", file(t, part5, uafx.NamespaceIndexes{Data: 5, AC: 6, CM: 7}, setsBody(t, uafx.NamespaceIndexes{Data: 5, AC: 6, CM: 7}, validConf()))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeFile(tc.b)
			if !errors.Is(err, ErrConfig) || StatusOf(err) != ua.StatusBadTypeMismatch {
				t.Errorf("%v, want Bad_TypeMismatch (Table F.40)", err)
			}
		})
	}
}

func TestFileNamespacesBeyondIndexes(t *testing.T) {
	uris := make([]string, 0x10001)
	uris[0x10000] = fxcmid.NamespaceURI
	if _, ok := fileNamespaces(uris, 1); ok {
		t.Error("an index beyond 65535")
	}
}

func TestEncodeFileErrors(t *testing.T) {
	if _, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{nil}); StatusOf(err) != ua.StatusBadInvalidArgument {
		t.Errorf("nil set: %v", err)
	}
	c := validConf()
	c.ConnectionConfigurationSetProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "k"}, Value: ua.MustVariant(ua.NewExtensionObject(struct{ X chan int }{}))}}
	if _, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{c}); StatusOf(err) != ua.StatusBadInvalidArgument {
		t.Errorf("unencodable set: %v", err)
	}
}

// FuzzDecodeFile decodes untrusted file content. A file that decodes must
// encode again and decode to the same number of sets, and validating its
// sets must not panic.
func FuzzDecodeFile(f *testing.F) {
	valid, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{validConf()})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	empty, _ := EncodeFile(nil)
	f.Add(empty)
	arr := uafx.NamespaceIndexes{CM: 1, AC: 2, Data: 3}
	f.Add(file(f, []string{uaNamespace, fxcmid.NamespaceURI, fxacid.NamespaceURI, fxdataid.NamespaceURI}, arr, setsBody(f, arr, validConf())))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		sets, err := DecodeFile(b)
		if err != nil {
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("error outside ErrConfig: %v", err)
			}
			return
		}
		for _, s := range sets {
			_, _ = NewConfig(s)
		}
		again, err := EncodeFile(sets)
		if err != nil {
			t.Fatalf("decoded sets do not encode: %v", err)
		}
		sets2, err := DecodeFile(again)
		if err != nil || len(sets2) != len(sets) {
			t.Fatalf("round trip: %d %d %v", len(sets), len(sets2), err)
		}
	})
}

// Hand-written bytes of a file (Part 5 §12.31, Part 6 §5.2), independent of
// the generated codec and of EncodeFile: one ConnectionConfigurationSetConf
// (Table F.1) with BrowseName "S", the Folder ["F"], empty arrays,
// RollbackOnError TRUE, the null SecurityKeyServer (Table F.10, no optional
// field), Version 7 and no properties.
func handFile(uris []string, cmIndex byte) []byte {
	var b []byte
	i32 := func(v int32) { b = append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	str := func(s string) { i32(int32(len(s))); b = append(b, s...) }
	// Namespaces.
	i32(int32(len(uris)))
	for _, u := range uris {
		str(u)
	}
	i32(-1)             // StructureDataTypes
	i32(-1)             // EnumDataTypes
	i32(-1)             // SimpleDataTypes
	i32(-1)             // SchemaLocation
	i32(-1)             // FileHeader
	b = append(b, 0x96) // Body: Variant, array of ExtensionObject (22 | 0x80)
	i32(1)
	// The ExtensionObject: four-byte NodeId ns=cmIndex;i=5029 (the Default
	// Binary encoding of ConnectionConfigurationSetConfDataType), binary
	// body.
	b = append(b, 0x01, cmIndex, 0xA5, 0x13, 0x01)
	var body []byte
	{
		saved := b
		b = nil
		str("S")
		i32(1)
		str("F")
		i32(0)              // Connections
		i32(0)              // CommunicationFlows
		i32(0)              // ServerAddresses
		i32(0)              // AutomationComponentConfigurations
		b = append(b, 0x01) // RollbackOnError
		i32(0)              // SecurityKeyServer: EncodingMask
		i32(-1)             // Address
		i32(-1)             // SecurityPolicyUri
		i32(-1)             // ServerUri
		b = append(b, 0x00) // UsePushModel
		i32(7)              // Version
		i32(-1)             // ConnectionConfigurationSetProperties
		body, b = b, saved
	}
	i32(int32(len(body)))
	return append(b, body...)
}

// TestFileFixtures reads the hand-written files: the indexes of Part 5
// with and without the OPC UA namespace, and the NamespaceArray indexes
// DecodeFile tolerates.
func TestFileFixtures(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"Part 5, F.2 Namespaces", handFile([]string{uaNamespace, fxcmid.NamespaceURI}, 2)},
		{"Part 5, no OPC UA namespace", handFile([]string{fxcmid.NamespaceURI}, 1)},
		{"NamespaceArray indexes (tolerated)", handFile([]string{uaNamespace, fxcmid.NamespaceURI}, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := DecodeFile(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			s := sets[0]
			if len(sets) != 1 || s.BrowseName != "S" || len(s.ConnectionConfigurationSetFolder) != 1 || s.ConnectionConfigurationSetFolder[0] != "F" ||
				!s.RollbackOnError || s.Version != 7 || !nullSKS(s.SecurityKeyServer) || len(s.Connections) != 0 {
				t.Errorf("%+v", s)
			}
		})
	}
	// The CM namespace at an index the Body does not use.
	if _, err := DecodeFile(handFile([]string{uaNamespace, fxcmid.NamespaceURI}, 3)); StatusOf(err) != ua.StatusBadTypeMismatch {
		t.Errorf("wrong index: %v", err)
	}
	// EncodeFile writes the same set to bytes DecodeFile reads like the
	// fixture.
	want, _ := DecodeFile(handFile([]string{uaNamespace, fxcmid.NamespaceURI}, 2))
	b, err := EncodeFile(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFile(b)
	if err != nil || got[0].BrowseName != "S" || got[0].Version != 7 {
		t.Errorf("%v %v", got, err)
	}
}

// TestEncodeFileLimit: EncodeFile does not write what DecodeFile refuses.
func TestEncodeFileLimit(t *testing.T) {
	c := validConf()
	c.ConnectionConfigurationSetProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "big"}, Value: ua.MustVariant(make([]byte, MaxFileSize))}}
	_, err := EncodeFile([]*uafx.ConnectionConfigurationSetConf{c})
	if StatusOf(err) != ua.StatusBadEncodingLimitsExceeded || !errors.Is(err, ErrConfig) {
		t.Errorf("%v", err)
	}
}
