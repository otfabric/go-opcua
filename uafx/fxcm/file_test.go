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
