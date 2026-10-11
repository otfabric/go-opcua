// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// The properties in this file all have the same shape:
//
//	binary -> value -> JSON or XML -> value -> binary
//
// must reproduce the first binary encoding byte for byte. The binary codec is
// the reference: it is what the wire uses and what is verified against other
// stacks. Any information JSON or XML would lose shows up as a difference.

var jsonForms = map[string]JSONForm{
	"compact": JSONCompact,
	"verbose": JSONVerbose,
	"legacy":  JSONLegacyReversible,
}

// viaJSON and viaXML push a value through an encoding and return the binary
// encoding of the result.
func viaJSON(v interface{}, opts ...CodecOption) (doc []byte, bin []byte, err error) {
	if doc, err = EncodeJSON(v, opts...); err != nil {
		return nil, nil, fmt.Errorf("EncodeJSON: %w", err)
	}
	out := reflect.New(reflect.TypeOf(v).Elem())
	if err = DecodeJSON(doc, out.Interface(), opts...); err != nil {
		return doc, nil, fmt.Errorf("DecodeJSON: %w", err)
	}
	bin, err = Encode(out.Interface())
	return doc, bin, err
}

func viaXML(v interface{}, opts ...CodecOption) (doc []byte, bin []byte, err error) {
	if doc, err = EncodeXML(v, opts...); err != nil {
		return nil, nil, fmt.Errorf("EncodeXML: %w", err)
	}
	out := reflect.New(reflect.TypeOf(v).Elem())
	if err = DecodeXML(doc, out.Interface(), opts...); err != nil {
		return doc, nil, fmt.Errorf("DecodeXML: %w", err)
	}
	bin, err = Encode(out.Interface())
	return doc, bin, err
}

// checkIdentity runs the binary -> JSON/XML -> binary identity for v, a
// pointer to a value. It returns a description of the first violation.
func checkIdentity(v interface{}, opts ...CodecOption) error {
	want, err := Encode(v)
	if err != nil {
		return fmt.Errorf("binary encode: %w", err)
	}
	// Start from what the binary decoder produces, as a client or server
	// would.
	in := reflect.New(reflect.TypeOf(v).Elem()).Interface()
	if _, err := Decode(want, in); err != nil {
		return fmt.Errorf("binary decode: %w", err)
	}
	for name, form := range jsonForms {
		doc, got, err := viaJSON(in, append([]CodecOption{WithJSONForm(form)}, opts...)...)
		if err != nil {
			return fmt.Errorf("json/%s: %w\n%s", name, err, doc)
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("json/%s changed the value\n doc:  %s\n want: %x\n got:  %x", name, doc, want, got)
		}
	}
	doc, got, err := viaXML(in, opts...)
	if err != nil {
		return fmt.Errorf("xml: %w\n%s", err, doc)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("xml changed the value\n doc:  %s\n want: %x\n got:  %x", doc, want, got)
	}
	return nil
}

func TestProperty_VariantJSONXMLIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		g := &valueGen{src: rapidRand{rt}, maxDepth: 2}
		if err := checkIdentity(g.variant(0)); err != nil {
			rt.Fatal(err)
		}
	})
}

func TestProperty_DataValueJSONXMLIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		g := &valueGen{src: rapidRand{rt}, maxDepth: 2}
		if err := checkIdentity(g.dataValue(0)); err != nil {
			rt.Fatal(err)
		}
	})
}

// TestProperty_NamespaceTables repeats the identity with a NamespaceArray and
// ServerArray, which switches NodeIds and QualifiedNames to the URI form.
func TestProperty_NamespaceTables(t *testing.T) {
	opts := []CodecOption{
		WithNamespaceArray([]string{"http://opcfoundation.org/UA/", "urn:ns:one", "urn:ns:two", "urn:ns:three"}),
		WithServerArray([]string{"urn:srv:local", "urn:srv:one", "urn:srv:two"}),
	}
	rapid.Check(t, func(rt *rapid.T) {
		g := &valueGen{src: rapidRand{rt}, maxDepth: 2}
		if err := checkIdentity(g.variant(0), opts...); err != nil {
			rt.Fatal(err)
		}
	})
}

// TestProperty_StructureJSONXMLIdentity draws a registered structure type
// and a random value for it.
func TestProperty_StructureJSONXMLIdentity(t *testing.T) {
	types := codecTypes.registeredStructs()
	rapid.Check(t, func(rt *rapid.T) {
		v := reflect.New(reflect.TypeOf(types[rapid.IntRange(0, len(types)-1).Draw(rt, "type")]).Elem())
		g := &valueGen{src: rapidRand{rt}, maxDepth: 1}
		g.fill(v.Elem(), 0)
		if err := checkIdentity(v.Interface()); err != nil {
			rt.Fatalf("%s: %v", v.Type(), err)
		}
	})
}

// TestEveryStructureJSONXMLIdentity sweeps the whole type registry: every
// generated structure (and whatever else is registered) is filled with
// deterministic pseudo-random values, plus its zero value, and must keep its
// binary encoding across JSON and XML.
func TestEveryStructureJSONXMLIdentity(t *testing.T) {
	types := codecTypes.registeredStructs()
	if len(types) < 300 {
		t.Fatalf("only %d structures registered, the generated metadata is missing", len(types))
	}
	rounds := 3
	if testing.Short() {
		rounds = 1
	}
	for i, zero := range types {
		typ := reflect.TypeOf(zero).Elem()
		// A document that leaves every field out must decode to a value
		// the binary encoder accepts, which then keeps its encoding.
		if err := DecodeJSON([]byte(`{}`), zero); err != nil {
			t.Errorf("%s (empty document): %v", typ, err)
			continue
		}
		if err := checkIdentity(zero); err != nil {
			t.Errorf("%s (empty document): %v", typ, err)
			continue
		}
		empty := reflect.New(typ).Interface()
		if err := DecodeXML([]byte(`<a/>`), empty); err != nil {
			t.Errorf("%s (empty element): %v", typ, err)
			continue
		}
		if _, err := Encode(empty); err != nil {
			t.Errorf("%s (empty element): %v", typ, err)
			continue
		}
		g := &valueGen{src: mathRand{rand.New(rand.NewSource(int64(i) + 1))}, maxDepth: 1}
		for r := 0; r < rounds; r++ {
			v := reflect.New(typ)
			g.fill(v.Elem(), 0)
			if err := checkIdentity(v.Interface()); err != nil {
				t.Errorf("%s: %v", typ, err)
				break
			}
		}
	}
}
