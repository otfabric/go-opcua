// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNeedsFillFirstUseIsConcurrent: the answer to "does this structure hold
// an ExpandedNodeId" must be the same for every goroutine, also while another
// goroutine is still working it out.
//
// needsFill used to park "false" in its cache while it walked the fields. A
// goroutine that asked in that window was told that nothing needs to be
// filled in, left the *ExpandedNodeID of a decoded structure nil, and the
// binary encoder then refused the value. The window is as wide as the walk,
// so the types of this test have many fields in front of the one that counts.
func TestNeedsFillFirstUseIsConcurrent(t *testing.T) {
	const (
		types   = 400
		askers  = 4
		padding = 300
	)
	for n := 0; n < types; n++ {
		fields := make([]reflect.StructField, 0, padding+1)
		for i := 0; i < padding; i++ {
			fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeOf(int32(0))})
		}
		fields = append(fields, reflect.StructField{
			Name: "ID",
			Type: typeExpNodeIDPtr,
			// The tag makes every type of every run a new one.
			Tag: reflect.StructTag(fmt.Sprintf(`opcua:"ID%d_%p"`, n, t)),
		})
		typ := reflect.StructOf(fields)

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			got   [askers]bool
		)
		for a := 0; a < askers; a++ {
			wg.Add(1)
			go func(a int) {
				defer wg.Done()
				<-start
				got[a] = needsFill(typ)
			}(a)
		}
		close(start)
		wg.Wait()
		for a := range got {
			require.True(t, got[a], "type %d, goroutine %d: needsFill reported false for a structure with an ExpandedNodeId", n, a)
		}
	}
}

// TestDecodeFillsExpandedNodeIDConcurrently is the same defect seen through
// the public API: concurrent first decodes of a structure whose ExpandedNodeId
// is left out of the document must all produce a value the binary encoder
// accepts.
func TestDecodeFillsExpandedNodeIDConcurrently(t *testing.T) {
	for n := 0; n < 200; n++ {
		fields := make([]reflect.StructField, 0, 201)
		for i := 0; i < 200; i++ {
			fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeOf(int32(0))})
		}
		fields = append(fields, reflect.StructField{
			Name: "ID",
			Type: typeExpNodeIDPtr,
			Tag:  reflect.StructTag(fmt.Sprintf(`opcua:"ID%d_%p"`, n, t)),
		})
		typ := reflect.StructOf(fields)

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			errs  [4]error
		)
		for a := range errs {
			wg.Add(1)
			go func(a int) {
				defer wg.Done()
				<-start
				v := reflect.New(typ).Interface()
				doc, format := []byte(`{"F1":7}`), "json"
				decode := DecodeJSON
				if a%2 == 1 {
					doc, format, decode = []byte(`<x><F1>7</F1></x>`), "xml", DecodeXML
				}
				if err := decode(doc, v); err != nil {
					errs[a] = fmt.Errorf("%s decode: %w", format, err)
					return
				}
				if _, err := Encode(v); err != nil {
					errs[a] = fmt.Errorf("binary encode of the %s decoded value: %w", format, err)
				}
			}(a)
		}
		close(start)
		wg.Wait()
		for a, err := range errs {
			require.NoError(t, err, "type %d, goroutine %d", n, a)
		}
	}
}

// Structures of the tests below. Each test registers its own: the registries
// are global and never forget.
type (
	regImmutable    struct{ A int32 }
	regRace         struct{ A int32 }
	regInfoFirst    struct{ A int32 }
	regDescribed    struct{ A int32 }
	regDescribedRef struct{ A int32 }
	regNeverUsed    struct{ A int32 }
)

// oncePerProcess skips a test whose subject, the first registration of v, has
// already happened in this process (go test -count=N).
func oncePerProcess(t *testing.T, v interface{}) {
	t.Helper()
	if eotypes.registered(reflect.TypeOf(v)) {
		t.Skip("the type registries are global: the first registration can only be tested once per process")
	}
}

// TestRegisterDataTypeInfoDoesNotModifyPublishedInfo: the codecs read the
// description of a structure without holding a lock. RegisterDataTypeInfo
// used to write the name and the NodeIds into the description they were
// reading - a data race with every concurrent encode or decode of the type,
// and a moment in which the name was new and the ids were old.
func TestRegisterDataTypeInfoDoesNotModifyPublishedInfo(t *testing.T) {
	oncePerProcess(t, new(regImmutable))
	typ := reflect.TypeOf(regImmutable{})
	RegisterExtensionObject(NewNumericNodeID(77, 1000), new(regImmutable))
	before := codecTypes.structInfo(typ)
	require.Equal(t, "regImmutable", before.name)
	require.Nil(t, before.dataTypeID)

	RegisterDataTypeInfo(new(regImmutable), DataTypeInfo{
		Name:           "Immutable",
		DataTypeID:     NewNumericNodeID(77, 1001),
		XMLEncodingID:  NewNumericNodeID(77, 1002),
		JSONEncodingID: NewNumericNodeID(77, 1003),
	})

	// What a concurrent reader holds is unchanged ...
	require.Equal(t, "regImmutable", before.name)
	require.Nil(t, before.dataTypeID)
	require.Nil(t, before.xmlID)
	require.Nil(t, before.jsonID)

	// ... and every way to find the type leads to the new description.
	after := codecTypes.structInfo(typ)
	require.NotSame(t, before, after)
	require.Equal(t, "Immutable", after.name)
	codecTypes.mu.RLock()
	defer codecTypes.mu.RUnlock()
	require.Same(t, after, codecTypes.byName["Immutable"])
	require.Same(t, after, codecTypes.byName["regImmutable"], "the old name still finds the type")
	for _, id := range []uint32{1001, 1002, 1003} {
		require.Same(t, after, codecTypes.byID[NewNumericNodeID(77, id).String()])
	}
}

// TestRegisterDataTypeInfoWhileEncoding is the race itself; it needs the race
// detector to fail on the old code.
func TestRegisterDataTypeInfoWhileEncoding(t *testing.T) {
	RegisterExtensionObject(NewNumericNodeID(77, 1100), new(regRace))
	eo := NewExtensionObject(&regRace{A: 5})
	legal := map[string]bool{
		`{"UaTypeId":"ns=77;i=1100","A":5}`: true, // before the metadata
		`{"UaTypeId":"ns=77;i=1101","A":5}`: true, // with it
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 8)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				doc, err := EncodeJSON(eo)
				if err == nil && !legal[string(doc)] {
					err = fmt.Errorf("unexpected document %s", doc)
				}
				if err == nil {
					_, err = EncodeXML(eo)
				}
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		RegisterDataTypeInfo(new(regRace), DataTypeInfo{
			Name:          "RegRace",
			DataTypeID:    NewNumericNodeID(77, 1101),
			XMLEncodingID: NewNumericNodeID(77, 1102),
		})
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}

// TestDataTypeInfoBeforeRegistrationIsNotUsable: metadata may be attached
// before the type is registered as an extension object. Until it is, the type
// used to be half known: a JSON or XML document naming its DataType decoded
// into an ExtensionObject without a binary encoding id, which the binary
// encoder then wrote as an object of type i=0.
func TestDataTypeInfoBeforeRegistrationIsNotUsable(t *testing.T) {
	oncePerProcess(t, new(regInfoFirst))
	RegisterDataTypeInfo(new(regInfoFirst), DataTypeInfo{
		Name:          "InfoFirst",
		DataTypeID:    NewNumericNodeID(77, 1201),
		XMLEncodingID: NewNumericNodeID(77, 1202),
	})
	jsonDoc := []byte(`{"UaTypeId":"ns=77;i=1201","A":5}`)
	xmlDoc := []byte(`<ExtensionObject><TypeId><Identifier>ns=77;i=1202</Identifier></TypeId><Body><InfoFirst><A>5</A></InfoFirst></Body></ExtensionObject>`)
	bare := []byte(`<Variant><Value><InfoFirst><A>5</A></InfoFirst></Value></Variant>`)

	// Not registered: unknown, in the way unknown types are reported.
	var eo ExtensionObject
	require.ErrorIs(t, DecodeJSON(jsonDoc, &eo), StatusBadDecodingError)
	eo = ExtensionObject{}
	require.NoError(t, DecodeXML(xmlDoc, &eo))
	require.IsType(t, new(XMLElement), eo.Value, "an unknown XML body is kept as it is")
	var v Variant
	require.ErrorIs(t, DecodeXML(bare, &v), StatusBadDecodingError)

	RegisterExtensionObject(NewNumericNodeID(77, 1200), new(regInfoFirst))

	// Registered: fully usable, with the metadata that was attached before.
	check := func(name string, eo *ExtensionObject) {
		t.Helper()
		require.Equal(t, &regInfoFirst{A: 5}, eo.Value, name)
		require.Equal(t, "ns=77;i=1200", eo.TypeID.NodeID.String(), name)
		doc, err := EncodeJSON(eo)
		require.NoError(t, err, name)
		require.JSONEq(t, string(jsonDoc), string(doc), name)
	}
	eo = ExtensionObject{}
	require.NoError(t, DecodeJSON(jsonDoc, &eo))
	check("json", &eo)
	eo = ExtensionObject{}
	require.NoError(t, DecodeXML(xmlDoc, &eo))
	check("xml", &eo)
	require.NoError(t, DecodeXML(bare, &v))
	check("bare", v.Value().(*ExtensionObject))
}

// TestStructureDescribedBeforeRegistrationIsFoundByName: whether a structure
// is found by its name (the bare form of a Variant value in XML) used to
// depend on what happened first, the registration or the first use of the
// type by a codec. Encoding a value as a plain structure before registering
// its type made the name unknown for the rest of the process, and a type
// that was registered but not used yet was not found by its name either.
func TestStructureDescribedBeforeRegistrationIsFoundByName(t *testing.T) {
	oncePerProcess(t, new(regDescribed))
	_, err := EncodeJSON(&regDescribed{A: 1}) // first use, not registered yet
	require.NoError(t, err)
	RegisterExtensionObject(NewNumericNodeID(77, 1300), new(regDescribed))

	RegisterExtensionObject(NewNumericNodeID(77, 1301), new(regDescribedRef)) // the usual order
	_, err = EncodeJSON(&regDescribedRef{A: 1})
	require.NoError(t, err)

	// And a type that no codec has seen at all before its name is asked for.
	RegisterExtensionObject(NewNumericNodeID(77, 1302), new(regNeverUsed))

	for _, name := range []string{"regDescribed", "regDescribedRef", "regNeverUsed"} {
		var v Variant
		doc := `<Variant><Value><` + name + `><A>5</A></` + name + `></Value></Variant>`
		require.NoError(t, DecodeXML([]byte(doc), &v), name)
		eo, ok := v.Value().(*ExtensionObject)
		require.True(t, ok, name)
		require.NotNil(t, eo.Value, name)
	}
}
