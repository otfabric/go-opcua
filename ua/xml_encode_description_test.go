// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

type regSwap struct{ A int32 }

// TestEncodeXMLUsesOneDescription: the XML form of an ExtensionObject names
// its type twice, with the NodeId in TypeId and with the element in Body.
// Both have to come from the same registration.
//
// The encoder used to look the type up once for each. A RegisterDataTypeInfo
// between the two lookups produced a document with the id of the old
// description and the name of the new one (found by chaos/codec in a fresh
// process with seed 1).
func TestEncodeXMLUsesOneDescription(t *testing.T) {
	if !eotypes.registered(reflect.TypeOf(new(regSwap))) {
		RegisterExtensionObject(NewNumericNodeID(77, 1400), new(regSwap))
	}
	infos := []DataTypeInfo{
		{Name: "SwapA", DataTypeID: NewNumericNodeID(77, 1401), XMLEncodingID: NewNumericNodeID(77, 1402)},
		{Name: "SwapB", DataTypeID: NewNumericNodeID(77, 1411), XMLEncodingID: NewNumericNodeID(77, 1412)},
	}
	RegisterDataTypeInfo(new(regSwap), infos[0])
	eo := NewExtensionObject(&regSwap{A: 5})
	legal := map[string]bool{}
	for _, info := range infos {
		legal[`<ExtensionObject xmlns="`+XMLTypesNamespace+`"><TypeId><Identifier>`+info.XMLEncodingID.String()+
			`</Identifier></TypeId><Body><`+info.Name+`><A>5</A></`+info.Name+`></Body></ExtensionObject>`] = true
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
				doc, err := EncodeXML(eo)
				if err == nil && !legal[string(doc)] {
					err = fmt.Errorf("id and name of different registrations: %s", doc)
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
	for i := 0; i < 5000; i++ {
		RegisterDataTypeInfo(new(regSwap), infos[i%2])
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}
