// SPDX-License-Identifier: MIT

package codec

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// Named structures that TestRegister_WhileCoding registers as extension
// objects first and gives metadata later. The registries of package ua are
// global and never forget, so within a process only the first run of the test
// sees them unregistered; the types built with reflect.StructOf are new in
// every run.
type (
	regA0 struct {
		A int32
		B string
		C []int32
		D float64
	}
	regA1 regA0
	regA2 regA0
	regA3 regA0
	regA4 regA0
	regA5 regA0
	regA6 regA0
	regA7 regA0
)

// regNamespace is the namespace index of every NodeId this file registers.
const regNamespace = 9

// regSerial hands out ids for the types and NodeIds that must be new in
// every run.
var regSerial atomic.Uint32

// dynType is a structure type that is registered while the codecs are in
// use, with the documents that hold one value of it.
type dynType struct {
	label string
	typ   reflect.Type
	val   any // pointer to the value all documents hold

	goName string // element name before the metadata is attached
	name   string // DataType name of the metadata
	// infoFirst: RegisterDataTypeInfo is called before
	// RegisterExtensionObject, which the documentation allows.
	infoFirst bool

	binID, dtID, xmlID, jsonID *ua.NodeID

	body  []byte // binary encoding of the structure
	eoBin []byte // binary encoding of the ExtensionObject

	jsonFields, xmlFields string

	// eoStarted / infoStarted are set before the registration call,
	// eoDone / infoDone after it returned.
	eoStarted, eoDone, infoStarted, infoDone atomic.Bool
}

func (d *dynType) jsonDoc(id *ua.NodeID) []byte {
	return []byte(`{"UaTypeId":"` + id.String() + `",` + d.jsonFields + `}`)
}

func (d *dynType) xmlDoc(id *ua.NodeID, elem string) []byte {
	return []byte(`<ExtensionObject xmlns="` + ua.XMLTypesNamespace + `"><TypeId><Identifier>` + id.String() +
		`</Identifier></TypeId><Body><` + elem + `>` + d.xmlFields + `</` + elem + `></Body></ExtensionObject>`)
}

func (d *dynType) bareDoc(elem string) []byte {
	return []byte(`<Variant><Value><` + elem + `>` + d.xmlFields + `</` + elem + `></Value></Variant>`)
}

func newDynType(label string, ptr any, infoFirst bool, base uint32, k int) (*dynType, error) {
	t := reflect.TypeOf(ptr).Elem()
	d := &dynType{
		label:     label,
		typ:       t,
		goName:    t.Name(),
		name:      fmt.Sprintf("ChaosType%d", base),
		infoFirst: infoFirst,
		// The compact binary form, which is what the JSON and XML
		// decoders produce for the NodeId of a type.
		binID:  numericNodeID(regNamespace, base),
		dtID:   numericNodeID(regNamespace, base+1),
		xmlID:  numericNodeID(regNamespace, base+2),
		jsonID: numericNodeID(regNamespace, base+3),
	}
	v := reflect.New(t)
	v.Elem().Field(0).SetInt(int64(k + 1))
	v.Elem().Field(1).SetString(fmt.Sprintf("b%d", k))
	v.Elem().Field(2).Set(reflect.ValueOf([]int32{1, 2, int32(k)}))
	v.Elem().Field(3).SetFloat(1.5)
	d.val = v.Interface()

	names := make([]string, t.NumField())
	for i := range names {
		names[i] = t.Field(i).Name
		if tag := t.Field(i).Tag.Get("opcua"); tag != "" {
			names[i] = tag
		}
	}
	d.jsonFields = fmt.Sprintf(`"%s":%d,"%s":"b%d","%s":[1,2,%d],"%s":1.5`, names[0], k+1, names[1], k, names[2], k, names[3])
	d.xmlFields = fmt.Sprintf(`<%[1]s>%[2]d</%[1]s><%[3]s>b%[4]d</%[3]s><%[5]s><Int32>1</Int32><Int32>2</Int32><Int32>%[4]d</Int32></%[5]s><%[6]s>1.5</%[6]s>`,
		names[0], k+1, names[1], k, names[2], names[3])

	var err error
	if d.body, err = ua.Encode(d.val); err != nil {
		return nil, err
	}
	// An ExtensionObject with an opaque body is written as it is, which
	// gives the binary encoding without the type being registered.
	d.eoBin, err = ua.Encode(&ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       &ua.ExpandedNodeID{NodeID: d.binID},
		Value:        d.body,
	})
	return d, err
}

func (d *dynType) info() ua.DataTypeInfo {
	return ua.DataTypeInfo{Name: d.name, DataTypeID: d.dtID, XMLEncodingID: d.xmlID, JSONEncodingID: d.jsonID}
}

// register runs the two registration calls in the order of the type.
func (d *dynType) register(pause func()) {
	eo := func() {
		d.eoStarted.Store(true)
		ua.RegisterExtensionObject(d.binID, d.val)
		d.eoDone.Store(true)
	}
	info := func() {
		d.infoStarted.Store(true)
		ua.RegisterDataTypeInfo(d.val, d.info())
		d.infoDone.Store(true)
	}
	if d.infoFirst {
		info()
		pause()
		eo()
	} else {
		eo()
		pause()
		info()
	}
}

// regState is what the registrar had announced at some moment.
type regState struct{ eoStarted, eoDone, infoStarted, infoDone bool }

// state is read before and after every observation: "done" before it means
// the type must be known, "not started" after it means it cannot be.
func (d *dynType) state() regState {
	return regState{d.eoStarted.Load(), d.eoDone.Load(), d.infoStarted.Load(), d.infoDone.Load()}
}

// regOps are the ways a worker looks at a type.
const (
	opBinary     = iota // binary ExtensionObject
	opJSONBin           // JSON, body identified by the binary encoding id
	opJSONDT            // JSON, by the DataType id
	opJSONEnc           // JSON, by the DefaultJson encoding id
	opXMLBin            // XML, by the binary encoding id
	opXMLEnc            // XML, by the DefaultXml encoding id
	opBareGoName        // XML Variant holding the structure under its Go name
	opBareName          // XML Variant holding the structure under its DataType name
	opPlain             // the value as a plain structure, no ExtensionObject
	numRegOps
)

// needsInfo reports whether the operation can only know the type once its
// metadata is attached.
func needsInfo(op int) bool {
	return op == opJSONDT || op == opJSONEnc || op == opXMLEnc || op == opBareName
}

// look runs one operation on the type and reports whether the codecs knew
// the type. Whatever they answer must be one of two things: a well-defined
// "unknown type", or the complete value in an ExtensionObject that every
// encoding writes back correctly. Anything in between is an error.
func (d *dynType) look(op int, before regState) (known bool, err error) {
	var (
		eo      ua.ExtensionObject
		usedID  = d.binID
		unknown bool
	)
	isUnknownErr := func(err error) bool { return err != nil && stderrors.Is(err, ua.StatusBadDecodingError) }

	switch op {
	case opPlain:
		// Always works, registered or not, and always gives the same
		// documents.
		doc, err := ua.EncodeJSON(d.val)
		if err != nil || string(doc) != "{"+d.jsonFields+"}" {
			return false, fmt.Errorf("plain JSON: %v: %s", err, doc)
		}
		out := reflect.New(d.typ).Interface()
		if err := ua.DecodeJSON(doc, out); err != nil {
			return false, fmt.Errorf("plain JSON decode: %w", err)
		}
		if bin, err := ua.Encode(out); err != nil || !bytes.Equal(bin, d.body) {
			return false, fmt.Errorf("plain JSON round trip changed the value: %v", err)
		}
		doc, err = ua.EncodeXML(d.val, ua.WithXMLRootName("V"), ua.WithoutXMLNamespace())
		if err != nil || string(doc) != "<V>"+d.xmlFields+"</V>" {
			return false, fmt.Errorf("plain XML: %v: %s", err, doc)
		}
		out = reflect.New(d.typ).Interface()
		if err := ua.DecodeXML(doc, out); err != nil {
			return false, fmt.Errorf("plain XML decode: %w", err)
		}
		if bin, err := ua.Encode(out); err != nil || !bytes.Equal(bin, d.body) {
			return false, fmt.Errorf("plain XML round trip changed the value: %v", err)
		}
		return true, nil

	case opBinary:
		if _, err := ua.Decode(d.eoBin, &eo); err != nil {
			return false, fmt.Errorf("binary decode: %w", err)
		}
		unknown = eo.Value == nil
		if unknown && (eo.TypeID == nil || eo.TypeID.NodeID.String() != d.binID.String()) {
			return false, fmt.Errorf("binary: unknown type lost its type id: %v", eo.TypeID)
		}

	case opJSONBin, opJSONDT, opJSONEnc:
		usedID = map[int]*ua.NodeID{opJSONBin: d.binID, opJSONDT: d.dtID, opJSONEnc: d.jsonID}[op]
		err := ua.DecodeJSON(d.jsonDoc(usedID), &eo)
		switch {
		case isUnknownErr(err) && strings.Contains(err.Error(), "unknown type"):
			unknown = true
		case err != nil:
			return false, fmt.Errorf("JSON decode: %w", err)
		}

	case opXMLBin, opXMLEnc:
		usedID = map[int]*ua.NodeID{opXMLBin: d.binID, opXMLEnc: d.xmlID}[op]
		if err := ua.DecodeXML(d.xmlDoc(usedID, "Body"), &eo); err != nil {
			return false, fmt.Errorf("XML decode: %w", err)
		}
		if _, opaque := eo.Value.(*ua.XMLElement); opaque {
			unknown = true
			if eo.TypeID == nil || eo.TypeID.NodeID.String() != usedID.String() {
				return false, fmt.Errorf("XML: unknown type lost its type id: %v", eo.TypeID)
			}
		}

	case opBareGoName, opBareName:
		elem := d.goName
		if op == opBareName {
			elem = d.name
		}
		if elem == "" {
			return false, nil // a type without a Go name has no such document
		}
		var v ua.Variant
		err := ua.DecodeXML(d.bareDoc(elem), &v)
		switch {
		case isUnknownErr(err) && strings.Contains(err.Error(), "unknown"):
			unknown = true
		case err != nil:
			return false, fmt.Errorf("XML decode: %w", err)
		default:
			p, ok := v.Value().(*ua.ExtensionObject)
			if !ok {
				return false, fmt.Errorf("XML: Variant holds %T", v.Value())
			}
			eo = *p
		}
	}
	if unknown {
		return false, nil
	}

	// Known: the value is complete and the object is usable everywhere.
	if reflect.TypeOf(eo.Value) != reflect.PointerTo(d.typ) {
		return true, fmt.Errorf("decoded body is %T", eo.Value)
	}
	if bin, err := ua.Encode(eo.Value); err != nil || !bytes.Equal(bin, d.body) {
		return true, fmt.Errorf("decoded body differs: %v: %x, want %x", err, bin, d.body)
	}
	if bin, err := ua.Encode(&eo); err != nil || !bytes.Equal(bin, d.eoBin) {
		return true, fmt.Errorf("half registered: the binary encoding of the decoded object is %x (%v), want %x (type id %v)", bin, err, d.eoBin, eo.TypeID)
	}
	// The JSON and XML encoders identify the body by the binary encoding
	// id until the metadata is attached, and by the DataType / DefaultXml
	// id from then on. Name and ids change together.
	doc, err := ua.EncodeJSON(&eo)
	if err != nil {
		return true, fmt.Errorf("JSON encode: %w", err)
	}
	switch string(doc) {
	case string(d.jsonDoc(d.dtID)):
	case string(d.jsonDoc(d.binID)):
		if before.infoDone {
			return true, fmt.Errorf("JSON written without the metadata that was registered before: %s", doc)
		}
	default:
		return true, fmt.Errorf("JSON encode: unexpected document %s", doc)
	}
	doc, err = ua.EncodeXML(&eo)
	if err != nil {
		return true, fmt.Errorf("XML encode: %w", err)
	}
	switch string(doc) {
	case string(d.xmlDoc(d.xmlID, d.name)):
	case string(d.xmlDoc(d.binID, d.goName)):
		if before.infoDone {
			return true, fmt.Errorf("XML written without the metadata that was registered before: %s", doc)
		}
	default:
		return true, fmt.Errorf("XML encode: unexpected document %s (metadata is all or nothing)", doc)
	}
	return true, nil
}

// TestRegister_WhileCoding registers new structure types - extension object
// first and metadata later, or the other way around - while other goroutines
// encode and decode values of those types and of types that have been
// registered all along, in the binary, JSON and XML encoding.
//
// Invariants: no data race, no panic. For every type and every way a
// document names it, the codecs either do not know the type - reported the
// documented way: a nil body (binary), StatusBadDecodingError (JSON), the
// body kept as XmlElement (XML) - or they know it completely: the decoded
// object carries the binary encoding id and is written back correctly in all
// three encodings, with a name and NodeIds that belong together. A type is
// unknown until its registration has begun, known once it has returned, and
// never becomes unknown again. Values of the other types keep encoding to
// their reference documents throughout.
func TestRegister_WhileCoding(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	c := sharedCorpus(t, seed)
	var stable []int // extension objects and custom structures of the corpus
	for i, it := range c.items {
		if strings.HasPrefix(it.name, "extobj/") || strings.HasSuffix(it.name, "Struct") || strings.HasPrefix(it.name, "variant/22/") {
			stable = append(stable, i)
		}
	}
	if len(stable) < 4 {
		t.Fatalf("only %d registered values in the corpus", len(stable))
	}

	// The types.
	var types []*dynType
	for k, ptr := range []any{new(regA0), new(regA1), new(regA2), new(regA3), new(regA4), new(regA5), new(regA6), new(regA7)} {
		d, err := newDynType(fmt.Sprintf("named %T", ptr), ptr, false, 5000+10*uint32(k), k)
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, d)
	}
	for k := 0; k < 8; k++ {
		n := regSerial.Add(1)
		tag := func(f string) reflect.StructTag { return reflect.StructTag(fmt.Sprintf(`opcua:"%s%d"`, f, n)) }
		typ := reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: reflect.TypeOf(int32(0)), Tag: tag("A")},
			{Name: "B", Type: reflect.TypeOf(""), Tag: tag("B")},
			{Name: "C", Type: reflect.TypeOf([]int32(nil)), Tag: tag("C")},
			{Name: "D", Type: reflect.TypeOf(float64(0)), Tag: tag("D")},
		})
		d, err := newDynType(fmt.Sprintf("generated %d", n), reflect.New(typ).Interface(), true, 100000+10*n, k)
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, d)
	}
	// A named type of an earlier run in this process is registered already.
	for _, d := range types {
		var eo ua.ExtensionObject
		if _, err := ua.Decode(d.eoBin, &eo); err != nil {
			t.Fatal(err)
		}
		if eo.Value != nil {
			for _, f := range []*atomic.Bool{&d.eoStarted, &d.eoDone, &d.infoStarted, &d.infoDone} {
				f.Store(true)
			}
		}
	}

	var (
		sink       chaoskit.ErrSink
		workers    sync.WaitGroup
		registrars sync.WaitGroup
		start      = make(chan struct{})
		registered = make(chan struct{})
		seen       [numRegOps]atomic.Int64 // known observations per operation
		unseen     atomic.Int64            // unknown observations
	)
	guard := func(who string) {
		if r := recover(); r != nil {
			buf := make([]byte, 16<<10)
			sink.Addf("%s: PANIC: %v\n%s", who, r, buf[:runtime.Stack(buf, false)])
		}
	}

	const numWorkers = 8
	for w := 0; w < numWorkers; w++ {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			defer guard(fmt.Sprintf("worker %d", w))
			rng := rand.New(rand.NewSource(seed + int64(w)))
			known := make([][numRegOps]bool, len(types))
			<-start
			extra := 0
			for sink.Len() == 0 {
				select {
				case <-registered:
					extra++
				default:
				}
				if extra > 400 {
					return
				}
				if rng.Intn(4) == 0 {
					i := stable[rng.Intn(len(stable))]
					j := rng.Intn(len(encodings))
					if err := checkEncode(c.items[i], encodings[j], c.ref[i][j]); err != nil {
						sink.Addf("worker %d: registered all along: %v", w, err)
					}
					if err := checkDecode(c.items[i], encodings[j], c.ref[i][j]); err != nil {
						sink.Addf("worker %d: registered all along: %v", w, err)
					}
					continue
				}
				ti, op := rng.Intn(len(types)), rng.Intn(numRegOps)
				d := types[ti]
				before := d.state()
				isKnown, err := d.look(op, before)
				after := d.state()
				if err != nil {
					sink.Addf("worker %d: %s: op %d: %v", w, d.label, op, err)
					continue
				}
				if op == opPlain || (op == opBareGoName && d.goName == "") {
					continue
				}
				mustKnow := before.eoDone && (before.infoDone || !needsInfo(op))
				cannotKnow := !after.eoStarted || (needsInfo(op) && !after.infoStarted)
				switch {
				case mustKnow && !isKnown:
					sink.Addf("worker %d: %s: op %d: unknown although the registration had returned", w, d.label, op)
				case cannotKnow && isKnown:
					sink.Addf("worker %d: %s: op %d: known before the registration began (half registered)", w, d.label, op)
				case known[ti][op] && !isKnown:
					sink.Addf("worker %d: %s: op %d: a known type became unknown again", w, d.label, op)
				}
				if isKnown {
					known[ti][op] = true
					seen[op].Add(1)
				} else {
					unseen.Add(1)
				}
			}
		}(w)
	}

	const numRegistrars = 2
	for r := 0; r < numRegistrars; r++ {
		registrars.Add(1)
		go func(r int) {
			defer registrars.Done()
			defer guard(fmt.Sprintf("registrar %d", r))
			rng := rand.New(rand.NewSource(seed ^ int64(r+1)<<32))
			pause := func() { time.Sleep(time.Duration(rng.Intn(3000)) * time.Microsecond) }
			<-start
			for i := r; i < len(types); i += numRegistrars {
				pause()
				types[i].register(pause)
			}
		}(r)
	}

	close(start)
	if !chaoskit.WaitGroupTimeout(&registrars, chaoskit.OpLimit) {
		t.Fatalf("DEADLOCK: the registrations did not finish\n%s", chaoskit.AllStacks())
	}
	close(registered)
	if !chaoskit.WaitGroupTimeout(&workers, chaoskit.OpLimit) {
		t.Fatalf("DEADLOCK: the workers did not finish\n%s", chaoskit.AllStacks())
	}
	sink.Report(t)

	// Everything is registered: every type is known in every way.
	for _, d := range types {
		for op := 0; op < numRegOps; op++ {
			if op == opBareGoName && d.goName == "" {
				continue
			}
			isKnown, err := d.look(op, d.state())
			if err != nil || !isKnown {
				t.Errorf("%s: op %d after all registrations: known=%v err=%v", d.label, op, isKnown, err)
			}
		}
	}
	var total int64
	for op := range seen {
		total += seen[op].Load()
	}
	t.Logf("%d types, observations while registering: %d unknown, %d known", len(types), unseen.Load(), total)
}

// TestRegister_Duplicates pins what a second registration does, also when
// the registrations race.
//
// Invariants: registering the same type under the same id again is a no-op,
// from any number of goroutines; of several different types that claim one
// id exactly one wins, every other attempt is refused with
// ErrTypeAlreadyRegistered (TypeRegistry.Register) or a panic naming it
// (RegisterExtensionObject), and the id decodes to the winner from then on;
// repeating RegisterDataTypeInfo with the same metadata changes nothing.
func TestRegister_Duplicates(t *testing.T) {
	const claimants = 8
	newType := func() reflect.Type {
		n := regSerial.Add(1)
		return reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: reflect.TypeOf(int32(0)), Tag: reflect.StructTag(fmt.Sprintf(`opcua:"A%d"`, n))},
		})
	}
	race := func(fn func(i int)) {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < claimants; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				fn(i)
			}(i)
		}
		close(start)
		wg.Wait()
	}

	t.Run("TypeRegistry", func(t *testing.T) {
		reg := ua.NewTypeRegistry()
		id := ua.NewNumericNodeID(regNamespace, 1)
		types := make([]reflect.Type, claimants)
		for i := range types {
			types[i] = newType()
		}
		errs := make([]error, claimants)
		race(func(i int) {
			errs[i] = reg.Register(id, reflect.New(types[i]).Interface())
			// The same claim again, and a second id for the same type.
			if err := reg.Register(ua.NewNumericNodeID(regNamespace, uint32(100+i)), reflect.New(types[i]).Interface()); err != nil {
				errs[i] = fmt.Errorf("own id: %w", err)
			}
		})
		winner := -1
		for i, err := range errs {
			switch {
			case err == nil && winner >= 0:
				t.Fatalf("claimants %d and %d both registered %v", winner, i, id)
			case err == nil:
				winner = i
			case !stderrors.Is(err, errors.ErrTypeAlreadyRegistered):
				t.Fatalf("claimant %d: %v", i, err)
			}
		}
		if winner < 0 {
			t.Fatal("no claimant registered the id")
		}
		if got := reflect.TypeOf(reg.New(id)); got != reflect.PointerTo(types[winner]) {
			t.Fatalf("the id creates %v, the winner is %v", got, types[winner])
		}
		for i := range types {
			// A type keeps the id it was registered under first. For the
			// winner that is either of its two ids, depending on which
			// call came first; for the others it is their own.
			got := reg.Lookup(reflect.New(types[i]).Interface())
			own := ua.NewNumericNodeID(regNamespace, uint32(100+i))
			if got == nil || (got.String() != own.String() && (i != winner || got.String() != id.String())) {
				t.Errorf("claimant %d (winner %d): Lookup = %v", i, winner, got)
			}
			if err := reg.Register(own, reflect.New(types[i]).Interface()); err != nil {
				t.Errorf("claimant %d: repeating a registration: %v", i, err)
			}
		}
	})

	t.Run("RegisterExtensionObject", func(t *testing.T) {
		id := ua.NewNumericNodeID(regNamespace, 200000+regSerial.Add(1))
		types := make([]reflect.Type, claimants)
		for i := range types {
			types[i] = newType()
		}
		outcome := make([]any, claimants)
		race(func(i int) {
			defer func() { outcome[i] = recover() }()
			for n := 0; n < 3; n++ { // the same registration again is fine
				ua.RegisterExtensionObject(id, reflect.New(types[i]).Interface())
			}
		})
		winner := -1
		for i, r := range outcome {
			switch {
			case r == nil && winner >= 0:
				t.Fatalf("claimants %d and %d both registered %v", winner, i, id)
			case r == nil:
				winner = i
			case !strings.Contains(fmt.Sprint(r), "already registered"):
				t.Fatalf("claimant %d: unexpected panic: %v", i, r)
			}
		}
		if winner < 0 {
			t.Fatal("no claimant registered the id")
		}
		// The id decodes to the winner, for everybody, every time.
		body, err := ua.Encode(reflect.New(types[winner]).Interface())
		if err != nil {
			t.Fatal(err)
		}
		bin, err := ua.Encode(&ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: &ua.ExpandedNodeID{NodeID: id}, Value: body})
		if err != nil {
			t.Fatal(err)
		}
		var sink chaoskit.ErrSink
		race(func(i int) {
			for n := 0; n < 50; n++ {
				var eo ua.ExtensionObject
				if _, err := ua.Decode(bin, &eo); err != nil || reflect.TypeOf(eo.Value) != reflect.PointerTo(types[winner]) {
					sink.Addf("goroutine %d: decoded %T (%v), want the winner %v", i, eo.Value, err, types[winner])
					return
				}
				var fromJSON ua.ExtensionObject
				doc := []byte(`{"UaTypeId":"` + id.String() + `"}`)
				if err := ua.DecodeJSON(doc, &fromJSON); err != nil || reflect.TypeOf(fromJSON.Value) != reflect.PointerTo(types[winner]) {
					sink.Addf("goroutine %d: JSON decoded %T (%v), want the winner %v", i, fromJSON.Value, err, types[winner])
					return
				}
			}
		})
		sink.Report(t)
		for i := range types {
			got := ua.ExtensionObjectTypeID(reflect.New(types[i]).Interface())
			if (i == winner) != (got.NodeID.String() == id.String()) {
				t.Errorf("claimant %d (winner %d): type id %v", i, winner, got.NodeID)
			}
		}
	})

	t.Run("RegisterDataTypeInfo", func(t *testing.T) {
		n := regSerial.Add(1)
		typ := newType()
		ptr := reflect.New(typ).Interface()
		ua.RegisterExtensionObject(ua.NewNumericNodeID(regNamespace, 300000+10*n), ptr)
		info := ua.DataTypeInfo{
			Name:          fmt.Sprintf("ChaosDup%d", n),
			DataTypeID:    ua.NewNumericNodeID(regNamespace, 300001+10*n),
			XMLEncodingID: ua.NewNumericNodeID(regNamespace, 300002+10*n),
		}
		ua.RegisterDataTypeInfo(ptr, info)
		eo := ua.NewExtensionObject(ptr)
		wantJSON, err := ua.EncodeJSON(eo)
		if err != nil {
			t.Fatal(err)
		}
		wantXML, err := ua.EncodeXML(eo)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(wantJSON), info.DataTypeID.String()) || !strings.Contains(string(wantXML), "<"+info.Name+">") {
			t.Fatalf("metadata not applied: %s %s", wantJSON, wantXML)
		}
		var sink chaoskit.ErrSink
		race(func(i int) {
			for k := 0; k < 50; k++ {
				if i%2 == 0 {
					ua.RegisterDataTypeInfo(ptr, info)
					continue
				}
				gotJSON, err1 := ua.EncodeJSON(eo)
				gotXML, err2 := ua.EncodeXML(eo)
				if err1 != nil || err2 != nil || !bytes.Equal(gotJSON, wantJSON) || !bytes.Equal(gotXML, wantXML) {
					sink.Addf("goroutine %d: repeating the registration changed the output: %v %v\n%s\n%s", i, err1, err2, gotJSON, gotXML)
					return
				}
			}
		})
		sink.Report(t)
	})
}
