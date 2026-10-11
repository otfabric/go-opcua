// SPDX-License-Identifier: MIT

package codec

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// limits is a pair of decoder limits. The option slices are shared by all
// goroutines.
type limits struct {
	depth, array int
	opts         []ua.CodecOption
}

var hostileLimits = []*limits{
	{depth: ua.DefaultCodecMaxDepth, array: ua.MaxVariantArrayLength},
	{depth: 8, array: 16, opts: []ua.CodecOption{ua.WithMaxDepth(8), ua.WithMaxArrayLength(16)}},
	{depth: 32, array: 100, opts: []ua.CodecOption{ua.WithMaxDepth(32), ua.WithMaxArrayLength(100)}},
	{depth: 100, array: 1000, opts: []ua.CodecOption{ua.WithMaxArrayLength(1000), ua.WithNamespaceArray(sharedNamespaces), ua.WithServerArray(sharedServers)}},
}

// hostileDoc is a document and the type it is decoded into.
type hostileDoc struct {
	name   string
	xml    bool
	doc    []byte
	target func() any
}

func (h *hostileDoc) decode(doc []byte, target any, opts []ua.CodecOption) error {
	if h.xml {
		return ua.DecodeXML(doc, target, opts...)
	}
	return ua.DecodeJSON(doc, target, opts...)
}

// hostileSeeds are valid documents of the shared corpus, the raw material of
// the mutations.
func hostileSeeds(c *corpus) []*hostileDoc {
	var use []int
	for j, enc := range encodings {
		switch enc.name {
		case "json/compact/plain", "json/verbose/tables", "json/legacy/plain", "xml/plain", "xml/tables":
			use = append(use, j)
		}
	}
	var out []*hostileDoc
	for i, it := range c.items {
		if strings.HasPrefix(it.name, "struct/") && i%5 != 0 {
			continue // a fifth of the plain structures is plenty
		}
		for _, j := range use {
			if len(c.ref[i][j]) > 8<<10 {
				continue
			}
			out = append(out, &hostileDoc{name: it.name + " as " + encodings[j].name, xml: encodings[j].xml, doc: c.ref[i][j], target: it.target})
		}
	}
	return out
}

var (
	jsonTokens = []string{`{`, `}`, `[`, `]`, `,`, `:`, `"`, `null`, `true`, `1e999`, `-0`, `99999999999999999999`, `-`, `0.`, `1e`,
		`"UaType":`, `"UaTypeId":"i=296",`, `"UaEncoding":1,`, `"UaBody":`, `"Dimensions":[1,1],`, `"Dimensions":[65536,65536],`, `"Value":`, `"Body":`, `"Type":25,`,
		`\u0000`, `\ud800`, `\`, "\x00", "\xff", `"nsu=;`, `"svr=4294967296;i=1"`, `"g=xyz"`, `"b=!"`, `"NaN"`, `"-Infinity"`, `{"a":{"a":{"a":`}
	xmlTokens = []string{`<`, `>`, `</`, `/>`, `<a>`, `</a>`, `&amp;`, `&#0;`, `&bogus;`, `<![CDATA[`, `]]>`, ` xsi:nil="true"`, ` xmlns=""`, `<!--`, `-->`, `<?x?>`,
		`<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>`, `&b;`, `<Matrix><Dimensions><Int32>1</Int32></Dimensions><Elements>`, `<ListOfInt32>`,
		`<Value>`, `</Value>`, `<Body>`, `<ByteString>AAAA</ByteString>`, `<TypeId><Identifier>i=297</Identifier></TypeId>`, `<ExtensionObject>`, `<Variant>`, "\x00", "\xff", `<x:y xmlns:x="`}
	numberTweaks = []string{`-1`, `0`, `1`, `25`, `26`, `255`, `256`, `65535`, `65536`, `2147483647`, `2147483648`, `4294967295`, `4294967296`,
		`9223372036854775807`, `9223372036854775808`, `18446744073709551616`, `1e400`, `-1e400`, `1.5`, `1e5`, `00`}
)

// mutate applies one random mutation to doc and returns the result. It never
// modifies doc.
func mutate(rng *rand.Rand, h *hostileDoc, doc []byte, seeds []*hostileDoc) []byte {
	if len(doc) == 0 {
		return []byte(jsonTokens[rng.Intn(len(jsonTokens))])
	}
	out := bytes.Clone(doc)
	pos := rng.Intn(len(out))
	span := func(max int) (int, int) {
		n := 1 + rng.Intn(max)
		if pos+n > len(out) {
			n = len(out) - pos
		}
		return pos, pos + n
	}
	splice := func(a, b int, with []byte) []byte {
		res := make([]byte, 0, len(out)-(b-a)+len(with))
		res = append(res, out[:a]...)
		res = append(res, with...)
		return append(res, out[b:]...)
	}
	switch rng.Intn(8) {
	case 0: // one byte
		out[pos] = byte(rng.Intn(256))
	case 1: // delete
		a, b := span(8)
		out = splice(a, b, nil)
	case 2: // insert a token
		tokens := jsonTokens
		if h.xml {
			tokens = xmlTokens
		}
		out = splice(pos, pos, []byte(tokens[rng.Intn(len(tokens))]))
	case 3: // repeat a span
		a, b := span(48)
		out = splice(a, b, bytes.Repeat(out[a:b], 2+rng.Intn(20)))
	case 4: // truncate
		out = out[:pos]
	case 5: // splice in a piece of another document of the same kind
		other := seeds[rng.Intn(len(seeds))]
		if other.xml == h.xml && len(other.doc) > 0 {
			from := rng.Intn(len(other.doc))
			to := from + 1 + rng.Intn(min(64, len(other.doc)-from))
			a, b := span(32)
			out = splice(a, b, other.doc[from:to])
		}
	case 6: // replace a number
		a := bytes.IndexAny(out[pos:], "0123456789")
		if a >= 0 {
			a += pos
			b := a
			for b < len(out) && out[b] >= '0' && out[b] <= '9' {
				b++
			}
			out = splice(a, b, []byte(numberTweaks[rng.Intn(len(numberTweaks))]))
		}
	default: // swap two bytes
		other := rng.Intn(len(out))
		out[pos], out[other] = out[other], out[pos]
	}
	return out
}

// binaryBomb is the binary encoding of an Argument whose ArrayDimensions
// claim n elements.
func binaryBomb(n uint32) string {
	b := []byte{1, 0, 0, 0, 'x', 0, 6, 1, 0, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, n)
	return base64.StdEncoding.EncodeToString(b)
}

// bomb returns a document built to exhaust the decoder rather than to confuse
// it: deep nesting, long arrays, many dimensions, sizes that are only
// claimed.
func bomb(rng *rand.Rand, lim *limits) *hostileDoc {
	variant := func() any { return new(ua.Variant) }
	n := []int{lim.array - 1, lim.array, lim.array + 1, 2 * lim.array}[rng.Intn(4)]
	if n > 5000 {
		n = 5000 + rng.Intn(3) - 1 // a size that is still cheap to build and parse
	}
	depth := []int{lim.depth - 1, lim.depth, lim.depth + 1, 4000, 20000}[rng.Intn(5)]
	dims := []string{"1,1", strings.TrimSuffix(strings.Repeat("1,", 33), ","), strings.TrimSuffix(strings.Repeat("1,", 2000), ","),
		"65536,65536", "65536,65536,1", "2147483647,2", "-1", "0", "2,3", "1"}[rng.Intn(10)]
	xmlDims := "<Int32>" + strings.ReplaceAll(dims, ",", "</Int32><Int32>") + "</Int32>"
	huge := []uint32{0x7fffffff, 0xfffffffe, 0x10000, 1 << 20}[rng.Intn(4)]

	switch rng.Intn(12) {
	case 0:
		return &hostileDoc{name: "json nested arrays", doc: []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth)), target: func() any { return new([]*ua.Variant) }}
	case 1:
		return &hostileDoc{name: "json nested objects", doc: []byte(strings.Repeat(`{"InnerDiagnosticInfo":`, depth) + "{}" + strings.Repeat("}", depth)), target: func() any { return new(ua.DiagnosticInfo) }}
	case 2:
		return &hostileDoc{name: "json nested variants", doc: []byte(strings.Repeat(`{"UaType":24,"Value":[`, depth) + strings.Repeat("]}", depth)), target: variant}
	case 3:
		return &hostileDoc{name: "json long array", doc: []byte(`{"UaType":6,"Value":[` + strings.TrimSuffix(strings.Repeat("0,", n), ",") + `]}`), target: variant}
	case 4:
		return &hostileDoc{name: "json dimensions", doc: []byte(`{"UaType":6,"Value":[1,2,3,4,5,6],"Dimensions":[` + dims + `]}`), target: variant}
	case 5:
		return &hostileDoc{name: "json empty matrix", doc: []byte(`{"UaType":12,"Value":[],"Dimensions":[` + dims + `]}`), target: func() any { return new(ua.DataValue) }}
	case 6:
		return &hostileDoc{name: "json binary body", doc: []byte(`{"UaTypeId":"i=296","UaEncoding":1,"UaBody":"` + binaryBomb(huge) + `"}`), target: func() any { return new(ua.ExtensionObject) }}
	case 7:
		return &hostileDoc{name: "xml nested elements", xml: true, doc: []byte(strings.Repeat("<InnerDiagnosticInfo>", depth) + strings.Repeat("</InnerDiagnosticInfo>", depth)), target: func() any { return new(ua.DiagnosticInfo) }}
	case 8:
		return &hostileDoc{name: "xml long array", xml: true, doc: []byte(`<Variant><Value><ListOfInt32>` + strings.Repeat("<Int32>0</Int32>", n) + `</ListOfInt32></Value></Variant>`), target: variant}
	case 9:
		return &hostileDoc{name: "xml matrix", xml: true, doc: []byte(`<Variant><Value><Matrix><Dimensions>` + xmlDims + `</Dimensions><Elements>` +
			strings.Repeat("<Int32>1</Int32>", 6) + `</Elements></Matrix></Value></Variant>`), target: variant}
	case 10:
		return &hostileDoc{name: "xml binary body", xml: true, doc: []byte(`<ExtensionObject><TypeId><Identifier>i=297</Identifier></TypeId><Body><ByteString>` +
			binaryBomb(huge) + `</ByteString></Body></ExtensionObject>`), target: func() any { return new(ua.ExtensionObject) }}
	default:
		return &hostileDoc{name: "xml nested variants", xml: true, doc: []byte(strings.Repeat(`<Value><ListOfVariant><Variant>`, depth) +
			strings.Repeat(`</Variant></ListOfVariant></Value>`, depth)), target: variant}
	}
}

// inspect walks a decoded value and returns the first violation of the
// limits: an array in a Variant that is longer than the limit allows, or a
// Variant with more dimensions than any decoder accepts.
func inspect(v reflect.Value, lim *limits, depth int) error {
	if !v.IsValid() || depth > 400 {
		return nil
	}
	if v.CanInterface() {
		if m, ok := v.Interface().(*ua.Variant); ok && m != nil {
			if int(m.ArrayLength()) > lim.array {
				return fmt.Errorf("Variant with %d elements, the limit is %d", m.ArrayLength(), lim.array)
			}
			if len(m.ArrayDimensions()) > 32 {
				return fmt.Errorf("Variant with %d dimensions", len(m.ArrayDimensions()))
			}
			return inspect(reflect.ValueOf(m.Value()), lim, depth+1)
		}
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return inspect(v.Elem(), lim, depth+1)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := inspect(v.Index(i), lim, depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				if err := inspect(v.Field(i), lim, depth+1); err != nil {
					return err
				}
			}
		}
	default:
	}
	return nil
}

// holdsXMLElement reports whether a decoded value contains a non-empty
// XmlElement anywhere.
func holdsXMLElement(v reflect.Value, depth int) bool {
	if !v.IsValid() || depth > 400 {
		return false
	}
	if v.Type() == typXML {
		return v.Len() > 0
	}
	if v.CanInterface() {
		if m, ok := v.Interface().(*ua.Variant); ok && m != nil {
			return holdsXMLElement(reflect.ValueOf(m.Value()), depth+1)
		}
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil() && holdsXMLElement(v.Elem(), depth+1)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if holdsXMLElement(v.Index(i), depth+1) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && holdsXMLElement(v.Field(i), depth+1) {
				return true
			}
		}
	default:
	}
	return false
}

// hostileStats counts what the decoders did with the documents.
type hostileStats struct {
	docs, rejected, accepted, reencoded, unstable atomic.Int64
	slowest                                       atomic.Int64 // ns
}

// tryDecode feeds one document to the decoder and checks every invariant of
// the hostile scenarios. It returns a description of the violation.
func tryDecode(h *hostileDoc, doc []byte, lim *limits, stats *hostileStats) (violation string) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 8<<10)
			violation = fmt.Sprintf("PANIC: %v\n%s", r, buf[:runtime.Stack(buf, false)])
		}
	}()
	stats.docs.Add(1)
	target := h.target()
	start := time.Now()
	err := h.decode(doc, target, lim.opts)
	took := time.Since(start)
	for {
		cur := stats.slowest.Load()
		if int64(took) <= cur || stats.slowest.CompareAndSwap(cur, int64(took)) {
			break
		}
	}
	// Far above what any of these documents needs, also on a machine that
	// is busy with the other tests: this is about hangs.
	if took > 60*time.Second {
		return fmt.Sprintf("decoding %d bytes took %v", len(doc), took)
	}
	if err != nil {
		stats.rejected.Add(1)
		// Every error of the decoders wraps a StatusCode.
		var sc ua.StatusCode
		if !stderrors.As(err, &sc) {
			return fmt.Sprintf("the error does not wrap a StatusCode: %v", err)
		}
		return ""
	}
	stats.accepted.Add(1)
	if err := inspect(reflect.ValueOf(target), lim, 0); err != nil {
		return "limit not honoured: " + err.Error()
	}

	// Whatever was accepted can be handed to every encoder. They may
	// refuse it (an error), they must not panic.
	val := target
	if t := reflect.TypeOf(target).Elem(); t.Kind() != reflect.Struct {
		val = reflect.ValueOf(target).Elem().Interface()
	}
	_, _ = ua.Encode(val)
	var compact []byte
	for _, form := range []ua.JSONForm{ua.JSONCompact, ua.JSONVerbose, ua.JSONLegacyReversible, ua.JSONLegacyNonReversible} {
		out, err := ua.EncodeJSON(val, ua.WithJSONForm(form))
		if form == ua.JSONCompact && err == nil {
			compact = out
		}
	}
	xmlDoc, xmlErr := ua.EncodeXML(val)
	stats.reencoded.Add(1)

	// And what the encoders write of it is a fixed point: it decodes, and
	// encoding the result gives the same document. (The comparison is not
	// with the accepted value itself: an encoding may normalise it - JSON
	// has no null array, neither format carries invalid UTF-8.)
	check := func(what string, doc []byte, decode func([]byte, any, ...ua.CodecOption) error, encode func(any, ...ua.CodecOption) ([]byte, error)) string {
		again := h.target()
		if err := decode(doc, again); err != nil {
			return fmt.Sprintf("%s written from the accepted value is rejected: %v\n written: %s", what, err, clip(doc))
		}
		v := again
		if t := reflect.TypeOf(again).Elem(); t.Kind() != reflect.Struct {
			v = reflect.ValueOf(again).Elem().Interface()
		}
		if got, err := encode(v); err != nil || !bytes.Equal(got, doc) {
			return fmt.Sprintf("%s written from the accepted value is not stable (%v)\n first:  %s\n second: %s", what, err, clip(doc), clip(got))
		}
		return ""
	}
	if compact != nil {
		if v := check("JSON", compact, ua.DecodeJSON, ua.EncodeJSON); v != "" {
			stats.unstable.Add(1)
			return v
		}
	}
	// An XmlElement is written into an XML document as the markup it is;
	// if a mutation damaged that markup, so is the document.
	if xmlErr == nil && !holdsXMLElement(reflect.ValueOf(target), 0) {
		if v := check("XML", xmlDoc, ua.DecodeXML, ua.EncodeXML); v != "" {
			stats.unstable.Add(1)
			return v
		}
	}
	return ""
}

// TestHostile_ConcurrentMutations decodes mutated documents from many
// goroutines for a while (CHAOS_DURATION): valid JSON and XML documents of
// every type with seeded random damage - bytes flipped, pieces removed,
// repeated or spliced in from other documents, structural tokens and
// out-of-range numbers inserted - and documents built to exhaust a decoder
// (nesting, long arrays, dimensions, lengths that are only claimed), each
// with one of several WithMaxDepth / WithMaxArrayLength settings.
//
// Invariants: the decoders never panic and never hang; an error always wraps
// a StatusCode; a value that is accepted honours the array limit and can be
// given to every encoder without a panic; what the encoders write of it is
// accepted again and is a fixed point (decode and encode reproduce it byte
// for byte); the documents handed to the decoders are not modified.
func TestHostile_ConcurrentMutations(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	c := sharedCorpus(t, seed)
	seeds := hostileSeeds(c)
	pristine := make([][]byte, len(seeds))
	for i, h := range seeds {
		pristine[i] = bytes.Clone(h.doc)
	}
	duration := chaoskit.Duration(t, 1500*time.Millisecond)
	deadline := time.Now().Add(duration)

	var (
		sink  chaoskit.ErrSink
		stats hostileStats
		wg    sync.WaitGroup
	)
	const workers = 4
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(w)*1_000_003))
			for n := 0; time.Now().Before(deadline) && sink.Len() == 0; n++ {
				lim := hostileLimits[rng.Intn(len(hostileLimits))]
				var h *hostileDoc
				var doc []byte
				if rng.Intn(25) == 0 {
					h = bomb(rng, lim)
					doc = h.doc
				} else {
					h = seeds[rng.Intn(len(seeds))]
					doc = h.doc
					for k := 1 + rng.Intn(3); k > 0; k-- {
						doc = mutate(rng, h, doc, seeds)
					}
				}
				if v := tryDecode(h, doc, lim, &stats); v != "" {
					sink.Addf("worker %d, document %d (%s, depth limit %d, array limit %d): %s\n input (%d bytes): %s",
						w, n, h.name, lim.depth, lim.array, v, len(doc), strconv.QuoteToASCII(clip(doc)))
				}
			}
		}(w)
	}
	if !chaoskit.WaitGroupTimeout(&wg, duration+chaoskit.OpLimit) {
		t.Fatalf("HANG: the decoders did not return\n%s", chaoskit.AllStacks())
	}
	sink.Report(t)
	for i, h := range seeds {
		if !bytes.Equal(h.doc, pristine[i]) {
			t.Errorf("%s: a decoder modified the document it was given", h.name)
		}
	}
	t.Logf("%d documents in %v: %d rejected, %d accepted (%d re-encoded), slowest decode %v",
		stats.docs.Load(), duration, stats.rejected.Load(), stats.accepted.Load(), stats.reencoded.Load(), time.Duration(stats.slowest.Load()).Round(time.Microsecond))
	if stats.accepted.Load() == 0 || stats.rejected.Load() == 0 {
		t.Errorf("the mutations are one-sided: %d accepted, %d rejected", stats.accepted.Load(), stats.rejected.Load())
	}
}

// allocatedBytes returns the number of bytes fn allocates. It is only
// meaningful while nothing else runs in the process.
func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestHostile_Limits pins the limits of the decoders one by one, and what a
// document that exceeds them costs.
//
// Invariants: nesting beyond WithMaxDepth and a Variant array beyond
// WithMaxArrayLength are refused with StatusBadEncodingLimitsExceeded, the
// limit itself is accepted; the number of dimensions of a Variant is bounded
// and their product is checked without overflow; a length that a document
// only claims (in the binary body of an ExtensionObject) allocates nothing;
// no document makes a decoder allocate more than a small multiple of its own
// size.
//
// The test measures allocations of the whole process and therefore does not
// run in parallel with the other tests.
func TestHostile_Limits(t *testing.T) {
	type tc struct {
		name    string
		xml     bool
		doc     string
		target  any
		opts    []ua.CodecOption
		wantErr error // nil: must decode
	}
	rep := strings.Repeat
	list := func(n int) string { return strings.TrimSuffix(rep("0,", n), ",") }
	ones := func(n int) string { return strings.TrimSuffix(rep("1,", n), ",") }
	depth8, array16 := []ua.CodecOption{ua.WithMaxDepth(8)}, []ua.CodecOption{ua.WithMaxArrayLength(16)}
	limit, bad := error(ua.StatusBadEncodingLimitsExceeded), error(ua.StatusBadDecodingError)

	cases := []tc{
		{name: "json depth at the limit", doc: rep("[", 8) + rep("]", 8), target: new([][][][][][][][]int32), opts: depth8},
		{name: "json depth beyond the limit", doc: rep("[", 9) + rep("]", 9), target: new([][][][][][][][][]int32), opts: depth8, wantErr: limit},
		{name: "json default depth", doc: rep("[", 101) + rep("]", 101), target: new(ua.Variant), wantErr: limit},
		{name: "json nesting bomb", doc: rep("[", 1<<20), target: new(ua.Variant), wantErr: limit},
		{name: "json object bomb", doc: rep(`{"a":`, 1<<18), target: new(ua.DataValue), wantErr: limit},
		{name: "xml depth at the limit", xml: true, doc: rep("<a>", 8) + rep("</a>", 8), target: new(ua.DiagnosticInfo), opts: depth8},
		{name: "xml depth beyond the limit", xml: true, doc: rep("<a>", 9) + rep("</a>", 9), target: new(ua.DiagnosticInfo), opts: depth8, wantErr: limit},
		{name: "xml nesting bomb", xml: true, doc: rep("<a>", 1<<18), target: new(ua.Variant), wantErr: limit},

		{name: "json array at the limit", doc: `{"UaType":6,"Value":[` + list(16) + `]}`, target: new(ua.Variant), opts: array16},
		{name: "json array beyond the limit", doc: `{"UaType":6,"Value":[` + list(17) + `]}`, target: new(ua.Variant), opts: array16, wantErr: limit},
		{name: "json array beyond the default limit", doc: `{"UaType":6,"Value":[` + list(ua.MaxVariantArrayLength+1) + `]}`, target: new(ua.Variant), wantErr: limit},
		{name: "json array in a DataValue", doc: `{"UaType":6,"Value":[` + list(17) + `]}`, target: new(ua.DataValue), opts: array16, wantErr: limit},
		{name: "json array in a nested Variant", doc: `{"UaType":24,"Value":[{"UaType":6,"Value":[` + list(17) + `]}]}`, target: new(ua.Variant), opts: array16, wantErr: limit},
		{name: "json legacy array", doc: `{"Type":6,"Body":[` + list(17) + `]}`, target: new(ua.Variant), opts: array16, wantErr: limit},
		{name: "xml array at the limit", xml: true, doc: `<v><Value><ListOfInt32>` + rep("<Int32>0</Int32>", 16) + `</ListOfInt32></Value></v>`, target: new(ua.Variant), opts: array16},
		{name: "xml array beyond the limit", xml: true, doc: `<v><Value><ListOfInt32>` + rep("<Int32>0</Int32>", 17) + `</ListOfInt32></Value></v>`, target: new(ua.Variant), opts: array16, wantErr: limit},
		{name: "xml matrix beyond the limit", xml: true, doc: `<v><Value><Matrix><Dimensions><Int32>17</Int32><Int32>1</Int32></Dimensions><Elements>` + rep("<Int32>0</Int32>", 17) + `</Elements></Matrix></Value></v>`, target: new(ua.Variant), opts: array16, wantErr: limit},

		{name: "json 32 dimensions", doc: `{"UaType":6,"Value":[7],"Dimensions":[` + ones(32) + `]}`, target: new(ua.Variant)},
		{name: "json 33 dimensions", doc: `{"UaType":6,"Value":[7],"Dimensions":[` + ones(33) + `]}`, target: new(ua.Variant), wantErr: bad},
		{name: "json dimension bomb", doc: `{"UaType":6,"Value":[7],"Dimensions":[` + ones(200000) + `]}`, target: new(ua.Variant), wantErr: bad},
		{name: "json dimensions overflow", doc: `{"UaType":6,"Value":[],"Dimensions":[65536,65536]}`, target: new(ua.Variant), wantErr: bad},
		{name: "json dimensions mismatch", doc: `{"UaType":6,"Value":[1,2,3],"Dimensions":[2,2]}`, target: new(ua.Variant), wantErr: bad},
		{name: "json negative dimension", doc: `{"UaType":6,"Value":[1],"Dimensions":[-1,-1]}`, target: new(ua.Variant), wantErr: bad},
		{name: "xml dimension bomb", xml: true, doc: `<v><Value><Matrix><Dimensions>` + rep("<Int32>1</Int32>", 100000) + `</Dimensions><Elements><Int32>7</Int32></Elements></Matrix></Value></v>`, target: new(ua.Variant), wantErr: bad},

		{name: "json claimed length in a binary body", doc: `{"UaTypeId":"i=296","UaEncoding":1,"UaBody":"` + binaryBomb(0x7fffffff) + `"}`, target: new(ua.ExtensionObject), wantErr: bad},
		{name: "xml claimed length in a binary body", xml: true, doc: `<e><TypeId><Identifier>i=297</Identifier></TypeId><Body><ByteString>` + binaryBomb(0x7fffffff) + `</ByteString></Body></e>`, target: new(ua.ExtensionObject), wantErr: bad},
		{name: "json long string", doc: `"` + rep("a", 1<<20) + `"`, target: new(string)},
		{name: "xml entity expansion", xml: true, doc: `<!DOCTYPE x [<!ENTITY a "` + rep("a", 1000) + `">]><String>` + rep("&a;", 1000) + `</String>`, target: new(string), wantErr: bad},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				err      error
				panicked any
			)
			doc := []byte(c.doc)
			done := make(chan struct{})
			var used uint64
			go func() {
				defer close(done)
				used = allocatedBytes(func() {
					defer func() { panicked = recover() }()
					if c.xml {
						err = ua.DecodeXML(doc, c.target, c.opts...)
					} else {
						err = ua.DecodeJSON(doc, c.target, c.opts...)
					}
				})
			}()
			select {
			case <-done:
			case <-time.After(chaoskit.OpLimit):
				t.Fatalf("HANG: decoding %d bytes did not return\n%s", len(doc), chaoskit.AllStacks())
			}
			if panicked != nil {
				t.Fatalf("PANIC: %v", panicked)
			}
			switch {
			case c.wantErr == nil && err != nil:
				t.Fatalf("rejected: %v", err)
			case c.wantErr != nil && !stderrors.Is(err, c.wantErr):
				t.Fatalf("error = %v, want %v", err, c.wantErr)
			}
			// A decoder may copy what it reads a few times over; it must
			// not allocate what a document merely claims.
			if budget := uint64(1<<20 + 400*len(doc)); used > budget {
				t.Fatalf("decoding %d bytes allocated %d bytes (budget %d)", len(doc), used, budget)
			}
		})
	}
}
