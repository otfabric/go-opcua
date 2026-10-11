// SPDX-License-Identifier: MIT

package codec

import (
	"bytes"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

func sortItems(items []*item) {
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
}

// The option sets are shared by every goroutine of every scenario: the same
// slices and the same namespace and server arrays.
var (
	sharedNamespaces = []string{"http://opcfoundation.org/UA/", "urn:ns:one", "urn:ns:two", "urn:ns:three"}
	sharedServers    = []string{"urn:srv:local", "urn:srv:one", "urn:srv:two"}

	optsNone   []ua.CodecOption
	optsTables = []ua.CodecOption{ua.WithNamespaceArray(sharedNamespaces), ua.WithServerArray(sharedServers)}
	optsLimits = []ua.CodecOption{ua.WithIndent("  "), ua.WithMaxDepth(64), ua.WithMaxArrayLength(4096)}
	optsXML    = []ua.CodecOption{ua.WithXMLRootName("Root"), ua.WithoutXMLNamespace(), ua.WithNamespaceArray(sharedNamespaces)}
)

// encoding is one way to write an item: a JSON form or XML, with one of the
// shared option sets.
type encoding struct {
	name string
	xml  bool
	// reversible is false for the 1.04 non-reversible JSON form, which
	// cannot be decoded.
	reversible bool
	opts       []ua.CodecOption
}

func (e *encoding) encode(v any) ([]byte, error) {
	if e.xml {
		return ua.EncodeXML(v, e.opts...)
	}
	return ua.EncodeJSON(v, e.opts...)
}

func (e *encoding) decode(doc []byte, target any) error {
	if e.xml {
		return ua.DecodeXML(doc, target, e.opts...)
	}
	return ua.DecodeJSON(doc, target, e.opts...)
}

// encodings is every combination the scenarios run: the four JSON forms and
// XML, each with the shared option sets.
var encodings = func() []*encoding {
	var out []*encoding
	// The form options are created once, like the option sets: every
	// goroutine applies the very same option values.
	with := func(base []ua.CodecOption, form ua.JSONForm) []ua.CodecOption {
		return append(append([]ua.CodecOption{}, base...), ua.WithJSONForm(form))
	}
	for _, set := range []struct {
		name string
		opts []ua.CodecOption
	}{{"plain", optsNone}, {"tables", optsTables}, {"limits", optsLimits}} {
		for _, form := range []struct {
			name string
			form ua.JSONForm
		}{{"compact", ua.JSONCompact}, {"verbose", ua.JSONVerbose}, {"legacy", ua.JSONLegacyReversible}, {"nonreversible", ua.JSONLegacyNonReversible}} {
			out = append(out, &encoding{
				name:       "json/" + form.name + "/" + set.name,
				reversible: form.form != ua.JSONLegacyNonReversible,
				opts:       with(set.opts, form.form),
			})
		}
		out = append(out, &encoding{name: "xml/" + set.name, xml: true, reversible: true, opts: set.opts})
	}
	out = append(out, &encoding{name: "xml/root", xml: true, reversible: true, opts: optsXML})
	return out
}()

// reference holds, for every item and encoding, the document a single
// goroutine produced.
type reference [][][]byte

// buildReference encodes every item in every encoding on the calling
// goroutine and checks that the documents decode to the same value.
func buildReference(items []*item) (reference, error) {
	ref := make(reference, len(items))
	for i, it := range items {
		ref[i] = make([][]byte, len(encodings))
		for j, enc := range encodings {
			doc, err := enc.encode(it.val)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: encode: %w", it.name, enc.name, err)
			}
			ref[i][j] = doc
			if err := checkDecode(it, enc, doc); err != nil {
				return nil, err
			}
		}
	}
	return ref, nil
}

// checkDecode decodes doc and verifies that the result is the value of the
// item.
func checkDecode(it *item, enc *encoding, doc []byte) error {
	if !enc.reversible {
		return nil
	}
	target := it.target()
	if err := enc.decode(doc, target); err != nil {
		return fmt.Errorf("%s: %s: decode: %w\n%s", it.name, enc.name, err, clip(doc))
	}
	got, err := it.binaryOf(target)
	if err != nil {
		return fmt.Errorf("%s: %s: decoded value cannot be encoded: %w\n%s", it.name, enc.name, err, clip(doc))
	}
	if !bytes.Equal(got, it.bin) {
		return fmt.Errorf("%s: %s: round trip changed the value\n doc:  %s\n want: %x\n got:  %x", it.name, enc.name, clip(doc), clipBytes(it.bin), clipBytes(got))
	}
	return nil
}

func clip(doc []byte) string {
	if len(doc) > 600 {
		return string(doc[:600]) + "..."
	}
	return string(doc)
}

func clipBytes(b []byte) []byte {
	if len(b) > 300 {
		return b[:300]
	}
	return b
}

// checkEncode encodes the item and verifies that the document is byte for
// byte the reference.
func checkEncode(it *item, enc *encoding, want []byte) error {
	doc, err := enc.encode(it.val)
	if err != nil {
		return fmt.Errorf("%s: %s: encode: %w", it.name, enc.name, err)
	}
	if !bytes.Equal(doc, want) {
		return fmt.Errorf("%s: %s: output differs from the single-threaded reference\n want: %s\n got:  %s", it.name, enc.name, clip(want), clip(doc))
	}
	return nil
}

// hammer starts workers goroutines on a barrier. Every goroutine walks all
// items in the same order - so that the first use of each type happens in
// many goroutines at once - and runs the encodings pick selects for it.
// Even goroutines encode first, odd ones decode first.
//
// ref may be nil: then nothing has been encoded in this process before, the
// documents to decode come from docs, and the outputs of the goroutines are
// returned to be compared with a reference that is built afterwards.
func hammer(t *testing.T, items []*item, ref, docs reference, workers, rounds int, pick func(worker, item, enc int) bool) []reference {
	t.Helper()
	var (
		sink  chaoskit.ErrSink
		wg    sync.WaitGroup
		start = make(chan struct{})
		outs  = make([]reference, workers)
	)
	if docs == nil {
		docs = ref
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 16<<10)
					sink.Addf("worker %d: PANIC: %v\n%s", w, r, buf[:runtime.Stack(buf, false)])
				}
			}()
			out := make(reference, len(items))
			outs[w] = out
			<-start
			for round := 0; round < rounds; round++ {
				for i, it := range items {
					if out[i] == nil {
						out[i] = make([][]byte, len(encodings))
					}
					for j, enc := range encodings {
						if !pick(w, i, j) {
							continue
						}
						encode := func() {
							doc, err := enc.encode(it.val)
							switch {
							case err != nil:
								sink.Addf("worker %d: %s: %s: encode: %v", w, it.name, enc.name, err)
							case ref != nil && !bytes.Equal(doc, ref[i][j]):
								sink.Addf("worker %d: %s: %s: output differs from the single-threaded reference\n want: %s\n got:  %s", w, it.name, enc.name, clip(ref[i][j]), clip(doc))
							}
							out[i][j] = doc
						}
						decode := func() {
							if err := checkDecode(it, enc, docs[i][j]); err != nil {
								sink.Addf("worker %d: %v", w, err)
							}
						}
						if w%2 == 0 {
							encode()
							decode()
						} else {
							decode()
							encode()
						}
					}
				}
			}
		}(w)
	}
	close(start)
	if !chaoskit.WaitGroupTimeout(&wg, chaoskit.OpLimit) {
		t.Fatalf("DEADLOCK: codec workers did not finish within %v\n%s", chaoskit.OpLimit, chaoskit.AllStacks())
	}
	sink.Report(t)
	return outs
}

// snapshot returns the binary encoding of every item, to prove that nothing
// changed the shared values.
func snapshot(t *testing.T, items []*item) [][]byte {
	t.Helper()
	out := make([][]byte, len(items))
	for i, it := range items {
		b, err := ua.Encode(it.val)
		if err != nil {
			t.Fatalf("%s: binary encode: %v", it.name, err)
		}
		out[i] = b
	}
	return out
}

func requireUnchanged(t *testing.T, items []*item, before [][]byte) {
	t.Helper()
	after := snapshot(t, items)
	for i := range items {
		if !bytes.Equal(before[i], after[i]) {
			t.Errorf("%s: the shared value was modified\n before: %x\n after:  %x", items[i].name, clipBytes(before[i]), clipBytes(after[i]))
		}
	}
	wantNS := []string{"http://opcfoundation.org/UA/", "urn:ns:one", "urn:ns:two", "urn:ns:three"}
	wantSrv := []string{"urn:srv:local", "urn:srv:one", "urn:srv:two"}
	if fmt.Sprint(sharedNamespaces) != fmt.Sprint(wantNS) || fmt.Sprint(sharedServers) != fmt.Sprint(wantSrv) {
		t.Errorf("the shared namespace or server array was modified: %v %v", sharedNamespaces, sharedServers)
	}
}
