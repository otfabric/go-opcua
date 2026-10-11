// SPDX-License-Identifier: MIT

package codec

import (
	"bytes"
	"context"
	"encoding/gob"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// corpus is the shared values of this process with their single-threaded
// reference documents.
type corpus struct {
	items []*item
	ref   reference
}

var (
	corpusOnce sync.Once
	corpusVal  *corpus
	corpusErr  error
)

// sharedCorpus builds the corpus once per process. The seed is the same for
// every test of a process, see chaoskit.Seed.
func sharedCorpus(t *testing.T, seed int64) *corpus {
	t.Helper()
	corpusOnce.Do(func() {
		items, err := buildItems(seed)
		if err != nil {
			corpusErr = err
			return
		}
		ref, err := buildReference(items)
		corpusVal, corpusErr = &corpus{items: items, ref: ref}, err
	})
	if corpusErr != nil {
		t.Fatalf("building the shared values: %v", corpusErr)
	}
	return corpusVal
}

// quarter gives every worker a rotating quarter of the encodings of each
// item. A pair of workers (an encode-first and a decode-first one) shares a
// selection, and four pairs cover every encoding of every item.
func quarter(worker, item, enc int) bool { return (enc+item+worker/2)%4 == 0 }

func everything(int, int, int) bool { return true }

// envChild marks the re-executed test binary of TestFirstUse_FreshProcess.
// Its value is the path of the reference documents written by the parent.
const envChild = "CHAOS_CODEC_CHILD"

// TestFirstUse_FreshProcess runs the first use of every type concurrently.
//
// The codecs build their type tables lazily (the classification of a Go
// type, the description of a structure, whether a structure needs its
// ExpandedNodeIds filled in). Once a process has encoded a type, those tables
// are populated and their construction is no longer exercised, so the
// scenario runs in fresh processes: the test binary re-executes itself several
// times, and in each child the very first codec calls are made by goroutines
// released on a barrier, all walking several hundred distinct types in the
// same order.
//
// Invariants: no data race (the children run under the race detector like the
// parent), no panic; every document a goroutine writes is byte for byte what
// a single goroutine writes afterwards in the same process, and what the
// parent process wrote; every document decodes to the value it was written
// from; the shared values are not modified.
func TestFirstUse_FreshProcess(t *testing.T) {
	t.Parallel()
	if os.Getenv(envChild) != "" {
		t.Skip("this is a child of the test")
	}
	seed := chaoskit.Seed(t)
	c := sharedCorpus(t, seed)

	path := t.TempDir() + "/reference.gob"
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c.ref); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	const children = 2
	ctx, cancel := context.WithTimeout(context.Background(), chaoskit.OpLimit)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < children; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFirstUseChild$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(),
				envChild+"="+path,
				chaoskit.EnvSeed+"="+strconv.FormatInt(seed, 10),
			)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "--- PASS: TestFirstUseChild") {
				t.Errorf("child %d: %v\n%s", i, err, out)
			}
		}(i)
	}
	wg.Wait()
}

// TestFirstUseChild is the body of TestFirstUse_FreshProcess in the child
// process. It must be the first test of the process to use the JSON and XML
// codecs, which -test.run guarantees.
func TestFirstUseChild(t *testing.T) {
	path := os.Getenv(envChild)
	if path == "" {
		t.Skip("only runs as a child of TestFirstUse_FreshProcess")
	}
	seed := chaoskit.Seed(t)
	items, err := buildItems(seed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parent reference
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&parent); err != nil {
		t.Fatal(err)
	}
	if len(parent) != len(items) {
		t.Fatalf("the parent has %d shared values, this process %d", len(parent), len(items))
	}
	before := snapshot(t, items)

	start := time.Now()
	outs := hammer(t, items, nil, parent, 8, 1, quarter)
	t.Logf("%d values, %d encodings, first use in 8 goroutines: %v", len(items), len(encodings), time.Since(start).Round(time.Millisecond))

	// Only now a single goroutine uses the codecs.
	ref, err := buildReference(items)
	if err != nil {
		t.Fatalf("after the concurrent phase: %v", err)
	}
	bad := 0
	for i, it := range items {
		for j, enc := range encodings {
			if !bytes.Equal(ref[i][j], parent[i][j]) && bad < 20 {
				bad++
				t.Errorf("%s: %s: this process and its parent disagree\n parent: %s\n child:  %s", it.name, enc.name, clip(parent[i][j]), clip(ref[i][j]))
			}
			for w := range outs {
				if doc := outs[w][i][j]; doc != nil && !bytes.Equal(doc, ref[i][j]) && bad < 20 {
					bad++
					t.Errorf("worker %d: %s: %s: output differs from the single-threaded reference\n want: %s\n got:  %s", w, it.name, enc.name, clip(ref[i][j]), clip(doc))
				}
			}
		}
	}
	requireUnchanged(t, items, before)
}

// TestConcurrent_SharedValues encodes and decodes the same values from many
// goroutines: one instance of every structure the codecs know, Variants of
// every built-in type as scalar, array and matrix, DataValues,
// ExtensionObjects with generated and custom bodies, nested top-level arrays.
// All goroutines use the same instances, the same option slices and the same
// namespace and server arrays, in the four JSON forms and in XML.
//
// Invariants: no data race, no panic; every encoding of a value is byte for
// byte the single-threaded reference; every document decodes to a value with
// the binary encoding of the original; the shared values and the shared
// arrays are not modified.
func TestConcurrent_SharedValues(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	c := sharedCorpus(t, seed)
	before := snapshot(t, c.items)

	start := time.Now()
	hammer(t, c.items, c.ref, nil, 8, 1, quarter)
	t.Logf("%d values, %d encodings, 8 goroutines: %v", len(c.items), len(encodings), time.Since(start).Round(time.Millisecond))
	requireUnchanged(t, c.items, before)

	// The values that are not plain structures (Variants, matrices,
	// DataValues, ExtensionObjects, arrays) again, in every encoding.
	var special []*item
	var ref reference
	for i, it := range c.items {
		if !strings.HasPrefix(it.name, "struct/") {
			special = append(special, it)
			ref = append(ref, c.ref[i])
		}
	}
	start = time.Now()
	hammer(t, special, ref, nil, 8, 1, everything)
	t.Logf("%d values, every encoding, 8 goroutines: %v", len(special), time.Since(start).Round(time.Millisecond))
	requireUnchanged(t, c.items, before)
}
