// SPDX-License-Identifier: MIT

package main

import (
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/internal/nodeset"
)

// chdirRoot runs the test from the module root, where the paths of the
// families are.
func chdirRoot(t *testing.T) {
	t.Helper()
	t.Chdir(filepath.Join("..", ".."))
}

const ns0NodeSet = "internal/schema/Opc.Ua.NodeSet2.xml"

var ns0 = sync.OnceValues(func() (*nodeset.Set, error) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ns0NodeSet))
	if err != nil {
		return nil, err
	}
	return nodeset.Parse(raw)
})

// ns0Set is the NodeSet of namespace 0, parsed once: a parse takes seconds
// under the race detector.
func ns0Set(t *testing.T) *nodeset.Set {
	t.Helper()
	set, err := ns0()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestGenerated: the families emit the committed file (make check-gen holds
// that too), and the output is gofmt'ed Go.
func TestGenerated(t *testing.T) {
	chdirRoot(t)
	for _, f := range families {
		types, err := load(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := emit(f, types)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(f.Out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is not what the generator emits: run make gen", f.Out)
		}
		if _, err := format.Source(got); err != nil {
			t.Error(err)
		}
	}
}

// TestNextFamilies: the ObjectTypes the roadmap names next resolve with the
// DataTypes of namespace 0 the generator knows, structures included.
func TestNextFamilies(t *testing.T) {
	f := family{
		NodeSet: ns0NodeSet,
		Package: "uamethod",
		Out:     "unused",
		Types:   []string{"TrustListType", "PubSubConfigurationType", "PubSubKeyServiceType"},
	}
	types, err := resolve(ns0Set(t), f)
	if err != nil {
		t.Fatal(err)
	}
	src, err := emit(f, types)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TrustListTypeOpenWithMasks", "PubSubConfigurationTypeCloseAndUpdate", "PubSubKeyServiceTypeGetSecurityKeys"} {
		if !strings.Contains(string(src), "var "+want+" = ") {
			t.Errorf("no contract %s", want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	set := ns0Set(t)
	for _, f := range []family{
		{NodeSet: ns0NodeSet, Types: []string{"NoSuchType"}},
		{NodeSet: ns0NodeSet, Namespace: "urn:none", Types: []string{"FileType"}},
	} {
		if _, err := resolve(set, f); err == nil {
			t.Errorf("%+v: no error", f)
		}
	}
	chdirRoot(t)
	if _, err := load(family{NodeSet: "internal/schema/none.xml", Types: []string{"FileType"}}); err == nil {
		t.Error("load of a missing NodeSet: no error")
	}
	if err := run([]family{{NodeSet: "internal/schema/none.xml"}}); err == nil {
		t.Error("run: no error")
	}
}

func TestClause(t *testing.T) {
	for doc, want := range map[string]string{
		"https://reference.opcfoundation.org/v105/Core/docs/Part20/4.2.2":  "OPC 10000-20 §4.2.2",
		"https://reference.opcfoundation.org/v105/Core/docs/Part20/4.2.2/": "OPC 10000-20 §4.2.2",
		"":                          "",
		"https://example.com/other": "",
	} {
		if got := clause(doc); got != want {
			t.Errorf("clause(%q) = %q, want %q", doc, got, want)
		}
	}
}
