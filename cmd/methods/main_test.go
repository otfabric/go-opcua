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

// TestNextFamilies: the ObjectTypes the roadmap names next do not resolve
// with the generator as it is. The Methods of the GDS DirectoryType have
// arguments of DataTypes outside namespace 0 (ApplicationRecordDataType of
// the GDS NodeSet); those of CertificateDirectoryType have arguments of
// subtypes of built-in types (UtcTime) that the GDS NodeSet alone does not
// resolve. When one resolves, add it to families.
func TestNextFamilies(t *testing.T) {
	chdirRoot(t)
	for typ, want := range map[string]string{
		"DirectoryType":            "is not of namespace 0",
		"CertificateDirectoryType": "DataType i=294 is not supported",
	} {
		_, err := load(family{
			NodeSet:   "internal/schema/Opc.Ua.Gds.NodeSet2.xml",
			Namespace: "http://opcfoundation.org/UA/GDS/",
			Package:   "gdsmethod",
			Out:       "unused",
			Types:     []string{typ},
		})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q (when it resolves, add it to families)", typ, err, want)
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
		"https://reference.opcfoundation.org/v105/Core/docs/Part20/4.2.2":          "OPC 10000-20 §4.2.2",
		"https://reference.opcfoundation.org/v105/Core/docs/Part20/4.2.2/":         "OPC 10000-20 §4.2.2",
		"https://reference.opcfoundation.org/v105/Core/docs/Part12/7.8.2/#7.8.2.3": "OPC 10000-12 §7.8.2.3",
		"":                          "",
		"https://example.com/other": "",
	} {
		if got := clause(doc); got != want {
			t.Errorf("clause(%q) = %q, want %q", doc, got, want)
		}
	}
}
