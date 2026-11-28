// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/ua"
)

// updateGolden rewrites testdata/nodeset_golden.txt.
var updateGolden = flag.Bool("update-nodeset-golden", false, "rewrite testdata/nodeset_golden.txt")

// goldenNodeSets are the embedded NodeSets the address space digest covers,
// in the order of their RequiredModels.
var goldenNodeSets = []struct{ name, path string }{
	{"GDS", ""}, // internal/schema.OpcUaGdsNodeSet2
	{"DI", "../uafx/internal/model/Opc.Ua.Di.NodeSet2.xml"},
	{"FX Data", "../uafx/internal/model/opc.ua.fx.data.nodeset2.xml"},
	{"FX AC", "../uafx/internal/model/opc.ua.fx.ac.nodeset2.xml"},
	{"FX CM", "../uafx/internal/model/opc.ua.fx.cm.nodeset2.xml"},
}

// TestImportedAddressSpaceGolden: the address space of a new server
// (namespace 0 from the embedded NodeSet) and of a server that imports the
// GDS, DI and UAFX NodeSets as well is the one recorded in
// testdata/nodeset_golden.txt: per namespace the number of nodes and
// references and a digest of every node's attributes, references, role
// permissions and value. It was recorded with the reader of v1.41.0
// (internal/schema.UANodeSet), before internal/nodeset.Parse replaced it;
// a change of the import that is meant must rewrite it
// (-update-nodeset-golden) and say why. GO_OPCUA_NODESET_DUMP=<prefix>
// writes the dump of each node, to compare two versions with diff.
//
// Values the server sets itself (ServerStatus and the like) differ between
// two reads or two servers and are left out.
func TestImportedAddressSpaceGolden(t *testing.T) {
	var got strings.Builder
	// Two of each server: a value that differs between them, or between
	// two reads, is one the server sets itself (StartTime, CurrentTime).
	got.WriteString(addressSpaceDigest(t, "ns0", newGoldenServer(t), newGoldenServer(t)))
	got.WriteString(addressSpaceDigest(t, "ns0+GDS+DI+FX", importGoldenNodeSets(t), importGoldenNodeSets(t)))

	path := filepath.Join("testdata", "nodeset_golden.txt")
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("the imported address space differs from %s:\ngot\n%s\nwant\n%s", path, got.String(), want)
	}
}

// importGoldenNodeSets returns a new server with the goldenNodeSets
// imported with the namespace indexes of the server, as
// uafx/fxserver.ImportNodeSet does.
func importGoldenNodeSets(t *testing.T) *Server {
	t.Helper()
	s := newGoldenServer(t)
	for _, ns := range goldenNodeSets {
		data := schema.OpcUaGdsNodeSet2
		if ns.path != "" {
			var err error
			if data, err = os.ReadFile(ns.path); err != nil {
				t.Fatal(err)
			}
		}
		out, err := nodeset.Remap(data, func(uri string) (uint16, error) {
			for i, have := range s.Namespaces() {
				if have.Name() == uri {
					return uint16(i), nil
				}
			}
			return NewNodeNameSpace(s, uri).ID(), nil
		})
		if err != nil {
			t.Fatalf("%s: %v", ns.name, err)
		}
		if err := s.ImportNodeSetXML(out); err != nil {
			t.Fatalf("%s: %v", ns.name, err)
		}
	}
	return s
}

func newGoldenServer(t *testing.T) *Server {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// addressSpaceDigest returns a line per namespace of s: its URI, its
// number of nodes and references and the SHA-256 of a dump of its nodes.
// other is a server built the same way.
func addressSpaceDigest(t *testing.T, label string, s, other *Server) string {
	t.Helper()
	first := dumpNamespaces(t, s)
	time.Sleep(20 * time.Millisecond)
	second := dumpNamespaces(t, s)
	third := dumpNamespaces(t, other)
	if len(third) != len(first) {
		t.Fatalf("%s: %d and %d namespaces", label, len(first), len(third))
	}
	var b strings.Builder
	var dump strings.Builder
	defer func() {
		if path := os.Getenv("GO_OPCUA_NODESET_DUMP"); path != "" {
			_ = os.WriteFile(path+"."+label, []byte(dump.String()), 0o644)
		}
	}()
	for i, ns := range first {
		h := sha256.New()
		refs := 0
		for j, n := range ns.nodes {
			h.Write(n.static)
			fmt.Fprintf(&dump, "ns=%d %s", i, n.text)
			if len(third[i].nodes) != len(ns.nodes) {
				t.Fatalf("%s: ns=%d has %d and %d nodes", label, i, len(ns.nodes), len(third[i].nodes))
			}
			if bytes.Equal(n.value, second[i].nodes[j].value) && bytes.Equal(n.value, third[i].nodes[j].value) {
				h.Write(n.value)
				fmt.Fprintf(&dump, "  v %x\n", n.value)
			}
			refs += n.refs
		}
		fmt.Fprintf(&b, "%s ns=%d %s nodes=%d refs=%d sha256=%s\n", label, i, ns.uri, len(ns.nodes), refs, hex.EncodeToString(h.Sum(nil)))
	}
	return b.String()
}

type dumpedNode struct {
	text   string // static, one line per item, for GO_OPCUA_NODESET_DUMP
	static []byte // NodeId, attributes but the Value, references, role permissions
	value  []byte
	refs   int
}

type dumpedNamespace struct {
	uri   string
	nodes []dumpedNode
}

func dumpNamespaces(t *testing.T, s *Server) []dumpedNamespace {
	t.Helper()
	var out []dumpedNamespace
	for _, ns := range s.Namespaces() {
		d := dumpedNamespace{uri: ns.Name()}
		nn, ok := ns.(*NodeNameSpace)
		if !ok {
			out = append(out, d)
			continue
		}
		nn.mu.RLock()
		nodes := slices.Clone(nn.nodes)
		nn.mu.RUnlock()
		for _, n := range nodes {
			d.nodes = append(d.nodes, dumpNode(t, n))
		}
		out = append(out, d)
	}
	return out
}

func dumpNode(t *testing.T, n *Node) dumpedNode {
	t.Helper()
	enc := func(v any) []byte {
		b, err := ua.Encode(v)
		if err != nil {
			t.Fatalf("%v: encode %T: %v", n.id, v, err)
		}
		return b
	}
	n.mu.RLock()
	val := n.val
	var b bytes.Buffer
	var text strings.Builder
	b.Write(enc(n.id))
	fmt.Fprintf(&text, "%v\n", n.id)
	ids := make([]ua.AttributeID, 0, len(n.attr))
	for id := range n.attr {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "a%d", id)
		if dv := n.attr[id]; dv != nil {
			b.Write(enc(dv))
			fmt.Fprintf(&text, "  a%d %x\n", id, enc(dv))
		}
	}
	for _, r := range n.refs {
		b.WriteString("r")
		b.Write(enc(r))
		fmt.Fprintf(&text, "  r %x\n", enc(r))
	}
	for _, p := range n.rolePermissions {
		b.WriteString("p")
		b.Write(enc(p))
		fmt.Fprintf(&text, "  p %x\n", enc(p))
	}
	d := dumpedNode{text: text.String(), static: b.Bytes(), refs: len(n.refs)}
	n.mu.RUnlock()
	if val != nil {
		if dv := val(); dv != nil {
			d.value = enc(dv)
		}
	}
	return d
}
