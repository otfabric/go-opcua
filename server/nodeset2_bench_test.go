// SPDX-License-Identifier: MIT

package server

import (
	"os"
	"testing"

	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/internal/schema"
)

// BenchmarkParseBuiltinNodeSet parses the NodeSet of namespace 0, as the
// first server of a process does.
func BenchmarkParseBuiltinNodeSet(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := nodeset.Parse(schema.OpcUaNodeSet2); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNewServer creates a server, which imports the parsed NodeSet
// of namespace 0 into its address space.
func BenchmarkNewServer(b *testing.B) {
	if _, err := New(); err != nil { // parse the built-in NodeSet once
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		s, err := New()
		if err != nil {
			b.Fatal(err)
		}
		_ = s.Close()
	}
}

// BenchmarkImportNodeSetXML imports the DI NodeSet into a new server.
func BenchmarkImportNodeSetXML(b *testing.B) {
	data, err := os.ReadFile("../uafx/internal/model/Opc.Ua.Di.NodeSet2.xml")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		s, err := New()
		if err != nil {
			b.Fatal(err)
		}
		out, err := nodeset.Remap(data, func(uri string) (uint16, error) { return NewNodeNameSpace(s, uri).ID(), nil })
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := s.ImportNodeSetXML(out); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = s.Close()
		b.StartTimer()
	}
}
