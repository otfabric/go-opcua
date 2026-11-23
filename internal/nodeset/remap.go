// SPDX-License-Identifier: MIT

// Package nodeset prepares NodeSet2 documents for import into a server
// whose namespace table differs from the table of the document.
//
// A NodeSet2 document carries its own namespace table, NamespaceUris: a
// NamespaceIndex in a NodeId or a QualifiedName of the document is an index
// into that table, where 1 is its first entry and 0 the OPC UA namespace
// (Part 6 §F.2). On a server the same namespaces have the indexes of its
// NamespaceArray, which depend on what else the server holds. Remap rewrites
// the indexes of a document to those of the server.
package nodeset

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
)

// Resolver returns the index the namespace uri has on the server, adding
// the namespace to the server when it has none.
type Resolver func(uri string) (uint16, error)

// maxURIs bounds the namespace table a document may declare: a
// NamespaceIndex is a UInt16 (Part 3 §8.2.2).
const maxURIs = 1<<16 - 1

var (
	// nodeIDIndex matches the namespace index of a NodeId in the string
	// form of Part 6 §5.3.1.10 ("ns=1;i=5"), as attribute value, alias or
	// element text. The character before "ns" must not be a letter, so
	// that "nsu=" and words ending in "ns" are left alone.
	nodeIDIndex = regexp.MustCompile(`(^|[^A-Za-z])ns=(\d+);`)
	// nameIndex matches the namespace prefix of the BrowseName of a node
	// and of the Name of a DataType definition ("1:Name", Part 6 §F.3).
	nameIndex = regexp.MustCompile(`( (?:Browse)?Name=")(\d+):`)
	// qnIndex matches the NamespaceIndex of a QualifiedName value.
	qnIndex = regexp.MustCompile(`(<NamespaceIndex>)(\d+)(</NamespaceIndex>)`)
	// browseName matches a BrowseName attribute; prefixed reports whether
	// its value starts with a namespace prefix.
	browseName = regexp.MustCompile(` BrowseName="([^"]*)"`)
	prefixed   = regexp.MustCompile(`^\d+:`)
)

// URIs returns the namespace table of the document src, in order: the
// namespace of index 1 first.
func URIs(src []byte) ([]string, error) {
	i := bytes.Index(src, []byte("<NamespaceUris>"))
	if i < 0 {
		return nil, nil
	}
	j := bytes.Index(src[i:], []byte("</NamespaceUris>"))
	if j < 0 {
		return nil, fmt.Errorf("nodeset: NamespaceUris is not closed")
	}
	var t struct {
		URI []string `xml:"Uri"`
	}
	if err := xml.Unmarshal(src[i:i+j+len("</NamespaceUris>")], &t); err != nil {
		return nil, fmt.Errorf("nodeset: NamespaceUris: %w", err)
	}
	if len(t.URI) > maxURIs {
		return nil, fmt.Errorf("nodeset: %d namespaces do not fit a UInt16 namespace index", len(t.URI))
	}
	return t.URI, nil
}

// Remap returns a copy of the NodeSet2 document src in which every
// namespace index of the document is replaced by the index resolve returns
// for its URI, and without its NamespaceUris, so that an importer that adds
// the namespaces of a document does not add them a second time. A
// BrowseName without a prefix is a name in namespace 0 (Part 6 §F.3) and
// gets the prefix "0:", so that it is not read as a name in the namespace
// of its node. An index outside the namespace table of the document is an
// error.
func Remap(src []byte, resolve Resolver) ([]byte, error) {
	uris, err := URIs(src)
	if err != nil {
		return nil, err
	}
	table := make([]uint16, len(uris)+1) // table[0] = 0: the OPC UA namespace
	for k, uri := range uris {
		idx, err := resolve(uri)
		if err != nil {
			return nil, fmt.Errorf("nodeset: namespace %q: %w", uri, err)
		}
		table[k+1] = idx
	}

	var bad error
	mapIndex := func(s []byte) []byte {
		n, err := strconv.ParseUint(string(s), 10, 16)
		if err != nil || n >= uint64(len(table)) {
			if bad == nil {
				bad = fmt.Errorf("nodeset: namespace index %s is not in the namespace table of the document (%d entries)", s, len(uris))
			}
			return s
		}
		return strconv.AppendUint(nil, uint64(table[n]), 10)
	}

	out := src
	if i := bytes.Index(out, []byte("<NamespaceUris>")); i >= 0 {
		// URIs found the end of the table after its start.
		j := i + bytes.Index(out[i:], []byte("</NamespaceUris>")) + len("</NamespaceUris>")
		out = append(append([]byte(nil), out[:i]...), out[j:]...)
	}
	out = replaceIndex(out, nodeIDIndex, func(m [][]byte) []byte {
		return concat(m[1], []byte("ns="), mapIndex(m[2]), []byte(";"))
	})
	out = replaceIndex(out, nameIndex, func(m [][]byte) []byte {
		return concat(m[1], mapIndex(m[2]), []byte(":"))
	})
	out = replaceIndex(out, qnIndex, func(m [][]byte) []byte {
		return concat(m[1], mapIndex(m[2]), m[3])
	})
	out = replaceIndex(out, browseName, func(m [][]byte) []byte {
		if prefixed.Match(m[1]) {
			return m[0]
		}
		return concat([]byte(` BrowseName="0:`), m[1], []byte(`"`))
	})
	if bad != nil {
		return nil, bad
	}
	return out, nil
}

// replaceIndex replaces each match of re in src by f of its submatches.
func replaceIndex(src []byte, re *regexp.Regexp, f func(m [][]byte) []byte) []byte {
	return re.ReplaceAllFunc(src, func(match []byte) []byte {
		return f(re.FindSubmatch(match))
	})
}

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
