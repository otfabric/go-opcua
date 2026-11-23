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
//
// The document is read as XML and only the places where Part 6 Annex F
// puts a NodeId or a QualifiedName are rewritten (see [Remap]); text,
// comments, the content of Extensions and attributes of other names are
// copied byte for byte.
package nodeset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// Resolver returns the index the namespace uri has on the server, adding
// the namespace to the server when it has none.
type Resolver func(uri string) (uint16, error)

// maxURIs bounds the namespace table a document may declare: a
// NamespaceIndex is a UInt16 (Part 3 §8.2.2).
const maxURIs = 1<<16 - 1

// Where Part 6 Annex F puts NodeIds and QualifiedNames.
var (
	// nodeIDAttrs are the attributes whose value is a NodeId or an alias
	// (Part 6 §F.3 to §F.11).
	nodeIDAttrs = map[string]bool{"NodeId": true, "ParentNodeId": true, "DataType": true, "ReferenceType": true, "MethodDeclarationId": true}
	// nodeIDText are the elements whose text is a NodeId: an alias, the
	// target of a reference, the role of a RolePermission (§F.3, §F.4),
	// and the Identifier of a NodeId, ExpandedNodeId or TypeId in a
	// value (§5.3.1.10, §5.3.1.11, §5.3.1.16).
	nodeIDText = map[string]bool{"Alias": true, "Reference": true, "RolePermission": true, "Identifier": true}
)

var (
	// nodeIDIndex matches the namespace index of a NodeId in the string
	// form of Part 6 §5.3.1.10 ("ns=1;i=5"). The character before "ns"
	// must not be a letter, so that "nsu=" is left alone.
	nodeIDIndex = regexp.MustCompile(`(^|[^A-Za-z])ns=(\d+);`)
	// attr matches an attribute of a start tag: its name, the "=" with
	// the white space around it, and its quoted value.
	attr = regexp.MustCompile(`(\s)([A-Za-z_][\w.:-]*)(\s*=\s*)("[^"]*"|'[^']*')`)
	// prefix matches the namespace prefix of a QualifiedName ("1:Name").
	prefix = regexp.MustCompile(`^(\d+):`)
	// number matches the NamespaceIndex of a QualifiedName value.
	number = regexp.MustCompile(`^(\s*)(\d+)(\s*)$`)
)

// token is a token of a document with the bytes it was read from.
type token struct {
	tok xml.Token
	raw []byte
}

// walk calls f with every token of src and the local names of the elements
// that enclose it, innermost last. The raw bytes of the tokens make up src.
func walk(src []byte, f func(t token, stack []string) error) error {
	d := xml.NewDecoder(bytes.NewReader(src))
	var stack []string
	prev := int64(0)
	for {
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("nodeset: %w", err)
		}
		off := d.InputOffset()
		raw := src[prev:off]
		prev = off
		if e, ok := tok.(xml.EndElement); ok && len(stack) > 0 && stack[len(stack)-1] == e.Name.Local {
			stack = stack[:len(stack)-1]
		}
		if err := f(token{tok, raw}, stack); err != nil {
			return err
		}
		if s, ok := tok.(xml.StartElement); ok {
			stack = append(stack, s.Name.Local)
		}
	}
}

// URIs returns the namespace table of the document src, in order: the
// namespace of index 1 first. The table is the first NamespaceUris element
// of the document.
func URIs(src []byte) ([]string, error) {
	var (
		uris    []string
		in, uri bool
		done    = errors.New("done")
		text    []byte
	)
	err := walk(src, func(t token, _ []string) error {
		switch tok := t.tok.(type) {
		case xml.StartElement:
			switch {
			case tok.Name.Local == "NamespaceUris" && !in:
				in = true
			case in && tok.Name.Local == "Uri" && !uri:
				uri, text = true, text[:0]
			case in:
				return fmt.Errorf("nodeset: NamespaceUris holds %s", tok.Name.Local)
			}
		case xml.CharData:
			if uri {
				text = append(text, tok...)
			}
		case xml.EndElement:
			switch {
			case uri && tok.Name.Local == "Uri":
				uri = false
				if len(uris) == maxURIs {
					return fmt.Errorf("nodeset: more namespaces than a UInt16 namespace index addresses")
				}
				uris = append(uris, string(bytes.TrimSpace(text)))
			case uri:
				return fmt.Errorf("nodeset: Uri is not closed")
			case in && tok.Name.Local == "NamespaceUris":
				return done
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, done):
		return uris, nil
	case err != nil:
		return nil, err
	case in:
		return nil, fmt.Errorf("nodeset: NamespaceUris is not closed")
	}
	return nil, nil
}

// Remap returns a copy of the NodeSet2 document src in which every
// namespace index of the document is replaced by the index resolve returns
// for its URI, and without its NamespaceUris, so that an importer that adds
// the namespaces of a document does not add them a second time.
//
// Rewritten are the NodeIds of the attributes NodeId, ParentNodeId,
// DataType, ReferenceType and MethodDeclarationId; of the text of Alias,
// Reference, RolePermission and of the Identifier of a NodeId in a value;
// the prefix of BrowseName attributes and of the Name of a DataType
// Definition; and the NamespaceIndex of a QualifiedName value. A
// BrowseName without a prefix is a name in namespace 0 (Part 6 §F.3) and
// gets the prefix "0:", so that it is not read as a name in the namespace
// of its node. Everything else, Extensions included, is copied as it is.
// An index outside the namespace table of the document is an error.
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
	mapNodeID := func(s []byte) []byte {
		return nodeIDIndex.ReplaceAllFunc(s, func(m []byte) []byte {
			sub := nodeIDIndex.FindSubmatch(m)
			return concat(sub[1], []byte("ns="), mapIndex(sub[2]), []byte(";"))
		})
	}

	out := make([]byte, 0, len(src))
	var (
		cutting bool // in the NamespaceUris that is cut out
		cut     bool // the table is cut out
		depth   int  // of cutting
	)
	err = walk(src, func(t token, stack []string) error {
		if cutting {
			switch t.tok.(type) {
			case xml.StartElement:
				depth++
			case xml.EndElement:
				depth--
				cutting = depth > 0
			}
			return nil
		}
		if contains(stack, "Extensions") {
			out = append(out, t.raw...)
			return nil
		}
		switch tok := t.tok.(type) {
		case xml.StartElement:
			if tok.Name.Local == "NamespaceUris" && !cut {
				cutting, cut, depth = true, true, 1
				if len(t.raw) >= 2 && bytes.HasSuffix(t.raw, []byte("/>")) {
					// <NamespaceUris/>: no end tag follows.
					cutting = false
				}
				return nil
			}
			out = append(out, remapTag(t.raw, tok.Name.Local, mapIndex, mapNodeID)...)
		case xml.CharData:
			if len(stack) == 0 {
				out = append(out, t.raw...)
				break
			}
			switch el := stack[len(stack)-1]; {
			case nodeIDText[el]:
				out = append(out, mapNodeID(t.raw)...)
			case el == "NamespaceIndex":
				if m := number.FindSubmatch(t.raw); m != nil {
					out = append(out, concat(m[1], mapIndex(m[2]), m[3])...)
				} else {
					out = append(out, t.raw...)
				}
			default:
				out = append(out, t.raw...)
			}
		default:
			out = append(out, t.raw...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if bad != nil {
		return nil, bad
	}
	return out, nil
}

// remapTag rewrites the attributes of the start tag raw of the element el.
func remapTag(raw []byte, el string, mapIndex, mapNodeID func([]byte) []byte) []byte {
	return attr.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := attr.FindSubmatch(m)
		name, value := local(sub[2]), sub[4]
		q, v := value[:1], value[1:len(value)-1]
		switch {
		case nodeIDAttrs[name]:
			v = mapNodeID(v)
		case name == "BrowseName":
			if p := prefix.FindSubmatch(v); p != nil {
				v = concat(mapIndex(p[1]), []byte(":"), v[len(p[0]):])
			} else {
				v = concat([]byte("0:"), v)
			}
		case name == "Name" && el == "Definition":
			if p := prefix.FindSubmatch(v); p != nil {
				v = concat(mapIndex(p[1]), []byte(":"), v[len(p[0]):])
			}
		default:
			return m
		}
		return concat(sub[1], sub[2], sub[3], q, v, q)
	})
}

// local returns name without its XML namespace prefix.
func local(name []byte) string {
	if i := bytes.LastIndexByte(name, ':'); i >= 0 {
		return string(name[i+1:])
	}
	return string(name)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// NodeIDs returns the NodeIds the document src uses in the places Remap
// rewrites, as written in the document (in its own namespace indexes),
// once each: the NodeIds the aliases stand for included, and an alias
// name where an attribute holds one.
func NodeIDs(src []byte) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(s []byte) {
		v := string(bytes.TrimSpace(s))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	err := walk(src, func(t token, stack []string) error {
		if contains(stack, "Extensions") || contains(stack, "NamespaceUris") {
			return nil
		}
		switch tok := t.tok.(type) {
		case xml.StartElement:
			for _, a := range tok.Attr {
				if nodeIDAttrs[a.Name.Local] {
					add([]byte(a.Value))
				}
			}
		case xml.CharData:
			if len(stack) > 0 && nodeIDText[stack[len(stack)-1]] {
				add(tok)
			}
		}
		return nil
	})
	return out, err
}

// Nodes returns the nodes the document src defines: their NodeId, as
// written in the document, and the name of the element that defines them
// (UAObject, UAObjectType, UAVariable, ...).
func Nodes(src []byte) (map[string]string, error) {
	out := map[string]string{}
	err := walk(src, func(t token, stack []string) error {
		s, ok := t.tok.(xml.StartElement)
		if !ok || len(stack) != 1 || len(s.Name.Local) < 3 || s.Name.Local[:2] != "UA" {
			return nil
		}
		for _, a := range s.Attr {
			if a.Name.Local == "NodeId" {
				out[a.Value] = s.Name.Local
			}
		}
		return nil
	})
	return out, err
}
