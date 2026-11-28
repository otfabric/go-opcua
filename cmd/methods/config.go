// SPDX-License-Identifier: MIT

package main

// family is a set of ObjectTypes of one NodeSet whose Methods the generator
// emits into one file of one package.
type family struct {
	// NodeSet is the NodeSet2 file, relative to the module root; it must be
	// pinned in schema/manifest.json.
	NodeSet string
	// Namespace is the URI of the namespace of the types; "" is namespace 0.
	Namespace string
	// Package and Out are the Go package and the file written, relative to
	// the module root. The package has the hand-written part of the
	// contracts (uamethod/method.go: Method, the argument checks and the
	// call).
	Package, Out string
	// Types are the BrowseNames of the ObjectTypes. The Methods of a type
	// are its own HasComponent Methods, not those of its supertypes.
	Types []string
}

// families are the Method families generated. A new family is a new entry:
// an ObjectType whose Methods use a DataType the generator does not know
// fails the generator (builtinTypes in model.go), which is where to add it.
//
// Next: TrustListType (OPC 10000-12 §7.8.2), PubSubConfigurationType
// (Part 14 §9.1.3.7) and PubSubKeyServiceType of Part 14, which resolve
// as they are (TestNextFamilies); the GDS DirectoryType and
// CertificateDirectoryType need DataTypes outside namespace 0 and a package
// of their own (gds/gdsmethod).
var families = []family{
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/methods_gen.go",
		Types:   []string{"FileType", "FileDirectoryType", "ServerType"},
	},
}
