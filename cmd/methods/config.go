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
// Next: the GDS DirectoryType and CertificateDirectoryType, which need
// DataTypes outside namespace 0 and a package of their own (gds/gdsmethod).
var families = []family{
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/methods_gen.go",
		Types:   []string{"FileType", "FileDirectoryType", "ServerType"},
	},
	// The RoleSet and Role Methods of OPC 10000-18 §4.2 and §4.4.
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/roles_gen.go",
		Types:   []string{"RoleSetType", "RoleType"},
	},
	// The TrustList Methods of OPC 10000-12 §7.8.2 (the FileType Methods
	// of a TrustList are those of FileType).
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/trustlist_gen.go",
		Types:   []string{"TrustListType"},
	},
	// The PubSub configuration file (OPC 10000-14 §9.1.3.7) and the
	// Security Key Service (§8.4) Methods of Part 14.
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/pubsub_gen.go",
		Types:   []string{"PubSubConfigurationType", "PubSubKeyServiceType"},
	},
	// The push certificate management Methods of ServerConfigurationType
	// (OPC 10000-12 §7.10).
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/serverconfig_gen.go",
		Types:   []string{"ServerConfigurationType"},
	},
	// The SecurityGroup folders (OPC 10000-14 §8.5), the key push targets
	// of an SKS (§8.6, §8.7) and the Methods of the PublishSubscribe
	// Object (§9.1.3: SetSecurityKeys, AddConnection, RemoveConnection).
	{
		NodeSet: "internal/schema/Opc.Ua.NodeSet2.xml",
		Package: "uamethod",
		Out:     "uamethod/securitygroup_gen.go",
		Types: []string{
			"SecurityGroupFolderType", "PubSubKeyPushTargetType",
			"PubSubKeyPushTargetFolderType", "PublishSubscribeType",
		},
	},
}
