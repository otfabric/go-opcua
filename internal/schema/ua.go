// SPDX-License-Identifier: MIT

// Package schema embeds the NodeSets the server imports itself: namespace 0
// (Opc.Ua.NodeSet2.xml), which every server imports, and the Global
// Discovery Server (Opc.Ua.Gds.NodeSet2.xml), which package gds/gdsserver
// imports. Package internal/nodeset reads them.
package schema

import _ "embed"

// OpcUaNodeSet2 is the NodeSet of namespace 0, http://opcfoundation.org/UA/.
//
//go:embed Opc.Ua.NodeSet2.xml
var OpcUaNodeSet2 []byte
