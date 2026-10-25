// SPDX-License-Identifier: MIT

package schema

import _ "embed"

// OpcUaGdsNodeSet2 is the NodeSet of the Global Discovery Server of OPC UA
// Part 12 (namespace http://opcfoundation.org/UA/GDS/, NodeIds in
// namespace index 1), which package gds/gdsserver imports.
//
//go:embed Opc.Ua.Gds.NodeSet2.xml
var OpcUaGdsNodeSet2 []byte
